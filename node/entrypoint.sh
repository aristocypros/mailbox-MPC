#!/bin/bash
set -e

echo "=== Initializing $NODE_ID ==="

# 1. SSH Setup
mkdir -p /root/.ssh
chmod 700 /root/.ssh

if [ ! -f /root/.ssh/id_rsa ]; then
    echo "Generating SSH key..."
    ssh-keygen -t rsa -N "" -f /root/.ssh/id_rsa -q
fi

# Wait for git-server host key to be available (CWE-295 fix)
# This ensures we can verify the server's identity and prevent MITM attacks
echo "Waiting for git-server host key..."
HOST_KEY_FILE="/shared_keys/git-server-host-key.pub"
MAX_ATTEMPTS=30
ATTEMPT=0
until [ -f "$HOST_KEY_FILE" ] && [ -s "$HOST_KEY_FILE" ]; do
    ATTEMPT=$((ATTEMPT + 1))
    if [ $ATTEMPT -ge $MAX_ATTEMPTS ]; then
        echo "ERROR: git-server host key not available after $MAX_ATTEMPTS attempts"
        exit 1
    fi
    sleep 1
done
echo "Git-server host key found."

# Add git-server host key to known_hosts for verification
# Format in file is: hostname key-type key-data
cp "$HOST_KEY_FILE" /root/.ssh/known_hosts
chmod 644 /root/.ssh/known_hosts
echo "Git-server host key added to known_hosts."

# SSH config for git-server with strict host key verification (CWE-295 fix)
printf '%s\n' \
    "Host git-server" \
    "    StrictHostKeyChecking yes" \
    "    UserKnownHostsFile /root/.ssh/known_hosts" \
    "    LogLevel ERROR" \
    "    User git" \
    > /root/.ssh/config
chmod 600 /root/.ssh/config

# 2. Register SSH key via shared volume (no SSH required for bootstrap)
echo "Registering SSH key via shared volume..."
cp /root/.ssh/id_rsa.pub "/shared_keys/${NODE_ID}.pub"
echo "SSH key written to /shared_keys/${NODE_ID}.pub"

# 3. Wait for git-server SSH port to be available
echo "Waiting for git-server SSH port..."
MAX_ATTEMPTS=30
ATTEMPT=0
until nc -z git-server 22 2>/dev/null; do
    ATTEMPT=$((ATTEMPT + 1))
    if [ $ATTEMPT -ge $MAX_ATTEMPTS ]; then
        echo "ERROR: git-server port not available after $MAX_ATTEMPTS attempts"
        exit 1
    fi
    sleep 1
done
echo "git-server port is ready."

# 4. Wait for SSH key to be registered (git-server watcher adds it)
echo "Waiting for SSH key to be registered..."
ATTEMPT=0
until ssh -o ConnectTimeout=2 git@git-server "echo ok" 2>/dev/null; do
    ATTEMPT=$((ATTEMPT + 1))
    if [ $ATTEMPT -ge $MAX_ATTEMPTS ]; then
        echo "ERROR: SSH key not registered after $MAX_ATTEMPTS attempts"
        exit 1
    fi
    sleep 1
done
echo "SSH authentication successful."

# 5. Git Identity
git config --global user.email "$NODE_ID@mpc.local"
git config --global user.name "$NODE_ID"

# 6. SoftHSM Setup
mkdir -p /app/data
export SOFTHSM2_CONF=/app/data/softhsm.conf

if [ ! -d "/app/data/softhsm/tokens" ]; then
    echo "Initializing SoftHSM..."
    mkdir -p /app/data/softhsm/tokens
    
    # Create config file
    printf '%s\n' \
        "directories.tokendir = /app/data/softhsm/tokens" \
        "objectstore.backend = file" \
        "log.level = INFO" \
        > "$SOFTHSM2_CONF"
    
    # Validate SO_PIN is set (CWE-798 fix: avoid hardcoded credentials)
    if [ -z "$SO_PIN" ]; then
        echo "ERROR: SO_PIN environment variable not set."
        echo "The Security Officer PIN is required for HSM token initialization."
        echo "Please set SO_PIN in your .env.node* file."
        exit 1
    fi

    # Initialize token with secure SO_PIN from environment
    softhsm2-util --init-token --slot 0 --label "MPC_Token" --pin "$PIN" --so-pin "$SO_PIN"
    
    # Find PKCS11 library
    PKCS11_LIB=$(find /usr -name "libsofthsm2.so" 2>/dev/null | head -1)
    if [ -z "$PKCS11_LIB" ]; then
        echo "ERROR: Could not find libsofthsm2.so"
        exit 1
    fi
    echo "Using PKCS11 library: $PKCS11_LIB"
    
    # Generate identity key
    pkcs11-tool --module "$PKCS11_LIB" --login --pin "$PIN" \
        --keypairgen --key-type rsa:2048 --label "IDENTITY_KEY" --id 01
    
    echo "SoftHSM initialized with IDENTITY_KEY"
else
    echo "SoftHSM already initialized."
fi

echo "=== $NODE_ID ready ==="
exec "$@"
