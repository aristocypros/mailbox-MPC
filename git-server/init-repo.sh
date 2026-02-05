#!/bin/bash
set -e

# Export SSH host key for node verification (CWE-295 fix)
# Nodes will use this to verify git-server identity and prevent MITM attacks
echo "Exporting SSH host key for node verification..."
HOST_KEY_FILE="/shared_keys/git-server-host-key.pub"

# Prefer ed25519, fallback to rsa if not available
if [ -f /etc/ssh/ssh_host_ed25519_key.pub ]; then
    HOST_KEY_TYPE="ed25519"
    HOST_KEY_CONTENT=$(cat /etc/ssh/ssh_host_ed25519_key.pub)
elif [ -f /etc/ssh/ssh_host_rsa_key.pub ]; then
    HOST_KEY_TYPE="rsa"
    HOST_KEY_CONTENT=$(cat /etc/ssh/ssh_host_rsa_key.pub)
else
    echo "ERROR: No SSH host key found. Cannot enable host key verification."
    exit 1
fi

# Write host key in known_hosts format: hostname key-type key-data
# Include both 'git-server' hostname and IP for flexibility
echo "git-server ${HOST_KEY_CONTENT}" > "$HOST_KEY_FILE"
chmod 644 "$HOST_KEY_FILE"
echo "SSH host key (${HOST_KEY_TYPE}) exported to ${HOST_KEY_FILE}"

if [ ! -d "/var/lib/git/board.git" ]; then
    echo "Initializing bare repository..."

    # Run all git operations as the git user to avoid ownership issues
    su - git -c '
        set -e
        git init --bare /var/lib/git/board.git

        # Create initial commit so clones work
        TEMP_DIR=$(mktemp -d)
        cd "$TEMP_DIR"
        git clone /var/lib/git/board.git repo
        cd repo
        git config user.email "init@mpc.local"
        git config user.name "init"
        mkdir -p identity dkg signing
        echo "# MPC Bulletin Board" > README.md
        git add .
        git commit -m "Initial commit"
        git push origin master
        cd /
        rm -rf "$TEMP_DIR"
    '

    echo "Repository initialized."
fi

# Start SSH key watcher - checks /shared_keys for new node pubkeys and adds to authorized_keys
echo "Starting SSH key watcher..."
(
    AUTHORIZED_KEYS="/var/lib/git/.ssh/authorized_keys"
    while true; do
        # Check for any .pub files in /shared_keys
        if [ -d "/shared_keys" ]; then
            for pubkey in /shared_keys/*.pub; do
                [ -f "$pubkey" ] || continue

                # Read the key
                KEY_CONTENT=$(cat "$pubkey" 2>/dev/null)
                [ -n "$KEY_CONTENT" ] || continue

                # Check if key already exists in authorized_keys (avoid duplicates)
                if ! grep -qF "$KEY_CONTENT" "$AUTHORIZED_KEYS" 2>/dev/null; then
                    echo "$KEY_CONTENT" >> "$AUTHORIZED_KEYS"
                    chown git:git "$AUTHORIZED_KEYS"
                    chmod 600 "$AUTHORIZED_KEYS"
                    echo "Added SSH key from $(basename "$pubkey")"
                fi
            done
        fi
        sleep 1
    done
) &

echo "Starting SSH daemon..."
exec /usr/sbin/sshd -D -e
