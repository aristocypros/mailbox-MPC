# CLAUDE.md - AI Assistant Guide for Mailbox MPC

## Project Overview

**Mailbox MPC** is an asynchronous Multi-Party Computation (MPC) demo for crypto custody. It implements:

- **Feldman VSS (Verifiable Secret Sharing)** for Distributed Key Generation (DKG)
- **Threshold Schnorr-like Signing** where the private key never exists in full
- **Git-based "Bulletin Board"** for asynchronous message passing
- **SoftHSM (PKCS#11)** for hardware security module simulation

The key insight: nodes communicate through a shared Git repository (like a dead drop), enabling truly asynchronous operation where nodes never need to be online simultaneously.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         BULLETIN BOARD                            │
│                    (git-server: bare Git repo)                    │
│                                                                   │
│  board.git/                                                       │
│  ├── identity/          # Node public keys (RSA for encryption)  │
│  ├── dkg/{round_id}/    # DKG ceremony messages                  │
│  │   ├── commitments/   # Polynomial commitments                 │
│  │   ├── shares/        # Encrypted shares (node_to_node.enc)    │
│  │   └── complaints/    # Verification failures                  │
│  └── signing/{tx_id}/   # Signing ceremony messages              │
│      ├── request.json   # What to sign                           │
│      ├── session.json   # Locked participant set (first finalizer)│
│      ├── commitments/   # Nonce commitments (R_i)                │
│      ├── partials/      # Partial signatures (s_i)               │
│      └── result.json    # Final combined signature               │
└──────────────────────────────────────────────────────────────────┘
           ▲                    ▲                    ▲
           │                    │                    │
    ┌──────┴──────┐      ┌──────┴──────┐      ┌──────┴──────┐
    │    node1    │      │    node2    │      │    node3    │
    │  ┌────────┐ │      │  ┌────────┐ │      │  ┌────────┐ │
    │  │SoftHSM │ │      │  │SoftHSM │ │      │  │SoftHSM │ │
    │  │(shares)│ │      │  │(shares)│ │      │  │(shares)│ │
    │  └────────┘ │      │  └────────┘ │      │  └────────┘ │
    └─────────────┘      └─────────────┘      └─────────────┘
```

## Git Server (Bulletin Board)

The git-server acts as an asynchronous "dead drop" bulletin board enabling truly asynchronous MPC operation.

### Components

- **Base Image**: Alpine Linux with Git and OpenSSH
- **Repository**: Bare Git repo at `/var/lib/git/board.git`
- **SSH Authentication**: Public key only (no passwords)
- **SSH Key Watcher**: Background daemon that auto-registers node SSH keys from shared volume

### Initialization Flow (`init-repo.sh`)

1. **Export SSH host key** (for node verification - prevents MITM attacks):
   - Exports ed25519 or RSA host public key to `/shared_keys/git-server-host-key.pub`
   - Nodes use this to verify git-server identity before connecting

2. **Create bare repository** (runs as `git` user to avoid ownership issues):
   ```bash
   git init --bare /var/lib/git/board.git
   ```

3. **Initialize bulletin board structure** (identity/, dkg/, signing/ directories)

4. **Start SSH key watcher** (background loop):
   - Watches `/shared_keys/*.pub` for new node public keys
   - Appends to `/var/lib/git/.ssh/authorized_keys`
   - Deduplicates to prevent duplicate entries
   - Polling interval: 1 second

5. **Start SSH daemon** (foreground):
   ```bash
   exec /usr/sbin/sshd -D -e
   ```

### SSH Key Bootstrap Process

1. Git-server exports host key to `/shared_keys/git-server-host-key.pub`
2. Node waits for host key file and adds it to `known_hosts`
3. Node generates RSA keypair in entrypoint
4. Node writes public key to `/shared_keys/{NODE_ID}.pub` (Docker shared volume)
5. Git-server watcher detects and adds key to `authorized_keys`
6. Node waits for SSH connectivity with host key verification (`StrictHostKeyChecking yes`)

## Node Entrypoint (`entrypoint.sh`)

The node entrypoint handles bootstrap before the Python application runs:

1. **SSH Setup with Host Key Verification** (lines 6-38):
   - Generate RSA keypair if missing
   - Wait for git-server host key at `/shared_keys/git-server-host-key.pub`
   - Add host key to `known_hosts` for MITM protection
   - Configure SSH with `StrictHostKeyChecking yes` (secure by default)

2. **SSH Key Registration** (lines 40-43):
   - Copy public key to shared volume for git-server pickup

3. **Wait for SSH** (lines 45-70):
   - Wait for git-server port (nc -z)
   - Wait for SSH authentication to succeed (with host key verification)

4. **Git Configuration** (lines 72-74):
   - Set user.email and user.name for commits

5. **SoftHSM Setup** (lines 59-92):
   - Create `softhsm.conf` config file
   - Initialize token with PIN: `softhsm2-util --init-token`
   - Generate RSA-2048 identity key via `pkcs11-tool`
   - Idempotent: skips if already initialized

## Key Files and Their Purposes

### Node Application (`node/app/` - ~2,300 lines total)

| File | Lines | Purpose | Key Classes/Functions |
|------|-------|---------|----------------------|
| `main.py` | 858 | CLI entry point | All `@cli.command()` handlers (`init`, `status`, `dkg-*`, `sign-*`) |
| `hardware.py` | 669 | HSM interface (PKCS#11) | `HardwareToken` - keys, encryption, shares, **deterministic nonce derivation** (`derive_nonce`, `initialize_nonce_derivation`); `NonceDerivation`; `SecurityError` |
| `crypto.py` | 371 | Cryptographic primitives | `FeldmanDKG`, `ThresholdSigner`, `point_to_hex`, `hex_to_point`, `create_nonce_commitment_from_k` |
| `transport.py` | 165 | Git-based messaging | `Mailbox` - post/read/sync via Git with retry logic |
| `state.py` | 142 | Persistent state with safety | `RigidState` - atomic updates, nonce tracking, `record_nonce_derivation`, `_load_state_data` (internal) |
| `protocol.py` | 87 | Message type definitions | `IdentityMessage`, `DKGCommitment`, `SigningRequest`, `NonceCommitment`, `PartialSignature`, `FinalSignature` |

### Git Server (`git-server/`)

| File | Purpose |
|------|---------|
| `Dockerfile` | Alpine-based image with Git and OpenSSH |
| `init-repo.sh` | Initialize bare repo, SSH key watcher daemon |

### Infrastructure

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Orchestrates git-server + 3 nodes with shared volumes |
| `.env.node1/2/3` | Per-node HSM PINs (gitignored) |
| `test_ceremony.sh` | Automated end-to-end ceremony test |

## Cryptographic Protocol

### DKG (Distributed Key Generation) - Feldman VSS

```
Phase 1: Commitment
  Each node i:
    1. Generate random polynomial f_i(x) = a_i0 + a_i1*x + ... + a_i(t-1)*x^(t-1)
    2. Compute commitments C_ij = a_ij * G (curve points)
    3. Broadcast commitments to bulletin board

Phase 2: Share Distribution
  Each node i:
    1. For each node j: compute share s_ij = f_i(j)
    2. Encrypt s_ij with node j's RSA public key
    3. Post encrypted share to bulletin board

Phase 3: Verification & Finalization
  Each node j:
    1. Decrypt received shares
    2. Verify: s_ij * G == Σ (j^k * C_ik) for k=0..t-1
    3. Compute final share: S_j = Σ s_ij for all i
    4. Store S_j in HSM (never exportable in production)

Result:
  - Group public key: Y = Σ C_i0 (sum of free term commitments)
  - Each node has share S_j; no one knows full private key
```

### Threshold Signing (Schnorr-like)

```
Phase 1: Nonce Commitment
  Each participating node i:
    1. Generate random nonce k_i
    2. Compute R_i = k_i * G
    3. Post R_i to bulletin board
    ⚠️ CRITICAL: k_i must NEVER be reused

Phase 2: Partial Signature
  After seeing all commitments:
    1. Aggregate R = Σ R_i
    2. Compute challenge e = H(R || Y || message)
    3. Compute Lagrange coefficient λ_i
    4. Partial sig: s_i = k_i + e * λ_i * S_i
    5. Post s_i to bulletin board
    6. WIPE k_i from memory immediately

Phase 3: Combination
  When threshold reached:
    1. s = Σ s_i (sum of partial signatures)
    2. Signature = (R, s)
    3. Verify: s*G == R + e*Y
```

### Participant Set Coordination

**Critical Insight**: In threshold signing, ALL finalizers must use the SAME set of commitments for the aggregate R computation. Otherwise, the Lagrange coefficients won't match and the signature will be invalid.

**Problem scenario** (before fix):
```
3 nodes approve: R1, R2, R3 posted to board
Node1 finalizes: computes s1 with R = R1+R2+R3 (sees all 3 commitments)
Node2 finalizes: computes s2 with R = R1+R2+R3
Node3 never finalizes
Combining: R' = R1+R2 (only 2 partials) ≠ R = R1+R2+R3
Result: INVALID SIGNATURE!
```

**Solution: Session Locking**

The first node to finalize "locks" the participant set on the bulletin board:

```
signing/{request_id}/session.json:
{
  "participants": ["node1", "node2"],  // Exactly threshold nodes
  "locked_by": "node1",
  "timestamp": 1234567890.123
}
```

**Workflow**:
1. Multiple nodes may approve (post R_i commitments) - flexible human-in-the-loop
2. First finalizer locks `session.json` with exactly `threshold` participants
3. Subsequent finalizers read and use the locked participant set
4. All partial signatures use consistent R = Σ R_i for locked participants
5. Combining uses same participant set → Valid signature

**Asynchronous flexibility**:
- Any `threshold` nodes can finalize (no enforced order)
- Extra approvals don't block signing (just unused in this session)
- Nodes not in locked set are informed and can participate in future requests

## CLI Commands

```bash
# Initialization
python3 -m app.main init              # Setup HSM, post identity key
python3 -m app.main status            # Show node state

# DKG Ceremony (run on all nodes)
python3 -m app.main dkg-start --round-id <id> --threshold 2 --total 3
python3 -m app.main dkg-status --round-id <id>
python3 -m app.main dkg-distribute --round-id <id>
python3 -m app.main dkg-finalize --round-id <id>

# Signing (after DKG complete)
python3 -m app.main sign-request --message "..."
python3 -m app.main sign-list
python3 -m app.main sign-approve --request-id tx_xxxx  # Each approving node
python3 -m app.main sign-finalize --request-id tx_xxxx # Each approving node must run!
```

## Critical Safety Invariants

### 1. Deterministic Nonce Derivation (SLIP-10/BIP32 Style)

**Why this matters**: In Schnorr signing, reusing nonce `k` with different messages leaks the private key:
```
s1 = k + e1*lambda*S
s2 = k + e2*lambda*S
=> S = (s1-s2) / ((e1-e2)*lambda)  // PRIVATE KEY SHARE LEAKED!
```

The system implements **deterministic nonce derivation** combined with **triple-layer protection**:

```
┌─────────────────────────────────────────────────────────────────┐
│           DETERMINISTIC NONCE DERIVATION (SLIP-10 style)        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  HSM stores (one-time setup during 'init'):                     │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ NONCE_MASTER_SEED (32 bytes, non-extractable in prod)   │    │
│  │ MONOTONIC_COUNTER (uint64, only increments)             │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  Derivation formula:                                             │
│  k = HMAC-SHA512(seed, 0x00||counter||request_id||msg_hash)[0:32] mod n
│                                                                  │
│  Benefits:                                                       │
│  • Disaster recovery: regenerate nonces from master + counter   │
│  • HSM capacity: O(1) storage instead of O(n) per signing       │
│  • Same security via monotonic counter (never decrements)       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Implementation in hardware.py**:
```python
# Initialize during 'init' command (one-time)
hsm.initialize_nonce_derivation()

# Derive nonce during 'sign-approve' (atomically increments counter)
derivation = hsm.derive_nonce(request_id, message_hash)
# derivation.k = the nonce value
# derivation.R_hex = k * G (commitment)
# derivation.counter = which counter value was used
```

### 2. Triple-Layer Nonce Reuse Prevention

In addition to deterministic derivation, the system implements **three independent layers** of nonce reuse protection:

```python
# Layer 1: Local filesystem state (survives board rewind attacks)
# In state.py
if not state.check_nonce_unused(request_id):
    raise SecurityError("Nonce already used in local state!")

# Layer 2: HSM-backed storage (survives filesystem restore/VM snapshot attacks)
# In hardware.py
if hsm.has_nonce_commitment(request_id):
    raise SecurityError("Nonce already used in HSM!")

# Layer 3: Bulletin board check (survives local state corruption)
# In main.py sign-approve
if mailbox.read(f"signing/{request_id}/commitments/{NODE_ID}.json"):
    raise SecurityError("Commitment already on board!")
```

**Critical ordering when recording** (defense in depth):
```python
# 1. Derive nonce (atomically increments HSM counter)
derivation = hsm.derive_nonce(request_id, message_hash)

# 2. Store backup commitment in HSM
hsm.store_nonce_commitment(request_id, R_hex)

# 3. Record in local state with derivation metadata
state.record_nonce_derivation(request_id, counter, R_hex, msg_hash_hex)

# 4. Post to board LAST (only after all recordings succeed)
mailbox.post(f"signing/{request_id}/commitments/{NODE_ID}.json", ...)
```

**Attack scenarios protected against:**

| Attack Vector | Protection Layer |
|---------------|------------------|
| Git server force-push/rewind | Layer 1 (local) + Layer 2 (HSM counter) |
| VM snapshot restore | Layer 2 (HSM counter persists) + Layer 3 (board) |
| Local state.json corruption | Layer 2 (HSM) + Layer 3 (board) |
| Coordinated local + board attack | Layer 2 (HSM monotonic counter is isolated) |
| HSM capacity exhaustion | Deterministic derivation uses O(1) storage |

**Audit command**: `python3 -m app.main status` shows:
- Nonce consistency between local state and HSM
- Current monotonic counter value
- Number of derivation records

### 4. Atomic State Updates
```python
# In state.py - All writes use atomic rename pattern
tmp = self.state_file.with_suffix('.tmp')
with open(tmp, 'w') as f:
    json.dump(data, f)
    f.flush()
    os.fsync(f.fileno())  # Force to disk
os.replace(tmp, self.state_file)  # Atomic
```

### 5. Share Protection
```python
# In hardware.py - HSM_MODE controls security attributes via helper methods
# The HardwareToken class provides:
#   _get_sensitive_attr()    -> bool (based on HSM_MODE)
#   _get_extractable_attr()  -> bool (based on HSM_MODE)

# Production Mode (HSM_MODE=production - DEFAULT):
Attribute.SENSITIVE: True      # Cannot read VALUE attribute
Attribute.EXTRACTABLE: False   # Cannot export key material

# Demo Mode (HSM_MODE=demo):
Attribute.SENSITIVE: False     # Can read VALUE for debugging
Attribute.EXTRACTABLE: True    # Can export for testing

# Usage in hardware.py (all 6 secret storage locations):
session.create_object({
    Attribute.SENSITIVE: self._get_sensitive_attr(),
    Attribute.EXTRACTABLE: self._get_extractable_attr(),
    # ... other attributes
})
```

**Security Best Practice**: Always run production deployments with `HSM_MODE=production` (the default). Use `HSM_MODE=demo` only for development and testing where secret extraction is needed for verification.

### 6. File Locking (Deadlock Prevention)
```python
# In state.py - The update() method must NOT call load() directly
# because load() also acquires a lock, causing self-deadlock.
# Use _load_state_data() which reads without locking.
def update(self, updater):
    with open(self.lock_file, 'w') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        state = self._load_state_data()  # NOT self.load()!
        updater(state)
        self._save(state)
```

## Common Development Tasks

### Adding a New CLI Command

```python
# In main.py:
@cli.command('my-command')
@click.option('--param', required=True, help='Description')
def my_command(param):
    """Docstring shown in --help."""
    from .state import RigidState
    from .transport import Mailbox
    
    state = RigidState(DATA_DIR, NODE_ID)
    mailbox = Mailbox(GIT_URL, f"{DATA_DIR}/board", NODE_ID)
    
    # Implementation...
    click.echo("✅ Done")
```

### Adding a New Message Type

```python
# In protocol.py:
@dataclass
class MyMessage:
    node_id: str
    some_field: str
    timestamp: float
    
    def to_json(self) -> bytes:
        return json.dumps(asdict(self)).encode()
    
    @classmethod
    def from_json(cls, data: bytes) -> 'MyMessage':
        return cls(**json.loads(data))
```

### Modifying the Crypto Protocol

**Warning**: Changes to `crypto.py` require deep understanding of:
- Elliptic curve cryptography (secp256k1)
- Polynomial evaluation and Lagrange interpolation
- Feldman VSS security proofs

Key functions to understand:
```python
# Point serialization (compressed format)
point_to_hex(P)  # -> "02" or "03" + 64 hex chars
hex_to_point(h)  # -> Point on curve

# Lagrange coefficient for threshold
# λ_i = Π (j / (j - i)) for all j ≠ i, evaluated at x=0
```

## Testing

### Automated Test
```bash
./test_ceremony.sh
```

**Prerequisites:** The `docker-compose.yml` must have `HSM_MODE=demo` set for all nodes (this is the default). The test script verifies this before running.

**What the test does** (7 steps):
1. **Verify demo mode** - Checks all nodes have `HSM_MODE=demo`
2. **Initialize nodes** - Runs `init` on all 3 nodes (displays demo mode warning)
3. **DKG Phase 1** - All nodes run `dkg-start --round-id demo --threshold 2 --total 3`
4. **DKG Phase 2** - All nodes run `dkg-distribute --round-id demo`
5. **DKG Phase 3** - All nodes run `dkg-finalize --round-id demo`
6. **Sign approval** - node1 and node2 approve with interactive "y" confirmation
7. **Finalize** - Both approving nodes run `sign-finalize` to post partial signatures and combine

### Manual Testing
```bash
# Terminal 1
docker exec -it mpc-node1 bash
python3 -m app.main init
python3 -m app.main dkg-start --round-id test1 --threshold 2 --total 3

# Terminal 2
docker exec -it mpc-node2 bash
# ... same commands

# Check board state
docker exec mpc-node1 cat /app/data/board/dkg/test1/commitments/node1.json
```

### Debugging HSM Issues
```bash
# Inside container (PIN is already loaded from .env.nodeX):
export SOFTHSM2_CONF=/app/data/softhsm.conf
softhsm2-util --show-slots
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    --login --pin $PIN --list-objects
```

### Debugging Git/Transport Issues
```bash
# Inside container:
cd /app/data/board
git log --oneline -10
git status
ls -la dkg/*/commitments/
```

## Bugs Fixed (Historical Reference)

The following bugs were identified and fixed during initial development:

### 1. Git Server "Dubious Ownership" Error
**File:** `git-server/init-repo.sh`
**Problem:** Git security feature blocked operations when repo owned by different user
**Fix:** Run all git operations (init, clone, commit, push) as the `git` user in a single `su - git -c '...'` block

### 2. Missing SOFTHSM2_CONF Environment Variable
**File:** `docker-compose.yml`
**Problem:** `docker exec` commands didn't inherit env vars set in entrypoint
**Fix:** Added `SOFTHSM2_CONF=/app/data/softhsm.conf` to all node services in docker-compose.yml

### 3. State Update Deadlock
**File:** `node/app/state.py`
**Problem:** `update()` acquired exclusive lock then called `load()` which tried to acquire shared lock on same file = deadlock
**Fix:** Created `_load_state_data()` internal method that reads without locking, called from within `update()`

### 4. Missing Identity Element in fastecdsa
**File:** `node/app/crypto.py`
**Problem:** Code referenced `Point.IDENTITY_ELEMENT` which doesn't exist in `fastecdsa`
**Fix:** Created `IDENTITY = G + (-G)` constant and `is_identity()` helper function

### 5. PKCS#11 AttributeSensitive Error
**File:** `node/app/hardware.py`
**Problem:** `SENSITIVE: True` prevented reading VALUE attribute even with `EXTRACTABLE: True`
**Fix:** Changed to `SENSITIVE: False` for demo mode to allow reading DKG shares

### 6. Test Script stdin Handling
**File:** `test_ceremony.sh`
**Problem:** `echo "y" | docker exec ...` didn't work without `-i` flag
**Fix:** Added `run_node_interactive()` helper with `-i` flag for commands that need stdin

### 7. Incomplete Signing Finalization
**File:** `test_ceremony.sh`
**Problem:** Only node1 ran `sign-finalize`, but all approving nodes need to finalize
**Fix:** Added node2 finalize step to post both partial signatures before combining

### 8. Invalid Signature with Flexible Participant Set
**File:** `node/app/main.py`
**Problem:** When more nodes approved than finalized (e.g., 3 approve, 2 finalize), partial signatures were computed with R = R1+R2+R3 but combining used R = R1+R2 (only the finalizers), causing signature verification to fail.
**Fix:** Implemented `session.json` locking mechanism:
- First finalizer creates `signing/{request_id}/session.json` with locked participant set
- Subsequent finalizers read and use the same participant set
- All partial signatures and combining use consistent R value
- Supports asynchronous human-in-the-loop workflows where any threshold nodes can finalize

## Known Limitations and TODOs

### Current Limitations
1. **Demo-only security**: HSM shares are extractable for debugging
2. **No complaint handling**: DKG complaints are detected but not processed
3. **Single coordinator assumption**: Git conflicts possible under heavy load
4. **No key rotation**: Once DKG complete, no way to refresh shares
5. **Schnorr-like, not BIP-340**: Signature format not Bitcoin-compatible

### Future Improvements
- [ ] Implement ECDSA threshold signing (GG20/CGGMP) for Bitcoin/Ethereum
- [ ] Add DKG complaint resolution protocol
- [ ] Implement proactive secret sharing (share refresh)
- [ ] Add proper audit logging with signatures
- [ ] Support YubiKey HSM (real PKCS#11 device)
- [ ] Web UI for human operators

## Docker Volumes

| Volume | Mount Point | Purpose |
|--------|-------------|---------|
| `git_data` | `/var/lib/git` (git-server) | Persistent bulletin board repository |
| `shared_keys` | `/shared_keys` (all containers) | SSH key bootstrap (rw for nodes, ro for git-server) |
| `node1_data` | `/app/data` (node1) | Node 1 persistent state + HSM tokens |
| `node2_data` | `/app/data` (node2) | Node 2 persistent state + HSM tokens |
| `node3_data` | `/app/data` (node3) | Node 3 persistent state + HSM tokens |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_ID` | `node1` | Node identifier (node1, node2, etc.) |
| `PIN` | *(loaded from env_file)* | **HSM User PIN for authentication** - Must be unique per node, cryptographically random, 8+ digits. Loaded from `.env.node1`, `.env.node2`, `.env.node3` files via `env_file` directive in docker-compose.yml. **CRITICAL**: Never use weak or shared PINs in production. |
| `SO_PIN` | *(loaded from env_file)* | **HSM Security Officer PIN** - Administrative PIN for HSM token management (reset user PIN, destroy keys). Must be unique per node, cryptographically random, 8+ digits. Loaded from `.env.node*` files. **CRITICAL**: Must be different from user PIN and kept secure (CWE-798 fix). |
| `DATA_DIR` | `/app/data` | Persistent storage directory |
| `GIT_URL` | `ssh://git@git-server/var/lib/git/board.git` | Bulletin board URL |
| `SOFTHSM2_CONF` | `/app/data/softhsm.conf` | SoftHSM config file path (set in docker-compose.yml) |
| `HSM_MODE` | `production` | HSM security mode: `production` (non-extractable secrets) or `demo` (extractable for debugging) |

### PIN Security Requirements

**The HSM PINs are the authentication barriers protecting private key shares and all cryptographic operations.**

There are two types of PINs:
- **User PIN (`PIN`)**: Required for all cryptographic operations (signing, key usage)
- **Security Officer PIN (`SO_PIN`)**: Administrative access for token management (reset user PIN, destroy keys)

**Security Requirements for Both PINs:**

- **Uniqueness**: Each node MUST have different PINs (both PIN and SO_PIN unique per node)
- **Separation**: SO_PIN must be different from PIN on the same node
- **Strength**: Minimum 8 digits, cryptographically random (use `secrets.randbelow(10**8)` in Python)
- **Storage**: Stored in node-specific `.env.node*` files that are gitignored
- **Production**: Use hardware security modules (HSM) or secrets management systems (AWS Secrets Manager, HashiCorp Vault, etc.)
- **Rotation**: Implement PIN rotation procedures for production deployments

**Setup Process**:
```bash
# Generate strong unique PINs (example)
for i in 1 2 3; do
  PIN=$(python3 -c "import secrets; print(f'{secrets.randbelow(90000000)+10000000}')")
  SO_PIN=$(python3 -c "import secrets; print(f'{secrets.randbelow(90000000)+10000000}')")
  echo -e "PIN=$PIN\nSO_PIN=$SO_PIN" > .env.node$i
done

# Verify all 6 PINs are unique (3 nodes x 2 PINs each)
cat .env.node* | sort -u | wc -l  # Should output: 6
```

See `README.md` Prerequisites section for complete setup instructions.

## Docker Container Layout

### Node Container (Python 3.11-slim)

**Installed Packages**: softhsm2, opensc, libsofthsm2, git, openssh-client, netcat-openbsd, gcc, libgmp-dev, libmpc-dev

**Python Dependencies**: python-pkcs11, gitpython, cryptography, click, fastecdsa, attrs

```
/app/
├── app/                    # Python application code (~2,300 lines)
│   ├── __init__.py
│   ├── main.py             # CLI entry point (858 lines)
│   ├── crypto.py           # Feldman DKG, Threshold Signing (371 lines)
│   ├── hardware.py         # PKCS#11 HSM interface (669 lines)
│   ├── transport.py        # Git-based Mailbox (165 lines)
│   ├── state.py            # Atomic state management (142 lines)
│   └── protocol.py         # Message type definitions (87 lines)
└── data/                   # Persistent volume mount (node_data volume)
    ├── softhsm.conf        # HSM configuration
    ├── softhsm/tokens/     # HSM token storage (IDENTITY_KEY, DKG shares, nonces)
    ├── state.json          # RigidState (nonce tracking, DKG phase)
    ├── board/              # Git clone of bulletin board
    ├── dkg_*.json          # Local DKG ceremony state
    └── signer_*.json       # Signing session state
```

### Git Server Container (Alpine)

```
/var/lib/git/
├── .ssh/
│   └── authorized_keys     # Auto-populated by SSH key watcher
└── board.git/              # Bare Git repository (git_data volume)
    ├── objects/            # Git object database
    ├── refs/heads/master   # Main branch
    └── ...

/shared_keys/               # Bootstrap volume (shared_keys)
├── node1.pub               # Node SSH public keys
├── node2.pub
└── node3.pub
```

## Security Considerations

### For Production Use
1. **Set `HSM_MODE=production`** (the default) to ensure non-extractable secrets. Never use `HSM_MODE=demo` in production!
2. **Replace SoftHSM with real HSM** (YubiKey HSM, AWS CloudHSM, etc.)
3. **SSH host key verification** - Now enabled by default via shared volume key distribution
4. **Implement rate limiting** on signing requests
5. **Add multi-factor approval** for signing
6. **Audit log all operations** with tamper-evident storage

### Threat Model
- **Assumed**: Up to t-1 nodes can be compromised (for t-of-n threshold)
- **Protected against**: Key theft from any single node
- **Protected against**: Nonce reuse via state rewind attacks (triple-layer protection)
- **Protected against**: Bulletin board rewind (HSM + local state remember nonces)
- **Protected against**: MITM attacks on Git transport (SSH host key verification)
- **NOT protected against**: t or more colluding malicious nodes
- **NOT protected against**: Compromised Git server (can DoS, not steal keys)
- **NOT protected against**: HSM compromise (but real HSM would be tamper-resistant)

## Quick Reference

### Curve Parameters (secp256k1)
```
p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
```

### File Naming Conventions
```
identity/{node_id}.json           # Identity public key
dkg/{round_id}/commitments/{node_id}.json
dkg/{round_id}/shares/{sender}_to_{recipient}.enc
signing/{request_id}/request.json
signing/{request_id}/session.json # Locked participant set (first finalizer creates)
signing/{request_id}/commitments/{node_id}.json
signing/{request_id}/partials/{node_id}.json
signing/{request_id}/result.json
```

### State Machine

```
Node State:
  init → identity_posted → dkg_committed → dkg_distributed → dkg_finalized
                                                                    ↓
                                                              [ready to sign]

Signing State (per request):
  request_created → committed → partial_computed → [threshold] → combined
```
