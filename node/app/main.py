#!/usr/bin/env python3
"""MPC Node CLI - Human-in-the-loop async threshold signing."""
import click
import os
import time
import json
import hashlib
import secrets
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

NODE_ID = os.environ.get('NODE_ID', 'node1')
DATA_DIR = os.environ.get('DATA_DIR', '/app/data')
GIT_URL = os.environ.get('GIT_URL', 'ssh://git@git-server/var/lib/git/board.git')
HSM_MODE = os.environ.get('HSM_MODE', 'production')  # Valid values: 'demo' or 'production'

# PIN validation - no default value, must be explicitly configured
PIN = os.environ.get('PIN')
if not PIN:
    raise RuntimeError(
        "PIN environment variable is required but not set. "
        "The HSM PIN protects private key shares and must be configured explicitly. "
        "See README.md for PIN security requirements."
    )
if len(PIN) < 8:
    raise RuntimeError(
        f"PIN must be at least 8 digits for security (got {len(PIN)}). "
        "Use a cryptographically random PIN: python3 -c \"import secrets; print(f'{secrets.randbelow(10**8):08d}')\""
    )


@click.group()
def cli():
    """MPC Node - Asynchronous Threshold Custody Demo"""
    pass


@cli.command()
def init():
    """Initialize node: verify HSM, post identity public key, setup nonce derivation."""
    from .hardware import HardwareToken
    from .transport import Mailbox
    from .state import RigidState

    state = RigidState(DATA_DIR, NODE_ID)
    current = state.load()

    if current.identity_key_posted:
        click.echo(f"⚠️  {NODE_ID} already initialized.")
        return

    click.echo(f"🔧 Initializing {NODE_ID}...")

    # Security mode warning
    if HSM_MODE == 'demo':
        click.echo("")
        click.echo("⚠️  " + "=" * 60)
        click.echo("⚠️  WARNING: Running in DEMO MODE (HSM_MODE=demo)")
        click.echo("⚠️  " + "=" * 60)
        click.echo("⚠️  All secrets are configured as EXTRACTABLE.")
        click.echo("⚠️  Private key shares can be exported from the HSM.")
        click.echo("⚠️  DO NOT use this mode in production!")
        click.echo("⚠️  Set HSM_MODE=production for non-extractable secrets.")
        click.echo("⚠️  " + "=" * 60)
        click.echo("")
    else:
        click.echo(f"🔐 Security mode: PRODUCTION (non-extractable secrets)")

    click.echo("🔐 Connecting to HSM...")
    with HardwareToken() as hsm:
        hsm.login(PIN)
        pubkey = hsm.get_identity_public_key_pem()
        click.echo(f"   ✓ Identity key found ({len(pubkey)} bytes)")

        # Initialize deterministic nonce derivation system
        click.echo("🎲 Setting up deterministic nonce derivation...")
        if hsm.initialize_nonce_derivation():
            click.echo("   ✓ Nonce master seed created (SLIP-10/BIP32 style)")
            click.echo("   ✓ Monotonic counter initialized at 0")
        else:
            click.echo("   ✓ Nonce derivation already initialized")

    click.echo("📤 Posting identity to bulletin board...")
    mailbox = Mailbox(GIT_URL, f"{DATA_DIR}/board", NODE_ID)
    mailbox.post_identity(pubkey)

    def _update(s):
        s.initialized = True
        s.identity_key_posted = True
    state.update(_update)

    click.echo("✅ Initialization complete!")


@cli.command()
def status():
    """Show node status with security audit info."""
    from .state import RigidState
    from .transport import Mailbox
    from .hardware import HardwareToken

    state = RigidState(DATA_DIR, NODE_ID)
    current = state.load()

    click.echo(f"\n📊 Node Status: {NODE_ID}")
    click.echo("=" * 40)

    # Security mode display
    if HSM_MODE == 'demo':
        click.echo(f"HSM Mode:        ⚠️  DEMO (secrets extractable)")
    else:
        click.echo(f"HSM Mode:        🔐 PRODUCTION (secrets protected)")

    click.echo(f"Initialized:     {'✓' if current.initialized else '✗'}")
    click.echo(f"Identity Posted: {'✓' if current.identity_key_posted else '✗'}")
    click.echo(f"\n📋 DKG:")
    click.echo(f"   Round: {current.dkg.round_id or 'None'}")
    click.echo(f"   Phase: {current.dkg.phase}")
    click.echo(f"   Share: {'✓' if current.dkg.my_share_stored else '✗'}")
    if current.dkg.group_pubkey_hex:
        click.echo(f"   PubKey: {current.dkg.group_pubkey_hex[:32]}...")

    # Nonce tracking audit - compare local state vs HSM
    click.echo(f"\n🔏 Nonce Security Audit:")
    local_nonces = len(current.signing.used_nonces)
    click.echo(f"   Local state nonces: {local_nonces}")

    hsm_nonces = 0
    hsm_nonce_list = []
    deriv_info = None
    try:
        with HardwareToken() as hsm:
            hsm.login(PIN)
            hsm_nonce_list = hsm.list_used_nonces()
            hsm_nonces = len(hsm_nonce_list)

            # Get derivation system info
            deriv_info = hsm.get_nonce_derivation_info()

        click.echo(f"   HSM nonces:         {hsm_nonces}")

        # Check for discrepancies (security audit)
        local_set = set(current.signing.used_nonces.keys())
        hsm_set = set(hsm_nonce_list)

        if local_set == hsm_set:
            click.echo(f"   Consistency:        ✓ MATCHED")
        else:
            click.echo(f"   Consistency:        ⚠️  MISMATCH (potential issue)")
            only_local = local_set - hsm_set
            only_hsm = hsm_set - local_set
            if only_local:
                click.echo(f"   Only in local: {list(only_local)[:3]}...")
            if only_hsm:
                click.echo(f"   Only in HSM:   {list(only_hsm)[:3]}...")

        # Show deterministic derivation info
        click.echo(f"\n🎲 Deterministic Nonce Derivation (SLIP-10/BIP32):")
        if deriv_info:
            click.echo(f"   Master seed:        ✓ Initialized")
            click.echo(f"   Monotonic counter:  {deriv_info['current_counter']}")
            click.echo(f"   Derivation records: {deriv_info['derivation_count']}")
            local_derivations = len(current.signing.nonce_derivations)
            click.echo(f"   Local derivations:  {local_derivations}")
            if deriv_info['derivation_count'] == local_derivations:
                click.echo(f"   Derivation match:   ✓ MATCHED")
            else:
                click.echo(f"   Derivation match:   ⚠️  MISMATCH")
        else:
            click.echo(f"   Master seed:        ✗ Not initialized (run 'init')")

    except Exception as e:
        click.echo(f"   HSM nonces:         Error - {e}")

    try:
        mailbox = Mailbox(GIT_URL, f"{DATA_DIR}/board", NODE_ID)
        identities = mailbox.list_identities()
        click.echo(f"\n📬 Board: {', '.join(sorted(identities)) or 'Empty'}")
    except Exception as e:
        click.echo(f"\n📬 Board: Error - {e}")


@cli.command('dkg-start')
@click.option('--round-id', required=True, help='Unique round identifier')
@click.option('--threshold', default=2, help='Signing threshold (t)')
@click.option('--total', default=3, help='Total participants (n)')
def dkg_start(round_id, threshold, total):
    """DKG Phase 1: Generate polynomial, broadcast commitments."""
    from .state import RigidState
    from .transport import Mailbox
    from .crypto import FeldmanDKG
    from .protocol import DKGCommitment
    
    state = RigidState(DATA_DIR, NODE_ID)
    current = state.load()
    
    if current.dkg.phase not in ('none', ''):
        click.echo(f"⚠️  DKG already in progress: {current.dkg.round_id}")
        return
    
    click.echo(f"🎲 Starting DKG: {round_id} ({threshold}-of-{total})")
    
    dkg = FeldmanDKG(round_id, NODE_ID, threshold, total)
    commits = dkg.generate_polynomial()
    
    click.echo(f"   Generated {len(commits)} commitments")
    
    msg = DKGCommitment(
        node_id=NODE_ID,
        round_id=round_id,
        threshold=threshold,
        total_nodes=total,
        commitments=commits,
        timestamp=time.time()
    )
    
    mailbox = Mailbox(GIT_URL, f"{DATA_DIR}/board", NODE_ID)
    mailbox.post(f"dkg/{round_id}/commitments/{NODE_ID}.json", msg.to_json())
    
    # Save local state
    dkg_file = Path(DATA_DIR) / f"dkg_{round_id}.json"
    with open(dkg_file, 'w') as f:
        json.dump({
            'coefficients': dkg.state.my_coefficients,
            'commitments': commits,
            'threshold': threshold,
            'total_nodes': total
        }, f)
    
    def _update(s):
        s.dkg.round_id = round_id
        s.dkg.phase = 'committed'
        s.dkg.threshold = threshold
        s.dkg.total_nodes = total
    state.update(_update)
    
    click.echo("✅ DKG Phase 1 complete. Run 'dkg-distribute' next.")


@cli.command('dkg-status')
@click.option('--round-id', required=True)
def dkg_status(round_id):
    """Check DKG progress."""
    from .transport import Mailbox
    from .state import RigidState
    
    state = RigidState(DATA_DIR, NODE_ID)
    current = state.load()
    mailbox = Mailbox(GIT_URL, f"{DATA_DIR}/board", NODE_ID)
    
    click.echo(f"\n📊 DKG Round: {round_id}")
    click.echo("=" * 40)
    
    commits = mailbox.list_files(f"dkg/{round_id}/commitments")
    click.echo(f"Commitments ({len(commits)}/{current.dkg.total_nodes or '?'}):")
    for c in sorted(commits):
        node = c.replace('.json', '')
        marker = " ← you" if node == NODE_ID else ""
        click.echo(f"   ✓ {node}{marker}")
    
    shares = mailbox.list_files(f"dkg/{round_id}/shares")
    my_shares = [s for s in shares if s.endswith(f"_to_{NODE_ID}.enc")]
    click.echo(f"\nShares received ({len(my_shares)}):")
    for s in sorted(my_shares):
        sender = s.split('_to_')[0]
        click.echo(f"   ✓ from {sender}")


@cli.command('dkg-distribute')
@click.option('--round-id', required=True)
def dkg_distribute(round_id):
    """DKG Phase 2: Send encrypted shares to other nodes."""
    from .state import RigidState
    from .transport import Mailbox
    from .hardware import HardwareToken
    from .crypto import FeldmanDKG
    
    state = RigidState(DATA_DIR, NODE_ID)
    current = state.load()
    
    if current.dkg.phase == 'distributed':
        click.echo("⚠️  Already distributed.")
        return
    
    if current.dkg.phase != 'committed':
        click.echo(f"❌ Wrong phase: {current.dkg.phase}. Run dkg-start first.")
        return
    
    click.echo(f"📦 Distributing shares for: {round_id}")
    
    dkg_file = Path(DATA_DIR) / f"dkg_{round_id}.json"
    with open(dkg_file, 'r') as f:
        dkg_data = json.load(f)
    
    dkg = FeldmanDKG(round_id, NODE_ID, dkg_data['threshold'], dkg_data['total_nodes'])
    dkg.state.my_coefficients = dkg_data['coefficients']
    
    mailbox = Mailbox(GIT_URL, f"{DATA_DIR}/board", NODE_ID)
    identities = mailbox.list_identities()
    click.echo(f"   Found {len(identities)} nodes")

    # Worker function for parallel share encryption (crypto only, no Git operations)
    def encrypt_share(target):
        """Compute and encrypt share for a single target node (parallel-safe)."""
        if target == NODE_ID:
            return None

        try:
            share = dkg.compute_share_for(target)
            identity = mailbox.get_identity(target)

            if not identity:
                return {'target': target, 'status': 'no_identity', 'error': 'No identity found'}

            encrypted = HardwareToken.encrypt_for_recipient(
                identity.pubkey_pem.encode(),
                share.to_bytes(32, 'big')
            )

            return {'target': target, 'status': 'success', 'encrypted': encrypted}
        except Exception as e:
            return {'target': target, 'status': 'error', 'error': str(e)}

    # Parallelize share encryption (CPU-bound crypto operations)
    click.echo("   🔒 Encrypting shares in parallel...")
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=min(len(identities), 10)) as executor:
        results = list(executor.map(encrypt_share, identities))
    encryption_time = time.time() - start_time
    click.echo(f"   ⚡ Parallel encryption completed in {encryption_time:.3f}s")

    # Sequential posting to avoid Git conflicts
    click.echo("   📤 Posting shares sequentially...")
    for result in results:
        if result is None:
            continue
        if result['status'] == 'success':
            mailbox.post(f"dkg/{round_id}/shares/{NODE_ID}_to_{result['target']}.enc", result['encrypted'])
            click.echo(f"   ✓ Sent to {result['target']}")
        elif result['status'] == 'no_identity':
            click.echo(f"   ⚠️  No identity for {result['target']}")
        elif result['status'] == 'error':
            click.echo(f"   ❌ Error encrypting for {result['target']}: {result['error']}")
    
    def _update(s):
        s.dkg.phase = 'distributed'
    state.update(_update)
    
    click.echo("✅ DKG Phase 2 complete. Run 'dkg-finalize' next.")


@cli.command('dkg-finalize')
@click.option('--round-id', required=True)
def dkg_finalize(round_id):
    """DKG Phase 3: Verify shares, compute final share."""
    from .state import RigidState
    from .transport import Mailbox
    from .hardware import HardwareToken
    from .crypto import FeldmanDKG, hex_to_point, point_to_hex
    from .protocol import DKGCommitment
    
    state = RigidState(DATA_DIR, NODE_ID)
    current = state.load()
    
    if current.dkg.phase == 'finalized':
        click.echo("⚠️  Already finalized.")
        return
    
    click.echo(f"🔐 Finalizing DKG: {round_id}")
    
    dkg_file = Path(DATA_DIR) / f"dkg_{round_id}.json"
    with open(dkg_file, 'r') as f:
        dkg_data = json.load(f)
    
    dkg = FeldmanDKG(round_id, NODE_ID, dkg_data['threshold'], dkg_data['total_nodes'])
    dkg.state.my_coefficients = dkg_data['coefficients']
    dkg.state.my_commitments = [hex_to_point(c) for c in dkg_data['commitments']]
    
    mailbox = Mailbox(GIT_URL, f"{DATA_DIR}/board", NODE_ID)
    
    # Load commitments
    click.echo("📥 Loading commitments...")
    for cf in mailbox.list_files(f"dkg/{round_id}/commitments"):
        node = cf.replace('.json', '')
        if node == NODE_ID:
            continue
        data = mailbox.read(f"dkg/{round_id}/commitments/{cf}")
        msg = DKGCommitment.from_json(data)
        dkg.receive_commitment(node, msg.commitments)
        click.echo(f"   ✓ {node}")
    
    # Decrypt and verify shares
    click.echo("🔓 Decrypting shares...")
    shares = mailbox.list_files(f"dkg/{round_id}/shares")
    my_shares = [s for s in shares if s.endswith(f"_to_{NODE_ID}.enc")]

    expected = dkg_data['total_nodes'] - 1
    if len(my_shares) < expected:
        click.echo(f"⏳ Only {len(my_shares)}/{expected} shares. Wait for others.")
        return

    # Worker function for parallel share decryption and verification
    def decrypt_and_verify_share(share_file):
        """Decrypt and verify a single share (parallel-safe with own HSM session)."""
        sender = share_file.split('_to_')[0]

        try:
            encrypted = mailbox.read(f"dkg/{round_id}/shares/{share_file}")

            # Each thread gets its own HSM session (PKCS#11 is thread-safe)
            with HardwareToken() as hsm:
                hsm.login(PIN)
                share_bytes = hsm.decrypt_with_identity_key(encrypted)
                share_value = int.from_bytes(share_bytes, 'big')

            # Verify the share (cryptographic verification)
            if not dkg.receive_share(sender, share_value):
                return {'sender': sender, 'status': 'verify_failed'}

            return {'sender': sender, 'status': 'success', 'share_value': share_value}
        except Exception as e:
            return {'sender': sender, 'status': 'error', 'error': str(e)}

    # Parallelize share decryption and verification (crypto-heavy operations)
    click.echo("   🔒 Decrypting and verifying shares in parallel...")
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=min(len(my_shares), 10)) as executor:
        results = list(executor.map(decrypt_and_verify_share, my_shares))
    decryption_time = time.time() - start_time
    click.echo(f"   ⚡ Parallel decryption/verification completed in {decryption_time:.3f}s")

    # Check results for any failures - collect ALL errors before aborting
    failures = []
    for result in results:
        if result['status'] == 'success':
            click.echo(f"   ✓ {result['sender']} verified")
        elif result['status'] == 'verify_failed':
            click.echo(f"   ❌ Verification failed from {result['sender']}!")
            failures.append(f"{result['sender']}: verification failed")
        elif result['status'] == 'error':
            click.echo(f"   ❌ Decrypt failed from {result['sender']}: {result['error']}")
            failures.append(f"{result['sender']}: {result['error']}")

    # Abort if ANY verification failed
    if failures:
        click.echo(f"\n💥 DKG finalization ABORTED due to {len(failures)} failure(s):")
        for failure in failures:
            click.echo(f"   • {failure}")
        click.echo("\nℹ️  All shares must verify correctly. Check bulletin board for complaints.")
        return

    # All verifications passed - proceed to finalize
    click.echo("🧮 Computing final share...")
    final_share, group_pk = dkg.finalize()
    pk_hex = point_to_hex(group_pk)

    click.echo("💾 Storing in HSM...")
    with HardwareToken() as hsm:
        hsm.login(PIN)
        hsm.store_dkg_share(round_id, final_share.to_bytes(32, 'big'))
    
    def _update(s):
        s.dkg.phase = 'finalized'
        s.dkg.my_share_stored = True
        s.dkg.group_pubkey_hex = pk_hex
    state.update(_update)
    
    click.echo(f"✅ DKG complete!")
    click.echo(f"   Group Public Key: {pk_hex}")


@cli.command('sign-request')
@click.option('--message', required=True, help='Message to sign')
def sign_request(message):
    """Create a signing request."""
    from .transport import Mailbox
    from .protocol import SigningRequest
    
    request_id = f"tx_{secrets.token_hex(4)}"
    message_hash = hashlib.sha256(message.encode()).hexdigest()
    
    msg = SigningRequest(
        request_id=request_id,
        message_hash=message_hash,
        message_preview=message[:50],
        requester=NODE_ID,
        timestamp=time.time()
    )
    
    mailbox = Mailbox(GIT_URL, f"{DATA_DIR}/board", NODE_ID)
    mailbox.post(f"signing/{request_id}/request.json", msg.to_json())
    
    click.echo(f"✅ Request created: {request_id}")
    click.echo(f"   Message: {message[:40]}...")
    click.echo(f"   Hash: {message_hash}")


@cli.command('sign-list')
def sign_list():
    """List signing requests."""
    from .transport import Mailbox
    
    mailbox = Mailbox(GIT_URL, f"{DATA_DIR}/board", NODE_ID)
    mailbox.sync()
    
    signing_path = mailbox.local_path / "signing"
    if not signing_path.exists():
        click.echo("No signing requests.")
        return
    
    click.echo("\n📋 Signing Requests:")
    for req_dir in sorted(signing_path.iterdir()):
        if not req_dir.is_dir():
            continue
        
        req_file = req_dir / "request.json"
        if not req_file.exists():
            continue
        
        with open(req_file) as f:
            req = json.load(f)
        
        commits = list((req_dir / "commitments").glob("*.json")) if (req_dir / "commitments").exists() else []
        partials = list((req_dir / "partials").glob("*.json")) if (req_dir / "partials").exists() else []
        has_result = (req_dir / "result.json").exists()
        
        status = "✅ SIGNED" if has_result else f"⏳ {len(commits)}c/{len(partials)}p"
        
        click.echo(f"\n{req_dir.name}: {status}")
        click.echo(f"   From: {req.get('requester')}")
        click.echo(f"   Msg: {req.get('message_preview', '')[:30]}...")


@cli.command('sign-approve')
@click.option('--request-id', required=True)
def sign_approve(request_id):
    """Approve a signing request with triple-layer nonce protection."""
    from .state import RigidState
    from .transport import Mailbox
    from .hardware import HardwareToken, SecurityError
    from .crypto import ThresholdSigner, hex_to_point
    from .protocol import SigningRequest, NonceCommitment

    state = RigidState(DATA_DIR, NODE_ID)
    current = state.load()

    if not current.dkg.my_share_stored:
        click.echo("❌ DKG not complete.")
        return

    # =========================================================================
    # TRIPLE-LAYER NONCE REUSE PROTECTION
    # =========================================================================
    # Layer 1: Check local filesystem state (survives board rewind)
    # Layer 2: Check HSM for nonce commitment (survives filesystem restore)
    # Layer 3: Check bulletin board (survives local state corruption)
    # ALL THREE must pass before we proceed.
    # =========================================================================

    # Layer 1: Local state check
    if not state.check_nonce_unused(request_id):
        click.echo("❌ SECURITY: Nonce already used (local state)!")
        click.echo("   This request was already approved by this node.")
        return

    mailbox = Mailbox(GIT_URL, f"{DATA_DIR}/board", NODE_ID)

    # Layer 2: HSM check (do this early, before any user interaction)
    with HardwareToken() as hsm:
        hsm.login(PIN)

        if hsm.has_nonce_commitment(request_id):
            stored_R = hsm.get_nonce_commitment(request_id)
            click.echo("❌ SECURITY: Nonce already used (HSM)!")
            click.echo(f"   Stored commitment: {stored_R[:32]}...")
            click.echo("   This may indicate a state restore attack.")
            return

        # Layer 3: Bulletin board check
        existing_commitment = mailbox.read(f"signing/{request_id}/commitments/{NODE_ID}.json")
        if existing_commitment:
            click.echo("❌ SECURITY: Commitment already on bulletin board!")
            click.echo("   This may indicate local state was corrupted/restored.")
            # Attempt to recover by recording in local state and HSM
            try:
                existing_data = json.loads(existing_commitment)
                existing_R = existing_data.get('R_commitment', 'unknown')
                click.echo(f"   Existing R: {existing_R[:32]}...")
                # Record in HSM to prevent future issues
                hsm.store_nonce_commitment(request_id, existing_R)
                state.record_nonce_use(request_id, existing_R)
                click.echo("   Recovered: recorded existing commitment to HSM and local state.")
            except Exception as e:
                click.echo(f"   Recovery failed: {e}")
            return

    # All safety checks passed - now proceed with request review
    req_data = mailbox.read(f"signing/{request_id}/request.json")
    
    if not req_data:
        click.echo(f"❌ Request {request_id} not found.")
        return

    req = SigningRequest(**json.loads(req_data))

    click.echo(f"\n📋 Request: {request_id}")
    click.echo(f"   From: {req.requester}")
    click.echo(f"   Message: {req.message_preview}")
    click.echo(f"   Hash: {req.message_hash}")
    click.echo(f"\n🔒 Security checks passed:")
    click.echo(f"   Layer 1: Local state - nonce unused")
    click.echo(f"   Layer 2: HSM - no prior commitment")
    click.echo(f"   Layer 3: Board - no existing commitment")

    if not click.confirm("\n🤔 Approve?"):
        click.echo("❌ Rejected.")
        return

    with HardwareToken() as hsm:
        hsm.login(PIN)

        # In production mode, share extraction is blocked (SENSITIVE=True)
        if hsm.is_production_mode():
            click.echo("❌ Cannot sign in production mode with SoftHSM.")
            click.echo("   Production mode prevents share extraction (SENSITIVE=True).")
            click.echo("   For SoftHSM demo, set HSM_MODE=demo to enable signing.")
            click.echo("   For real production, use an HSM that supports secp256k1 operations.")
            return

        share = int.from_bytes(hsm.get_dkg_share(current.dkg.round_id), 'big')

        # =================================================================
        # DETERMINISTIC NONCE DERIVATION (SLIP-10/BIP32 style)
        # =================================================================
        # Instead of generating a random nonce, we derive it deterministically
        # from a master seed stored in HSM + a monotonic counter.
        #
        # Benefits:
        # - Disaster recovery: Can regenerate nonces from master + counter
        # - HSM capacity: O(1) storage instead of O(n) per signing session
        # - Same security guarantees via monotonic counter
        #
        # Formula: k = HMAC(master_seed, counter || request_id || msg_hash) mod n
        # =================================================================

        message_hash_bytes = bytes.fromhex(req.message_hash)

        try:
            # Derive nonce deterministically (counter is atomically incremented)
            derivation = hsm.derive_nonce(request_id, message_hash_bytes)
            click.echo(f"   HSM: nonce derived (counter={derivation.counter})")
        except SecurityError as e:
            click.echo(f"❌ SECURITY: {e}")
            return
        except Exception as e:
            click.echo(f"❌ Nonce derivation failed: {e}")
            return

        R_hex = derivation.R_hex

        # Create signer session with derived nonce
        signer = ThresholdSigner(
            NODE_ID, share, hex_to_point(current.dkg.group_pubkey_hex)
        )
        signer.create_nonce_commitment_from_k(
            request_id, message_hash_bytes,
            derivation.k, derivation.R_hex
        )

        # Also store traditional nonce commitment for backward compatibility
        # with triple-layer checking (this is a backup/audit record)
        try:
            hsm.store_nonce_commitment(request_id, R_hex)
            click.echo(f"   HSM: nonce commitment stored (backup record)")
        except SecurityError as e:
            # This is expected if derivation already recorded it
            click.echo(f"   HSM: commitment already recorded via derivation")
        except Exception as e:
            click.echo(f"   Warning: backup record failed: {e}")

    # Step 2: Local state recording (with derivation metadata)
    state.record_nonce_derivation(
        request_id,
        derivation.counter,
        derivation.R_hex,
        derivation.message_hash_hex
    )
    click.echo(f"   Local: nonce derivation recorded (counter={derivation.counter})")

    # Step 3: Post to bulletin board (only after both recordings)
    msg = NonceCommitment(
        node_id=NODE_ID,
        request_id=request_id,
        R_commitment=R_hex,
        timestamp=time.time()
    )
    mailbox.post(f"signing/{request_id}/commitments/{NODE_ID}.json", msg.to_json())
    click.echo(f"   Board: commitment posted")

    # Save signer state for finalization (using JSON for safe serialization)
    signer_file = Path(DATA_DIR) / f"signer_{request_id}.json"
    with open(signer_file, 'wb') as f:
        f.write(signer.to_json())

    click.echo("\n✅ Approved with triple-layer nonce protection.")
    click.echo("   Run 'sign-finalize' when threshold reached.")


@cli.command('sign-finalize')
@click.option('--request-id', required=True)
def sign_finalize(request_id):
    """Finalize signing after threshold."""
    from .state import RigidState
    from .transport import Mailbox
    from .crypto import ThresholdSigner, hex_to_point
    from .protocol import NonceCommitment, PartialSignature, FinalSignature, SigningRequest
    
    state = RigidState(DATA_DIR, NODE_ID)
    current = state.load()
    mailbox = Mailbox(GIT_URL, f"{DATA_DIR}/board", NODE_ID)
    
    signer_file = Path(DATA_DIR) / f"signer_{request_id}.json"
    if not signer_file.exists():
        click.echo("❌ No session. Run 'sign-approve' first.")
        return

    with open(signer_file, 'rb') as f:
        signer = ThresholdSigner.from_json(f.read())
    
    # Collect commitments
    commit_files = mailbox.list_files(f"signing/{request_id}/commitments")

    if len(commit_files) < current.dkg.threshold:
        click.echo(f"⏳ {len(commit_files)}/{current.dkg.threshold} commitments. Waiting...")
        return

    # Check if this node has a commitment
    my_commit = f"{NODE_ID}.json"
    if my_commit not in commit_files:
        click.echo(f"❌ This node ({NODE_ID}) hasn't approved this request yet.")
        return

    # =========================================================================
    # PARTICIPANT SET COORDINATION
    # =========================================================================
    # In threshold signing, ALL finalizers must use the SAME set of commitments
    # for R computation. Otherwise, the Lagrange coefficients won't match and
    # the signature will be invalid.
    #
    # Solution: First finalizer "locks in" the participant set on the board.
    # Subsequent finalizers use that locked set.
    # =========================================================================

    session_file = f"signing/{request_id}/session.json"
    session_data = mailbox.read(session_file)

    if session_data:
        # Use the locked participant set
        session = json.loads(session_data)
        participants = session['participants']
        click.echo(f"📥 Using locked participant set: {participants}")

        if NODE_ID not in participants:
            click.echo(f"⚠️  This node ({NODE_ID}) is not in the locked participant set.")
            click.echo(f"   Your commitment won't be used in this signing session.")
            click.echo(f"   (Another signing request can use your commitment)")
            return
    else:
        # First finalizer - lock in participant set
        # Strategy: use threshold commitments, preferring this node + earliest others
        sorted_commits = sorted(commit_files)

        # Ensure this node is included, then fill with others up to threshold
        if my_commit in sorted_commits[:current.dkg.threshold]:
            selected_commits = sorted_commits[:current.dkg.threshold]
        else:
            # Include self + first (t-1) others
            others = [c for c in sorted_commits if c != my_commit]
            selected_commits = sorted([my_commit] + others[:current.dkg.threshold - 1])

        participants = [c.replace('.json', '') for c in selected_commits]

        # Lock the participant set on the board
        session_info = {
            'participants': participants,
            'locked_by': NODE_ID,
            'timestamp': time.time()
        }
        mailbox.post(session_file, json.dumps(session_info).encode())
        click.echo(f"📥 Locked participant set: {participants}")

    click.echo(f"   Loading {len(participants)} commitments (threshold={current.dkg.threshold})...")

    for node in participants:
        cf = f"{node}.json"
        data = mailbox.read(f"signing/{request_id}/commitments/{cf}")
        msg = NonceCommitment(**json.loads(data))
        signer.receive_nonce_commitment(request_id, node, msg.R_commitment)
        click.echo(f"   ✓ {node}")
    
    click.echo("📝 Computing partial signature...")
    partial_s = signer.compute_partial_signature(request_id, participants)
    
    msg = PartialSignature(
        node_id=NODE_ID,
        request_id=request_id,
        partial_s=partial_s,
        timestamp=time.time()
    )
    mailbox.post(f"signing/{request_id}/partials/{NODE_ID}.json", msg.to_json())
    click.echo("✅ Partial signature posted.")
    
    # Check threshold
    partial_files = mailbox.list_files(f"signing/{request_id}/partials")
    click.echo(f"   Partials: {len(partial_files)}/{current.dkg.threshold}")
    
    if len(partial_files) >= current.dkg.threshold:
        click.echo("🎉 Threshold reached! Combining...")

        # Load partials only from the selected participants
        partials = {}
        for node in participants:
            pf = f"{node}.json"
            data = mailbox.read(f"signing/{request_id}/partials/{pf}")
            if data:
                p = PartialSignature(**json.loads(data))
                partials[node] = int(p.partial_s, 16)

        if len(partials) < current.dkg.threshold:
            click.echo(f"⏳ Only {len(partials)}/{current.dkg.threshold} partials from selected participants.")
            return

        # CRITICAL: Use the same `participants` list that was used for partial sig computation
        R_hex, s_hex = ThresholdSigner.combine_signatures(
            partials,
            signer.sessions[request_id].nonce_commitments,
            participants  # Must match the set used in compute_partial_signature
        )
        
        # Verify
        req_data = mailbox.read(f"signing/{request_id}/request.json")
        req = SigningRequest(**json.loads(req_data))
        
        if ThresholdSigner.verify_signature(
            R_hex, s_hex,
            hex_to_point(current.dkg.group_pubkey_hex),
            bytes.fromhex(req.message_hash)
        ):
            click.echo("✅ VALID SIGNATURE!")
            
            result = FinalSignature(
                request_id=request_id,
                R=R_hex,
                s=s_hex,
                participants=participants,  # The deterministic set used for signing
                timestamp=time.time()
            )
            mailbox.post(f"signing/{request_id}/result.json", result.to_json())
            
            click.echo(f"   R: {R_hex}")
            click.echo(f"   s: {s_hex}")
        else:
            click.echo("❌ INVALID SIGNATURE!")


if __name__ == '__main__':
    cli()
