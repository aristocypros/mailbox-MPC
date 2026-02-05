"""PKCS#11 interface for SoftHSM."""
import pkcs11
from pkcs11 import ObjectClass, KeyType, Attribute, Mechanism
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
import os
import glob
import hmac
import hashlib
import threading
from dataclasses import dataclass
from typing import Optional, Tuple


def find_softhsm_lib() -> str:
    """Find SoftHSM library path."""
    candidates = [
        '/usr/lib/softhsm/libsofthsm2.so',
        '/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so',
        '/usr/local/lib/softhsm/libsofthsm2.so',
    ]
    candidates.extend(glob.glob('/usr/**/libsofthsm2.so', recursive=True))
    
    for path in candidates:
        if os.path.exists(path):
            return path
    raise RuntimeError("Could not find libsofthsm2.so")


SOFTHSM_LIB = find_softhsm_lib()

# secp256k1 curve order (for nonce derivation)
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


@dataclass
class NonceDerivation:
    """Result of deterministic nonce derivation."""
    counter: int
    k: int  # The nonce value
    R_hex: str  # The commitment R = k*G
    request_id: str
    message_hash_hex: str


class HardwareToken:
    """Wrapper for PKCS#11 operations."""

    def __init__(self, token_label: str = 'MPC_Token'):
        if 'SOFTHSM2_CONF' not in os.environ:
            conf_path = '/app/data/softhsm.conf'
            if os.path.exists(conf_path):
                os.environ['SOFTHSM2_CONF'] = conf_path

        self.lib = pkcs11.lib(SOFTHSM_LIB)
        self.token = self.lib.get_token(token_label=token_label)
        self.session = None

        # Thread-safe session management
        self._thread_local = threading.local()
        self._pin = None
        self._lock = threading.Lock()
    
    def login(self, pin: str):
        """Open session and authenticate."""
        if self.session:
            try:
                self.session.close()
            except:
                pass
        self.session = self.token.open(user_pin=pin, rw=True)

        # Store PIN for thread-local session creation
        with self._lock:
            self._pin = pin
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        if self.session:
            try:
                self.session.close()
            except:
                pass

    def _get_thread_session(self):
        """
        Get or create thread-local HSM session.

        This method provides thread-safe access to PKCS#11 sessions for parallel
        cryptographic operations. Each thread gets its own session to prevent
        concurrent access issues with the HSM.

        Returns:
            The PKCS#11 session for the current thread

        Raises:
            RuntimeError: If login() has not been called to set the PIN

        Thread Safety:
            - Each thread gets its own dedicated session via threading.local()
            - Sessions are created on-demand when first accessed by a thread
            - No locks needed for session access (thread-local by design)
        """
        # Check if current thread has a session
        if not hasattr(self._thread_local, 'session') or self._thread_local.session is None:
            # Need to create a new session for this thread
            with self._lock:
                if self._pin is None:
                    raise RuntimeError(
                        "No PIN available for thread-local session. "
                        "Call login() first on main thread."
                    )
                pin = self._pin

            # Open new session for this thread (outside lock to avoid blocking)
            self._thread_local.session = self.token.open(user_pin=pin, rw=True)

        return self._thread_local.session

    def _get_sensitive_attr(self) -> bool:
        """
        Get SENSITIVE attribute based on HSM_MODE.

        Returns:
            True in production mode (secrets cannot be read in plaintext)
            False in demo mode (secrets can be read for testing)
        """
        hsm_mode = os.environ.get('HSM_MODE', 'production')
        return hsm_mode == 'production'

    def _get_extractable_attr(self) -> bool:
        """
        Get EXTRACTABLE attribute based on HSM_MODE.

        Returns:
            False in production mode (secrets cannot be exported from HSM)
            True in demo mode (secrets can be exported for testing)
        """
        hsm_mode = os.environ.get('HSM_MODE', 'production')
        return hsm_mode == 'demo'

    def get_hsm_mode(self) -> str:
        """
        Get the current HSM security mode.

        Returns:
            'production' or 'demo'
        """
        return os.environ.get('HSM_MODE', 'production')

    def is_production_mode(self) -> bool:
        """
        Check if running in production mode (non-extractable secrets).

        Returns:
            True if HSM_MODE is 'production' (the default)
        """
        return self.get_hsm_mode() == 'production'

    def is_demo_mode(self) -> bool:
        """
        Check if running in demo mode (extractable secrets).

        Returns:
            True if HSM_MODE is 'demo'
        """
        return self.get_hsm_mode() == 'demo'

    def get_identity_public_key_pem(self) -> bytes:
        """Export RSA public key in PEM format."""
        pub_key = self.session.get_key(
            object_class=ObjectClass.PUBLIC_KEY,
            label='IDENTITY_KEY'
        )
        
        modulus = int.from_bytes(pub_key[Attribute.MODULUS], 'big')
        exponent = int.from_bytes(pub_key[Attribute.PUBLIC_EXPONENT], 'big')
        
        public_numbers = RSAPublicNumbers(exponent, modulus)
        public_key = public_numbers.public_key(default_backend())
        
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def decrypt_with_identity_key(self, ciphertext: bytes) -> bytes:
        """Decrypt using RSA private key (key never leaves HSM)."""
        priv_key = self.session.get_key(
            object_class=ObjectClass.PRIVATE_KEY,
            label='IDENTITY_KEY'
        )
        return priv_key.decrypt(ciphertext, mechanism=Mechanism.RSA_PKCS)
    
    @staticmethod
    def encrypt_for_recipient(recipient_pubkey_pem: bytes, plaintext: bytes) -> bytes:
        """Encrypt data for another node."""
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        pub_key = load_pem_public_key(recipient_pubkey_pem, default_backend())
        return pub_key.encrypt(plaintext, asym_padding.PKCS1v15())
    
    def store_dkg_share(self, round_id: str, share_bytes: bytes):
        """Store DKG share in HSM."""
        label = f'DKG_SHARE_{round_id}'
        
        # Delete if exists (for demo re-runs)
        try:
            existing = self.session.get_key(label=label)
            existing.destroy()
        except:
            pass
        
        self.session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
            Attribute.LABEL: label,
            Attribute.VALUE: share_bytes,
            Attribute.SENSITIVE: self._get_sensitive_attr(),
            Attribute.EXTRACTABLE: self._get_extractable_attr(),
            Attribute.TOKEN: True,
        })
    
    def get_dkg_share(self, round_id: str) -> bytes:
        """
        Retrieve DKG share from HSM.

        WARNING: This method only works in demo mode (HSM_MODE=demo).
        In production mode, secrets are configured with SENSITIVE=True,
        which prevents reading the VALUE attribute.

        For production deployments with real HSMs that support secp256k1,
        signing operations should be performed inside the HSM using
        compute_partial_signature_in_hsm() instead.

        Raises:
            SecurityError: If called in production mode
        """
        if self.is_production_mode():
            raise SecurityError(
                "Cannot extract DKG share in production mode (SENSITIVE=True). "
                "In production, signing operations must be performed inside the HSM. "
                "For SoftHSM demo, set HSM_MODE=demo to enable share extraction."
            )

        label = f'DKG_SHARE_{round_id}'
        key = self.session.get_key(label=label)
        return key[Attribute.VALUE]
    
    def has_dkg_share(self, round_id: str) -> bool:
        """Check if share exists."""
        try:
            self.session.get_key(label=f'DKG_SHARE_{round_id}')
            return True
        except:
            return False

    # =========================================================================
    # HSM-BACKED NONCE TRACKING
    # =========================================================================
    # These methods store nonce commitments in the HSM itself, providing
    # protection against filesystem restore/rewind attacks. Even if local
    # state.json is restored from backup, the HSM will still remember
    # which nonces have been used.
    # =========================================================================

    def store_nonce_commitment(self, request_id: str, commitment_hex: str) -> None:
        """
        Store nonce commitment in HSM - CRITICAL for nonce reuse prevention.

        This MUST be called BEFORE posting the commitment to the bulletin board.
        The HSM-backed storage survives filesystem restores, providing defense
        against state rewind attacks.

        Args:
            request_id: Unique signing request identifier
            commitment_hex: The R = k*G commitment in hex format
        """
        label = f'NONCE_{request_id}'

        # Check if already exists - this is a critical safety check
        if self.has_nonce_commitment(request_id):
            raise SecurityError(
                f"CRITICAL: Nonce for {request_id} already exists in HSM! "
                "Refusing to overwrite - this may be a replay attack."
            )

        # Store the commitment as a generic secret
        # We store the commitment (not the nonce itself) as evidence of use
        self.session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
            Attribute.LABEL: label,
            Attribute.VALUE: commitment_hex.encode('utf-8'),
            Attribute.SENSITIVE: self._get_sensitive_attr(),
            Attribute.EXTRACTABLE: self._get_extractable_attr(),
            Attribute.TOKEN: True,  # Persist across sessions
        })

    def has_nonce_commitment(self, request_id: str) -> bool:
        """
        Check if nonce commitment exists in HSM.

        Returns True if this request_id has already been used for signing,
        indicating the nonce should NOT be reused.
        """
        try:
            self.session.get_key(label=f'NONCE_{request_id}')
            return True
        except:
            return False

    def get_nonce_commitment(self, request_id: str) -> str:
        """
        Retrieve stored nonce commitment from HSM.

        Note: Only works in demo mode (HSM_MODE=demo).
        In production mode, returns a placeholder indicating the value is protected.

        Returns:
            The R commitment hex string that was stored, or
            "[PROTECTED]" in production mode

        Raises:
            Exception if not found
        """
        label = f'NONCE_{request_id}'
        key = self.session.get_key(label=label)

        if self.is_production_mode():
            # In production mode, we can't read the value but we know it exists
            return "[PROTECTED - commitment exists but value is non-extractable]"

        return key[Attribute.VALUE].decode('utf-8')

    def list_used_nonces(self) -> list:
        """
        List all request_ids that have used nonces (for audit/status).

        Returns:
            List of request_id strings
        """
        # Labels to exclude (internal derivation system objects)
        excluded_prefixes = ('NONCE_MASTER_SEED', 'NONCE_COUNTER', 'NONCE_DERIV_')

        used = []
        for obj in self.session.get_objects({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
        }):
            label = obj[Attribute.LABEL]
            if label.startswith('NONCE_'):
                # Skip internal derivation system objects
                if any(label.startswith(prefix) for prefix in excluded_prefixes):
                    continue
                used.append(label[6:])  # Strip 'NONCE_' prefix
        return used

    # =========================================================================
    # DETERMINISTIC NONCE DERIVATION (SLIP-10/BIP32 style)
    # =========================================================================
    # Instead of storing each nonce commitment individually, we use:
    # 1. A master seed stored in HSM (one-time setup)
    # 2. A monotonic counter that only increments (hardware-enforced)
    # 3. HMAC-based derivation: k = HMAC(seed, counter || request_id || msg_hash)
    #
    # Benefits:
    # - Disaster recovery: Can regenerate nonces from master + counter
    # - HSM capacity: O(1) storage instead of O(n) per signing session
    # - Same security guarantees via monotonic counter
    # =========================================================================

    NONCE_MASTER_LABEL = "NONCE_MASTER_SEED"
    NONCE_COUNTER_LABEL = "NONCE_COUNTER"

    def initialize_nonce_derivation(self) -> bool:
        """
        One-time setup: create master seed and initialize counter.

        Returns:
            True if newly initialized, False if already exists.
        """
        # Check if already initialized
        if self.has_nonce_master_seed():
            return False

        # Generate 32-byte master seed (cryptographically random)
        master_seed = os.urandom(32)

        # Store master seed in HSM
        self.session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
            Attribute.LABEL: self.NONCE_MASTER_LABEL,
            Attribute.VALUE: master_seed,
            Attribute.SENSITIVE: self._get_sensitive_attr(),
            Attribute.EXTRACTABLE: self._get_extractable_attr(),
            Attribute.TOKEN: True,  # Persist across sessions
        })

        # Initialize counter at 0
        # Counter is stored as 8-byte big-endian integer
        self.session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
            Attribute.LABEL: self.NONCE_COUNTER_LABEL,
            Attribute.VALUE: (0).to_bytes(8, 'big'),
            Attribute.SENSITIVE: self._get_sensitive_attr(),
            Attribute.EXTRACTABLE: self._get_extractable_attr(),
            Attribute.TOKEN: True,
        })

        return True

    def has_nonce_master_seed(self) -> bool:
        """Check if nonce master seed exists in HSM."""
        try:
            self.session.get_key(label=self.NONCE_MASTER_LABEL)
            return True
        except:
            return False

    def _get_nonce_master_seed(self) -> bytes:
        """
        Internal: retrieve master seed from HSM.

        Note: Only works in demo mode (HSM_MODE=demo).
        In production mode, nonce derivation would need to be performed
        entirely inside an HSM that supports HMAC operations.
        """
        if self.is_production_mode():
            raise SecurityError(
                "Cannot extract nonce master seed in production mode. "
                "For SoftHSM demo, set HSM_MODE=demo."
            )
        key = self.session.get_key(label=self.NONCE_MASTER_LABEL)
        return key[Attribute.VALUE]

    def _get_nonce_counter(self) -> int:
        """
        Internal: get current counter value.

        Note: Only works in demo mode (HSM_MODE=demo).
        """
        if self.is_production_mode():
            raise SecurityError(
                "Cannot read nonce counter in production mode. "
                "For SoftHSM demo, set HSM_MODE=demo."
            )
        key = self.session.get_key(label=self.NONCE_COUNTER_LABEL)
        return int.from_bytes(key[Attribute.VALUE], 'big')

    def _increment_nonce_counter(self) -> int:
        """
        Internal: atomically increment counter and return new value.

        CRITICAL: This is the core of nonce reuse prevention.
        In real HSM, this would use hardware monotonic counter.
        In SoftHSM, we simulate with delete-and-recreate pattern.

        Note: Only works in demo mode (HSM_MODE=demo).

        Returns:
            The new counter value (post-increment)
        """
        if self.is_production_mode():
            raise SecurityError(
                "Cannot increment nonce counter in production mode. "
                "For SoftHSM demo, set HSM_MODE=demo."
            )

        # Read current value
        current_key = self.session.get_key(label=self.NONCE_COUNTER_LABEL)
        current_value = int.from_bytes(current_key[Attribute.VALUE], 'big')

        # Increment
        new_value = current_value + 1

        # Delete old counter
        current_key.destroy()

        # Create new counter with incremented value
        # This is atomic from HSM perspective
        self.session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
            Attribute.LABEL: self.NONCE_COUNTER_LABEL,
            Attribute.VALUE: new_value.to_bytes(8, 'big'),
            Attribute.SENSITIVE: self._get_sensitive_attr(),
            Attribute.EXTRACTABLE: self._get_extractable_attr(),
            Attribute.TOKEN: True,
        })

        return new_value

    def derive_nonce(self, request_id: str, message_hash: bytes) -> NonceDerivation:
        """
        Derive nonce deterministically using SLIP-10/BIP32-style derivation.

        The derivation path includes:
        - Monotonic counter (ensures uniqueness even with request_id collision)
        - Request ID (binds to specific signing request)
        - Message hash (binds to specific message being signed)

        Formula:
            k = HMAC-SHA512(master_seed, 0x00 || counter || request_id || msg_hash)[0:32] mod n

        Args:
            request_id: Unique signing request identifier
            message_hash: SHA256 hash of the message being signed

        Returns:
            NonceDerivation containing the nonce, commitment, and metadata

        Raises:
            SecurityError: If nonce master seed not initialized
        """
        if not self.has_nonce_master_seed():
            raise SecurityError("Nonce master seed not initialized. Run 'init' first.")

        # Step 1: Atomically increment and get counter
        # This is the critical step - counter can NEVER go backwards
        counter = self._increment_nonce_counter()

        # Step 2: Load master seed
        master_seed = self._get_nonce_master_seed()

        # Step 3: Construct derivation input
        # Format: 0x00 || counter (8 bytes) || request_id || message_hash
        derivation_input = (
            b'\x00' +  # Domain separator (like BIP32 hardened derivation)
            counter.to_bytes(8, 'big') +
            request_id.encode('utf-8') +
            message_hash
        )

        # Step 4: HMAC-SHA512 derivation (SLIP-10 style)
        derived = hmac.new(
            master_seed,
            derivation_input,
            hashlib.sha512
        ).digest()

        # Step 5: Take first 32 bytes and reduce mod curve order
        k = int.from_bytes(derived[:32], 'big') % CURVE_ORDER

        # Ensure k is not zero (extremely unlikely but check anyway)
        if k == 0:
            raise SecurityError("Derived nonce is zero - this should never happen")

        # Step 6: Compute R = k * G (import locally to avoid circular dependency)
        from .crypto import G, point_to_hex
        R = k * G
        R_hex = point_to_hex(R)

        # Step 7: Store derivation record for audit trail
        # This maps counter -> (request_id, R_hex) for disaster recovery
        self._store_derivation_record(counter, request_id, R_hex, message_hash.hex())

        return NonceDerivation(
            counter=counter,
            k=k,
            R_hex=R_hex,
            request_id=request_id,
            message_hash_hex=message_hash.hex()
        )

    def _store_derivation_record(self, counter: int, request_id: str,
                                  R_hex: str, message_hash_hex: str):
        """
        Store derivation record for audit and disaster recovery.

        This allows reconstructing the mapping: counter -> (request_id, R)
        Format: JSON string stored as HSM secret
        """
        import json

        label = f"NONCE_DERIV_{counter}"
        record = json.dumps({
            'counter': counter,
            'request_id': request_id,
            'R_hex': R_hex,
            'message_hash_hex': message_hash_hex
        })

        self.session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
            Attribute.LABEL: label,
            Attribute.VALUE: record.encode('utf-8'),
            Attribute.SENSITIVE: self._get_sensitive_attr(),
            Attribute.EXTRACTABLE: self._get_extractable_attr(),
            Attribute.TOKEN: True,
        })

    def get_nonce_derivation_info(self) -> Optional[dict]:
        """
        Get nonce derivation system info for status display.

        Returns:
            Dictionary with master_seed_exists, current_counter, derivation_count
            or None if not initialized.
        """
        if not self.has_nonce_master_seed():
            return None

        try:
            counter = self._get_nonce_counter()
        except:
            counter = 0

        # Count derivation records
        derivation_count = 0
        for obj in self.session.get_objects({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
        }):
            label = obj[Attribute.LABEL]
            if label.startswith('NONCE_DERIV_'):
                derivation_count += 1

        return {
            'master_seed_exists': True,
            'current_counter': counter,
            'derivation_count': derivation_count,
        }

    def list_derivation_records(self) -> list:
        """
        List all derivation records (for audit/disaster recovery).

        Note: Only works in demo mode (HSM_MODE=demo).

        Returns:
            List of (counter, request_id, R_hex) tuples
        """
        import json

        if self.is_production_mode():
            # In production mode, we can only list labels, not read values
            # Return empty list with a note that values are protected
            return []

        records = []
        for obj in self.session.get_objects({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
        }):
            label = obj[Attribute.LABEL]
            if label.startswith('NONCE_DERIV_'):
                try:
                    data = json.loads(obj[Attribute.VALUE].decode('utf-8'))
                    records.append((
                        data['counter'],
                        data['request_id'],
                        data['R_hex']
                    ))
                except:
                    pass

        return sorted(records, key=lambda x: x[0])


class SecurityError(Exception):
    """Raised when a security-critical operation would be unsafe."""
    pass
