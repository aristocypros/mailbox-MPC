"""
Feldman VSS for DKG + Threshold Schnorr Signing
Using secp256k1 curve (Bitcoin/Ethereum compatible)
"""
from dataclasses import dataclass
from typing import List, Dict, Tuple
import secrets
import hashlib

from fastecdsa.curve import secp256k1
from fastecdsa.point import Point

CURVE = secp256k1
ORDER = CURVE.q
G = CURVE.G

# Identity element (point at infinity) - created once
IDENTITY = G + (-G)


def is_identity(p: Point) -> bool:
    """Check if point is the identity element (point at infinity)."""
    return p.x == 0 and p.y == 0


def point_to_hex(p: Point) -> str:
    """Serialize point to compressed hex."""
    if is_identity(p):
        return "00"
    prefix = "02" if p.y % 2 == 0 else "03"
    return prefix + format(p.x, '064x')


def hex_to_point(h: str) -> Point:
    """Deserialize compressed hex to point."""
    if h == "00":
        return IDENTITY
    prefix = h[:2]
    x = int(h[2:], 16)
    # Compute y from x
    y_squared = (pow(x, 3, CURVE.p) + CURVE.a * x + CURVE.b) % CURVE.p
    y = pow(y_squared, (CURVE.p + 1) // 4, CURVE.p)
    if (prefix == "02" and y % 2 != 0) or (prefix == "03" and y % 2 == 0):
        y = CURVE.p - y
    return Point(x, y, curve=CURVE)


def mod_inverse(a: int, m: int) -> int:
    """Modular multiplicative inverse."""
    return pow(a, -1, m)


# =============================================================================
# Feldman VSS - Distributed Key Generation
# =============================================================================

@dataclass
class DKGRound:
    """State for one DKG ceremony."""
    round_id: str
    node_id: str
    my_index: int
    threshold: int
    total_nodes: int
    my_coefficients: List[int] = None
    my_commitments: List[Point] = None
    shares_for_others: Dict[str, int] = None
    received_shares: Dict[str, int] = None
    other_commitments: Dict[str, List[Point]] = None
    my_final_share: int = None
    group_public_key: Point = None


class FeldmanDKG:
    """
    Feldman's Verifiable Secret Sharing for DKG.
    
    Each node:
    1. Picks random polynomial f_i(x) of degree t-1
    2. Broadcasts commitments C_ij = a_ij * G
    3. Sends f_i(j) to node j (encrypted)
    4. Verifies: f_i(j) * G == Σ (j^k * C_ik)
    5. Final share: s_j = Σ f_i(j)
    6. Public key: Y = Σ C_i0
    """
    
    def __init__(self, round_id: str, node_id: str, threshold: int, total_nodes: int):
        self.state = DKGRound(
            round_id=round_id,
            node_id=node_id,
            my_index=int(node_id.replace("node", "")),
            threshold=threshold,
            total_nodes=total_nodes,
            shares_for_others={},
            received_shares={},
            other_commitments={}
        )
    
    def generate_polynomial(self) -> List[str]:
        """Generate random polynomial and return hex-encoded commitments."""
        t = self.state.threshold
        self.state.my_coefficients = [secrets.randbelow(ORDER) for _ in range(t)]
        self.state.my_commitments = [
            self.state.my_coefficients[k] * G for k in range(t)
        ]
        return [point_to_hex(c) for c in self.state.my_commitments]
    
    def compute_share_for(self, target_node_id: str) -> int:
        """Evaluate polynomial at target's index."""
        target_index = int(target_node_id.replace("node", ""))
        result = 0
        for k, coeff in enumerate(self.state.my_coefficients):
            result = (result + coeff * pow(target_index, k, ORDER)) % ORDER
        return result
    
    def receive_commitment(self, from_node: str, commitments_hex: List[str]):
        """Store another node's commitments."""
        self.state.other_commitments[from_node] = [
            hex_to_point(c) for c in commitments_hex
        ]
    
    def receive_share(self, from_node: str, share_value: int) -> bool:
        """Verify and store a received share."""
        if from_node not in self.state.other_commitments:
            return False
        
        commitments = self.state.other_commitments[from_node]
        
        # Verify: share * G == Σ (my_index^k * C_k)
        left = share_value * G
        right = IDENTITY
        for k, C_k in enumerate(commitments):
            coeff = pow(self.state.my_index, k, ORDER)
            right = right + (coeff * C_k)
        
        if left != right:
            return False
        
        self.state.received_shares[from_node] = share_value
        return True
    
    def finalize(self) -> Tuple[int, Point]:
        """Compute final share and group public key."""
        # My contribution to my own share
        my_own_share = 0
        for k, coeff in enumerate(self.state.my_coefficients):
            my_own_share = (my_own_share + coeff * pow(self.state.my_index, k, ORDER)) % ORDER
        
        # Sum all shares
        final_share = my_own_share
        for share in self.state.received_shares.values():
            final_share = (final_share + share) % ORDER
        
        # Group public key = sum of all a0*G
        group_pk = self.state.my_commitments[0]
        for commitments in self.state.other_commitments.values():
            group_pk = group_pk + commitments[0]
        
        return (final_share, group_pk)


# =============================================================================
# Threshold Signing
# =============================================================================

@dataclass
class SigningRound:
    """State for one signing ceremony."""
    request_id: str
    message_hash: bytes
    my_nonce_k: int = None
    nonce_commitments: Dict[str, Point] = None
    partial_signatures: Dict[str, int] = None

    def to_dict(self) -> dict:
        """Serialize to JSON-safe dictionary."""
        return {
            'request_id': self.request_id,
            'message_hash': self.message_hash.hex(),
            'my_nonce_k': format(self.my_nonce_k, 'x') if self.my_nonce_k is not None else None,
            'nonce_commitments': {
                node_id: point_to_hex(point)
                for node_id, point in (self.nonce_commitments or {}).items()
            },
            'partial_signatures': {
                node_id: format(sig, 'x')
                for node_id, sig in (self.partial_signatures or {}).items()
            }
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'SigningRound':
        """Deserialize from JSON-safe dictionary."""
        return cls(
            request_id=data['request_id'],
            message_hash=bytes.fromhex(data['message_hash']),
            my_nonce_k=int(data['my_nonce_k'], 16) if data.get('my_nonce_k') else None,
            nonce_commitments={
                node_id: hex_to_point(hex_str)
                for node_id, hex_str in (data.get('nonce_commitments') or {}).items()
            },
            partial_signatures={
                node_id: int(sig, 16)
                for node_id, sig in (data.get('partial_signatures') or {}).items()
            }
        )


class ThresholdSigner:
    """
    Threshold Schnorr-like signing.
    
    1. Each participant generates nonce k_i, broadcasts R_i = k_i * G
    2. Compute aggregate R = Σ R_i
    3. Challenge e = H(R || P || m)
    4. Partial sig: s_i = k_i + e * λ_i * x_i
    5. Combine: s = Σ s_i
    """
    
    def __init__(self, node_id: str, my_share: int, group_pubkey: Point):
        self.node_id = node_id
        self.my_index = int(node_id.replace("node", ""))
        self.my_share = my_share
        self.group_pubkey = group_pubkey
        self.sessions: Dict[str, SigningRound] = {}
    
    def create_nonce_commitment(self, request_id: str, message_hash: bytes) -> str:
        """Generate random nonce, return commitment (legacy method)."""
        k_i = secrets.randbelow(ORDER)
        R_i = k_i * G

        self.sessions[request_id] = SigningRound(
            request_id=request_id,
            message_hash=message_hash,
            my_nonce_k=k_i,
            nonce_commitments={self.node_id: R_i},
            partial_signatures={}
        )

        return point_to_hex(R_i)

    def create_nonce_commitment_from_k(self, request_id: str, message_hash: bytes,
                                        k: int, R_hex: str) -> str:
        """
        Create nonce commitment from externally-derived nonce.

        Used with deterministic nonce derivation (SLIP-10/BIP32 style).
        The nonce k and commitment R are provided by the HSM's derive_nonce().

        Args:
            request_id: Unique signing request identifier
            message_hash: SHA256 hash of message being signed
            k: The derived nonce value (from HSM)
            R_hex: The commitment R = k*G in hex format (from HSM)

        Returns:
            R_hex (passed through for consistency with create_nonce_commitment)
        """
        R_i = hex_to_point(R_hex)

        self.sessions[request_id] = SigningRound(
            request_id=request_id,
            message_hash=message_hash,
            my_nonce_k=k,
            nonce_commitments={self.node_id: R_i},
            partial_signatures={}
        )

        return R_hex
    
    def receive_nonce_commitment(self, request_id: str, from_node: str, R_hex: str):
        """Collect another participant's nonce commitment."""
        self.sessions[request_id].nonce_commitments[from_node] = hex_to_point(R_hex)
    
    def compute_partial_signature(self, request_id: str, participants: List[str]) -> str:
        """Compute partial signature."""
        session = self.sessions[request_id]
        
        # Aggregate nonce
        R = IDENTITY
        for node_id in participants:
            R = R + session.nonce_commitments[node_id]
        
        # Challenge
        data = (point_to_hex(R) + point_to_hex(self.group_pubkey)).encode() + session.message_hash
        e = int.from_bytes(hashlib.sha256(data).digest(), 'big') % ORDER
        
        # Lagrange coefficient
        participant_indices = [int(n.replace("node", "")) for n in participants]
        num, den = 1, 1
        for j in participant_indices:
            if j != self.my_index:
                num = (num * (-j)) % ORDER
                den = (den * (self.my_index - j)) % ORDER
        lambda_i = (num * mod_inverse(den, ORDER)) % ORDER
        
        # Partial signature
        s_i = (session.my_nonce_k + e * lambda_i * self.my_share) % ORDER
        
        # CRITICAL: Wipe nonce
        session.my_nonce_k = None
        session.partial_signatures[self.node_id] = s_i
        
        return format(s_i, '064x')
    
    @staticmethod
    def combine_signatures(
        partials: Dict[str, int],
        nonce_commitments: Dict[str, Point],
        participants: List[str]
    ) -> Tuple[str, str]:
        """Combine partial signatures."""
        R = IDENTITY
        for node_id in participants:
            R = R + nonce_commitments[node_id]
        s = sum(partials.values()) % ORDER
        return (point_to_hex(R), format(s, '064x'))
    
    @staticmethod
    def verify_signature(R_hex: str, s_hex: str, pubkey: Point, message_hash: bytes) -> bool:
        """Verify: s*G == R + e*P"""
        R = hex_to_point(R_hex)
        s = int(s_hex, 16)

        data = (R_hex + point_to_hex(pubkey)).encode() + message_hash
        e = int.from_bytes(hashlib.sha256(data).digest(), 'big') % ORDER

        return s * G == R + (e * pubkey)

    def to_json(self) -> bytes:
        """
        Serialize signer state to JSON.

        JSON is used for safe serialization to prevent CWE-502 vulnerabilities.
        JSON only supports primitive types and cannot execute arbitrary code.
        """
        data = {
            'node_id': self.node_id,
            'my_index': self.my_index,
            'my_share': format(self.my_share, 'x'),
            'group_pubkey': point_to_hex(self.group_pubkey),
            'sessions': {
                req_id: session.to_dict()
                for req_id, session in self.sessions.items()
            }
        }
        import json
        return json.dumps(data).encode()

    @classmethod
    def from_json(cls, data: bytes) -> 'ThresholdSigner':
        """
        Deserialize signer state from JSON.

        This safe deserialization method only accepts well-defined JSON
        structures and cannot execute arbitrary code.
        """
        import json
        obj = json.loads(data)

        signer = cls(
            node_id=obj['node_id'],
            my_share=int(obj['my_share'], 16),
            group_pubkey=hex_to_point(obj['group_pubkey'])
        )
        signer.my_index = obj['my_index']
        signer.sessions = {
            req_id: SigningRound.from_dict(session_data)
            for req_id, session_data in obj.get('sessions', {}).items()
        }
        return signer
