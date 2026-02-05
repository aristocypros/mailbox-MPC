"""Protocol message definitions for the bulletin board."""
from dataclasses import dataclass, asdict
from typing import List
import json


@dataclass
class IdentityMessage:
    """Posted to: identity/{node_id}.json"""
    node_id: str
    pubkey_pem: str
    timestamp: float
    
    def to_json(self) -> bytes:
        return json.dumps(asdict(self)).encode()
    
    @classmethod
    def from_json(cls, data: bytes) -> 'IdentityMessage':
        return cls(**json.loads(data))


@dataclass
class DKGCommitment:
    """Posted to: dkg/{round_id}/commitments/{node_id}.json"""
    node_id: str
    round_id: str
    threshold: int
    total_nodes: int
    commitments: List[str]  # Hex-encoded curve points
    timestamp: float
    
    def to_json(self) -> bytes:
        return json.dumps(asdict(self)).encode()
    
    @classmethod
    def from_json(cls, data: bytes) -> 'DKGCommitment':
        return cls(**json.loads(data))


@dataclass
class SigningRequest:
    """Posted to: signing/{request_id}/request.json"""
    request_id: str
    message_hash: str
    message_preview: str
    requester: str
    timestamp: float
    
    def to_json(self) -> bytes:
        return json.dumps(asdict(self)).encode()


@dataclass
class NonceCommitment:
    """Posted to: signing/{request_id}/commitments/{node_id}.json"""
    node_id: str
    request_id: str
    R_commitment: str
    timestamp: float
    
    def to_json(self) -> bytes:
        return json.dumps(asdict(self)).encode()


@dataclass
class PartialSignature:
    """Posted to: signing/{request_id}/partials/{node_id}.json"""
    node_id: str
    request_id: str
    partial_s: str
    timestamp: float
    
    def to_json(self) -> bytes:
        return json.dumps(asdict(self)).encode()


@dataclass
class FinalSignature:
    """Posted to: signing/{request_id}/result.json"""
    request_id: str
    R: str
    s: str
    participants: List[str]
    timestamp: float
    
    def to_json(self) -> bytes:
        return json.dumps(asdict(self)).encode()
