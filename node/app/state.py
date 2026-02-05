"""Rigid state management with atomic updates."""
import json
import os
import fcntl
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict


@dataclass
class DKGState:
    """DKG participation state."""
    round_id: str = ""
    phase: str = "none"
    threshold: int = 0
    total_nodes: int = 0
    my_share_stored: bool = False
    group_pubkey_hex: str = ""


@dataclass
class SigningState:
    """Signing state with nonce tracking."""
    used_nonces: Dict[str, str] = field(default_factory=dict)
    # Derivation tracking: request_id -> {counter, R_hex, message_hash_hex}
    nonce_derivations: Dict[str, dict] = field(default_factory=dict)


@dataclass
class NodeState:
    """Complete node state."""
    node_id: str
    initialized: bool = False
    identity_key_posted: bool = False
    dkg: DKGState = field(default_factory=DKGState)
    signing: SigningState = field(default_factory=SigningState)


class RigidState:
    """Manages persistent state with atomic updates."""
    
    def __init__(self, state_dir: str, node_id: str):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.state_dir / "state.json"
        self.lock_file = self.state_dir / "state.lock"
        self.node_id = node_id
        
        if not self.state_file.exists():
            self._save(NodeState(node_id=node_id))
    
    def _save(self, state: NodeState):
        """Atomic save."""
        tmp = self.state_file.with_suffix('.tmp')
        with open(tmp, 'w') as f:
            json.dump(asdict(state), f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_file)
    
    def load(self) -> NodeState:
        """Load with lock."""
        self.lock_file.touch()
        with open(self.lock_file, 'r') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
            with open(self.state_file, 'r') as f:
                data = json.load(f)
        
        dkg = DKGState(**data.get('dkg', {}))
        signing_data = data.get('signing', {})
        signing = SigningState(
            used_nonces=signing_data.get('used_nonces', {}),
            nonce_derivations=signing_data.get('nonce_derivations', {})
        )

        return NodeState(
            node_id=data['node_id'],
            initialized=data.get('initialized', False),
            identity_key_posted=data.get('identity_key_posted', False),
            dkg=dkg,
            signing=signing
        )

    def _load_state_data(self) -> NodeState:
        """Internal: load state without acquiring lock (caller must hold lock)."""
        with open(self.state_file, 'r') as f:
            data = json.load(f)

        dkg = DKGState(**data.get('dkg', {}))
        signing_data = data.get('signing', {})
        signing = SigningState(
            used_nonces=signing_data.get('used_nonces', {}),
            nonce_derivations=signing_data.get('nonce_derivations', {})
        )

        return NodeState(
            node_id=data['node_id'],
            initialized=data.get('initialized', False),
            identity_key_posted=data.get('identity_key_posted', False),
            dkg=dkg,
            signing=signing
        )

    def update(self, updater):
        """Atomic update."""
        self.lock_file.touch()
        with open(self.lock_file, 'w') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            state = self._load_state_data()
            updater(state)
            self._save(state)
    
    def check_nonce_unused(self, request_id: str) -> bool:
        """Check if nonce is unused."""
        return request_id not in self.load().signing.used_nonces
    
    def record_nonce_use(self, request_id: str, commitment: str):
        """Record nonce use."""
        def _update(s):
            s.signing.used_nonces[request_id] = commitment
        self.update(_update)

    def record_nonce_derivation(self, request_id: str, counter: int,
                                 R_hex: str, message_hash_hex: str):
        """
        Record nonce derivation metadata for audit trail.

        This stores the mapping: request_id -> {counter, R_hex, message_hash_hex}
        Used alongside record_nonce_use() for triple-layer protection.
        """
        def _update(s):
            s.signing.used_nonces[request_id] = R_hex
            s.signing.nonce_derivations[request_id] = {
                'counter': counter,
                'R_hex': R_hex,
                'message_hash_hex': message_hash_hex
            }
        self.update(_update)

    def get_derivation_info(self, request_id: str) -> dict:
        """Get derivation info for a specific request."""
        return self.load().signing.nonce_derivations.get(request_id)
