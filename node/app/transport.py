"""Git-based bulletin board transport layer."""
import git
import os
import time
import subprocess
import shutil
import random
from pathlib import Path
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)


class Mailbox:
    """Uses a Git repository as an asynchronous message board."""
    
    RETRY_ATTEMPTS = 5
    RETRY_DELAY = 1.0
    
    def __init__(self, repo_url: str, local_path: str, node_id: str):
        self.repo_url = repo_url
        self.local_path = Path(local_path)
        self.node_id = node_id
        self.repo = None
        self._ensure_cloned()
    
    def _ensure_cloned(self):
        """Clone repo if not exists."""
        if self.local_path.exists() and (self.local_path / '.git').exists():
            self.repo = git.Repo(str(self.local_path))
            return
        
        if self.local_path.exists():
            shutil.rmtree(self.local_path)
        
        self.local_path.parent.mkdir(parents=True, exist_ok=True)
        
        for attempt in range(self.RETRY_ATTEMPTS):
            result = subprocess.run(
                ['git', 'clone', self.repo_url, str(self.local_path)],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                self.repo = git.Repo(str(self.local_path))
                return
            logger.warning(f"Clone attempt {attempt + 1} failed: {result.stderr}")
            time.sleep(self.RETRY_DELAY)
        
        raise RuntimeError(f"Failed to clone {self.repo_url}")
    
    def sync(self):
        """Pull latest changes with retry logic for git lock contention."""
        for attempt in range(self.RETRY_ATTEMPTS):
            try:
                # Add random jitter to reduce concurrent lock conflicts
                if attempt > 0:
                    jitter = random.uniform(0, 0.5 * attempt)
                    time.sleep(self.RETRY_DELAY * attempt + jitter)

                self.repo.remotes.origin.fetch()
                self.repo.git.reset('--hard', 'origin/master')
                return  # Success

            except git.exc.GitCommandError as e:
                # Check if this is a lock file error
                if 'index.lock' in str(e):
                    logger.debug(f"Git lock contention (attempt {attempt + 1}/{self.RETRY_ATTEMPTS})")
                    # Try to clean up stale lock file on last attempt
                    if attempt == self.RETRY_ATTEMPTS - 1:
                        lock_file = self.local_path / '.git' / 'index.lock'
                        try:
                            if lock_file.exists():
                                lock_file.unlink()
                                logger.info("Removed stale git lock file")
                        except:
                            pass
                    continue
                else:
                    logger.warning(f"Sync error: {e}")
                    return  # Non-lock error, don't retry

            except Exception as e:
                logger.warning(f"Sync error: {e}")
                return  # Unexpected error, don't retry
    
    def post(self, path: str, data: bytes, retries: int = None) -> bool:
        """Post data to repository."""
        if retries is None:
            retries = self.RETRY_ATTEMPTS
        
        for attempt in range(retries):
            try:
                self.sync()
                
                full_path = self.local_path / path
                full_path.parent.mkdir(parents=True, exist_ok=True)
                
                mode = 'wb' if isinstance(data, bytes) else 'w'
                with open(full_path, mode) as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                
                rel_path = str(full_path.relative_to(self.local_path))
                self.repo.index.add([rel_path])
                
                try:
                    self.repo.index.commit(f"{self.node_id}: posted {path}")
                except Exception:
                    return True  # Nothing to commit
                
                self.repo.remotes.origin.push()
                return True
                
            except Exception as e:
                logger.warning(f"Post attempt {attempt + 1} failed: {e}")
                time.sleep(self.RETRY_DELAY * (attempt + 1))
                try:
                    self.repo.git.reset('--hard', 'origin/master')
                except:
                    pass
        
        raise Exception(f"Failed to post {path} after {retries} attempts")
    
    def read(self, path: str) -> Optional[bytes]:
        """Read data from repository."""
        self.sync()
        full_path = self.local_path / path
        if not full_path.exists():
            return None
        with open(full_path, 'rb') as f:
            return f.read()
    
    def list_files(self, directory: str) -> List[str]:
        """List files in directory."""
        self.sync()
        dir_path = self.local_path / directory
        if not dir_path.exists():
            return []
        return [f.name for f in dir_path.iterdir() if f.is_file()]
    
    def list_identities(self) -> List[str]:
        """List all nodes with posted identities."""
        files = self.list_files("identity")
        return [f.replace(".json", "") for f in files if f.endswith(".json")]
    
    def post_identity(self, pubkey_pem: bytes):
        """Post this node's identity."""
        from .protocol import IdentityMessage
        msg = IdentityMessage(
            node_id=self.node_id,
            pubkey_pem=pubkey_pem.decode('utf-8'),
            timestamp=time.time()
        )
        self.post(f"identity/{self.node_id}.json", msg.to_json())
    
    def get_identity(self, node_id: str) -> Optional['IdentityMessage']:
        """Fetch another node's identity."""
        from .protocol import IdentityMessage
        data = self.read(f"identity/{node_id}.json")
        if data is None:
            return None
        return IdentityMessage.from_json(data)
