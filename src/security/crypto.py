"""
Aether AI Optimized Cryptography Module
Uses Rust backend (aether_rust) for high-performance encryption and hashing.
"""
import os
import base64
from typing import Optional, Tuple
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Try to import Rust extension
try:
    import aether_rust
    RUST_AVAILABLE = True
    logger.info("Aether Rust optimization loaded successfully")
except ImportError:
    RUST_AVAILABLE = False
    logger.warning("aether_rust module not found. Falling back to Python implementation.")
    # Fallback imports
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend


class AetherCrypto:
    """
    High-performance cryptography using Rust FFI.
    Falls back to Python/Fernet if Rust module is missing.
    """
    
    def __init__(self, master_password: Optional[str] = None):
        self.master_password = master_password or os.getenv("AETHER_MASTER_PASSWORD") or _raise_password_error()
        self._fernet = None
        
        # Derive 32-byte key for Rust AES-GCM (if available)
        # For simplicity in this hybrid, we use the password as source
        if RUST_AVAILABLE:
            # Simple derivation for demo (in prod use proper KDF cached)
            self._key = self._derive_key_rust(self.master_password)
            
    def _derive_key_rust(self, password: str) -> bytes:
        """Derive 32-byte key using SHA-256 for Rust AES-256-GCM"""
        import hashlib
        return hashlib.sha256(password.encode()).digest()

    def encrypt(self, data: str) -> str:
        """Encrypt string data"""
        if RUST_AVAILABLE:
            try:
                # Generate 12-byte nonce
                nonce = os.urandom(12)
                encrypted_bytes = aether_rust.encrypt(
                    self._key, 
                    data.encode(), 
                    nonce
                )
                # Combine nonce + ciphertext for storage (typical pattern)
                # Format: base64(nonce + ciphertext)
                combined = nonce + bytes(encrypted_bytes)
                return base64.urlsafe_b64encode(combined).decode()
            except Exception as e:
                logger.error(f"Rust encryption failed: {e}")
                # Fallback? No, inconsistency risk. Raise.
                raise
        else:
            return self._encrypt_python(data)

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt string data"""
        if RUST_AVAILABLE:
            try:
                decoded = base64.urlsafe_b64decode(encrypted_data.encode())
                # Extract nonce (first 12 bytes)
                if len(decoded) < 12:
                    raise ValueError("Invalid encrypted data length")
                    
                nonce = decoded[:12]
                ciphertext = decoded[12:]
                
                decrypted_bytes = aether_rust.decrypt(
                    self._key, 
                    ciphertext, 
                    nonce
                )
                return bytes(decrypted_bytes).decode()
            except Exception as e:
                logger.error(f"Rust decryption failed: {e}")
                raise
        else:
            return self._decrypt_python(encrypted_data)

    # --- Python Fallback Methods (from original encryption.py) ---
    def _encrypt_python(self, data: str) -> str:
        if not self._fernet:
            self._init_fernet()
        return self._fernet.encrypt(data.encode()).decode() # type: ignore

    def _decrypt_python(self, encrypted_data: str) -> str:
        if not self._fernet:
            self._init_fernet()
        return self._fernet.decrypt(encrypted_data.encode()).decode() # type: ignore

    def _init_fernet(self):
        # ... (Implementation from encryption.py essentially)
        salt = b'static_salt_for_compat' # In real usage, store salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_password.encode()))
        self._fernet = Fernet(key)

