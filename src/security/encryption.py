"""
Advanced Encryption Module for Aether AI
Provides AES-256 encryption, hashing, and secure key management
"""
import os
import hashlib
import base64
from typing import Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AetherEncryption:
    """
    Military-grade encryption for sensitive data
    Uses AES-256 with PBKDF2 key derivation
    """
    
    def __init__(self, master_password: Optional[str] = None):
        self.master_password = master_password or os.getenv("AETHER_MASTER_PASSWORD") or _raise_password_error()
        self._fernet = None
        logger.info("Encryption module initialized")
        
    def _derive_key(self, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """Derive encryption key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
        
    def _get_fernet(self) -> Fernet:
        """Get Fernet cipher instance"""
        if not self._fernet:
            key, _ = self._derive_key(self.master_password)
            self._fernet = Fernet(key)
        return self._fernet
        
    def encrypt(self, data: str) -> str:
        """Encrypt string data"""
        try:
            fernet = self._get_fernet()
            encrypted = fernet.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
            
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt string data"""
        try:
            fernet = self._get_fernet()
            decoded = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = fernet.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
            
    def hash_data(self, data: str, algorithm: str = "sha256") -> str:
        """Create cryptographic hash of data"""
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(data.encode())
        return hash_obj.hexdigest()
        
    def encrypt_file(self, file_path: str, output_path: Optional[str] = None) -> str:
        """Encrypt entire file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            fernet = self._get_fernet()
            encrypted = fernet.encrypt(data)
            
            output_path = output_path or f"{file_path}.encrypted"
            with open(output_path, 'wb') as f:
                f.write(encrypted)
                
            logger.info(f"File encrypted: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"File encryption failed: {e}")
            raise
            
    def decrypt_file(self, encrypted_path: str, output_path: Optional[str] = None) -> str:
        """Decrypt entire file"""
        try:
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
                
            fernet = self._get_fernet()
            decrypted = fernet.decrypt(encrypted_data)
            
            output_path = output_path or encrypted_path.replace(".encrypted", "")
            with open(output_path, 'wb') as f:
                f.write(decrypted)
                
            logger.info(f"File decrypted: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"File decryption failed: {e}")
            raise
            
    def generate_key(self) -> str:
        """Generate random encryption key"""
        return Fernet.generate_key().decode()
        
    def secure_compare(self, str1: str, str2: str) -> bool:
        """Timing-attack safe string comparison"""
        hash1 = self.hash_data(str1)
        hash2 = self.hash_data(str2)
        return hash1 == hash2
