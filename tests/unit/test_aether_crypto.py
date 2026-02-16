import pytest
import os
from src.security.crypto import AetherCrypto

def test_rust_optimization_encryption():
    """Test that AetherCrypto works (using Rust if available)"""
    # Use a dummy password
    crypto = AetherCrypto("test_password")
    data = "Secret Data 123"
    
    # Encrypt
    encrypted = crypto.encrypt(data)
    assert encrypted != data
    assert isinstance(encrypted, str)
    
    # Decrypt
    decrypted = crypto.decrypt(encrypted)
    assert decrypted == data

def test_large_payload():
    """Test with larger payload to verify buffer handling"""
    crypto = AetherCrypto("test_password_2")
    data = "A" * 10000 # 10KB
    
    encrypted = crypto.encrypt(data)
    decrypted = crypto.decrypt(encrypted)
    assert decrypted == data

def test_key_derivation():
    """Test implicit key derivation"""
    crypto = AetherCrypto("password123")
    # Access private key for verification (if Rust available)
    if hasattr(crypto, '_key'):
         assert len(crypto._key) == 32
