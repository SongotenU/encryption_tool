"""
Unit tests for key derivation module.
"""

import pytest
import secrets
from src.crypto.key_derivation import derive_key, generate_salt, ARGON2_SALT_LEN


class TestDeriveKey:
    """Tests for derive_key function."""
    
    def test_derive_key_returns_32_bytes(self):
        """Key should always be 32 bytes (256 bits)."""
        salt = secrets.token_bytes(16)
        key = derive_key("test_password", salt)
        assert len(key) == 32, f"Expected 32 bytes, got {len(key)}"
    
    def test_same_password_same_salt_produces_same_key(self):
        """Same password and salt should always produce the same key (deterministic)."""
        password = "my_secret_password"
        salt = secrets.token_bytes(16)
        
        key1 = derive_key(password, salt)
        key2 = derive_key(password, salt)
        
        assert key1 == key2, "Same password and salt should produce identical keys"
    
    def test_different_passwords_produce_different_keys(self):
        """Different passwords should produce different keys."""
        salt = secrets.token_bytes(16)
        
        key1 = derive_key("password1", salt)
        key2 = derive_key("password2", salt)
        
        assert key1 != key2, "Different passwords should produce different keys"
    
    def test_different_salts_produce_different_keys(self):
        """Different salts should produce different keys for same password."""
        password = "same_password"
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)
        
        key1 = derive_key(password, salt1)
        key2 = derive_key(password, salt2)
        
        assert key1 != key2, "Different salts should produce different keys"
    
    def test_empty_password_still_works(self):
        """Empty password should still produce a valid key."""
        salt = secrets.token_bytes(16)
        key = derive_key("", salt)
        
        assert len(key) == 32, "Empty password should still produce 32-byte key"
    
    def test_unicode_password_works(self):
        """Unicode passwords should be handled correctly."""
        salt = secrets.token_bytes(16)
        
        # Test various unicode characters
        key = derive_key("パスワード🔐", salt)
        assert len(key) == 32, "Unicode password should produce 32-byte key"
        
        # Same unicode password should be deterministic
        key2 = derive_key("パスワード🔐", salt)
        assert key == key2, "Same unicode password should produce same key"
    
    def test_long_password_works(self):
        """Long passwords should work correctly."""
        salt = secrets.token_bytes(16)
        long_password = "a" * 1000  # 1000 character password
        
        key = derive_key(long_password, salt)
        assert len(key) == 32, "Long password should produce 32-byte key"
    
    def test_invalid_salt_length_raises_error(self):
        """Salt must be exactly 16 bytes."""
        with pytest.raises(ValueError, match="Salt must be exactly 16 bytes"):
            derive_key("password", b"short")
        
        with pytest.raises(ValueError, match="Salt must be exactly 16 bytes"):
            derive_key("password", b"this_is_too_long_for_salt")


class TestGenerateSalt:
    """Tests for generate_salt function."""
    
    def test_generate_salt_returns_16_bytes(self):
        """Generated salt should be 16 bytes."""
        salt = generate_salt()
        assert len(salt) == ARGON2_SALT_LEN, f"Expected {ARGON2_SALT_LEN} bytes, got {len(salt)}"
    
    def test_generate_salt_produces_random_salts(self):
        """Each call should produce a different random salt."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        
        assert salt1 != salt2, "Each salt should be unique"
    
    def test_generated_salt_works_with_derive_key(self):
        """Generated salt should work with derive_key."""
        salt = generate_salt()
        key = derive_key("test_password", salt)
        
        assert len(key) == 32, "Generated salt should work with derive_key"
