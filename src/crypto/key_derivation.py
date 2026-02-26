"""
Key derivation module for FileCrypt.
Uses Argon2id for secure, memory-hard password-to-key conversion.
"""

import argon2.low_level
from typing import Optional


# Argon2id parameters for brute-force resistance
# These parameters provide strong security while remaining practical
ARGON2_TIME_COST = 3  # Number of iterations
ARGON2_MEMORY_COST = 65536  # 64 MB memory usage
ARGON2_PARALLELISM = 4  # Number of parallel threads
ARGON2_HASH_LEN = 32  # 256 bits for AES-256
ARGON2_SALT_LEN = 16  # 128 bits for salt


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit encryption key from a password using Argon2id.
    
    Argon2id is a memory-hard key derivation function that provides
    strong resistance against GPU and ASIC brute-force attacks.
    
    Args:
        password: The user's password (any length, will be encoded to UTF-8)
        salt: A 16-byte random salt for key derivation uniqueness
        
    Returns:
        A 32-byte (256-bit) key suitable for AES-256 encryption
        
    Raises:
        ValueError: If salt is not exactly 16 bytes
        
    Example:
        >>> import secrets
        >>> salt = secrets.token_bytes(16)
        >>> key = derive_key("my-secret-password", salt)
        >>> len(key)
        32
        
        # Same password + salt always produces same key (deterministic)
        >>> key2 = derive_key("my-secret-password", salt)
        >>> key == key2
        True
    """
    if len(salt) != ARGON2_SALT_LEN:
        raise ValueError(f"Salt must be exactly {ARGON2_SALT_LEN} bytes, got {len(salt)}")
    
    # Encode password to bytes (Argon2 requires bytes input)
    password_bytes = password.encode('utf-8')
    
    # Derive key using Argon2id
    # Using low_level API for precise control over parameters
    key = argon2.low_level.hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=argon2.low_level.Type.ID,  # Argon2id hybrid mode
    )
    
    # Clear password bytes from memory (best effort)
    # Note: Python's memory management makes this not fully guaranteed
    del password_bytes
    
    return key


def generate_salt() -> bytes:
    """
    Generate a cryptographically secure random salt.
    
    Returns:
        A 16-byte random salt suitable for key derivation
        
    Example:
        >>> salt = generate_salt()
        >>> len(salt)
        16
    """
    import secrets
    return secrets.token_bytes(ARGON2_SALT_LEN)
