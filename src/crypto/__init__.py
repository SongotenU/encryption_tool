"""
Crypto module for FileCrypt.
Provides AES-256-GCM encryption and Argon2id key derivation.
"""

from .key_derivation import derive_key, generate_salt
from .encryptor import encrypt_file, decrypt_file, EncryptedFileHeader

__all__ = [
    "derive_key",
    "generate_salt",
    "encrypt_file",
    "decrypt_file",
    "EncryptedFileHeader",
]