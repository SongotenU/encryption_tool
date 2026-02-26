"""
File encryption module for FileCrypt.
Uses AES-256-GCM for authenticated encryption with Argon2id key derivation.
"""

import os
import secrets
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .key_derivation import derive_key, generate_salt


# File format constants
MAGIC_BYTES = b'FCRY'  # File identification
FILE_VERSION = 1
NONCE_SIZE = 12  # 96 bits for AES-GCM
SALT_SIZE = 16  # 128 bits for Argon2id
HEADER_BASE_SIZE = 4 + 1 + 1 + SALT_SIZE + NONCE_SIZE + 2  # magic + version + flags + salt + nonce + filename_len


@dataclass
class EncryptedFileHeader:
    """
    Header structure for encrypted files.
    
    Format:
    - magic: 4 bytes ("FCRY")
    - version: 1 byte (currently 1)
    - flags: 1 byte (reserved, currently 0)
    - salt: 16 bytes (for Argon2id key derivation)
    - nonce: 12 bytes (for AES-GCM)
    - original_filename_len: 2 bytes (uint16, little-endian)
    - original_filename: variable (UTF-8 encoded)
    """
    magic: bytes
    version: int
    salt: bytes
    nonce: bytes
    original_filename: str
    flags: int = 0
    
    def __post_init__(self):
        """Validate header fields."""
        if len(self.magic) != 4:
            raise ValueError("Magic must be exactly 4 bytes")
        if len(self.salt) != SALT_SIZE:
            raise ValueError(f"Salt must be exactly {SALT_SIZE} bytes")
        if len(self.nonce) != NONCE_SIZE:
            raise ValueError(f"Nonce must be exactly {NONCE_SIZE} bytes")
    
    @property
    def header_size(self) -> int:
        """Calculate total header size including filename."""
        return HEADER_BASE_SIZE + len(self.original_filename.encode('utf-8'))
    
    def to_bytes(self) -> bytes:
        """Serialize header to bytes."""
        filename_bytes = self.original_filename.encode('utf-8')
        filename_len = len(filename_bytes)
        
        return (
            self.magic +
            struct.pack('<B', self.version) +
            struct.pack('<B', self.flags) +
            self.salt +
            self.nonce +
            struct.pack('<H', filename_len) +
            filename_bytes
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> tuple['EncryptedFileHeader', int]:
        """
        Deserialize header from bytes.
        
        Returns:
            Tuple of (header, bytes_consumed)
        """
        if len(data) < HEADER_BASE_SIZE:
            raise ValueError(f"Data too short for header: need at least {HEADER_BASE_SIZE}, got {len(data)}")
        
        # Parse fixed-size fields
        magic = data[0:4]
        if magic != MAGIC_BYTES:
            raise ValueError(f"Invalid magic bytes: expected {MAGIC_BYTES!r}, got {magic!r}")
        
        version = struct.unpack('<B', data[4:5])[0]
        flags = struct.unpack('<B', data[5:6])[0]
        salt = data[6:6 + SALT_SIZE]
        nonce = data[6 + SALT_SIZE:6 + SALT_SIZE + NONCE_SIZE]
        
        # Parse filename
        filename_len_offset = 6 + SALT_SIZE + NONCE_SIZE
        filename_len = struct.unpack('<H', data[filename_len_offset:filename_len_offset + 2])[0]
        
        filename_start = filename_len_offset + 2
        filename_end = filename_start + filename_len
        if len(data) < filename_end:
            raise ValueError(f"Data too short for filename: need {filename_end}, got {len(data)}")
        
        original_filename = data[filename_start:filename_end].decode('utf-8')
        
        header = cls(
            magic=magic,
            version=version,
            salt=salt,
            nonce=nonce,
            original_filename=original_filename,
            flags=flags,
        )
        
        return header, header.header_size


def encrypt_file(
    input_path: Union[str, Path],
    output_path: Optional[Union[str, Path]] = None,
    password: str = "",
) -> Path:
    """
    Encrypt a file using AES-256-GCM with Argon2id key derivation.
    
    Args:
        input_path: Path to the file to encrypt
        output_path: Optional output path (default: input_path + '.fcrypt')
        password: Password for encryption
        
    Returns:
        Path to the encrypted file
        
    Raises:
        FileNotFoundError: If input file doesn't exist
        ValueError: If file is too large (warning for files > 1GB)
        
    Example:
        >>> encrypt_file("document.txt", "document.fcrypt", "my_password")
        PosixPath('document.fcrypt')
    """
    input_path = Path(input_path)
    
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    
    # Determine output path
    if output_path is None:
        output_path = Path(str(input_path) + '.fcrypt')
    else:
        output_path = Path(output_path)
    
    # Check file size (warn for very large files)
    file_size = input_path.stat().st_size
    if file_size > 1_000_000_000:  # 1GB
        # Log warning but continue
        import warnings
        warnings.warn(
            f"Large file detected ({file_size / 1_000_000:.1f} MB). "
            "Encryption may use significant memory.",
            UserWarning
        )
    
    # Generate cryptographic materials
    salt = generate_salt()
    nonce = secrets.token_bytes(NONCE_SIZE)
    
    # Derive key from password
    key = derive_key(password, salt)
    
    # Read file content
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    # Encrypt with AES-256-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    # Create header
    header = EncryptedFileHeader(
        magic=MAGIC_BYTES,
        version=FILE_VERSION,
        salt=salt,
        nonce=nonce,
        original_filename=input_path.name,
    )
    
    # Write encrypted file
    with open(output_path, 'wb') as f:
        f.write(header.to_bytes())
        f.write(ciphertext)
    
    # Clear sensitive data from memory (best effort)
    del key
    del plaintext
    
    return output_path


def decrypt_file(
    input_path: Union[str, Path],
    output_path: Optional[Union[str, Path]] = None,
    password: str = "",
) -> Path:
    """
    Decrypt a file encrypted with encrypt_file.
    
    Args:
        input_path: Path to the encrypted file
        output_path: Optional output path (default: original filename from header)
        password: Password used for encryption
        
    Returns:
        Path to the decrypted file
        
    Raises:
        FileNotFoundError: If input file doesn't exist
        ValueError: If file is not a valid encrypted file
        ValueError: If password is incorrect (authentication failure)
        
    Example:
        >>> decrypt_file("document.fcrypt", password="my_password")
        PosixPath('document.txt')
    """
    input_path = Path(input_path)
    
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    
    # Read encrypted file
    with open(input_path, 'rb') as f:
        file_data = f.read()
    
    # Parse header
    try:
        header, header_size = EncryptedFileHeader.from_bytes(file_data)
    except ValueError as e:
        raise ValueError(f"Invalid encrypted file: {e}") from e
    
    # Derive key from password
    key = derive_key(password, header.salt)
    
    # Extract ciphertext
    ciphertext = file_data[header_size:]
    
    # Decrypt with AES-256-GCM
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(header.nonce, ciphertext, None)
    except Exception as e:
        # Generic error message to avoid revealing information
        raise ValueError("Decryption failed. Incorrect password or corrupted file.") from e
    
    # Determine output path
    # Use the same directory as the encrypted file for output
    if output_path is None:
        output_path = input_path.parent / header.original_filename
    else:
        output_path = Path(output_path)
    # Write decrypted file
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    
    # Clear sensitive data from memory (best effort)
    del key
    del plaintext
    
    return output_path
