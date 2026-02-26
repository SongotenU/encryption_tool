"""
Unit tests for file encryptor module.
"""

import os
import struct
import tempfile
import pytest
from pathlib import Path

from src.crypto.encryptor import (
    encrypt_file,
    decrypt_file,
    EncryptedFileHeader,
    MAGIC_BYTES,
    FILE_VERSION,
)


class TestEncryptedFileHeader:
    """Tests for EncryptedFileHeader class."""
    
    def test_header_creation(self):
        """Should create a valid header."""
        header = EncryptedFileHeader(
            magic=MAGIC_BYTES,
            version=FILE_VERSION,
            salt=b's' * 16,
            nonce=b'n' * 12,
            original_filename='test.txt',
        )
        assert header.magic == MAGIC_BYTES
        assert header.version == FILE_VERSION
        assert len(header.salt) == 16
        assert len(header.nonce) == 12
        assert header.original_filename == 'test.txt'
    
    def test_header_serialization(self):
        """Should serialize and deserialize correctly."""
        original = EncryptedFileHeader(
            magic=MAGIC_BYTES,
            version=FILE_VERSION,
            salt=b'a' * 16,
            nonce=b'b' * 12,
            original_filename='document.pdf',
        )
        
        serialized = original.to_bytes()
        deserialized, consumed = EncryptedFileHeader.from_bytes(serialized)
        
        assert deserialized.magic == original.magic
        assert deserialized.version == original.version
        assert deserialized.salt == original.salt
        assert deserialized.nonce == original.nonce
        assert deserialized.original_filename == original.original_filename
        assert consumed == len(serialized)
    
    def test_header_with_unicode_filename(self):
        """Should handle unicode filenames."""
        header = EncryptedFileHeader(
            magic=MAGIC_BYTES,
            version=FILE_VERSION,
            salt=b's' * 16,
            nonce=b'n' * 12,
            original_filename='文档.pdf',
        )
        
        serialized = header.to_bytes()
        deserialized, _ = EncryptedFileHeader.from_bytes(serialized)
        
        assert deserialized.original_filename == '文档.pdf'
    
    def test_invalid_magic_bytes(self):
        """Should reject invalid magic bytes when deserializing."""
        # Create invalid header bytes
        invalid_data = b'BAD!' + struct.pack('<B', 1) + struct.pack('<B', 0)
        invalid_data += b's' * 16 + b'n' * 12 + struct.pack('<H', 4) + b'test'
        
        with pytest.raises(ValueError, match="Invalid magic bytes"):
            EncryptedFileHeader.from_bytes(invalid_data)
    def test_invalid_salt_length(self):
        """Should reject invalid salt length."""
        with pytest.raises(ValueError, match="Salt must be exactly"):
            EncryptedFileHeader(
                magic=MAGIC_BYTES,
                version=FILE_VERSION,
                salt=b'short',
                nonce=b'n' * 12,
                original_filename='test.txt',
            )


class TestEncryptFile:
    """Tests for encrypt_file function."""
    
    def test_encrypt_file_creates_fcrypt_file(self):
        """Should create .fcrypt file from input."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('test content')
            temp_path = f.name
        
        try:
            encrypted_path = encrypt_file(temp_path, password='test_password')
            
            assert encrypted_path.exists()
            assert encrypted_path.suffix == '.fcrypt'
            assert encrypted_path.stat().st_size > len('test content')
            
            # Cleanup
            os.unlink(encrypted_path)
        finally:
            os.unlink(temp_path)
    
    def test_encrypted_file_has_header(self):
        """Encrypted file should start with FCRY magic bytes."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('test content')
            temp_path = f.name
        
        try:
            encrypted_path = encrypt_file(temp_path, password='test_password')
            
            with open(encrypted_path, 'rb') as ef:
                magic = ef.read(4)
            
            assert magic == MAGIC_BYTES
            
            os.unlink(encrypted_path)
        finally:
            os.unlink(temp_path)
    
    def test_encrypted_file_is_different_from_original(self):
        """Encrypted content should not match original."""
        original_content = b'this is secret data'
        
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(original_content)
            temp_path = f.name
        
        try:
            encrypted_path = encrypt_file(temp_path, password='test_password')
            
            with open(encrypted_path, 'rb') as ef:
                encrypted_content = ef.read()
            
            # Encrypted content should not contain original plaintext
            assert original_content not in encrypted_content
            
            os.unlink(encrypted_path)
        finally:
            os.unlink(temp_path)
    
    def test_different_passwords_create_different_output(self):
        """Different passwords should produce different encrypted files."""
        content = b'same content'
        
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.txt', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            encrypted1 = encrypt_file(temp_path, temp_path + '.1.fcrypt', 'password1')
            encrypted2 = encrypt_file(temp_path, temp_path + '.2.fcrypt', 'password2')
            
            with open(encrypted1, 'rb') as f1, open(encrypted2, 'rb') as f2:
                content1 = f1.read()
                content2 = f2.read()
            
            # Different passwords should produce different ciphertext
            assert content1 != content2
            
            os.unlink(encrypted1)
            os.unlink(encrypted2)
        finally:
            os.unlink(temp_path)
    
    def test_encrypt_empty_file(self):
        """Should handle empty files."""
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.txt', delete=False) as f:
            # Write nothing
            temp_path = f.name
        
        try:
            encrypted_path = encrypt_file(temp_path, password='test_password')
            
            assert encrypted_path.exists()
            
            os.unlink(encrypted_path)
        finally:
            os.unlink(temp_path)
    
    def test_encrypt_binary_file(self):
        """Should handle binary files."""
        binary_content = bytes(range(256)) * 100  # 256KB of binary data
        
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(binary_content)
            temp_path = f.name
        
        try:
            encrypted_path = encrypt_file(temp_path, password='test_password')
            
            assert encrypted_path.exists()
            assert encrypted_path.stat().st_size > len(binary_content)
            
            os.unlink(encrypted_path)
        finally:
            os.unlink(temp_path)
    
    def test_file_not_found_raises_error(self):
        """Should raise FileNotFoundError for non-existent file."""
        with pytest.raises(FileNotFoundError):
            encrypt_file('/nonexistent/file.txt', password='test')


class TestDecryptFile:
    """Tests for decrypt_file function."""
    
    def test_decrypt_restores_original_content(self):
        """Decrypted file should match original."""
        original_content = 'This is the original content! 🎉'
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(original_content)
            temp_path = f.name
        
        try:
            encrypted_path = encrypt_file(temp_path, password='my_password')
            decrypted_path = decrypt_file(encrypted_path, password='my_password')
            
            with open(decrypted_path, 'r') as f:
                decrypted_content = f.read()
            
            assert decrypted_content == original_content
            
            os.unlink(encrypted_path)
            os.unlink(decrypted_path)
        finally:
            os.unlink(temp_path)
    
    def test_wrong_password_fails(self):
        """Wrong password should fail to decrypt."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('secret data')
            temp_path = f.name
        
        try:
            encrypted_path = encrypt_file(temp_path, password='correct_password')
            
            with pytest.raises(ValueError, match="Decryption failed"):
                decrypt_file(encrypted_path, password='wrong_password')
            
            os.unlink(encrypted_path)
        finally:
            os.unlink(temp_path)
    
    def test_decrypt_binary_file(self):
        """Should decrypt binary files correctly."""
        original_binary = os.urandom(1024)  # 1KB random binary
        
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(original_binary)
            temp_path = f.name
        
        try:
            encrypted_path = encrypt_file(temp_path, password='test')
            decrypted_path = decrypt_file(encrypted_path, password='test')
            
            with open(decrypted_path, 'rb') as f:
                decrypted_binary = f.read()
            
            assert decrypted_binary == original_binary
            
            os.unlink(encrypted_path)
            os.unlink(decrypted_path)
        finally:
            os.unlink(temp_path)
    
    def test_decrypt_non_encrypted_file_fails(self):
        """Should fail gracefully on non-encrypted file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('not encrypted')
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError, match="Invalid encrypted file"):
                decrypt_file(temp_path, password='test')
        finally:
            os.unlink(temp_path)


class TestRoundTrip:
    """End-to-end encryption/decryption tests."""
    
    def test_roundtrip_text_file(self):
        """Should encrypt and decrypt text file correctly."""
        content = "Hello, World!\n" * 100
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            encrypted = encrypt_file(temp_path, password='secret')
            decrypted = decrypt_file(encrypted, password='secret')
            
            with open(decrypted, 'r') as f:
                result = f.read()
            
            assert result == content
            
            os.unlink(encrypted)
            os.unlink(decrypted)
        finally:
            os.unlink(temp_path)
    
    def test_roundtrip_large_file(self):
        """Should handle larger files (10MB)."""
        # Create 10MB file
        content = os.urandom(10 * 1024 * 1024)
        
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            encrypted = encrypt_file(temp_path, password='test_password')
            decrypted = decrypt_file(encrypted, password='test_password')
            
            with open(decrypted, 'rb') as f:
                result = f.read()
            
            assert result == content
            
            os.unlink(encrypted)
            os.unlink(decrypted)
        finally:
            os.unlink(temp_path)
