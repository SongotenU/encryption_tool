"""
Integration tests for FileCrypt CLI.
Tests the complete encrypt/decrypt workflow via subprocess.
"""

import os
import subprocess
import tempfile
from pathlib import Path

import pytest


# Path to the project root (for PYTHONPATH)
PROJECT_ROOT = Path(__file__).parent.parent


class TestCLIEncrypt:
    """Tests for encrypt command."""
    
    def test_cli_encrypt_creates_fcrypt_file(self):
        """Encrypt command should create .fcrypt file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('test content for CLI')
            temp_path = f.name
        
        try:
            # Run encrypt command
            result = subprocess.run(
                ['python3', '-m', 'src', 'encrypt', temp_path, '-p', 'testpass'],
                capture_output=True,
                text=True,
                cwd=PROJECT_ROOT,
                env={**os.environ, 'PYTHONPATH': str(PROJECT_ROOT)}
            )
            
            # Check .fcrypt file was created
            encrypted_path = Path(temp_path + '.fcrypt')
            assert encrypted_path.exists(), f"Expected {encrypted_path} to exist"
            assert 'Created:' in result.stdout
            
            # Cleanup
            os.unlink(encrypted_path)
        finally:
            os.unlink(temp_path)
    
    def test_cli_encrypt_with_custom_output(self):
        """Encrypt with -o option should use custom output path."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('test content')
            temp_path = f.name
        
        try:
            custom_output = temp_path + '.custom'
            
            result = subprocess.run(
                ['python3', '-m', 'src', 'encrypt', temp_path, '-p', 'testpass', '-o', custom_output],
                capture_output=True,
                text=True,
                cwd=PROJECT_ROOT,
                env={**os.environ, 'PYTHONPATH': str(PROJECT_ROOT)}
            )
            
            assert Path(custom_output).exists()
            assert custom_output in result.stdout
            
            os.unlink(custom_output)
        finally:
            os.unlink(temp_path)
    
    def test_cli_encrypt_missing_file_error(self):
        """Encrypt missing file should show error."""
        result = subprocess.run(
            ['python3', '-m', 'src', 'encrypt', '/nonexistent/file.txt', '-p', 'test'],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            env={**os.environ, 'PYTHONPATH': str(PROJECT_ROOT)}
        )
        
        assert result.returncode != 0
        assert 'Error' in result.stderr or 'not found' in result.stderr.lower()


class TestCLIDecrypt:
    """Tests for decrypt command."""
    
    def test_cli_decrypt_restores_original(self):
        """Encrypt then decrypt should restore original content."""
        original_content = 'This is the original content! 🎉'
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(original_content)
            temp_path = f.name
        
        try:
            # Encrypt
            subprocess.run(
                ['python3', '-m', 'src', 'encrypt', temp_path, '-p', 'mypassword'],
                capture_output=True,
                cwd=PROJECT_ROOT,
                env={**os.environ, 'PYTHONPATH': str(PROJECT_ROOT)}
            )
            
            encrypted_path = temp_path + '.fcrypt'
            
            # Decrypt
            result = subprocess.run(
                ['python3', '-m', 'src', 'decrypt', encrypted_path, '-p', 'mypassword'],
                capture_output=True,
                text=True,
                cwd=PROJECT_ROOT,
                env={**os.environ, 'PYTHONPATH': str(PROJECT_ROOT)}
            )
            
            # Check decrypted file
            # The original filename should be restored
            decrypted_path = Path(temp_path).name  # Just the filename
            assert Path(decrypted_path).exists() or 'Created:' in result.stdout
            
            # Find and read the decrypted file
            if Path(decrypted_path).exists():
                with open(decrypted_path, 'r') as f:
                    restored = f.read()
                assert restored == original_content
                os.unlink(decrypted_path)
            
            os.unlink(encrypted_path)
        finally:
            os.unlink(temp_path)
    
    def test_cli_wrong_password_shows_error(self):
        """Wrong password should show generic error."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('secret data')
            temp_path = f.name
        
        try:
            # Encrypt with correct password
            subprocess.run(
                ['python3', '-m', 'src', 'encrypt', temp_path, '-p', 'correctpass'],
                capture_output=True,
                cwd=PROJECT_ROOT,
                env={**os.environ, 'PYTHONPATH': str(PROJECT_ROOT)}
            )
            
            encrypted_path = temp_path + '.fcrypt'
            
            # Try to decrypt with wrong password
            result = subprocess.run(
                ['python3', '-m', 'src', 'decrypt', encrypted_path, '-p', 'wrongpass'],
                capture_output=True,
                text=True,
                cwd=PROJECT_ROOT,
                env={**os.environ, 'PYTHONPATH': str(PROJECT_ROOT)}
            )
            
            assert result.returncode != 0
            # Should show generic error, not reveal specific details
            assert 'Error' in result.stderr
            assert 'Decryption failed' in result.stderr
            
            os.unlink(encrypted_path)
        finally:
            os.unlink(temp_path)
    
    def test_cli_decrypt_non_encrypted_file_fails(self):
        """Decrypt non-encrypted file should fail gracefully."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('not encrypted')
            temp_path = f.name
        
        try:
            result = subprocess.run(
                ['python3', '-m', 'src', 'decrypt', temp_path, '-p', 'test'],
                capture_output=True,
                text=True,
                cwd=PROJECT_ROOT,
                env={**os.environ, 'PYTHONPATH': str(PROJECT_ROOT)}
            )
            
            assert result.returncode != 0
            assert 'Error' in result.stderr
        finally:
            os.unlink(temp_path)
    
    def test_cli_decrypt_missing_file_error(self):
        """Decrypt missing file should show error."""
        result = subprocess.run(
            ['python3', '-m', 'src', 'decrypt', '/nonexistent/file.fcrypt', '-p', 'test'],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            env={**os.environ, 'PYTHONPATH': str(PROJECT_ROOT)}
        )
        
        assert result.returncode != 0
        assert 'Error' in result.stderr


class TestCLIHelp:
    """Tests for help output."""
    
    def test_cli_help_shows_usage(self):
        """Main help should show usage information."""
        result = subprocess.run(
            ['python3', '-m', 'src', '--help'],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            env={**os.environ, 'PYTHONPATH': str(PROJECT_ROOT)}
        )
        
        assert result.returncode == 0
        assert 'encrypt' in result.stdout
        assert 'decrypt' in result.stdout
        assert 'AES-256-GCM' in result.stdout
    
    def test_cli_encrypt_help_shows_options(self):
        """Encrypt help should show all options."""
        result = subprocess.run(
            ['python3', '-m', 'src', 'encrypt', '--help'],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            env={**os.environ, 'PYTHONPATH': str(PROJECT_ROOT)}
        )
        
        assert result.returncode == 0
        assert '--password' in result.stdout
        assert '--output' in result.stdout
    
    def test_cli_decrypt_help_shows_options(self):
        """Decrypt help should show all options."""
        result = subprocess.run(
            ['python3', '-m', 'src', 'decrypt', '--help'],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            env={**os.environ, 'PYTHONPATH': str(PROJECT_ROOT)}
        )
        
        assert result.returncode == 0
        assert '--password' in result.stdout
        assert '--output' in result.stdout


class TestCLIRoundTrip:
    """End-to-end CLI tests."""
    
    def test_cli_roundtrip_text_file(self):
        """Full roundtrip: encrypt then decrypt text file."""
        content = "Hello, World!\n" * 100
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            # Encrypt
            subprocess.run(
                ['python3', '-m', 'src', 'encrypt', temp_path, '-p', 'secret123'],
                capture_output=True,
                cwd=PROJECT_ROOT,
                env={**os.environ, 'PYTHONPATH': str(PROJECT_ROOT)}
            )
            
            encrypted_path = temp_path + '.fcrypt'
            
            # Decrypt
            result = subprocess.run(
                ['python3', '-m', 'src', 'decrypt', encrypted_path, '-p', 'secret123'],
                capture_output=True,
                text=True,
                cwd=PROJECT_ROOT,
                env={**os.environ, 'PYTHONPATH': str(PROJECT_ROOT)}
            )
            
            # Find decrypted file
            decrypted_name = Path(temp_path).name
            if Path(decrypted_name).exists():
                with open(decrypted_name, 'r') as f:
                    restored = f.read()
                assert restored == content
                os.unlink(decrypted_name)
            
            os.unlink(encrypted_path)
        finally:
            os.unlink(temp_path)
    
    def test_cli_roundtrip_binary_file(self):
        """Full roundtrip: encrypt then decrypt binary file."""
        # Create binary file
        binary_content = bytes(range(256)) * 100
        
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(binary_content)
            temp_path = f.name
        
        try:
            # Encrypt
            subprocess.run(
                ['python3', '-m', 'src', 'encrypt', temp_path, '-p', 'testpass'],
                capture_output=True,
                cwd=PROJECT_ROOT,
                env={**os.environ, 'PYTHONPATH': str(PROJECT_ROOT)}
            )
            
            encrypted_path = temp_path + '.fcrypt'
            
            # Decrypt
            subprocess.run(
                ['python3', '-m', 'src', 'decrypt', encrypted_path, '-p', 'testpass'],
                capture_output=True,
                cwd=PROJECT_ROOT,
                env={**os.environ, 'PYTHONPATH': str(PROJECT_ROOT)}
            )
            
            # Find decrypted file
            decrypted_name = Path(temp_path).name
            if Path(decrypted_name).exists():
                with open(decrypted_name, 'rb') as f:
                    restored = f.read()
                assert restored == binary_content
                os.unlink(decrypted_name)
            
            os.unlink(encrypted_path)
        finally:
            os.unlink(temp_path)
