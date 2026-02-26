# FileCrypt

A secure file encryption tool using AES-256-GCM and Argon2id key derivation. Encrypt any file with a password - only you can decrypt it.

## Features

- **AES-256-GCM encryption** - Authenticated encryption providing both confidentiality and integrity
- **Argon2id key derivation** - Memory-hard function resistant to GPU/ASIC brute-force attacks
- **Simple CLI** - Encrypt and decrypt files from the command line
- **Desktop GUI** - Drag-and-drop interface for easy file encryption
- **Any file type** - Works with documents, images, videos, binaries
- **Secure by design** - No password storage, generic error messages

## Installation

### Requirements

- Python 3.9 or higher
- pip (Python package manager)

### Option 1: pip Install (CLI)

```bash
# Clone the repository
git clone <repository-url>
cd encryption_tool

# Install the package
pip install -e .

# Now use 'filecrypt' command from anywhere
filecrypt --help
```

### Option 2: macOS App Bundle (GUI)

For GUI users who want a double-clickable app:

```bash
# Clone and build
git clone <repository-url>
cd encryption_tool
pip install -r requirements.txt
pip install pyinstaller

# Build the app
./build_app.sh

# The app bundle is created at dist/FileCrypt.app
# Double-click to run, or:
open dist/FileCrypt.app
```

### Option 3: Run from Source

```bash
# Clone the repository
git clone <repository-url>
cd encryption_tool

# Install dependencies
pip install -r requirements.txt

# Run CLI
python -m src encrypt myfile.txt

# Run GUI
python -m src.gui
```

## Usage

### CLI Usage

#### Encrypt a File

```bash
# Basic encryption (will prompt for password)
filecrypt encrypt myfile.txt

# With password on command line (less secure - visible in shell history)
filecrypt encrypt myfile.txt -p mypassword

# With custom output file
filecrypt encrypt myfile.txt -o encrypted.fcrypt
```

This creates `myfile.txt.fcrypt` (or your custom output path).

#### Decrypt a File

```bash
# Basic decryption (will prompt for password)
filecrypt decrypt myfile.txt.fcrypt

# With password on command line
filecrypt decrypt myfile.txt.fcrypt -p mypassword

# With custom output file
filecrypt decrypt myfile.txt.fcrypt -o restored.txt
```

The decrypted file will be restored to its original content.

#### Getting Help

```bash
# General help
filecrypt --help

# Encrypt command help
filecrypt encrypt --help

# Decrypt command help
filecrypt decrypt --help
```

### GUI Usage

1. Launch FileCrypt.app (or run `python -m src.gui`)
2. Drag a file onto the drop zone
3. Enter your password
4. Click "Encrypt" or "Decrypt" based on file type
5. The output file is created in the same directory

- **Encrypt**: Drop any file → Enter password → Click Encrypt
- **Decrypt**: Drop a `.fcrypt` file → Enter password → Click Decrypt

## File Format

Encrypted files use the `.fcrypt` extension and contain:

1. **Header** (variable length):
   - Magic bytes: `FCRY` (4 bytes) - file identification
   - Version: 1 (1 byte) - format version
   - Salt: 16 bytes - for Argon2id key derivation
   - Nonce: 12 bytes - for AES-GCM
   - Original filename - preserved for restoration

2. **Ciphertext** - AES-256-GCM encrypted data with authentication tag

## Security

### Encryption Details

- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key length**: 256 bits (32 bytes)
- **Nonce**: 96 bits (12 bytes), randomly generated per file
- **Authentication**: Built-in via GCM mode

### Key Derivation

- **Algorithm**: Argon2id (hybrid mode)
- **Memory cost**: 64 MB
- **Time cost**: 3 iterations
- **Parallelism**: 4 threads

These parameters provide strong resistance against brute-force attacks while remaining practical for everyday use.

### Security Best Practices

1. **Use strong passwords** - The encryption is only as strong as your password
2. **Don't share passwords** - Anyone with the password can decrypt your files
3. **Keep backups** - If you forget the password, your data is unrecoverable
4. **Verify file integrity** - Wrong password shows generic error (data is protected)

### What We Don't Do

- **No password storage** - We never store your password anywhere
- **No cloud integration** - Files stay local; you control where they go
- **No key escrow** - No backdoors; only you can decrypt your files

## Technical Details

### Dependencies

- `argon2-cffi>=23.1.0` - Argon2id key derivation
- `cryptography>=42.0.0` - AES-256-GCM encryption
- `PyQt6>=6.6.0` - GUI framework
### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_encryptor.py -v

# Run with coverage
python -m pytest tests/ -v --cov=src
```

### Project Structure

```
encryption_tool/
├── src/
│   ├── __init__.py         # Package initialization
│   ├── __main__.py         # CLI entry point
│   ├── cli.py              # Command-line interface
│   ├── crypto/
│   │   ├── __init__.py     # Crypto module exports
│   │   ├── key_derivation.py  # Argon2id implementation
│   │   └── encryptor.py    # AES-256-GCM encryption
│   └── gui/
│       ├── __init__.py     # GUI module
│       ├── __main__.py     # GUI entry point
│       ├── main_window.py  # Main window with drag-drop
│       └── password_dialog.py  # Password input
├── tests/
│   ├── __init__.py
│   ├── test_key_derivation.py
│   ├── test_encryptor.py
│   └── test_cli.py
├── pyproject.toml          # Project configuration
├── requirements.txt        # Dependencies
├── FileCrypt.spec          # PyInstaller config
├── build_app.sh            # Build script
└── README.md               # This file
```

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

---

*Built with security in mind.*
