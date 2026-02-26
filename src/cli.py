"""
Command-line interface for FileCrypt.
Provides encrypt and decrypt subcommands for file encryption operations.
"""

import argparse
import getpass
import sys
from pathlib import Path

from .crypto import encrypt_file, decrypt_file


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog='filecrypt',
        description='Secure file encryption using AES-256-GCM and Argon2id',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Encrypt a file:
    python -m filecrypt encrypt myfile.txt
    python -m filecrypt encrypt myfile.txt -p mypassword
    python -m filecrypt encrypt myfile.txt -o encrypted.fcrypt
  
  Decrypt a file:
    python -m filecrypt decrypt myfile.fcrypt
    python -m filecrypt decrypt myfile.fcrypt -p mypassword
    python -m filecrypt decrypt myfile.fcrypt -o restored.txt
'''
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Encrypt subcommand
    encrypt_parser = subparsers.add_parser(
        'encrypt',
        help='Encrypt a file',
        description='Encrypt a file using AES-256-GCM with Argon2id key derivation'
    )
    encrypt_parser.add_argument(
        'file',
        type=str,
        help='Path to the file to encrypt'
    )
    encrypt_parser.add_argument(
        '-p', '--password',
        type=str,
        help='Password for encryption (will prompt if not provided)'
    )
    encrypt_parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output file path (default: input file + .fcrypt)'
    )
    
    # Decrypt subcommand
    decrypt_parser = subparsers.add_parser(
        'decrypt',
        help='Decrypt a file',
        description='Decrypt a file that was encrypted with FileCrypt'
    )
    decrypt_parser.add_argument(
        'file',
        type=str,
        help='Path to the encrypted file (.fcrypt)'
    )
    decrypt_parser.add_argument(
        '-p', '--password',
        type=str,
        help='Password for decryption (will prompt if not provided)'
    )
    decrypt_parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output file path (default: original filename from encrypted file)'
    )
    
    return parser


def get_password(password: str = None) -> str:
    """
    Get password from argument or prompt.
    
    Args:
        password: Password from command line argument (may be None)
        
    Returns:
        Password string
    """
    if password is not None:
        return password
    
    return getpass.getpass('Enter password: ')


def cmd_encrypt(args) -> int:
    """
    Execute encrypt command.
    
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    try:
        input_path = Path(args.file)
        
        if not input_path.exists():
            print(f"Error: File not found: {input_path}", file=sys.stderr)
            return 1
        
        password = get_password(args.password)
        output_path = args.output
        
        print(f"Encrypting: {input_path}")
        result_path = encrypt_file(input_path, output_path, password)
        print(f"Created: {result_path}")
        
        return 0
        
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


def cmd_decrypt(args) -> int:
    """
    Execute decrypt command.
    
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    try:
        input_path = Path(args.file)
        
        if not input_path.exists():
            print(f"Error: File not found: {input_path}", file=sys.stderr)
            return 1
        
        password = get_password(args.password)
        output_path = args.output
        
        print(f"Decrypting: {input_path}")
        result_path = decrypt_file(input_path, output_path, password)
        print(f"Created: {result_path}")
        
        return 0
        
    except ValueError as e:
        # Don't reveal specific error details for wrong password
        error_msg = str(e)
        if "Decryption failed" in error_msg:
            print("Error: Decryption failed. Incorrect password or corrupted file.", file=sys.stderr)
        else:
            print(f"Error: {error_msg}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


def main() -> int:
    """
    Main entry point for the CLI.
    
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    parser = create_parser()
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        return 1
    
    if args.command == 'encrypt':
        return cmd_encrypt(args)
    elif args.command == 'decrypt':
        return cmd_decrypt(args)
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
