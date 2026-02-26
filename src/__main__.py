"""
Entry point for running FileCrypt as a module.

Usage:
    python -m filecrypt encrypt <file>
    python -m filecrypt decrypt <file>
"""

import sys

from .cli import main

if __name__ == '__main__':
    sys.exit(main())
