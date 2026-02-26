#!/bin/bash
# Build script for FileCrypt macOS .app bundle
# Usage: ./build_app.sh

set -e

echo "Building FileCrypt.app..."

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf build/ dist/

# Run PyInstaller
echo "Running PyInstaller..."
pyinstaller FileCrypt.spec

echo ""
echo "✓ Build complete!"
echo "App bundle: dist/FileCrypt.app"
echo ""
echo "To run: open dist/FileCrypt.app"
