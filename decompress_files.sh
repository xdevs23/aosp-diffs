#!/bin/bash

# Script to decompress all compressed files (gz, xz, zstd)

set -e

echo "=== Decompressing all compressed files ==="
echo "Supported formats: gz, xz, zstd"
echo

# Find and decompress gz files
find . -name "*.gz" -type f | while read file; do
    echo "Decompressing: $file"
    gzip -dv "$file"
    echo "✓ Done"
done

# Find and decompress xz files
find . -name "*.xz" -type f | while read file; do
    echo "Decompressing: $file"
    xz -dv "$file"
    echo "✓ Done"
done

# Find and decompress zst files
find . -name "*.zst" -type f | while read file; do
    echo "Decompressing: $file"
    zstd -dv --progress "$file"
    echo "✓ Done"
done

echo "Done!"