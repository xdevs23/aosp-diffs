#!/bin/bash

# Script to compress uncommitted files larger than 50MB using zstd
# MB = 1,000,000 bytes

set -e

# Size threshold in bytes (50MB)
THRESHOLD_BYTES=50000000

# Counters
total_files=0
compressed_files=0
total_original_size=0
total_compressed_size=0

echo "=== Compressing modified/untracked files > 50MB using zstd ==="
echo "Threshold: $(($THRESHOLD_BYTES / 1000000))MB"
echo

# Get list of uncommitted files (both staged and unstaged)
echo "Finding uncommitted files..."
uncommitted_files=$(git status --porcelain | grep -E '^(M|A|D|R|C|\?\?|\s)' | cut -c4-)

if [ -z "$uncommitted_files" ]; then
    echo "No uncommitted files found."
    exit 0
fi

echo "Found uncommitted files. Checking sizes..."
echo

# Process each uncommitted file
while IFS= read -r file; do
    if [ -f "$file" ]; then
        total_files=$((total_files + 1))

        # Get file size in bytes
        if command -v stat >/dev/null 2>&1; then
            # Try GNU stat first
            if stat -c%s "$file" >/dev/null 2>&1; then
                file_size=$(stat -c%s "$file")
            else
                # Try BSD stat
                file_size=$(stat -f%z "$file" 2>/dev/null || echo 0)
            fi
        else
            # Fallback to ls and awk
            file_size=$(ls -ln "$file" 2>/dev/null | awk '{print $5}' || echo 0)
        fi

        # Check if file is larger than threshold
        if [ "$file_size" -gt "$THRESHOLD_BYTES" ]; then
            file_size_mb=$(echo "scale=1; $file_size / 1000000" | bc -l 2>/dev/null || echo $((file_size / 1000000)))
            echo "Processing: $file (${file_size_mb}MB)"

            # Create compressed filename
            compressed_file="${file}.zst"

            # Compress with zstd using high compression level (19) with progress
            echo "  Compressing with zstd level 19..."
            if zstd -19 -v --progress "$file" -o "$compressed_file"; then
                # Get compressed file size
                if command -v stat >/dev/null 2>&1; then
                    if stat -c%s "$compressed_file" >/dev/null 2>&1; then
                        compressed_size=$(stat -c%s "$compressed_file")
                    else
                        compressed_size=$(stat -f%z "$compressed_file" 2>/dev/null || echo 0)
                    fi
                else
                    compressed_size=$(ls -ln "$compressed_file" 2>/dev/null | awk '{print $5}' || echo 0)
                fi

                compressed_size_mb=$(echo "scale=1; $compressed_size / 1000000" | bc -l 2>/dev/null || echo $((compressed_size / 1000000)))
                ratio=$(echo "scale=1; $compressed_size * 100 / $file_size" | bc -l 2>/dev/null || echo "0")

                echo "  ✓ Compressed: ${compressed_size_mb}MB (${ratio}% of original)"

                # Remove original file
                echo "  Removing original file..."
                rm "$file"

                # Update counters
                compressed_files=$((compressed_files + 1))
                total_original_size=$((total_original_size + file_size))
                total_compressed_size=$((total_compressed_size + compressed_size))

                echo "  ✓ Done: $file -> $compressed_file"
            else
                echo "  ✗ Failed to compress $file"
            fi
            echo
      fi
    fi
done <<< "$uncommitted_files"

# Summary
echo "=== Summary ==="
echo "Total modified/untracked files processed: $total_files"
echo "Files compressed: $compressed_files"
if [ "$compressed_files" -gt 0 ]; then
    total_original_mb=$(echo "scale=1; $total_original_size / 1000000" | bc -l 2>/dev/null || echo $((total_original_size / 1000000)))
    total_compressed_mb=$(echo "scale=1; $total_compressed_size / 1000000" | bc -l 2>/dev/null || echo $((total_compressed_size / 1000000)))
    overall_ratio=$(echo "scale=1; $total_compressed_size * 100 / $total_original_size" | bc -l 2>/dev/null || echo "0")
    space_saved=$((total_original_size - total_compressed_size))
    space_saved_mb=$(echo "scale=1; $space_saved / 1000000" | bc -l 2>/dev/null || echo $((space_saved / 1000000)))

    echo "Original total size: ${total_original_mb}MB"
    echo "Compressed total size: ${total_compressed_mb}MB"
    echo "Overall compression ratio: ${overall_ratio}%"
    echo "Space saved: ${space_saved_mb}MB"
fi
echo "Done!"