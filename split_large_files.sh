#!/bin/bash

# Script to split uncommitted files larger than 50MB into smaller chunks
# MB = 1,000,000 bytes

set -e

# Size threshold in bytes (50MB)
THRESHOLD_BYTES=50000000
# Maximum chunk size in bytes (50MB)
CHUNK_SIZE_BYTES=50000000

# Counters
total_files=0
split_files=0
total_original_size=0
total_chunks_created=0

echo "=== Splitting modified/untracked files > 50MB into chunks ==="
echo "Threshold: $(($THRESHOLD_BYTES / 1000000))MB"
echo "Maximum chunk size: $(($CHUNK_SIZE_BYTES / 1000000))MB"
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

            # Calculate number of chunks needed
            chunks_needed=$(( (file_size + CHUNK_SIZE_BYTES - 1) / CHUNK_SIZE_BYTES ))
            echo "  Will split into $chunks_needed chunk(s)"

            # Create base name for chunks
            dir_name=$(dirname "$file")
            base_name=$(basename "$file")
            chunk_base="${dir_name}/${base_name}.chunk"

            # Create chunks directory if it doesn't exist
            chunk_dir="${dir_name}/.${base_name}_chunks"
            mkdir -p "$chunk_dir"

            echo "  Splitting into chunks of max $(($CHUNK_SIZE_BYTES / 1000000))MB each..."

            # Split the file using split command
            if split -b "$CHUNK_SIZE_BYTES" -d -a 3 --additional-suffix=".part" "$file" "${chunk_dir}/"; then
                # Count created chunks
                actual_chunks=$(find "$chunk_dir" -name "*.part" -type f | wc -l)
                total_chunks_created=$((total_chunks_created + actual_chunks))

                echo "  ✓ Created $actual_chunks chunk(s) in $chunk_dir"

                # Create an info file with original file details
                info_file="${chunk_dir}/SPLIT_INFO.txt"
                cat > "$info_file" << EOF
Original file: $file
Original size: $file_size bytes ($(($file_size / 1000000))MB)
Split date: $(date)
Chunk size: $CHUNK_SIZE_BYTES bytes ($(($CHUNK_SIZE_BYTES / 1000000))MB)
Number of chunks: $actual_chunks
Command to recreate: cat ${chunk_dir}/*.part > "$file"
EOF

                echo "  ✓ Created info file: $info_file"

                # Remove original file
                echo "  Removing original file..."
                rm "$file"

                # Update counters
                split_files=$((split_files + 1))
                total_original_size=$((total_original_size + file_size))

                echo "  ✓ Done: $file -> split into $chunk_dir"
            else
                echo "  ✗ Failed to split $file"
                # Clean up partial chunks if split failed
                rm -rf "$chunk_dir" 2>/dev/null || true
            fi
            echo
      fi
    fi
done <<< "$uncommitted_files"

# Summary
echo "=== Summary ==="
echo "Total modified/untracked files processed: $total_files"
echo "Files split: $split_files"
echo "Total chunks created: $total_chunks_created"
if [ "$split_files" -gt 0 ]; then
    total_original_mb=$(echo "scale=1; $total_original_size / 1000000" | bc -l 2>/dev/null || echo $((total_original_size / 1000000)))
    echo "Total size of split files: ${total_original_mb}MB"
fi
echo
echo "To reassemble any split file, use the command found in the SPLIT_INFO.txt file"
echo "or run: cat .<filename>_chunks/*.part > <filename>"
echo "Done!"