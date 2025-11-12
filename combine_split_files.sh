#!/bin/bash

# Script to recombine split files back into original files and clean up split directories

set -e

# Counters
total_directories=0
combined_files=0
failed_combinations=0

echo "=== Combining split files back into original files ==="
echo

# Find all split chunk directories
echo "Finding split directories..."
split_dirs=$(find . -type d -name ".*_chunks" 2>/dev/null | sort)

if [ -z "$split_dirs" ]; then
    echo "No split directories found."
    exit 0
fi

echo "Found split directories. Processing..."
echo

# Process each split directory
while IFS= read -r chunk_dir; do
    total_directories=$((total_directories + 1))
    echo "Processing: $chunk_dir"

    # Check if SPLIT_INFO.txt exists
    info_file="${chunk_dir}/SPLIT_INFO.txt"
    if [ ! -f "$info_file" ]; then
        echo "  ⚠️  No SPLIT_INFO.txt found, will attempt to reconstruct"
        original_file=""
        chunk_files=($(find "$chunk_dir" -name "*.part" -type f | sort -V))
    else
        # Read info from SPLIT_INFO.txt
        original_file=$(grep "Original file:" "$info_file" | cut -d' ' -f3-)
        chunk_files=($(find "$chunk_dir" -name "*.part" -type f | sort -V))

        echo "  Original file: $original_file"
        echo "  Chunks found: ${#chunk_files[@]}"
    fi

    if [ ${#chunk_files[@]} -eq 0 ]; then
        echo "  ✗ No chunk files found in $chunk_dir"
        failed_combinations=$((failed_combinations + 1))
        echo
        continue
    fi

    # Determine original filename if not found in info
    if [ -z "$original_file" ]; then
        # Extract original filename from directory name
        dir_name=$(basename "$chunk_dir")
        original_file="${dir_name#.}"
        original_file="${original_file%_chunks}"
        echo "  Reconstructed original filename: $original_file"
    fi

    # Check if original file already exists
    if [ -f "$original_file" ]; then
        echo "  ⚠️  Original file already exists: $original_file"
        echo "  Skipping recombination"
        echo
        continue
    fi

    echo "  Combining ${#chunk_files[@]} chunks..."
    echo

    # Show progress for each chunk
    chunk_count=0
    total_size=0

    # Calculate total size first
    echo "  Calculating total size..."
    for chunk in "${chunk_files[@]}"; do
        chunk_size=$(stat -c%s "$chunk" 2>/dev/null || stat -f%z "$chunk" 2>/dev/null || echo 0)
        total_size=$((total_size + chunk_size))
    done

    total_size_mb=$(echo "scale=1; $total_size / 1000000" | bc -l 2>/dev/null || echo $((total_size / 1000000)))
    echo "  Total size to combine: ${total_size_mb}MB"
    echo

    # Combine chunks with progress
    current_size=0
    echo "  Combining chunks:"
    for chunk in "${chunk_files[@]}"; do
        chunk_count=$((chunk_count + 1))
        chunk_size=$(stat -c%s "$chunk" 2>/dev/null || stat -f%z "$chunk" 2>/dev/null || echo 0)
        chunk_size_mb=$(echo "scale=1; $chunk_size / 1000000" | bc -l 2>/dev/null || echo $((chunk_size / 1000000)))

        echo "    [$chunk_count/${#chunk_files[@]}] Adding $(basename "$chunk") (${chunk_size_mb}MB)"

        # Append chunk to original file
        if [ "$chunk_count" -eq 1 ]; then
            # First chunk - copy it
            cp "$chunk" "$original_file"
        else
            # Subsequent chunks - append them
            cat "$chunk" >> "$original_file"
        fi

        current_size=$((current_size + chunk_size))

        # Show progress percentage
        if [ "$total_size" -gt 0 ]; then
            progress=$((current_size * 100 / total_size))
            echo "    Progress: ${progress}% (${current_size}/${total_size} bytes)"
        fi
    done

    # Verify the combined file
    if [ -f "$original_file" ] && [ -s "$original_file" ]; then
        combined_size=$(stat -c%s "$original_file" 2>/dev/null || stat -f%z "$original_file" 2>/dev/null || echo 0)
        combined_size_mb=$(echo "scale=1; $combined_size / 1000000" | bc -l 2>/dev/null || echo $((combined_size / 1000000)))

        echo "  ✓ Combined file created: $original_file (${combined_size_mb}MB)"

        # Verify size matches expected
        if [ "$combined_size" -eq "$total_size" ]; then
            echo "  ✓ Size verification passed"

            # Clean up split directory
            echo "  Cleaning up split directory..."
            rm -rf "$chunk_dir"
            echo "  ✓ Removed $chunk_dir"

            combined_files=$((combined_files + 1))
        else
            echo "  ✗ Size verification failed! Combined: $combined_size, Expected: $total_size"
            echo "  Keeping original and chunks for manual inspection"
            failed_combinations=$((failed_combinations + 1))
        fi
    else
        echo "  ✗ Failed to create combined file"
        failed_combinations=$((failed_combinations + 1))
    fi

    echo
done <<< "$split_dirs"

# Summary
echo "=== Summary ==="
echo "Total split directories processed: $total_directories"
echo "Successfully combined: $combined_files"
echo "Failed combinations: $failed_combinations"

if [ "$failed_combinations" -gt 0 ]; then
    echo
    echo "⚠️  Some combinations failed. Please check the output above for details."
fi

echo "Done!"