#!/bin/bash

# Check if file argument exists
if [ $# -ne 1 ]; then
    echo "Usage: $0 <hash_file>"
    exit 1
fi

HASH_FILE="$1"

# Crack SHA256 hash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA256 "$HASH_FILE"

# Save cracked password
john --show --format=Raw-SHA256 "$HASH_FILE" | cut -d: -f2 | head -n 1 > 6-password.txt
