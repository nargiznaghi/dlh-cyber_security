#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 hash.txt"
    exit 1
fi

HASH_FILE="$1"
OUTPUT_FILE="4-password.txt"

# Force correct format (MD5)
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt "$HASH_FILE"

# Extract cracked passwords only
john --show --format=raw-md5 "$HASH_FILE" | cut -d ':' -f2 > "$OUTPUT_FILE"
