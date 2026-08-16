#!/bin/bash

# Check argument
if [ $# -ne 1 ]; then
    echo "Usage: $0 <hash_file>"
    exit 1
fi

HASH_FILE="$1"

# Crack MD5 hash using hashcat
hashcat -m 0 "$HASH_FILE" /usr/share/wordlists/rockyou.txt

# Save cracked password
hashcat -m 0 --show "$HASH_FILE" | cut -d: -f2 > 7-password.txt
