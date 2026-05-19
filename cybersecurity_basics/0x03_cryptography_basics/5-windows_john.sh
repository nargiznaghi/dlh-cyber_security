#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <hash_file>"
    exit 1
fi

HASH_FILE="$1"

john --wordlist=/usr/share/wordlists/rockyou.txt --format=nt "$HASH_FILE"

john --show --format=nt "$HASH_FILE" | cut -d: -f2 | head -n 1 > 5-password.txt
