#!/bin/bash

# Check argument
if [ $# -ne 1 ]; then
    echo "Usage: $0 hash.txt"
    exit 1
fi

HASH_FILE="$1"

WORDLIST1="wordlist1.txt"
WORDLIST2="wordlist2.txt"
OUTPUT_FILE="9-password.txt"

# Run hashcat (combination attack)
hashcat -m 0 -a 1 "$HASH_FILE" "$WORDLIST1" "$WORDLIST2" --quiet

# Extract cracked password and save it
hashcat -m 0 "$HASH_FILE" --show | awk -F: 'NR==1 {print $2}' > "$OUTPUT_FILE"

echo "Password saved in $OUTPUT_FILE"
