#!/bin/bash

# Check arguments
if [ $# -ne 2 ]; then
    echo "Usage: $0 <wordlist1> <wordlist2>"
    exit 1
fi

WORDLIST1="$1"
WORDLIST2="$2"

# Combine wordlists using hashcat combinator mode
hashcat --stdout -a 1 "$WORDLIST1" "$WORDLIST2" > combined.txt

# Show result as required (optional display step)
cat combined.txt
