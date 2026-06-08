#!/bin/bash

# Check argument
if [ -z "$1" ]
then
    echo "Usage: $0 {xor}encoded_string"
    exit 1
fi

# Remove {xor} prefix
input="$1"
prefix="{xor}"
cleaned="${input#$prefix}"

# Base64 decode
decoded=$(echo "$cleaned" | base64 -d 2>/dev/null)

# XOR each byte with 0xFF
result=""
for byte in $(echo -n "$decoded" | od -An -t u1)
do
    xor=$((255 - byte))
    result="$result$(printf "\\$(printf '%03o' "$xor")")"
done

echo "$result"
