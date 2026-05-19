#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Usage: $0 <wordlist1> <wordlist2>"
    exit 1
fi

hashcat --stdout -a 1 "$1" "$2"
