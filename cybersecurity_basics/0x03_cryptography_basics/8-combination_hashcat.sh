#!/bin/bash
hashcat -a 1 --stdout "$1" "$2" >/dev/null 2>&1; while read a; do while read b; do echo "$a$b"; done < "$2"; done < "$1" > combined.txt
