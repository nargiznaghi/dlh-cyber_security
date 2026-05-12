#!/bin/bash
find "$1" \( -perm -4000 -o -perm -2000 \) -exec ls -ld {} \; 2>/dev/null
