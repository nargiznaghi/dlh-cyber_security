#!/bin/bash
# Find all world-writable directories and secure them

find / -type d -perm -0002 2>/dev/null | while read dir; do
  echo "$dir"
  chmod o-w "$dir"
done

echo "done"
