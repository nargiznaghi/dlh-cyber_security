#!/bin/bash
find "$1" -perm -2000 -exec echo {} \; 2>/dev/null
