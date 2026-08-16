#!/bin/bash
find "$1" -perm -4000 -exec echo {} \; 2>/dev/null
