#!/bin/bash
while read a; do while read b; do echo "$a$b"; done < "$2"; done < "$1"
