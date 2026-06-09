#!/bin/bash

encoded="${1#\{xor\}}"

printf '%s' "$encoded" | base64 -d | od -An -t u1 | tr -s ' ' '\n' | while read -r byte
do
	if [ -n "$byte" ]
	then
		value=$((byte ^ 95))
		printf "\\$(printf '%03o' "$value")"
	fi
done

printf '\n'
