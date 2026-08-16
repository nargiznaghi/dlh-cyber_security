#!/bin/bash
hashcat -a 1 -m 0 "$1" wordlist1.txt wordlist2.txt --quiet
hashcat --show -m 0 "$1" | cut -d ':' -f2 > 9-password.txt
