#!/bin/bash
find / -type d -perm -0002 -exec chmod o-w {} \;
