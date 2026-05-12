#!/bin/bash
tee -a /etc/sudoers <<< "$1 ALL=(ALL) NOPASSWD: ALL"
