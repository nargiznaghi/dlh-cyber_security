#!/bin/bash
echo "$1 ALL=(ALL) NOPASSWD: ALL" | sudo EDITOR='tee -a' visudo
