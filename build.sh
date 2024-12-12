#!/bin/bash
sudo apt install clang libbpf-dev

# Build the eBPF program
PROJ_DIR=$(dirname $(realpath $0))
cd $PROJ_DIR && make