#!/bin/bash

mkdir -p /keys
[[ ! -f  /keys/ssh_host_ed25519_key ]] && ssh-keygen -t ed25519 -f /keys/ssh_host_ed25519_key -N ""

exec "$@"