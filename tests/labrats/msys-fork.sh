#!/usr/bin/env bash

set -o pipefail

ls -a .
echo "hello world <$(ls -A .)>"