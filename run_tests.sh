#!/usr/bin/env bash
# Runs every test that does not need root or a live kernel.
cd "$(dirname "$0")"
python3 -m unittest discover -s tests -p 'test_*.py' "$@"
