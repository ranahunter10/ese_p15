#!/bin/sh
# Runs the layer3 (detection track) tests. No root, no kernel, no network.
# Works from any directory; PYTHON overrides the interpreter, e.g.
#   PYTHON=python3.8 layer3/run_tests.sh
# Mirrors the top-level run_tests.sh, which stays locked at v3.7.
cd "$(dirname "$0")/.." || exit 2
exec "${PYTHON:-python3}" -m unittest discover -s layer3/tests -t . -p 'test_*.py' "$@"
