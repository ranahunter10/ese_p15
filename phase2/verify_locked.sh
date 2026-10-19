#!/bin/sh
# Proves the v3.7 baseline is untouched: every file locked at tag
# v3.7-locked must still hash to the value recorded there.
# Run from anywhere; exits non-zero and names the file if anything changed.
cd "$(dirname "$0")/.." || exit 2
if sha256sum --quiet -c phase2/LOCKED_v3.7.sha256; then
    echo "LOCKED v3.7: all $(wc -l < phase2/LOCKED_v3.7.sha256) files unchanged"
else
    echo "LOCKED v3.7: MODIFIED -- revert with: git checkout v3.7-locked -- <file>" >&2
    exit 1
fi
