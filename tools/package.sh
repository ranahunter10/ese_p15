#!/usr/bin/env bash
# Package the tree and verify the suite FROM INSIDE the zip, on every Python
# installed. Verifying the working tree proves nothing about what ships: a
# file left out of the archive still passes in the tree it was never removed
# from, and the changelog claims the suite was run from inside the zip. This
# is how that claim is produced.
#
#     bash tools/package.sh              # -> ../ese_p15_<version>.zip
#
# The version comes from VERSION, so the archive cannot be named for a build
# it does not contain.
set -euo pipefail

SRC=$(cd "$(dirname "$0")/.." && pwd)
VER=$(cat "$SRC/VERSION")
WORK=$(mktemp -d)
OUT="$(dirname "$SRC")/ese_p15_${VER}.zip"

echo "== packaging $VER"
rm -rf "$WORK/ese_p15"
mkdir -p "$WORK/ese_p15"
# copy, then prune: anything not explicitly pruned ships, so a new
# directory is included by default rather than silently dropped.
cp -a "$SRC"/. "$WORK/ese_p15/"
find "$WORK/ese_p15" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$WORK/ese_p15" -name '*.pyc' -delete
rm -rf "$WORK/ese_p15/.git" "$WORK/ese_p15"/*.zip

echo "== tree that will ship"
( cd "$WORK/ese_p15" && find . -type f | sed 's|^\./||' | sort )
echo "== file count: $(find "$WORK/ese_p15" -type f | wc -l)"

rm -f "$OUT"
( cd "$WORK" && zip -qr "$OUT" ese_p15 )
echo "== wrote $OUT ($(du -h "$OUT" | cut -f1))"

echo
echo "== verifying FROM THE ZIP (fresh unzip, not the working tree)"
VERIFY=$(mktemp -d)
( cd "$VERIFY" && unzip -q "$OUT" )
test -f "$VERIFY/ese_p15/run_tests.sh" || { echo "run_tests.sh missing from zip"; exit 1; }
chmod +x "$VERIFY/ese_p15/run_tests.sh"

fail=0
for py in python3.8 python3.9 python3.10 python3.11 python3.12 python3.13; do
  command -v "$py" >/dev/null 2>&1 || { echo "-- $py: not installed, skipped"; continue; }
  v=$("$py" -V 2>&1)
  printf -- "-- %s (%s): " "$py" "$v"
  if out=$( cd "$VERIFY/ese_p15" && "$py" -m unittest discover -s tests -p 'test_*.py' 2>&1 | tail -3 ); then
    echo "$out" | tr '\n' ' '; echo
  else
    echo "FAILED"; echo "$out"; fail=1
  fi
done

echo
echo "== version stamp inside the zip"
grep -h "__version__" "$VERIFY/ese_p15/hids/__init__.py"
head -1 "$VERIFY/ese_p15/README.md"
cat "$VERIFY/ese_p15/VERSION"

rm -rf "$WORK" "$VERIFY"
exit $fail
