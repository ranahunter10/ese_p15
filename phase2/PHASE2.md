# Phase 2 — repository rules

The full charter (threads, sync, interfaces) is the project doc
`claude/P2_00_CHARTER.md`. This file is the part that has to live next to
the code.

## The lock

- Tag **`v3.7-locked`** = the exact tree of `ese_p15_v3.7.zip`
  (sha256 `435db0c5…c29561`), 436 tests, VM-validated 2026-10-19.
- **No commit in Phase 2 modifies a locked file.** `phase2/verify_locked.sh`
  hashes all 78 of them against `phase2/LOCKED_v3.7.sha256` and fails naming
  any that changed. Run it before every commit (mutation-checked:
  appending one line to `hids/view.py` makes it fail).
- If a locked file truly must change (a Layer 1/2 bug found in Phase 2), that
  is a **new version, v3.8**: its own commit on `main`, a journal row, a new
  lock file, and the old tag stays as the revert target. Never a silent edit.
- The v3.7 suite stays green: `./run_tests.sh` must still print
  `Ran 436 tests … OK`.

## Layout

| Path | Owner | Status |
|---|---|---|
| `hids/ tools/ tests/ docs/ legacy/ runs/ run_tests.sh README.md VERSION` | — | **locked (v3.7)** |
| `layer3/` | DET thread | new — detection, exporter, its own `run_tests.sh` and tests |
| `fpga/` | FPGA thread | new — `rtl/ tb/ sim/ constr/` |
| `phase2/` | both (append-only) | rules, lock manifest, guard |

`layer3/` imports from `hids/` (read-only use, e.g. `hids.replay`) but never
patches it. New tests go in `layer3/tests/`, never `tests/` — the v3.7 test
count is pinned by its own drift guard.

## Branches and tags

- `main` — the lock plus merged, gate-passed work only.
- `p2/det`, `p2/fpga` — one per thread; each thread commits only to its own.
- Merge to `main` only after the stage gate passes; tag the merge
  (`det-s1`, `fpga-f1`, …) so every stage is a revert point.
- Commit messages name the gate and the evidence (test name, number).
