# layer3/ — detection track (DET thread)

Plan: project doc `claude/LANDSCAPE_PLAN_2026-10-19.md` §4 (stages S1–S9).
Status: project doc `claude/P2_DET_STATE.md` (single writer: the DET thread).

Rules:
- Python 3.8 compatible and stdlib-only for anything that runs on the VM
  (exporter, attack runner). PIDSMaker-side code (Python ≥ 3.9) is kept
  separate and never imported by VM code.
- Tests in `layer3/tests/`, run with `layer3/run_tests.sh` (no sudo).
- Every gate is a test that fails when the fix is reverted.

First stage: **S1 — exporter**, `replay recording → entities.tsv + edges.tsv`
to the contract in LANDSCAPE §5.1, gates S1(a)–(e).
