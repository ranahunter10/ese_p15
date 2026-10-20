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

## S1 status (exporter) — gates (a)–(c)

- `layer3/export_pidsmaker.py rec.p15raw out/` → `entities.tsv`, `edges.tsv`,
  `export_meta.json`. Every open decision (D9, D23, D24, time base, …) is a
  flag; `--help` lists them, the meta records the values used.
- Gates: `layer3/tests/test_export_s1.py` — `ConservationGateTest` (a),
  `DeterminismGateTest` (b), `DirectionGateTest` (c).
- Mutation evidence: `layer3/tests/MUTANTS_S1.md`, re-run with
  `python3 layer3/tests/mutate_s1.py`.
- Real VM recording: `layer3/fixtures/s1_mixed/` (sha256-pinned, recorded on
  the VM from v3.7). Gates S1(b-vm) byte-identical export and S1(m) marker
  steps → edges in `layer3/tests/test_vm_fixture_s1.py`. The VM's timezone is
  **UTC−4**.
- Gates (d) Postgres load and (e) PIDSMaker run: not started.
- Default timestamps are **boot-relative CLOCK_MONOTONIC**, not unix epoch: a
  P15R recording carries no wall-clock anchor (`--wall-offset-ns`).
