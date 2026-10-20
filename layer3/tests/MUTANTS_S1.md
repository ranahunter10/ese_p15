# S1 mutation record — gates (a)–(c)

A gate counts as passing only if breaking what it guards makes a named test
fail. Each mutant below is ONE exact text replacement in
`layer3/export_pidsmaker.py`, applied by `layer3/tests/mutate_s1.py` to a
temporary copy of `hids/` + `layer3/` — never to the worktree, so no mutant
can be left behind. The unmutated copy is run first and must pass.

Re-run: `python3 layer3/tests/mutate_s1.py` (any of 3.8 / 3.13). Exit 0 means
every mutant was killed.

Run 2026-10-20 against exporter commit 6f5a2b5, Python 3.8.20 and 3.13.16, identical
result: **baseline OK (16 tests), 20 mutants, 20 killed, 0 survived.**

All killing tests are in `layer3/tests/test_export_s1.py`; class prefixes
`Cons` = `ConservationGateTest`, `Det` = `DeterminismGateTest`, `Dir` =
`DirectionGateTest`.

| id | gate | mutant | killed by | failures |
|---|---|---|---|---|
| A1 | S1(a) | drop the last edge (`raw[:-1]`) | Cons.test_every_graph_edge_appears_exactly_once_under_every_option_set | 8 subtests |
| A2 | S1(a) | emit the first edge twice | Cons.test_every_graph_edge_appears_exactly_once_under_every_option_set | 8 |
| A3 | S1(a) | drop one edge AND duplicate another — **edge count unchanged** | Cons.test_every_graph_edge_appears_exactly_once_under_every_option_set | 8 |
| A4 | S1(a) | `_<int>` suffix not unique (`idx // 2`) | Cons.test_every_id_survives_their_index_parse | 1 |
| A5 | S1(a) | suffix their `int(rsplit("_"))` cannot parse (`-` separator) | Cons.test_every_id_survives_their_index_parse | 1 |
| A6 | S1(a) | one referenced entity not written (dangling edges) | Cons.test_every_graph_edge_…, Cons.test_entities_are_exactly_the_referenced_nodes | 9 |
| A7 | S1(a) | failed connects dropped but NOT counted (silent drop) | Cons.test_every_graph_edge_appears_exactly_once_under_every_option_set | 7 |
| B1 | S1(b) | tiebreak by arrival order (sort on ts only) | Det.test_arrival_order_of_tied_records_does_not_change_the_export | 1 |
| B2 | S1(b) | entity index order = `set` iteration order | Det.test_hash_randomisation_does_not_reach_the_output | 1 |
| B3 | S1(b) | wall-clock `time.time()` written into export_meta.json | Det.test_two_fresh_replays_export_byte_identical_files | 1 |
| C1 | S1(c) | READ written process→file | Dir.test_read_is_file_to_process | 1 |
| C2 | S1(c) | EXECUTE written process→file | Dir.test_execute_is_file_to_process | 1 |
| C3 | S1(c) | WRITE written file→process | Dir.test_write_is_process_to_file | 1 |
| C4 | S1(c) | CLONE written child→parent | Dir.test_clone_is_parent_to_child | 1 |
| C5 | S1(c) | accept written process→socket | Dir.test_accept_is_socket_to_process_as_connect_by_default | 1 |
| C6 | S1(c) | outbound connect written socket→process | Dir.test_outbound_connect_is_process_to_socket | 1 |
| C7 | S1(c) | RW open emits READ only (WRITE lost) | Dir.test_a_read_write_open_is_both_directions_by_default | 1 |
| E1 | escaping | a raw `\n` passes through unescaped | HostileStringsTest.test_a_hostile_path_cannot_add_lines_or_columns | 1 |
| E2 | escaping | `\` no longer escaped (rule not reversible) | HostileStringsTest.test_escaping_is_injective_on_the_classic_collision | 1 |
| T1 | D23 | timestamp text formatted via a float (`"%.9f" % (ns/1e9)`) | TimestampTest.test_float_seconds_text_is_exact_on_our_side | 1 |

## Notes

- **A3 is the reason for multiset equality.** It keeps the row count at 27,
  so any count-based check passes; the set comparison fails it.
- **B2 needs the PYTHONHASHSEED test.** Within one process the set order is
  stable, so two in-process exports agree; it differs only across hash
  seeds (subprocess runs with seeds 0, 1, 4242). The in-process
  determinism test does NOT kill B2 — that is why both exist.
- **B1 needs the swapped-arrival test.** Two fresh replays of one recording
  agree even with an arrival-order tiebreak, because arrival is then the
  same both times.
- **Equivalent mutant found and replaced.** The first E1 deleted `"\n"` from
  `_LETTER`; it SURVIVED because `_needs_hex` still escapes the newline as
  `\x0a`. The output is still safe, so it is an equivalent mutant (no test
  could kill it), not a missing test. Replaced by a mutant that lets a raw
  newline through, which the hostile-path test kills.
- Not covered by a mutant here: the less common option branches
  (`unix_endpoints=drop`, `probe_endpoints=drop`, `failed_connects=connect`,
  `open_as=rw-writeonly/open`, `accept_as=accept`, `clone_parent=original`)
  are each exercised by a test — conservation is re-checked under every
  option set, and `CloneParentOptionTest` / the Direction tests pin the
  option-specific output — but no mutant targets those branches.

## Manager review — independent sweep (20 Oct 2026)

A second sweep by someone other than the author, run as a full
`layer3/run_tests.sh` per mutant on Python 3.8.20. First pass: 16 mutants,
10 killed. Tests added in `test_export_review.py`; second pass: **15 of 16
killed, the survivor equivalent.**

| # | Mutant | Killed by |
|---|---|---|
| R1 | exe not space-escaped | `test_the_hostile_strings_are_recoverable_exactly` |
| R2 | unix SOCK path not space-escaped | `test_the_hostile_strings_are_recoverable_exactly` |
| R3 | FILE text = oldest name | **new** `test_file_text_is_the_newest_name_the_graph_holds` |
| R4 | CLONE stamped at `start_ns`, not `_fork_ts` | **new** `test_clone_uses_the_graph_fork_time_for_an_estimated_start` |
| R5 | probe filter `endswith("0")` (drops port 80) | conservation, option set `probe_endpoints=drop` |
| R6 | `rw-writeonly` collapses every read | conservation + `test_rw_writeonly_collapses_rw_to_write_and_counts_it` |
| R7 | control chars < 0x20 pass through | `test_escape_round_trips_every_awkward_character` |
| R8 | cmdline not escaped | hostile-strings, id-parse, referenced-nodes tests |
| R9 | CLI ignores the bootstrap sidecar | **new** `test_the_cli_uses_the_bootstrap_sidecar` |
| R10 | failed opens not reported | `test_graph_side_non_edges_are_reported` |
| R11 | `unix_endpoints=drop` ignored for accepts | conservation, option set `unix_endpoints=drop` |
| R12 | tiebreak compares dst before src | **equivalent** — still a total, deterministic order; no test should kill it |
| R13 | unknown endpoint scheme kept | **new** `test_an_unknown_endpoint_scheme_is_dropped_by_name` |
| R14 | space escaping on `" "` only (not NBSP etc.) | `test_escape_round_trips_every_awkward_character` |
| R15 | negative wall offset accepted | `test_a_negative_offset_is_refused` |
| R16 | meta never flags the loader patch | **new** `test_meta_says_when_their_loader_must_be_patched` |

**Limit found in review (not a defect):** the S1(a) reference reads
`FileNode.accesses`, which the graph trims at `MAX_ACCESSES_PER_FILE` (2000).
One file opened > 2000 times — `/etc/ld.so.cache` on any real host — makes
the reference and a *correct* export differ (probe: 3000 opens exported,
2000 in the reference). S1(a) is exact only below every graph cap; pinned by
`AccessCapLimitTest`.

**Contract check against PIDSMaker's source (review, `0a0f41d` cloned and
read).** `tsvread.loader_view` matches `create_database_provenance_benign.py`
`load_entities`/`load_edges`/`build_entity_index_map`, and the 10-type
vocabulary matches `rel2id_darpa_tc` (`dataset_utils.py:27-48`). Their
`possible_events` (`:49-82`) lists `EVENT_OPEN` only as (file, subject) and
(netflow, subject), so `--open-as open` now emits **file→process** (it was
process→file). Mutant "OPEN back to process→file" is killed by three tests.
The default accept mapping (`EVENT_CONNECT` sock→proc, as their own mapper
does) is **not** in that table; it is reported, not changed (D24).

## Real VM fixture `s1_mixed`: gates S1(b-vm) and S1(m) (20 Oct 2026)

`layer3/tests/test_vm_fixture_s1.py`, 9 tests. Each mutant below was run
twice: once against the VM-fixture tests alone (`-p test_vm_fixture_s1.py`)
and once against the full suite. Python 3.8.20.

| # | Mutant | VM tests alone | Full suite |
|---|---|---|---|
| V1 | accepts not exported | killed: `test_accept_on_127_0_0_1_port_8765` | killed |
| V2 | READ written process→file | killed: exec-chain and file-flow tests | killed |
| V3 | `--wall-offset-ns` ignored | killed: anchor, accept and outbound tests | killed |
| V4 | entity order taken from set iteration | killed: `test_export_of_two_fresh_replays_is_byte_identical` | killed |
| V5 | only a process's last exec exported | killed: `test_exec_chain_bash_sh_cat` | killed |
| V6 | repeated connects to one peer merged | killed: `test_connect_to_example_com` | killed |
| V7 | edges sorted by time only, ties left in arrival order | **survives, by construction** | killed: `test_arrival_order_of_tied_records_does_not_change_the_export` |
| V8 | CLONE into `cat` dropped | killed: exec-chain and file-flow tests | killed |

Why V7 survives the VM tests: one recording always replays in one order, so
a tiebreak by arrival order is still deterministic on that recording.
Byte-identity across runs of a single recording cannot detect it. Only a
second recording with the tied records swapped can, and that is the
synthetic test.

The first version of V6 (`set(node.conns)`) was an equivalent mutant,
because every connect has its own timestamp, so the set merged nothing. It
was replaced by a real merge on the peer.
