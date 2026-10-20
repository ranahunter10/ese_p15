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
