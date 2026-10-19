# fpga/ — Layer 4 enforcement track (FPGA thread)

Status: project doc `claude/P2_FPGA_STATE.md` (single writer: the FPGA thread).
Contract with detection: project doc `claude/P2_INTERFACE_alert_rule.md`.

Layout: `rtl/` synthesizable Verilog · `tb/` self-checking testbenches ·
`sim/` scripts and waveform configs · `constr/` XDC for the board.

Conventions:
- **Verilog-2001** for RTL (synthesizable subset, one module per file,
  parameters for every size: table depth, rate, burst, clock frequency).
- Every testbench is **self-checking**: it prints `PASS <name>` or
  `FAIL <name>: <expected> vs <got>` and ends with a summary line. A waveform
  is evidence for the report, never the test itself.
- Two simulators, same testbench: **Icarus Verilog 12** in the thread's
  container (fast iteration), **Vivado xsim** on the laptop (authoritative,
  and the waveforms for the Phase II report). Anything that passes in one
  and not the other is a finding, logged.
- Synthesis (timing / utilization / power) on the laptop in Vivado; the
  reports are committed under `sim/reports/<date>/`.
