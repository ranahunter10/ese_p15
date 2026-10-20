`timescale 1ns / 1ps
// ============================================================================
// tb_f1 -- top of the F1 gate: per-source token bucket.
// TESTBENCH ONLY.  Verilog-2001 (iverilog -g2001; intended to run unchanged
// in Vivado xsim -- not yet run there).
//
// Runs, in sequence, every harness below and prints one summary line:
//   U1  update unit, defaults (100 MHz, 5000 pps, B=500, TS_W=48), suite 1
//   U2  update unit, B=1 at 100 MHz / 5000 pps,                    suite 2
//   U3  update unit, 125 MHz / 3000 pps / B=37, TS_W=40 (non-integer
//       period 41,666.67 cycles), generic + random
//   U4  update unit, SMALL: 1 kHz / 100 pps / B=3, TS_W=12 (counter wraps
//       every 4.1 s, so the random run aliases often), generic + random
//   W1  clocked wrapper, SMALL set (same as U4), directed + 200k-cycle random
//   W2  clocked wrapper, default widths, wiring check
//
// Plusargs:
//   +seed=<n>   random seed (default 20261020); printed in the log
//   +vcd        dump fpga/sim/build/tb_f1.vcd (wrapper W1 signals only)
//
// Exit: $finish(0) after "SUMMARY: N passed, 0 failed"; on any failure the
// summary is followed by $fatal (vvp exits 1).  See F1_NO_FATAL below.
// ============================================================================
module tb_f1;

    reg         go;
    reg  [31:0] seed;
    wire        d1, d2, d3, d4, d5, d6;
    wire [31:0] p1, p2, p3, p4, p5, p6;
    wire [31:0] f1, f2, f3, f4, f5, f6;
    reg  [31:0] tp, tf;

    tb_f1_unit #(.CLK_HZ(64'd100_000_000), .RATE_PPS(64'd5_000), .BURST(64'd500),
                 .TS_W(48), .SUITE(1), .NAME("U1"), .NRAND(100000))
        u1 (.go(go), .seed_in(seed),          .done(d1), .npass(p1), .nfail(f1));
    tb_f1_unit #(.CLK_HZ(64'd100_000_000), .RATE_PPS(64'd5_000), .BURST(64'd1),
                 .TS_W(48), .SUITE(2), .NAME("U2"), .NRAND(100000))
        u2 (.go(d1), .seed_in(seed + 32'd1),  .done(d2), .npass(p2), .nfail(f2));
    tb_f1_unit #(.CLK_HZ(64'd125_000_000), .RATE_PPS(64'd3_000), .BURST(64'd37),
                 .TS_W(40), .SUITE(3), .NAME("U3"), .NRAND(100000))
        u3 (.go(d2), .seed_in(seed + 32'd2),  .done(d3), .npass(p3), .nfail(f3));
    tb_f1_unit #(.CLK_HZ(64'd1_000), .RATE_PPS(64'd100), .BURST(64'd3),
                 .TS_W(12), .SUITE(3), .NAME("U4"), .NRAND(100000))
        u4 (.go(d3), .seed_in(seed + 32'd3),  .done(d4), .npass(p4), .nfail(f4));
    tb_f1_wrap #(.CLK_HZ(64'd1_000), .RATE_PPS(64'd100), .BURST(64'd3),
                 .TS_W(12), .SUITE(1), .NAME("W1"), .NCYC(200000))
        w1 (.go(d4), .seed_in(seed + 32'd4),  .done(d5), .npass(p5), .nfail(f5));
    tb_f1_wrap #(.CLK_HZ(64'd100_000_000), .RATE_PPS(64'd5_000), .BURST(64'd500),
                 .TS_W(48), .SUITE(2), .NAME("W2"), .NCYC(0))
        w2 (.go(d5), .seed_in(seed + 32'd5),  .done(d6), .npass(p6), .nfail(f6));

    initial begin
        go = 1'b0;
        if (!$value$plusargs("seed=%d", seed))
            seed = 32'd20261020;
        $display("tb_f1: F1 token bucket gate, seed = %0d", seed);
        if ($test$plusargs("vcd")) begin
            $dumpfile("tb_f1.vcd");
            $dumpvars(0, w1.dut);
        end
        #10 go = 1'b1;
    end

    initial begin
        wait (d6 === 1'b1);
        #10;
        tp = p1 + p2 + p3 + p4 + p5 + p6;
        tf = f1 + f2 + f3 + f4 + f5 + f6;
        $display("SUMMARY: %0d passed, %0d failed", tp, tf);
        // $fatal is IEEE 1800 (SystemVerilog), not 1364-2001; Icarus -g2001
        // accepts it and exits 1.  If a Verilog-2001-strict tool rejects it,
        // compile with -DF1_NO_FATAL (xvlog: -d F1_NO_FATAL).  Then the exit
        // status carries no verdict ($finish's argument is only a message
        // level) and the SUMMARY line is the verdict -- run_f1.sh greps it.
        if (tf != 0) begin
`ifdef F1_NO_FATAL
            $display("F1 gate FAILED");
            $finish(1);
`else
            $fatal(1, "F1 gate FAILED");
`endif
        end
        $finish(0);
    end

endmodule
