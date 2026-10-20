`timescale 1ns / 1ps
// ============================================================================
// tb_f1_unit -- self-checking test harness for token_bucket_update (F1).
// TESTBENCH ONLY, not synthesizable.  Verilog-2001 (runs under iverilog
// -g2001; written to run unchanged in Vivado xsim).
//
// The unit under test is combinational and takes `now` as an input, so this
// harness drives exact timestamps at full-scale parameters (100 MHz,
// 5,000 pps) without simulating every clock cycle: each call advances the
// simulation by #1 and presents an arbitrary 64-bit "true time" whose low
// TS_W bits are the counter value the hardware would see.
//
// Every call is ALSO compared, output by output, against the independent
// reference model in f1_ref_model.vh (64/128-bit integer arithmetic, no
// derived widths).  A directed test passes only if its hand-derived
// expectation holds AND the reference model agreed on every call it made.
//
// SUITE selects the directed tests whose expected values are hand-derived
// for a particular parameter set (derivations: fpga/F1_NOTES.md):
//   1 = defaults (100 MHz, 5000 pps, B=500, TS_W=48)  -- full directed suite
//   2 = B=1 at 100 MHz / 5000 pps                      -- B=1 behaviour
//   3 = any other set                                  -- generic tests only
// Generic tests (formula-derived, any parameters) and the seeded random
// comparison run in every suite.
// ============================================================================
module tb_f1_unit #(
    parameter [63:0] CLK_HZ   = 64'd100_000_000,
    parameter [63:0] RATE_PPS = 64'd5_000,
    parameter [63:0] BURST    = 64'd500,
    parameter        TS_W     = 48,
    parameter        SUITE    = 3,
    parameter        NAME     = "S?",
    parameter        NRAND    = 100000
) (
    go, seed_in, done, npass, nfail
);
`include "f1_clog2.vh"
`include "f1_ref_model.vh"

    input  wire        go;
    input  wire [31:0] seed_in;
    output reg         done;
    output reg  [31:0] npass;
    output reg  [31:0] nfail;

    localparam [63:0]  COST   = CLK_HZ;
    localparam [63:0]  CAP    = BURST * CLK_HZ;
    localparam [63:0]  T_FULL = (CAP + RATE_PPS - 64'd1) / RATE_PPS;
    localparam integer TOK_W  = f1_bits(CAP);
    localparam [63:0]  TSMASK = (TS_W >= 64) ? ~64'd0 : ((64'd1 << TS_W) - 64'd1);
    localparam [63:0]  WRAP   = TSMASK + 64'd1;          // 2^TS_W
    localparam [63:0]  PERIOD = CLK_HZ / RATE_PPS;       // floor(1/R) in cycles
    localparam [63:0]  ALL1   = ~64'd0;

    // ---- unit under test -----------------------------------------------------
    reg              u_pkt, u_valid;
    reg [TS_W-1:0]   u_now, u_last;
    reg [TOK_W-1:0]  u_tok;
    wire [TOK_W-1:0] o_tok;
    wire [TS_W-1:0]  o_last;
    wire             o_conf, o_flag;

    token_bucket_update #(
        .CLK_HZ(CLK_HZ), .RATE_PPS(RATE_PPS), .BURST(BURST), .TS_W(TS_W)
    ) dut (
        .pkt(u_pkt), .now(u_now), .st_valid(u_valid), .st_tokens(u_tok),
        .st_last(u_last), .nx_tokens(o_tok), .nx_last(o_last),
        .conform(o_conf), .flag(o_flag)
    );

    // ---- harness state -------------------------------------------------------
    reg        d_valid;  reg [63:0] d_tok;  reg [TS_W-1:0] d_last;  // DUT-side
    reg        r_valid;  reg [63:0] r_tok;  reg [63:0]     r_last;  // ref (masked)
    reg        q_valid;  reg [63:0] q_tok;  reg [63:0]     q_last;  // ref (true time)
    reg        rc, rf, qc, qf;
    reg [63:0] rt, qt;
    reg        last_conf, last_flag;
    reg [63:0] last_tok;

    integer    mism, mism_total;
    integer    n_pkt, n_flag, n_conf, first_flag, conf_after_first;
    integer    q_flag;               // flags of the true-time model
    integer    n_full_hits;          // calls where the bucket was saturated
    integer    k, n;
    reg [63:0] t, t0, gap;
    reg [31:0] r32;
    integer    seed;

    // fixed-window behavioural model (REFERENCE ONLY, not the design)
    reg [63:0] fw_win;  reg [63:0] fw_cnt;  integer fw_flags;
    reg [63:0] fw_max_in_window;

    // ---- helpers -------------------------------------------------------------
    task clear_counts;
        begin
            mism = 0; n_pkt = 0; n_flag = 0; n_conf = 0; first_flag = -1;
            conf_after_first = -1; q_flag = 0; n_full_hits = 0;
            fw_win = ALL1; fw_cnt = 0; fw_flags = 0; fw_max_in_window = 0;
        end
    endtask

    task src_never_seen;   // also = state after reset
        begin
            d_valid = 1'b0; d_tok = 64'd0; d_last = {TS_W{1'b0}};
            r_valid = 1'b0; r_tok = 64'd0; r_last = 64'd0;
            q_valid = 1'b0; q_tok = 64'd0; q_last = 64'd0;
            clear_counts;
        end
    endtask

    task src_state;        // a stored state: tok tokens valid at true time tl
        input [63:0] tok;
        input [63:0] tl;
        begin
            d_valid = 1'b1; d_tok = tok; d_last = tl[TS_W-1:0];
            r_valid = 1'b1; r_tok = tok; r_last = tl;
            q_valid = 1'b1; q_tok = tok; q_last = tl;
            clear_counts;
        end
    endtask

    // One call of the update unit at true time tt; p = packet (1) / refresh (0).
    task step;
        input        p;
        input [63:0] tt;
        begin
            u_pkt   = p;
            u_now   = tt[TS_W-1:0];
            u_valid = d_valid;
            u_tok   = d_tok[TOK_W-1:0];
            u_last  = d_last;
            #1;
            last_conf = o_conf; last_flag = o_flag;
            last_tok  = {{(64-TOK_W){1'b0}}, o_tok};

            ref_step(p, r_valid, r_tok, r_last, tt, TSMASK, CAP, COST, RATE_PPS,
                     rc, rf, rt);
            ref_step(p, q_valid, q_tok, q_last, tt, ALL1, CAP, COST, RATE_PPS,
                     qc, qf, qt);

            if ((last_conf !== rc) || (last_flag !== rf) || (last_tok !== rt) ||
                (o_last !== tt[TS_W-1:0])) begin
                mism = mism + 1; mism_total = mism_total + 1;
                if (mism <= 3)
                    $display("  MISMATCH %0s t=%0d p=%0d: dut conf=%0d flag=%0d tok=%0d | ref conf=%0d flag=%0d tok=%0d",
                             NAME, tt, p, last_conf, last_flag, last_tok, rc, rf, rt);
            end

            if (p) begin
                if (last_flag) begin
                    n_flag = n_flag + 1;
                    if (first_flag < 0) first_flag = n_pkt;
                end
                if (last_conf) n_conf = n_conf + 1;
                if ((first_flag >= 0) && (n_pkt == first_flag + 1))
                    conf_after_first = last_conf;
                if (qf) q_flag = q_flag + 1;
                n_pkt = n_pkt + 1;
            end
            if ((last_tok == CAP) || (last_conf && (last_tok == CAP - COST)))
                n_full_hits = n_full_hits + 1;

            d_valid = 1'b1; d_tok = last_tok; d_last = o_last;
            r_valid = 1'b1; r_tok = rt;       r_last = tt;
            q_valid = 1'b1; q_tok = qt;       q_last = tt;
        end
    endtask

    task fw_pkt;           // fixed 1-second window counter, REFERENCE ONLY
        input [63:0] tt;
        begin
            if ((tt / CLK_HZ) != fw_win) begin
                fw_win = tt / CLK_HZ; fw_cnt = 0;
            end
            fw_cnt = fw_cnt + 1;
            if (fw_cnt > fw_max_in_window) fw_max_in_window = fw_cnt;
            if (fw_cnt > RATE_PPS) fw_flags = fw_flags + 1;
        end
    endtask

    task check;
        input [8*80-1:0] name;
        input [63:0]     exp;
        input [63:0]     got;
        begin
            if ((exp === got) && (mism == 0)) begin
                npass = npass + 1;
                $display("PASS %0s/%0s", NAME, name);
            end else begin
                nfail = nfail + 1;
                if (exp !== got)
                    $display("FAIL %0s/%0s: %0d vs %0d", NAME, name, exp, got);
                else
                    $display("FAIL %0s/%0s: 0 vs %0d reference-model mismatches",
                             NAME, name, mism);
            end
        end
    endtask

    // ---- the tests -------------------------------------------------------------
    initial begin
        done = 1'b0; npass = 0; nfail = 0; mism_total = 0;
        u_pkt = 0; u_valid = 0; u_now = 0; u_last = 0; u_tok = 0;
        @(posedge go);
        seed = seed_in;
        $display("---- %0s: CLK_HZ=%0d RATE_PPS=%0d BURST=%0d TS_W=%0d | COST=%0d CAP=%0d T_FULL=%0d TOK_W=%0d",
                 NAME, CLK_HZ, RATE_PPS, BURST, TS_W, COST, CAP, T_FULL, TOK_W);

        // ===== generic tests (expected values are formulas of the params) ====

        // Never-seen source = full bucket: first packet conforms, leaves CAP-COST.
        src_never_seen;
        step(1'b1, 64'd12345);
        check("init_never_seen_is_full_conform", 1, last_conf);
        check("init_never_seen_tokens_CAP_minus_COST", CAP - COST, last_tok);

        // Refresh call (pkt=0) never consumes and never decides.
        src_state(COST, 64'd0);
        step(1'b0, 64'd0);
        check("refresh_no_decision", 0, {last_conf, last_flag});
        check("refresh_no_consume", COST, last_tok);

        // Boundary of the compare: tokens == COST conforms, COST-1 flags.
        src_state(COST, 64'd100);
        step(1'b1, 64'd100);
        check("tokens_eq_COST_conforms", 1, last_conf);
        check("tokens_eq_COST_leaves_0", 0, last_tok);
        src_state(COST - 1, 64'd100);
        step(1'b1, 64'd100);
        check("tokens_COST_minus_1_flags", 1, last_flag);
        // Non-conforming packet consumes nothing ...
        check("flag_consumes_nothing", COST - 1, last_tok);
        // ... so one more cycle of refill is enough for the next packet.
        step(1'b1, 64'd101);
        check("after_flag_one_cycle_refill_conforms", 1, last_conf);
        check("after_flag_tokens",
              ((COST - 1 + RATE_PPS > CAP) ? CAP : COST - 1 + RATE_PPS) - COST, last_tok);

        // Refill exactness and saturation.
        src_state(64'd0, 64'd0);
        step(1'b0, T_FULL - 1);
        check("refill_T_FULL_minus_1_exact", (T_FULL - 1) * RATE_PPS, last_tok);
        src_state(64'd0, 64'd0);
        step(1'b0, T_FULL);
        check("refill_T_FULL_saturates_at_CAP", CAP, last_tok);
        src_state(CAP - COST, 64'd0);
        step(1'b0, T_FULL);
        check("refill_from_nonzero_caps_at_CAP", CAP, last_tok);
        src_state(CAP - COST, 64'd7);
        step(1'b0, 64'd8);
        check("refill_one_cycle_exact", CAP - COST + RATE_PPS, last_tok);
        src_state(64'd0, 64'd0);
        step(1'b0, ((T_FULL * 64'd37) / 64'd100) + 64'd3);
        check("refill_odd_gap_exact", (((T_FULL * 64'd37) / 64'd100) + 64'd3) * RATE_PPS,
              last_tok);
        // Gap just above the clamp-register range (2^EL_W + 5) -> still full.
        src_state(64'd0, 64'd0);
        gap = (64'd1 << f1_bits(T_FULL)) + 64'd5;
        if (gap > TSMASK) gap = TSMASK;
        step(1'b0, gap);
        check("idle_gap_2powEL_plus_5_is_full", CAP, last_tok);
        // Largest gap the counter represents exactly: 2^TS_W - 1 -> full.
        src_state(64'd0, 64'd0);
        step(1'b0, TSMASK);
        check("idle_gap_max_2powTS_minus_1_is_full", CAP, last_tok);

        // After a long idle the refill is capped: exactly B packets of burst.
        src_state(64'd0, 64'd0);
        t = T_FULL;                                 // idle exactly T_FULL
        step(1'b0, t);
        check("long_idle_bucket_exactly_CAP", CAP, last_tok);
        if (BURST * RATE_PPS < COST) begin
            // burst every cycle: B*R < COST, so refill during the burst
            // is < 1 packet: B conform, the (B+1)th flags.
            clear_counts;
            for (k = 1; k <= BURST + 1; k = k + 1) step(1'b1, t + k);
            check("cap_then_burst_B_plus_1_first_flag_index_B", BURST, first_flag);
            check("cap_then_burst_B_plus_1_one_flag", 1, n_flag);

            src_never_seen;
            for (k = 0; k < BURST; k = k + 1) step(1'b1, 64'd1000 + k);
            check("burst_B_from_full_no_flag", 0, n_flag);
            step(1'b1, 64'd1000 + BURST);
            check("burst_B_plus_1_from_full_one_flag", 1, n_flag);
            check("burst_B_plus_1_flag_on_last", BURST, first_flag);
        end

        // Counter wrap: the gap straddles 2^TS_W; elapsed = 5000 cycles exactly
        // (expected = min(CAP, 5000*R)).
        src_state(64'd0, WRAP - 64'd3000);
        step(1'b0, WRAP + 64'd2000);
        check("wrap_elapsed_exact_across_wrap",
              ((64'd5000 * RATE_PPS > CAP) ? CAP : 64'd5000 * RATE_PPS), last_tok);
        // Gap of exactly 2^TS_W + T_FULL: aliased residue >= T_FULL -> still exact.
        src_state(64'd0, 64'd0);
        step(1'b0, WRAP + T_FULL);
        check("wrap_alias_residue_ge_T_FULL_still_full", CAP, last_tok);
        // Gap of 2^TS_W + 100 from an empty bucket: DOCUMENTED LIMITATION.
        // The counter aliased: the unit sees 100 cycles, true time is a full
        // bucket.  Pinned here so any change of this behaviour is noticed.
        src_state(64'd0, 64'd0);
        step(1'b1, WRAP + 64'd100);
        check("wrap_alias_gap_2powTS_plus_100_DOCUMENTED_flag",
              (64'd100 * RATE_PPS < COST), last_flag);
        check("wrap_alias_true_time_model_would_conform", 1, qc);

        // Exactly R pps from an EMPTY bucket (zero slack), timestamps
        // t_k = ceil(k*CLK_HZ/R) also for non-integer periods: never flags
        // (proof in F1_NOTES.md, needs B >= 2).  Then the same stream
        // straddling the counter wrap.
        if (BURST >= 2) begin
            src_state(64'd0, 64'd0);
            n = 30000;
            for (k = 1; k <= n; k = k + 1)
                step(1'b1, (k * CLK_HZ + RATE_PPS - 1) / RATE_PPS);
            check("exact_R_from_EMPTY_30000pkts_zero_flags", 0, n_flag);
            t0 = WRAP - ((64'd20 * CLK_HZ) / RATE_PPS);   // 20 pkts before wrap
            src_state(64'd0, t0);
            for (k = 1; k <= 40; k = k + 1)
                step(1'b1, t0 + (k * CLK_HZ + RATE_PPS - 1) / RATE_PPS);
            check("exact_R_from_EMPTY_across_counter_wrap_zero_flags", 0, n_flag);
        end

        // ===== SUITE 1: defaults, hand-derived constants ======================
        if (SUITE == 1) begin
            // (i) sustained exactly R = 5000 pps (period 20,000 cycles) for
            // 10 s from a full bucket: zero flags, tokens stay CAP - COST.
            src_never_seen;
            for (k = 0; k < 50000; k = k + 1) step(1'b1, k * 64'd20000);
            check("exact_R_5000pps_10s_from_full_zero_flags", 0, n_flag);
            check("exact_R_5000pps_10s_tokens_stay_CAP_minus_COST",
                  64'd49_900_000_000, last_tok);
            // ... and from an empty bucket: every packet exactly refills one
            // token, zero flags, tokens end at exactly 0 (no drift).
            src_state(64'd0, 64'd0);
            for (k = 1; k <= 50000; k = k + 1) step(1'b1, k * 64'd20000);
            check("exact_R_5000pps_10s_from_EMPTY_zero_flags", 0, n_flag);
            check("exact_R_5000pps_10s_from_EMPTY_tokens_end_0", 0, last_tok);

            // (ii) sustained over-rate, period 19,000 cycles = 5263.16 pps,
            // from full.  Per packet the bucket loses D = COST - 19000*R
            // = 5e6 units; packet k flags first when CAP - k*D < COST:
            // k* = floor((CAP-COST)/D) + 1 = floor(4.99e10/5e6) + 1 = 9981.
            src_never_seen;
            for (k = 0; k <= 10000; k = k + 1) step(1'b1, k * 64'd19000);
            check("over_rate_5263pps_first_flag_at_index_9981", 9981, first_flag);
            // the flagged packet consumed nothing (9.5e7 left, + 9.5e7 refill)
            check("over_rate_5263pps_packet_after_flag_conforms", 1, conf_after_first);

            // (ii') 5001 pps, t_k = floor(k*1e8/5001), from full.  Tokens
            // before packet k are B - k/5001 packets (the integer floor of
            // the timestamps does not move the boundary, checked by the
            // reference model); first flag when B - k/5001 < 1:
            // k* = 5001*(B-1) + 1 = 2,495,500, at t = 499.0002 s.
            src_never_seen;
            k = 0;
            while ((first_flag < 0) && (k <= 2600000)) begin
                step(1'b1, (k * CLK_HZ) / 64'd5001);
                k = k + 1;
            end
            check("rate_5001pps_from_full_first_flag_at_index_2495500", 2495500, first_flag);

            // SPEC FINDING (O6): R+1 = 5001 packets evenly inside ONE fixed
            // window [0, 1 s): t_k = floor((k+1)*1e8/5001) - 1, k = 0..5000
            // (t_0 = 19,995, t_5000 = 99,999,999).
            //  - token bucket starting FULL (B=500): 0 flags (the burst
            //    allowance absorbs it -- "5000 vs 5001 in one second" is
            //    fixed-window thinking);
            //  - the fixed-window reference model on the same stimulus: 1 flag.
            src_never_seen;
            for (k = 0; k <= 5000; k = k + 1) begin
                t = ((k + 1) * CLK_HZ) / 64'd5001 - 64'd1;
                step(1'b1, t); fw_pkt(t);
            end
            check("specO6_R_plus_1_in_1s_FULL_bucket_zero_flags", 0, n_flag);
            check("specO6_R_plus_1_in_1s_fixed_window_model_one_flag", 1, fw_flags);
            // (iii) from an EMPTY bucket at t = 0, R+1 packets evenly in
            // (0, 1 s], t_k = floor((k+1)*1e8/5001), the last at exactly
            // 1 s: refill over the second is exactly R = 5000 packets, so
            // exactly ONE flag, on the first packet (t_0 = 19,996 cycles
            // refills 0.99980 pkt).  [Shifting every packet 1 cycle earlier
            // gives 2 flags: the refill falls R*1 cycle short of 5000 --
            // the boundary is exact to the cycle.]
            src_state(64'd0, 64'd0);
            for (k = 0; k <= 5000; k = k + 1) step(1'b1, ((k + 1) * CLK_HZ) / 64'd5001);
            check("R_plus_1_in_1s_EMPTY_bucket_exactly_one_flag", 1, n_flag);
            check("R_plus_1_in_1s_EMPTY_bucket_flag_is_first_packet", 0, first_flag);
            src_state(64'd0, 64'd0);
            for (k = 0; k <= 5000; k = k + 1) step(1'b1, ((k + 1) * CLK_HZ) / 64'd5001 - 64'd1);
            check("R_plus_1_EMPTY_one_cycle_earlier_two_flags", 2, n_flag);
            // The true one-second boundary from a FULL bucket is R+B:
            // N evenly in (0,1s] leaves 1 + (B-1)/N... >= 1 token for
            // N = R+B-1 and B/(R+B) < 1 for N = R+B (F1_NOTES.md).
            src_never_seen;
            for (k = 0; k < 5499; k = k + 1) step(1'b1, ((k + 1) * CLK_HZ) / 64'd5499);
            check("R_plus_B_minus_1_5499_in_1s_FULL_zero_flags", 0, n_flag);
            src_never_seen;
            for (k = 0; k < 5500; k = k + 1) step(1'b1, ((k + 1) * CLK_HZ) / 64'd5500);
            check("R_plus_B_5500_in_1s_FULL_exactly_one_flag", 1, n_flag);
            check("R_plus_B_5500_in_1s_FULL_flag_index_5490", 5490, first_flag);

            // #4 straddle: 10,000 packets at 50 kpps from t = 0.9 s to 1.1 s:
            // exactly 5000 in [0,1s) and 5000 in [1s,2s) -> a 1-s fixed window
            // never sees more than R; the bucket (from full) loses 0.9 pkt per
            // packet: first flag at k* = floor(4.99e10 / 9e7) + 1 = 555.
            src_never_seen;
            for (k = 0; k < 10000; k = k + 1) begin
                t = 64'd90_000_000 + k * 64'd2000;
                step(1'b1, t); fw_pkt(t);
            end
            check("straddle_fixed_window_max_per_window_is_R", 5000, fw_max_in_window);
            check("straddle_fixed_window_model_zero_flags", 0, fw_flags);
            check("straddle_bucket_first_flag_index_555", 555, first_flag);
            check("straddle_bucket_flags_nonzero", 1, (n_flag > 0));
            $display("  INFO straddle: bucket flagged %0d of 10000, fixed window flagged %0d",
                     n_flag, fw_flags);

            // Back-to-back packets every cycle (max rate, CLK_HZ pps), 100,000
            // packets from full: conforms = B + floor(99999*R/COST)
            // = 500 + floor(4.99995) = 504; flags = 99,496.
            src_never_seen;
            for (k = 0; k < 100000; k = k + 1) step(1'b1, k);
            check("back_to_back_100k_conforms_504", 504, n_conf);
            check("back_to_back_100k_flags_99496", 99496, n_flag);
        end

        // ===== SUITE 2: B = 1 at 100 MHz / 5000 pps ===========================
        if (SUITE == 2) begin
            // exactly R evenly from full: 0 flags.
            src_never_seen;
            for (k = 0; k < 5000; k = k + 1) step(1'b1, ((k + 1) * CLK_HZ) / 64'd5000);
            check("B1_exact_R_in_1s_zero_flags", 0, n_flag);
            // R+1 evenly in 1 s with B=1: NOT one flag.  The bucket cannot
            // bank the 0.9998-packet leftover above CAP=1 packet, so every
            // other packet flags: packets 1,3,5,...,4999 -> 2500 flags.
            src_never_seen;
            for (k = 0; k <= 5000; k = k + 1) step(1'b1, ((k + 1) * CLK_HZ) / 64'd5001);
            check("B1_R_plus_1_in_1s_FULL_2500_flags", 2500, n_flag);
            check("B1_R_plus_1_in_1s_FULL_first_flag_index_1", 1, first_flag);
            src_state(64'd0, 64'd0);
            for (k = 0; k <= 5000; k = k + 1) step(1'b1, ((k + 1) * CLK_HZ) / 64'd5001);
            check("B1_R_plus_1_in_1s_EMPTY_2501_flags", 2501, n_flag);
        end

        // ===== seeded random comparison vs reference model (all suites) =====
        // Regime changes every 1024 calls (seeded): 30% flood (gaps 1..PERIOD/2
        // or 1..16 cycles), 30% near-rate (PERIOD/2 .. 3*PERIOD/2), 20% exact
        // period (PERIOD or PERIOD+1), 10% sparse (1..2*T_FULL), 10% long
        // idle (0..3*2^TS_W: aliasing when TS_W is small).  10% of calls are
        // refresh (pkt=0).  Everything is compared with the reference model.
        $display("  INFO %0s random seed = %0d", NAME, seed);
        src_never_seen;
        t = 64'd0;
        k = 0;
        while (n_pkt < NRAND) begin
            if (k[9:0] == 10'd0) r32 = $random(seed);
            k = k + 1;
            if (r32[7:0] < 8'd38)
                gap = 64'd1 + ({$random(seed)} % 64'd16);
            else if (r32[7:0] < 8'd77)
                gap = 64'd1 + ({$random(seed)} % (PERIOD / 64'd2 + 64'd1));
            else if (r32[7:0] < 8'd154)
                gap = (PERIOD / 64'd2) + ({$random(seed)} % (PERIOD + 64'd1)) + 64'd1;
            else if (r32[7:0] < 8'd205)
                gap = PERIOD + ({$random(seed)} % 64'd2);
            else if (r32[7:0] < 8'd230)
                gap = 64'd1 + ({$random(seed), $random(seed)} % (64'd2 * T_FULL));
            else
                gap = {$random(seed), $random(seed)} % (64'd3 * WRAP);
            t = t + gap;
            step(({$random(seed)} % 10) != 0, t);
        end
        check("random_vs_ref_model_all_outputs_agree", 0, mism);
        check("random_coverage_has_flags", 1, (n_flag > 0));
        check("random_coverage_has_conforms", 1, (n_conf > 0));
        check("random_coverage_has_saturation", 1, (n_full_hits > 0));
        $display("  INFO %0s random: %0d packets, %0d conform, %0d flag, %0d saturated calls",
                 NAME, n_pkt, n_conf, n_flag, n_full_hits);

        done = 1'b1;
    end

endmodule
