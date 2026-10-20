`timescale 1ns / 1ps
// ============================================================================
// tb_f1_wrap -- self-checking, fully clocked test of token_bucket (F1 wrapper).
// TESTBENCH ONLY, not synthesizable.  Verilog-2001.
//
// Proves the wrapper is wired right: reset, the free-running counter (and its
// wrap), 1-cycle decision latency, state write-back, back-to-back packets.
// Every cycle is compared with the independent reference model
// (f1_ref_model.vh) driven by the testbench's own 64-bit cycle count.
//
// SUITE 1 = small parameter set with directed, hand-derived checks plus a
//           long seeded random run that crosses the counter wrap many times.
// SUITE 2 = default (full-scale) widths: short wiring check only.
// ============================================================================
module tb_f1_wrap #(
    parameter [63:0] CLK_HZ   = 64'd1_000,
    parameter [63:0] RATE_PPS = 64'd100,
    parameter [63:0] BURST    = 64'd3,
    parameter        TS_W     = 12,
    parameter        SUITE    = 1,
    parameter        NAME     = "W?",
    parameter        NCYC     = 200000
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
    localparam integer TOK_W  = f1_bits(CAP);
    localparam [63:0]  TSMASK = (TS_W >= 64) ? ~64'd0 : ((64'd1 << TS_W) - 64'd1);

    reg              clk, rst, pkt_in;
    wire             dec_valid, conform, flag;
    wire [TOK_W-1:0] tokens_o;
    wire [TS_W-1:0]  now_o;

    token_bucket #(
        .CLK_HZ(CLK_HZ), .RATE_PPS(RATE_PPS), .BURST(BURST), .TS_W(TS_W)
    ) dut (
        .clk(clk), .rst(rst), .pkt_in(pkt_in), .dec_valid(dec_valid),
        .conform(conform), .flag(flag), .tokens_o(tokens_o), .now_o(now_o)
    );

    // model state
    reg [63:0] m_cnt;          // true cycles since reset released
    reg        m_v;  reg [63:0] m_tok; reg [63:0] m_last;
    reg        mc, mf;  reg [63:0] mt;
    integer    mism, n_pkt, n_conf, n_flag, first_flag, k, wraps;
    integer    seed;
    reg [31:0] r32;
    reg        lat_ok;

    // clock: 10 time units (only relative timing matters to the design)
    initial clk = 1'b0;
    always #5 clk = ~clk;

    task clear_counts;
        begin
            mism = 0; n_pkt = 0; n_conf = 0; n_flag = 0; first_flag = -1;
        end
    endtask

    task do_reset;     // hold rst for 3 edges
        begin
            @(negedge clk); rst = 1'b1; pkt_in = 1'b0;
            @(negedge clk); @(negedge clk); @(negedge clk);
            rst = 1'b0;
            m_cnt = 64'd0; m_v = 1'b0; m_tok = 64'd0; m_last = 64'd0;
            clear_counts;
        end
    endtask

    // one clock cycle with pkt_in = p (driven at negedge, sampled at posedge)
    task cyc;
        input p;
        begin
            pkt_in = p;
            if (now_o !== m_cnt[TS_W-1:0]) begin
                mism = mism + 1;
                if (mism <= 3) $display("  MISMATCH %0s counter: model %0d dut %0d",
                                        NAME, m_cnt[TS_W-1:0], now_o);
            end
            ref_step(p, m_v, m_tok, m_last, m_cnt, TSMASK, CAP, COST, RATE_PPS,
                     mc, mf, mt);
            @(posedge clk); #1;
            if ((dec_valid !== p) || (conform !== mc) || (flag !== mf) ||
                (tokens_o !== (p ? mt[TOK_W-1:0] : (m_v ? m_tok[TOK_W-1:0] : CAP[TOK_W-1:0])))) begin
                mism = mism + 1;
                if (mism <= 3)
                    $display("  MISMATCH %0s cyc=%0d p=%0d: dut v=%0d c=%0d f=%0d tok=%0d | model c=%0d f=%0d tok=%0d",
                             NAME, m_cnt, p, dec_valid, conform, flag, tokens_o, mc, mf, mt);
            end
            if (p) begin
                m_v = 1'b1; m_tok = mt; m_last = m_cnt;
                if (flag) begin
                    n_flag = n_flag + 1;
                    if (first_flag < 0) first_flag = n_pkt;
                end
                if (conform) n_conf = n_conf + 1;
                n_pkt = n_pkt + 1;
            end
            m_cnt = m_cnt + 64'd1;
            @(negedge clk);
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

    initial begin
        done = 1'b0; npass = 0; nfail = 0; rst = 1'b1; pkt_in = 1'b0;
        @(posedge go);
        seed = seed_in;
        $display("---- %0s (clocked wrapper): CLK_HZ=%0d RATE_PPS=%0d BURST=%0d TS_W=%0d CAP=%0d",
                 NAME, CLK_HZ, RATE_PPS, BURST, TS_W, CAP);

        // --- reset behaviour ---------------------------------------------------
        do_reset;
        check("reset_counter_is_0", 0, now_o);
        check("reset_dec_valid_low", 0, {dec_valid, conform, flag});
        check("reset_source_never_seen_shows_CAP", CAP, tokens_o);
        cyc(1'b0); cyc(1'b0);
        check("counter_free_runs", 2, now_o);

        // --- latency: decision exactly one cycle after pkt_in --------------------
        // pkt_in high in cycle 2 only; dec_valid must be high in cycle 3 only.
        pkt_in = 1'b1;
        @(posedge clk);
        lat_ok = (dec_valid === 1'b0);          // old value at the edge
        #1;
        lat_ok = lat_ok && (dec_valid === 1'b1) && (conform === 1'b1);
        m_v = 1'b1; m_tok = CAP - COST; m_last = 64'd2; m_cnt = 64'd3;
        n_pkt = 1; n_conf = 1;
        @(negedge clk); pkt_in = 1'b0;
        @(posedge clk); #1;
        lat_ok = lat_ok && (dec_valid === 1'b0);
        m_cnt = 64'd4;
        @(negedge clk);
        check("latency_1_cycle_dec_valid_pulse", 1, lat_ok);
        check("latency_tokens_written_back", CAP - COST, tokens_o);

        if (SUITE == 1) begin
            // --- back-to-back packets every cycle from full ---------------------
            do_reset;
            for (k = 0; k < 40; k = k + 1) cyc(1'b1);
            // B=3, refill 100/cycle, cost 1000: tokens before packet k are
            // 3000 + 100k - 1000*(#conforms so far).  Conforms at k=0,1,2
            // (3000,2100,1200), then 300+... reaches 1000 again at k=10,
            // so 1 conform per 10 cycles: first flag at index 3; conforms
            // in 40 = 3 + floor((40-1)*100/1000) = 3 + 3 = 6 (checked by model).
            check("b2b_first_flag_index_3", 3, first_flag);
            check("b2b_conforms_in_40_cycles", 6, n_conf);
            check("b2b_flags_in_40_cycles", 34, n_flag);

            // --- reset mid-stream restores never-seen = full -------------------
            do_reset;
            check("reset_midstream_restores_CAP", CAP, tokens_o);
            for (k = 0; k < 3; k = k + 1) cyc(1'b1);
            check("after_reset_burst_B_conforms", 3, n_conf);

            // --- counter wrap (TS_W=12: wraps every 4096 cycles) ---------------
            // (a) a 105-cycle gap that straddles the wrap is measured exactly:
            //     packet at 4096-101, burst at 4100 -> elapsed 105 > T_FULL=30
            //     -> full bucket -> B=3 conform, 4th flags.
            do_reset;
            while (m_cnt < TSMASK - 64'd100) cyc(1'b0);
            cyc(1'b1); cyc(1'b1); cyc(1'b1);        // empty the bucket
            check("pre_wrap_burst_empties_bucket", 1, (tokens_o < COST));
            while (m_cnt < TSMASK - 64'd5) cyc(1'b0);
            check("counter_reaches_top", TSMASK - 5, now_o);
            for (k = 0; k < 10; k = k + 1) cyc(1'b0);
            check("counter_wrapped_to_4", 4, now_o);
            clear_counts;
            cyc(1'b1); cyc(1'b1); cyc(1'b1); cyc(1'b1);
            check("gap_across_wrap_exact_full_burst_B_conforms", 3, n_conf);
            check("gap_across_wrap_exact_4th_flags", 1, n_flag);
            // (b) DOCUMENTED ALIAS: idle 4097 cycles (> 2^TS_W) after a packet
            //     that left 2000 tokens.  The unit sees elapsed = 1 cycle and
            //     refills 100, not to full: 2 conform instead of 3.  The error
            //     is in the strict direction (less credit, never more).
            do_reset;
            cyc(1'b1);                               // t = 0 -> 2000 tokens
            while (m_cnt < 64'd4097) cyc(1'b0);
            clear_counts;
            cyc(1'b1); cyc(1'b1); cyc(1'b1);
            check("alias_idle_2powTS_plus_1_DOCUMENTED_2_conforms_not_3", 2, n_conf);

            // --- seeded random over many counter wraps --------------------------
            do_reset;
            wraps = 0;
            for (k = 0; k < NCYC; k = k + 1) begin
                r32 = $random(seed);
                // phases of 1024 cycles alternate dense / sparse / idle
                case (k[11:10])
                    2'd0: cyc(r32[2:0] != 3'd0);          // ~87% duty: flood
                    2'd1: cyc(r32[4:0] == 5'd0);          // ~3%: under rate
                    2'd2: cyc(r32[3:0] == 4'd0);          // ~6%: near rate
                    default: cyc(1'b0);                   // idle
                endcase
                if (now_o == {TS_W{1'b0}}) wraps = wraps + 1;
            end
            check("random_clocked_vs_ref_model_every_cycle", 0, mism);
            check("random_clocked_crossed_counter_wrap", 1, (wraps >= 10));
            check("random_clocked_has_flags_and_conforms", 1, (n_flag > 0) && (n_conf > 0));
            $display("  INFO %0s seed=%0d cycles=%0d packets=%0d conform=%0d flag=%0d wraps=%0d",
                     NAME, seed_in, NCYC, n_pkt, n_conf, n_flag, wraps);
        end

        if (SUITE == 2) begin
            // full-scale widths: 600 back-to-back packets from full ->
            // conforms = 500 + floor(599*5000/1e8) = 500, flags = 100.
            do_reset;
            for (k = 0; k < 600; k = k + 1) cyc(1'b1);
            check("fullscale_b2b_600_conforms_500", 500, n_conf);
            check("fullscale_b2b_600_first_flag_index_500", 500, first_flag);
            // after 20,000 idle cycles (one period at R) exactly one more
            // packet's worth has refilled: next packet conforms, 2nd flags.
            for (k = 0; k < 20000; k = k + 1) cyc(1'b0);
            clear_counts;
            cyc(1'b1); cyc(1'b1);
            check("fullscale_one_period_refills_one_packet", 1, n_conf);
            check("fullscale_vs_ref_model", 0, mism);
        end

        done = 1'b1;
    end

endmodule
