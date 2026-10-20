`timescale 1ns / 1ps
// ============================================================================
// token_bucket -- single-source token-bucket rate limiter (F1 wrapper).
// ESE-P15 Layer 4, stage F1.  Verilog-2001, synthesizable.
//
// Holds ONE source's state in registers plus a free-running TS_W-bit cycle
// counter, and calls the stateless token_bucket_update unit once per packet.
// F3 replaces these registers with a 256-entry BRAM and reuses the update
// unit unchanged.  All arithmetic, widths, rounding and wrap behaviour are
// documented in token_bucket_update.v and fpga/F1_NOTES.md.
//
// Ports
//   clk        system clock, CLK_HZ.
//   rst        synchronous, active-high.  Clears the counter to 0, marks the
//              source never-seen (=> full bucket on its next packet) and
//              clears the decision outputs.
//   pkt_in     1 for exactly one cycle per packet from this source.  At most
//              one packet per cycle (single port; there is no way to present
//              two packets in one cycle).  A packet in every cycle is legal
//              and is the maximum rate (CLK_HZ pps).
//   dec_valid  1 for one cycle: a decision for the packet sampled on the
//              previous rising edge.
//   conform    with dec_valid: packet within rate (consumed one token).
//   flag       with dec_valid: packet over rate (flood flag; no token used).
//   tokens_o   current stored tokens (1/CLK_HZ-packet units), debug/observe.
//              Shows CAP while the source is never-seen.
//   now_o      current counter value, debug/observe.
//
// Timing / latency
//   pkt_in is sampled at rising edge k with timestamp now = counter value
//   during cycle k.  The decision (dec_valid/conform/flag) and the new state
//   are registered at that same edge k, i.e. visible one cycle after pkt_in
//   was asserted: latency = 1 clock cycle, throughput = 1 packet / cycle.
//   The update itself is O(1): one combinational pass, no iteration.
// ============================================================================
module token_bucket #(
    parameter [63:0] CLK_HZ   = 64'd100_000_000,
    parameter [63:0] RATE_PPS = 64'd5_000,
    parameter [63:0] BURST    = 64'd500,
    parameter        TS_W     = 48
) (
    clk, rst, pkt_in, dec_valid, conform, flag, tokens_o, now_o
);
`include "f1_clog2.vh"

    localparam [63:0]  CAP   = BURST * CLK_HZ;
    localparam integer TOK_W = f1_bits(CAP);

    input  wire             clk;
    input  wire             rst;
    input  wire             pkt_in;
    output reg              dec_valid;
    output reg              conform;
    output reg              flag;
    output wire [TOK_W-1:0] tokens_o;
    output wire [TS_W-1:0]  now_o;

    reg  [TS_W-1:0]  cnt;        // free-running cycle counter (wraps mod 2^TS_W)
    reg              st_valid;   // source has stored state
    reg  [TOK_W-1:0] st_tokens;
    reg  [TS_W-1:0]  st_last;

    wire [TOK_W-1:0] nx_tokens;
    wire [TS_W-1:0]  nx_last;
    wire             u_conform, u_flag;

    token_bucket_update #(
        .CLK_HZ(CLK_HZ), .RATE_PPS(RATE_PPS), .BURST(BURST), .TS_W(TS_W)
    ) u_upd (
        .pkt(pkt_in), .now(cnt),
        .st_valid(st_valid), .st_tokens(st_tokens), .st_last(st_last),
        .nx_tokens(nx_tokens), .nx_last(nx_last),
        .conform(u_conform), .flag(u_flag)
    );

    always @(posedge clk) begin
        if (rst) begin
            cnt       <= {TS_W{1'b0}};
            st_valid  <= 1'b0;
            st_tokens <= {TOK_W{1'b0}};
            st_last   <= {TS_W{1'b0}};
            dec_valid <= 1'b0;
            conform   <= 1'b0;
            flag      <= 1'b0;
        end else begin
            cnt       <= cnt + {{(TS_W-1){1'b0}}, 1'b1};
            dec_valid <= pkt_in;
            conform   <= u_conform;
            flag      <= u_flag;
            if (pkt_in) begin
                st_valid  <= 1'b1;
                st_tokens <= nx_tokens;
                st_last   <= nx_last;
            end
        end
    end

    assign tokens_o = st_valid ? st_tokens : CAP[TOK_W-1:0];
    assign now_o    = cnt;

endmodule
