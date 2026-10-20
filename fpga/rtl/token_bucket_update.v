`timescale 1ns / 1ps
// ============================================================================
// token_bucket_update -- stateless, purely combinational token-bucket step.
// ESE-P15 Layer 4, stage F1.  Verilog-2001, synthesizable.
//
// One call = one decision for one source.  The caller owns the state (F1:
// registers in token_bucket.v; F3: one BRAM word per source) and writes
// nx_tokens / nx_last back whenever it wants the step to take effect.
//
// ---------------------------------------------------------------------------
// Fixed-point representation (exact, no rounding anywhere)
//   Tokens are counted in units of 1/CLK_HZ packet.
//     one packet costs        COST = CLK_HZ units
//     bucket capacity         CAP  = BURST * CLK_HZ units
//     refill per clock cycle  RATE_PPS units
//   so refill over e cycles = e * RATE_PPS, which is the exact real-valued
//   refill (e / CLK_HZ seconds * RATE_PPS pkt/s) scaled by CLK_HZ.  The only
//   quantisation in the whole design is time itself (1 cycle); tokens carry
//   zero rounding error, so a source sending exactly RATE_PPS forever never
//   drifts into a flag (tested from an EMPTY bucket, where the slack is 0).
//
// Saturation (no wrap of the multiplier)
//   T_FULL = ceil(CAP / RATE_PPS) cycles refills an empty bucket to full.
//   elapsed is clamped to T_FULL *before* the multiply, so the product is at
//   most T_FULL*RATE_PPS < CAP + RATE_PPS and can never overflow, whatever
//   the idle gap; any gap >= T_FULL yields a full bucket.  The sum is then
//   clamped to CAP.  Clamping elapsed first is exact: once elapsed >= T_FULL
//   the bucket is full regardless of the stored tokens.
//
// Timestamps and wrap
//   now / st_last are values of a free-running TS_W-bit cycle counter.
//   elapsed = (now - st_last) mod 2^TS_W.  Exact for every true idle gap
//   G <= 2^TS_W - 1 cycles.  For G >= 2^TS_W the counter has aliased and
//   elapsed = G mod 2^TS_W: if that residue is >= T_FULL the answer is
//   still exact (full bucket); if it is < T_FULL the source is refilled
//   LESS than it should be.  Error direction: never grants more tokens than
//   the true bucket (never lets extra traffic through), but CAN flag a
//   source that was quiet for ~k*2^TS_W cycles and then bursts.  See
//   fpga/F1_NOTES.md (at 100 MHz, TS_W=48: exact up to 32.6 days idle).
//
// Never-seen source
//   st_valid = 0 means "no stored state": the unit treats the source as a
//   FULL bucket and ignores st_tokens / st_last.  nx_* is always valid.
//
// Non-conforming packets do NOT consume tokens (standard token bucket /
// RFC 2697-style policing): only the refill and the timestamp are written.
//
// Ports
//   pkt        1 = a packet from this source is being decided now.
//              0 = refresh only: nx_* = state brought up to `now`, nothing
//                  consumed, conform = flag = 0 (usable by an F3 scrubber).
//   now        current counter value (cycle timestamp of this decision).
//   st_valid   stored state exists (see above).
//   st_tokens  stored tokens, units of 1/CLK_HZ packet, must be <= CAP.
//   st_last    timestamp at which st_tokens was valid.
//   nx_tokens  tokens after this step (write back).
//   nx_last    = now (write back).
//   conform    pkt & bucket held >= one packet; that packet consumed COST.
//   flag       pkt & bucket held < one packet  ("over rate": flood flag).
//
// Latency: 0 cycles (combinational).  A packet strobe registered at clock
// edge k gives a registered decision after edge k (1 cycle) in the wrapper.
// Single-port assumption: at most ONE packet per source per call; the
// caller serialises (one packet per cycle in token_bucket.v).
//
// Critical path (unpipelined, NOT timed yet): TS_W-bit subtract -> compare
// -> EL_W x R_W multiply (fits one DSP48E1 at defaults: 24x13) -> SUM_W add
// -> compare/clamp -> compare -> subtract.  Timing at 100 MHz on Artix-7 is
// unverified; F3 may need a pipeline register after the multiply.
//
// Widths at defaults (CLK_HZ=100e6, RATE_PPS=5000, BURST=500, TS_W=48)
//   CAP = 5e10 -> TOK_W = 36 bits (2^35 = 3.4e10 < 5e10 < 6.9e10 = 2^36)
//   T_FULL = 1e7 cycles (0.1 s) -> EL_W = 24 bits (2^24 = 1.68e7)
//   RATE_PPS = 5000 -> R_W = 13 bits;  PROD_W = EL_W + R_W = 37 (full
//   product, no truncation);  SUM_W = max(TOK_W, PROD_W) + 1 = 38.
//
// Parameter legality (elaboration fails on violation, via an undefined
// module instance -- portable Verilog-2001 static assert):
//   RATE_PPS >= 1, BURST >= 1, RATE_PPS <= CLK_HZ, CAP < 2^62,
//   T_FULL <= 2^TS_W - 1 (else a full refill would be unreachable), TS_W<=64.
// ============================================================================
module token_bucket_update #(
    parameter [63:0] CLK_HZ   = 64'd100_000_000, // clock frequency, Hz
    parameter [63:0] RATE_PPS = 64'd5_000,       // R: sustained packets/s
    parameter [63:0] BURST    = 64'd500,         // B: bucket depth, packets
    parameter        TS_W     = 48               // timestamp counter width
) (
    pkt, now, st_valid, st_tokens, st_last,
    nx_tokens, nx_last, conform, flag
);
`include "f1_clog2.vh"

    // ---- derived constants (all 64-bit constant arithmetic) ---------------
    localparam [63:0] COST   = CLK_HZ;
    localparam [63:0] CAP    = BURST * CLK_HZ;
    localparam [63:0] T_FULL = (CAP + RATE_PPS - 64'd1) / RATE_PPS;
    localparam integer TOK_W  = f1_bits(CAP);
    localparam integer EL_W   = f1_bits(T_FULL);
    localparam integer R_W    = f1_bits(RATE_PPS);
    localparam integer PROD_W = EL_W + R_W;
    localparam integer SUM_W  = ((TOK_W > PROD_W) ? TOK_W : PROD_W) + 1;

    input  wire             pkt;
    input  wire [TS_W-1:0]  now;
    input  wire             st_valid;
    input  wire [TOK_W-1:0] st_tokens;
    input  wire [TS_W-1:0]  st_last;
    output wire [TOK_W-1:0] nx_tokens;
    output wire [TS_W-1:0]  nx_last;
    output wire             conform;
    output wire             flag;

    // ---- static parameter checks -------------------------------------------
    generate
        if ((RATE_PPS == 64'd0) || (BURST == 64'd0) || (RATE_PPS > CLK_HZ) ||
            (CAP >= 64'h4000_0000_0000_0000) || (TS_W > 64) || (TS_W < 1) ||
            (EL_W > TS_W)) begin : g_param_error
            F1_ILLEGAL_PARAMETERS_see_token_bucket_update_header u_err ();
        end
    endgenerate

    localparam [TOK_W-1:0]  CAP_K    = CAP[TOK_W-1:0];
    localparam [TOK_W-1:0]  COST_K   = COST[TOK_W-1:0];
    localparam [EL_W-1:0]   T_FULL_K = T_FULL[EL_W-1:0];
    localparam [R_W-1:0]    RATE_K   = RATE_PPS[R_W-1:0];

    // ---- datapath -------------------------------------------------------------
    // Modular subtraction: TS_W-bit result wraps exactly like the counter.
    wire [TS_W-1:0]   elapsed = now - st_last;

    // Clamp elapsed to T_FULL before the multiply (no product overflow).
    wire              el_big  = (elapsed >= T_FULL);
    wire [EL_W-1:0]   el_sat  = el_big ? T_FULL_K : elapsed[EL_W-1:0];

    wire [PROD_W-1:0] refill  = el_sat * RATE_K;       // full-width product
    wire [TOK_W-1:0]  tok_in  = st_valid ? st_tokens : CAP_K;
    wire [SUM_W-1:0]  sum     = tok_in + refill;

    wire              full    = (!st_valid) || (sum >= CAP);
    wire [TOK_W-1:0]  avail   = full ? CAP_K : sum[TOK_W-1:0];

    wire              enough  = (avail >= COST_K);

    assign conform   = pkt &  enough;
    assign flag      = pkt & ~enough;
    assign nx_tokens = conform ? (avail - COST_K) : avail;
    assign nx_last   = now;

endmodule
