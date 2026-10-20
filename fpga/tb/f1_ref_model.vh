// f1_ref_model.vh -- BEHAVIOURAL REFERENCE MODEL, NOT SYNTHESIZABLE.
// Included inside testbench modules only.  Verilog-2001.
//
// Written independently of fpga/rtl/token_bucket_update.v from the spec:
//   - widths are not derived: everything is 64/128-bit integer arithmetic;
//   - no clamp-before-multiply: the refill is the full 128-bit product
//     elapsed * rate, then min(cap, tokens + refill);
//   - elapsed = (now - last) masked to the timestamp width (pass
//     mask = ~0 to model an infinitely wide counter, i.e. TRUE time);
//   - never-seen source (v = 0) = full bucket;
//   - a non-conforming packet consumes nothing.
// Units: tokens in 1/CLK_HZ packet, cost = CLK_HZ, cap = BURST * CLK_HZ.
task ref_step;
    input         p;      // packet this call
    input         v;      // stored state valid
    input  [63:0] tok;    // stored tokens
    input  [63:0] last;   // stored timestamp
    input  [63:0] now;    // current timestamp
    input  [63:0] mask;   // timestamp mask (2^TS_W - 1), or ~0 for true time
    input  [63:0] cap;
    input  [63:0] cost;
    input  [63:0] rate;
    output        conf;
    output        flg;
    output [63:0] ntok;
    reg   [127:0] el;
    reg   [127:0] acc;
    begin
        el = {64'd0, (now - last) & mask};
        if (!v)
            acc = {64'd0, cap};
        else begin
            acc = {64'd0, tok} + el * {64'd0, rate};
            if (acc > {64'd0, cap})
                acc = {64'd0, cap};
        end
        if (p && (acc >= {64'd0, cost})) begin
            conf = 1'b1;
            flg  = 1'b0;
            acc  = acc - {64'd0, cost};
        end else begin
            conf = 1'b0;
            flg  = p;
        end
        ntok = acc[63:0];
    end
endtask
