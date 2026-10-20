// f1_clog2.vh -- constant function shared by the F1 modules (Verilog-2001).
//
// Included *inside* a module body (`include "f1_clog2.vh"), so each module
// gets its own copy; this keeps "one module per file" and avoids $clog2,
// whose 64-bit-argument behaviour is not guaranteed by IEEE 1364-2001.
//
// f1_bits(v) = number of bits needed to hold the unsigned value v
//            = floor(log2(v)) + 1 for v > 0, and 1 for v == 0.
// Examples: f1_bits(5000) = 13, f1_bits(10_000_000) = 24,
//           f1_bits(50_000_000_000) = 36.
function integer f1_bits;
    input [63:0] v;
    reg   [63:0] x;
    integer      n;
    begin
        x = v;
        n = 0;
        for (n = 0; x != 64'd0; n = n + 1)
            x = x >> 1;
        if (n == 0)
            n = 1;
        f1_bits = n;
    end
endfunction
