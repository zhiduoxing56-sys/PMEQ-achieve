# PHASE8 audit and proof (written before implementation)

Direct input is sufficient. For each encoding bit let x=E0_i XOR E1_i.
CS0 starts with u0=1 XOR E0_i, CS1 with u1=E1_i. Their XOR is NOT x.
The balanced 256-leaf AND tree therefore returns equality, with 255 gates and
8 sequential layers. Input masking adapters serve no additional security role:
a sharing of a jointly private function's inputs need not itself be uniformly
random when each party's share is a function only of its existing private input.
Fresh independent triples make d/e openings simulatable. No E is sent.

For x=x0 XOR x1, y=y0 XOR y1 and c=a AND b, each party computes
z_u=c_u XOR (d AND b_u) XOR (e AND a_u), with CS0 alone XORing d AND e.
The XOR of outputs is x AND y. uint64 packing applies this identical F2 algebra
independently to 64 lanes; it is not arithmetic multiplication in Z/(2^64).
Extend the existing f2beaver package with packed storage and use ONE common
Finish formula for scalar and packed paths, with lane differential tests.

Option4: Y0-T0 = T1-Y1 iff Y0+Y1=T0+T1. Ristretto's canonical encoding is
injective, so equality of the 32-byte encodings is equivalent. No hashing,
truncation, scalar reinterpretation or full Y/T reconstruction is needed.

Flatten route order then public bucket ordinal. W=ceil(G/64), 255W triple words.
Each party holds three uint64 shares per word: 6120W bytes/party,12240W combined.
Each gate-word exchanges two uint64 d/e values per party:32 bytes combined.
PE online payload=8160W; input opening bytes=0. Framing accounted separately.
Unused last-word lanes are masked at input and output. G=0 uses no triples,
no online messages and returns an empty MatchShares array.

Old target_private_equality_bench.rs bitsliced/equality code handles separately
shared old ts/zs and adds a share exchange. That old representation is not the
current Option4 natural input. Old standalone Boolean tree is reference only;
no full-Y combine/Target DPF path may be used.

Lineage: load final PSMJ and payload manifests and own files with hash validation.
Bind LayoutID to trusted alignment lineage. PHASE7B did NOT persist alignment;
the native test must restore DealerLayout from the SAME sealed payload inside
trusted offline setup, before deriving any Anchor alignment. Do not substitute
fresh GeneratePayload results or construct runtime PE inputs from the oracle.
