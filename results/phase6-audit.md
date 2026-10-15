# PHASE 6 audit and reproducibility

Begin HEAD: `8b9f675e45e3c3c5317f42e9df9aaa3fee6c3f84`, clean worktree.
Target: `/home/tenggn/projects/clean_pmeq`. Old repository is read-only.

## Recovered old call graph

- `cmd/candidate-compaction-input/main.go`: `main -> LoadArea -> Build ->
  sigs -> ids`, then `routingmaterial.NewGlobalLayout/Generate`, creates
  verifier file `PMEQCC01`. This is a plaintext test coordinator, not a cloud.
- `cmd/secure-candidate-permute-bench/main.cpp`: coordinator reads that file,
  generates `rho/sigma`, calls `prepLayer` twice, execs two `--party` processes,
  and supplies only each party's local shares and materials over pipes.
  `party -> layer rho -> layer sigma -> exchange Keep -> selected indices ->
  local compact payload`. Coordinator reconstructs returned payloads for oracle
  comparison. No runner/script calls this isolated benchmark.
- `routing_selection_prep.rs -> routing_selection_io.rs ->
  anchor_routing_selection.rs -> ristretto_beaver::select_ristretto_party` is
  a different N-slot secret selection path, replacing inactive scalars by
  random dummies. Its main loads both parties in a test coordinator; the
  two threaded party functions consume local shares. It is not exact-K.
  `routing_selection_freshness.rs` reconstructs both outputs as a verifier.
- `cmd/target-e2e-bench/main.go:candidates` selects plaintext oracle IDs;
  `khprf_compacted_bench.rs` benchmarks an explicit K. Neither implements
  secure compaction. No KHPRF/Target code is executed or migrated this phase.
- `permutation_agg_proto.rs` is the old static record-alignment permutation
  experiment. Current `aggregation/permutation.go` has already migrated those
  masked-scatter equations for Z128. Its *static* factors cannot serve as the
  fresh candidate shuffle, and its Z128 arithmetic cannot represent payloads.

Old mathematical scheme reusable: **YES**. It is exactly secret-shared tuple
-> two hidden permutation layers -> open shuffled Keep -> retain exact K local
payload shares. The old payload was scalar additive plus a 16-byte XOR handle,
not the current Ring64/scalar/BucketShare tuple. This migration applies the same
old group equations independently to each current domain, with the same two
permutations for every field. No new compaction protocol is introduced.

Benchmark implementation defects must not be carried into production:

1. C++ coordinator uses a public deterministic `mt19937_64` seed for permutations
   and non-scalar masks. This cannot justify production secrecy. Current dealer
   uses `crypto/rand`, rejection-sampled Fisher-Yates, and fresh independent masks.
2. Old Go fixture generates full-byte Keep shares but C++ refreshes only their
   low bit. The common upper seven bits can act as stable tags. Current Keep
   is the existing `domain.Bit` boolean, so out-of-F2 shares are unrepresentable.

3. The C++ fork/exec wrapper does not close unrelated inherited descriptors
   before exec. Its input file contains both parties' fixtures. Consequently its
   wrapper is not evidence of hardened process isolation, even though the explicit
   prep pipes supply party-local material. This coordinator/process wrapper is
   not migrated; production APIs take only local shares and masked messages.

These are flaws in benchmark randomness/fixture/isolation, not requirements
for a party to know gamma, plaintext ID, or peer shares. The party-local masked
permutation equations need none of those. Raw DB/oracle reconstruction stays in
trusted offline/test code only.

## Algebra and holdings

Let P_t scatter from i to tau_t(i), and use +,- in the product group
F2 x Z/(2^64) x Z_l x F2^16. Dealer samples independent t0,r0,t1,r1 and sets
c0=P0(t0)-r0; c1=P1(t1)-r1.

CS0 holds `(tau0,c0,t1,r1)` and its input x0.
CS1 holds `(tau1,t0,r0,c1)` and its input x1.

1. CS1 sends d0=x1-t0, retains r0.
2. CS0 computes y0=P0(x0+d0)+c0. Thus y0+r0=P0(x).
3. CS0 sends d1=y0-t1, retains r1.
4. CS1 computes y1=P1(r0+d1)+c1. Thus r1+y1=P1(P0(x)).
5. Exchange only final Keep shares. Each party extracts its own payload fields
   at opened-one positions, in increasing *fresh shuffled* slot order.

Final tau=tau1 composed with tau0; Keep'[i]=Keep[tau^{-1}(i)].
All field masks are independent; only permutations are shared across domains.
The packet binds LayoutID, fresh CompactionID, shape and message stage. Copies
of packet handles share consumption state. Mutex/phase guards reject reuse,
wrong-query messages, premature opening and duplicate extraction. State releases
its N-sized buffers after extraction. Existing sealed PartyPool supports offline
provision/consume of CompactionID; no online refill or dealer callback is added.

Simulation is for the repository's semi-honest, non-colluding model and trusted
offline dealer. For CS0 the unseen fresh tau1 randomizes final order; for CS1 the
unseen fresh tau0 does so. Masked online messages are hidden by independent
product-group pads, and retained payload shares are fresh. A simulator given
public N and K samples a uniform K-subset for opened Keep and consistent local
masked messages/shares. Thus additional candidate leakage is K (and fixed public
N), not original gamma, IDs, coordinates, or stable candidate positions. This is
not a malicious-security claim or a claim to hide K. For K=0 or K=N the opened
pattern is necessarily constant; output payload shares/order are still refreshed.

## Interfaces

Input is existing `aggregation.CandidateInput`: LayoutID[16], KeepShare[N]
(F2), Payload[N] where PayloadShare has Ring64 additive RecordIDShare,
canonical 32-byte Ristretto additive KappaJoinShare and uint16 XOR BucketJoinShare.
All arrays share LayoutID and gamma order. Production N=120071; smaller public
N is supported for unit tests. No query-time ID/key/bucket reconstruction.

Output `CompactedCandidates`: LayoutID[16], fresh CompactionID[16], K,
RecordIDShare[K], KappaJoinShare[K], BucketJoinShare[K]. There are no original
indices, selected-index mapping or dummy outputs. K=0 has three zero-length
arrays. Party APIs never accept both payload shares. Opening messages contain
only shuffled Keep. There is no plaintext payload serialization operation.

## Accounting (logical payload bytes, no network codec claim)

One tuple: Keep 1 + ID 8 + scalar 32 + bucket 2 = 43 bytes.

| Component | Formula | N=120071 |
|---|---:|---:|
| Offline correlated masks, both parties | 6*43*N | 30,978,318 |
| Fresh permutations, both parties | 2*4*N | 960,568 |
| Offline total excluding metadata | 266*N | 31,938,886 |
| Stage 1 CS1 -> CS0 | 43*N | 5,163,053 |
| Stage 2 CS0 -> CS1 | 43*N | 5,163,053 |
| Keep opening both directions | 2*N | 240,142 |
| Total online server-to-server payload | 88*N | 10,566,248 |
| Final output per party | 42*K | variable |
| Final output both parties | 84*K | variable |

LayoutID/CompactionID are 32 bytes per packet/party (64 combined), plus public
shape/phase and optional framing/registry metadata. No persistent transport codec
is implemented here, so tables do not pretend to measure TCP traffic. Output
shares are retained locally and are NOT server-to-server communication.

`compactTuple` occupies 56 bytes on measured amd64; packet mask/permutation
backing storage is 344*N = 41,304,424 bytes for both parties. A conservative
bound for all packet and online temporary backing arrays, even before any
collection of dead arrays, is (10*56+11)*N = 68,560,541 bytes, plus O(1) headers
and allocator overhead, excluding caller-owned inputs, offline dealer generation scratch and 84*K output bytes.
This includes the test's extra N-byte opened-pattern array. It is a backing-array
bound, not total process RSS. No long-lived N-sized shuffled output cache exists.
Pool correlated payload storage is Q_pool * 31,938,886, plus metadata, when all
packets have N=120071. Every packet includes fresh permutations, not just masks.

## Historical reference only

`results/candidate_compaction_real_benchmark.csv` from old repository:
N=120071; tuple width 49, output width 48; one historical run per row.

| K | Workers | Online wall ms | CS0->CS1 bytes | CS1->CS0 bytes |
|---:|---:|---:|---:|---:|
| 1 | 1 | 91.8053 | 6,003,550 | 6,003,550 |
| 7 | 1 | 98.6610 | 6,003,550 | 6,003,550 |
| 488 | 1 | 108.1810 | 6,003,550 | 6,003,550 |
| 4552 | 1 | 97.5509 | 6,003,550 | 6,003,550 |

Old reported direction bytes are 50*N (49*N shuffle plus N Keep), excluding
framing. Old `secure_candidate_permutation_benchmark.csv` also contains earlier
32-byte permutation-only measurements (e.g. 37.5096 ms, 3,842,272 bytes/direction),
which are not current four-field compaction measurements.

## Reproduce

Use Go 1.27.1. Native LLAMA is external and only used with `phase6native` tag.
The optional adapter returns raw eval output; existing PHASE4/5 callers remove
key.rb exactly once. It does not replace sealed production PHASE5 logic.

```
bash tools/build_phase6_native.sh
CGO_LDFLAGS=/tmp/phase6-native/libphase6scmp.a PMEQ_AGG_FULL=1 \
  go test -tags phase6native ./internal/aggregation \
  -run '^TestReal1000Queries$' -count=1 -v -timeout=120m
PMEQ_COMPACTION_BENCH=1 PMEQ_COMPACTION_KS=0,1,8,64,512,<p50>,<p95>,<p99> \
  go test ./internal/aggregation -run '^TestCompactionBenchmark$' -count=1 -v
go test ./...
go vet ./...
git diff --check
```

Native build takes only source reads from the old tree and writes its artifacts
to /tmp. `PMEQ_EXTERNAL_SCMP` and `PMEQ_SCMP_BUILD` can override locations.
Benchmarks run both local party APIs in-process, sequentially, with independent
fresh packets every iteration and dealer time excluded. They measure computation
and local message creation, not network latency. Each K uses 10 warmups and 50
measured runs; percentile selection is nearest-rank. Correctness reconstructs
only in `_test.go` coordinator code. Measured results are in phase6-results.md.
