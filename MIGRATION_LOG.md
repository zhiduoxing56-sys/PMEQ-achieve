# PMEQ Migration Audit Log

## PHASE 0 record

- Old repository: `/home/tenggn/projects/new-pmeq`
- Old repository status: read-only reference
- Snapshot: `/home/tenggn/projects/PMEQ_SNAPSHOT_PRE_ANCHOR_AGG_20260915T190526+0800/source.tar`
- Actual verified SHA256: `a456dec8a84236b333c043b7ce68033b6418f6c6ac8e2ca494858b62f66792a0`
- Expected SHA256: `a456dec8a84236b333c043b7ce68033b6418f6c6ac8e2ca494858b62f66792a0`
- New repository: `/home/tenggn/projects/pmeq-clean`
- PHASE 0 date: `2026-09-15`
- PHASE 0 status: bootstrap specifications prepared; no source migration
- migrated source files = 0
- copied source files = 0
- production code files = 0

## Mandatory primitive migration sequence

Every primitive migration must complete these steps in order:

A. functional audit
B. minimum dependency-closure audit
C. retired/plaintext/oracle dependency audit
D. security party-view audit
E. unit testing again in the new repository
F. correctness PASS
G. single-party security PASS
H. independent Git commit

Bulk copying any package, crate, or cmd is prohibited. Compatibility shells are prohibited. A legacy directory is prohibited.

## Primitives eligible for later audit

- AnchorIndexEncode HMAC-128
- 128-bit DPF
- Additive Secret Sharing foundational types
- SCMP / comparison
- Secure Permutation
- KHPRF
- 256-bit Private Equality
- Candidate Compaction

Anchor Aggregation is explicitly excluded from the direct-migration list.

## PHASE 1 audit and implementation record

- PHASE 1A audit completed.
- PHASE 1B clean-room implementation completed.
- old source migrated = 0
- third-party dependencies = 0

The PHASE 1B foundational domains are deliberately distinct:

- `F_2` for Boolean-bit sharing;
- `Z/(2^32)` for 32-bit wrapping integer sharing;
- `Z/(2^64)` for 64-bit wrapping integer sharing.

ASS multiplication is intentionally absent. PHASE 1B provides only secure
DO-side splitting, authorized reconstruction, and party-local linear addition
and subtraction. It does not claim that a multiplication-capable ASS protocol
has been completed.

- correctness audit: **PASS** — exhaustive bit tests, integer boundary and
  wrapping tests, 10,000-sample Ring32 and Ring64 round trips, additive and
  subtractive homomorphism checks, entropy-read failure checks, and freshness
  wiring regression all passed under `go test ./...` and `go test -race ./...`.
- single-party structural audit: **PASS** — each production share type contains
  exactly one private local mathematical value; package import boundaries and
  the exact exported share API inventory passed automated regression checks.

These results are correctness evidence and structural party-view evidence.
They are not, by themselves, a complete cryptographic security proof. The
cryptographic argument for splitting additionally relies on `crypto/rand`
providing a uniform unpredictable first share, which makes either individual
share independent of the secret in its declared finite domain.

## PHASE 2 Anchor representation audit and implementation record

- PHASE 2A audit completed.
- PHASE 2B clean-room AnchorIndexEncode implementation completed.
- old source migrated = 0
- old HMAC implementation copied = 0
- third-party dependencies = 0

PHASE 2B implements only the canonical Anchor logical-key encoder, 256-bit key
generation/validation, and the HMAC-SHA256-based opaque 128-bit Anchor value.
Key provisioning, key serialization, cloud state, bucket mapping,
IndexOutsource, query-token generation, runners, and 128-bit DPF implementation
remain outside this phase.

- correctness audit: **PASS** — canonical-encoding and HMAC known-answer
  vectors, deterministic/key/qgram sensitivity, exact-width, field-boundary,
  UTF-8, four-code-point, no-normalization, zero-key, entropy-failure, and
  freshness wiring tests passed under `go test ./...` and
  `go test -race ./...`.
- single-party structural audit: **PASS** — the exact exported API and
  production import allowlist passed automated checks; no raw logical-key
  bypass, legacy 64-bit Anchor API, key serialization, key logging, cloud
  state, bucket implementation, or third-party dependency is present.

These results are correctness and structural party-view evidence, not a
complete cryptographic proof. The cryptographic argument additionally relies
on the standard PRF security of HMAC-SHA256 and on preserving the stated key
ownership boundary.

## PHASE 2D 128-bit Anchor DPF record

- PHASE 2C design audit completed and manually approved with the corrections
  frozen in the current engineering specification.
- PHASE 2D is a clean-room 128-bit Anchor DPF implementation.
- old DPF source migrated = 0
- old DPF source copied = 0
- third-party dependencies = 0
- output group = `F_2`
- production PRG = AES-128 seed-as-key with four fixed, distinct domain blocks
- DPF key serialization = deferred

The implementation contains no Boolean secure multiplication or B2A protocol;
those remain explicit future dependencies. The generator uses
`crypto/rand.Reader` with complete reads. The old 64-bit DPF, old arithmetic
output/wire format, and Target DPF are not present.

Correctness evidence includes independent OpenSSL PRG vectors, an independent
OpenSSL-backed full DPF vector, direct 128-layer correction-invariant checks,
edge and high/low-half regressions, 100,000 deterministic randomized alpha
cases with both match and non-match evaluation, entropy failure tests, and a
10,000-pair old/new reconstruction-semantics differential audit. These tests
do not establish the cryptographic security of the PRG or DPF.

The single-party structural audit checks that a cloud evaluation receives only
one opaque key and one public point and returns one local `F_2` share. Key fields
are unexported, and no alpha, peer key, peer root seed, runtime modulus, wire
format, key logging, or third-party dependency is present.

## PHASE 3B Target routing foundation record

- PHASE 3B-BRIDGE-DESIGN review passed; **OPTION 4 approved**.
- Target stored representation changed from `Z = Z0 XOR Z1` over encoded points
  to additive Ristretto255 point shares `T = T0 + T1`. This is a representation
  change only; Target Match remains full-256-bit Private Equality.
- migrated source files = 0
- copied source lines = 0
- copied packages = 0
- new direct third-party dependency = `github.com/gtank/ristretto255 v0.2.0`
  (transitively `filippo.io/edwards25519 v1.1.0`). No other dependency was
  added; no Rust or C++ build is used.

### Old KHPRF / private-equality reference status

The old 256-bit private-equality prototype was audited as an **algorithm
reference, correctness oracle, and benchmark baseline only**. Its confirmed
interface is:

    XOR-share input -> Boolean Beaver AND-tree -> XOR-share equality bit

Status: **REFERENCE / MIGRATION CANDIDATE**, not a new production
implementation. It is **not** present in the clean repository; PHASE 8 migrates
or ports it as an independent Go implementation. The old Rust crate, workspace,
drivers, wire magic, and controller are not migrated.

### PHASE 8 adapter communication (corrected)

The OPTION 4 adapter shares a private 256-bit input **per group**. For `g`
groups in a bucket:

    CS0 -> CS1:  32 * g bytes
    CS1 -> CS0:  32 * g bytes
    per party sent: 32 * g bytes ; per party sent+received: 64 * g bytes
    both parties total sent: 64 * g bytes

Earlier notes recorded "64 B per bucket", which is wrong by a factor of `g`.
The adapter belongs to PHASE 8 and is not implemented here.

### PHASE 3B evidence

- 100,000 routing consistency cases: two parties combining only their own
  `kappa_J` and `kappa_w` shares and evaluating only their own partial point
  recombine to the full group point.
- 100,000 point-share reconstruction cases.
- 100,000 OPTION 4 equal cases and 100,000 unequal cases.
- Known-answer vectors whose expected values were produced independently:
  HMAC digests and canonical frames by the Python standard library, and scalar,
  base-point, and group-point encodings by curve25519-dalek 4.1.3 (Rust). The
  locked base point encoding is
  `44bc37cc66414c556078145a5e869039ced44c8056a05eeccc0b66600f9f175f`.
- Entropy-failure, partial-read-failure, and split-freshness tests.
- Structural single-party audit: share types are plain value types holding one
  local value; no reconstruction, opening, revealing, or formatting entry point
  exists.

These results are correctness and structural party-view evidence. They are not
a cryptographic proof; the argument additionally relies on the PRF security of
HMAC-SHA512 and HMAC-SHA256, on Ristretto255 canonical-encoding injectivity, and
on CS0 and CS1 remaining non-colluding.

### Carried-forward open items

- SHORT-STRING COMPLETENESS = OPEN (644 `area`, 4,047 `area_alias` records).
  No out-of-domain policy is frozen and no short-string index exists.
- B RE-EVALUATION = OPEN. PHASE 3B requires only `B = 2^k` and does not freeze a
  production width.
- Paper modified = no; it will be synchronised once the protocol is stable.

## PHASE 3C1 base index builder record

- trusted offline package: `internal/indexbuild`
- input: raw MusicBrainz fullexport `20260905-002519` COPY text tables `area`
  and `area_alias`
- output: in-memory-only public metadata plus separate CS0 and CS1 indexes
- persistent index format implemented = no
- full-dataset index generated = no

The new parser performs field splitting before PostgreSQL COPY text unescaping,
recognizes raw `\N`, validates exact physical column counts (14 for `area`, 16
for `area_alias`), supports the required simple, octal, and hexadecimal
escapes, rejects illegal escapes, preserves empty strings and whitespace, and
validates projected text as UTF-8.

The old repository files actually consulted were:

- `index/index.go`: only the `[]rune` sliding-window idea and the requirement to
  preserve repeated q-gram occurrences;
- `psmj/index.go`: only the physical projection indices for `area_alias` and a
  warning example of why the old q-gram-only/opaque-tag grouping path must not
  be copied.

The old `strings.Split` readers were not correct COPY text parsers and were not
migrated. No old production index schema, generated index, E2E driver, wire
format, package, helper, or source line was copied. Copied old source lines =
0; migrated old helpers = 0. The parser and builder are new implementations
with new unit, real-data integration, reconstruction, freshness-wiring, and
party-state structural tests.

PHASE 3C1 freezes q=4 code-point positions, Anchor identity `qgram`, Target
identity `(joinID,qgram)`, MSB-first Anchor prefix buckets, XOR Target buckets,
the minimal party-local slot schemas, and uniform per-bucket maximum `L_pad`.
Short-string policy, final B choice, and PHASE 5 payload alignment remain OPEN.

## PHASE 3C2 full MusicBrainz validation record

The PHASE 3C1 parser and builder were rerun from the raw MusicBrainz fullexport
`20260905-002519` with no record limit. The current Go parser independently
reproduced the historical audit:

- `area`: 120,071 raw/usable rows, zero NULL names, zero empty names, 644 short
  names, 119,427 indexed records, 906,584 q-gram occurrences, 110,115 groups;
- `area_alias`: 67,896 raw/usable rows, zero NULL names, zero empty names, 4,047
  short names, 63,849 indexed records, 480,945 q-gram occurrences, 310,331
  `(area,qgram)` groups.

The share-free `AnalyzeLayout` path reuses the production logical grouping and
bucket functions. It allocates no party shares, dummy slots, or point-share
arrays. Full layout results were:

| k | B | Anchor padded/real | Anchor ratio | Target padded/real | Target ratio |
|---:|---:|---:|---:|---:|---:|
| 8 | 256 | 60,875,210 / 906,584 | 67.147898 | 2,982,727 / 480,945 | 6.201805 |
| 10 | 1,024 | 26,409,235 / 906,584 | 29.130489 | 2,757,076 / 480,945 | 5.732622 |
| 12 | 4,096 | 11,064,894 / 906,584 | 12.205040 | 2,132,676 / 480,945 | 4.434345 |
| 13 | 8,192 | 7,070,653 / 906,584 | 7.799225 | 1,692,115 / 480,945 | 3.518313 |
| 14 | 16,384 | 4,417,569 / 906,584 | 4.872763 | 1,304,291 / 480,945 | 2.711934 |

The largest Anchor group was trusted-analysis q-gram `aint`, with 5,211
occurrences. The largest Target group was `(joinID=3416,qgram="Buth")`, with
16 occurrences; this confirms that Target grouping did not regress to
q-gram-only identity.

Only k=14 was materially built. The calculated two-party lower bound was
511,486,080 bytes (0.476359 GiB), below the 12 GiB guard. The in-memory Build
took 40.569370667 seconds: 11.334530444 seconds for logical grouping/key and
crypto derivation and 29.234839249 seconds for sharing/padding. Sampled Go heap
peak was 1,285,709,336 bytes; the complete validation process maximum RSS was
1,767,572 KiB with zero swap.

Deterministic audits reconstructed 10,000 Anchor real slots, 10,000 Anchor
dummy slots, 10,000 Target real slots, 10,000 Target dummy slots, and 10,000
Target groups. Twenty thousand group-identity checks passed. There were 952
Anchor and 418 Target `(record,qgram)` pairs with repeated occurrences; their
maximum multiplicities were 2 and 3. The existing per-occurrence fresh-split
wiring test remains the strict freshness evidence, and a full-index spot check
confirmed equal, correct reconstructed routing semantics for repeated Anchor
occurrences.

The evidence recommends k=14 / B=16,384 among the tested choices because it has
the smallest padded indexes and lowest median/tail per-query bucket workload.
This is a recommendation only. **B final choice remains OPEN.** Short-string
completeness and PHASE 5 payload alignment also remain OPEN. No persistent
index format or index file was created, and PHASE 4 was not started.

## PHASE 3C3 tiered padding freeze

Production IndexOutsource padding is now per-group tiered padding with the
frozen ladder `{4,16,64,256,1024,4096,16384}`. `TierWidth(n)` returns the first
tier greater than or equal to nonzero real size `n` and errors above 16,384.
Both Anchor and Target use this ladder. The PHASE 3C2 per-bucket maximum remains
implemented only as a share-free experiment baseline.

Each party group now carries the same public `PadWidth` and exactly that many
local slots. Production buckets no longer carry `LPad`; public bucket metadata
contains bucket ID, group count, and `sum PadWidth`. Public `PadWidth` reveals a
coarse group-size class. This is frozen, allowed structural leakage accepted
for the padding reduction.

| side | width | groups | percentage | real | padded | overhead |
|---|---:|---:|---:|---:|---:|---:|
| Anchor | 4 | 80,632 | 73.225264% | 133,239 | 322,528 | 189,289 |
| Anchor | 16 | 19,584 | 17.785043% | 166,062 | 313,344 | 147,282 |
| Anchor | 64 | 7,766 | 7.052627% | 237,365 | 497,024 | 259,659 |
| Anchor | 256 | 1,858 | 1.687327% | 207,162 | 475,648 | 268,486 |
| Anchor | 1,024 | 257 | 0.233392% | 111,343 | 263,168 | 151,825 |
| Anchor | 4,096 | 14 | 0.012714% | 32,056 | 57,344 | 25,288 |
| Anchor | 16,384 | 4 | 0.003633% | 19,357 | 65,536 | 46,179 |
| Target | 4 | 304,003 | 97.960887% | 435,684 | 1,216,012 | 780,328 |
| Target | 16 | 6,328 | 2.039113% | 45,261 | 101,248 | 55,987 |

Higher Target tiers have zero groups. Total Anchor padding is 1,994,592 slots
for 906,584 real slots (`2.200118x`); Target is 1,317,260 for 480,945
(`2.738899x`). At k=8 this reduces the PHASE 3C2 uniform baselines by
`30.520131x` and `2.264342x`. Tier storage is independent of bucket width.

The mandatory full k=8 materialization passed. Its calculated two-party lower
bound was 283,959,328 bytes (0.264458 GiB). Build wall time was 46.354432638
seconds, sampled Go heap peak was 633,192,656 bytes, maximum RSS was 963,088
KiB, and swap was zero. Deterministic audits reconstructed 10,000 each of
Anchor real/dummy slots and Target real/dummy slots plus 10,000 Target groups.
An additional 10,000 Anchor and 10,000 Target groups passed exact `PadWidth ==
TierWidth(realSize)` and party-length agreement checks.

No Position Filtering or Aggregation implementation assumes a bucket-wide
width. Future Position Filtering can iterate group-local slot slices; future
hidden Aggregation is independent of group padding width. PHASE 4 was not
started. B final choice, short-string completeness, and PHASE 5 payload
alignment remain OPEN. Paper modified = no.

## PHASE 4A Anchor filtering foundation

PHASE 4A connects non-overlapping query q-chunks to the existing Anchor HMAC,
bucket function, 128-bit DPF, variable tier groups, secret validity, masked
position comparisons, and two batched F2 Beaver layers. The output is an F2
posting-hit share; no B2A or record aggregation was added.

The current raw MusicBrainz snapshot independently yielded Anchor/Target
maximum positions `54/62` and maximum indexed rune lengths `58/66`. The public
domain is therefore `U_pos=62`, with minimal signed-SCMP `Bin=7`. A 100,000-case
Ring32 reduction audit, exhaustive clipped-interval tests, real 5,000-record
k=8/k=14 integrations, dummy suppression, and repeated-occurrence tests pass.

The real external EzPC/LLAMA `keyGenSCMP`/`evalSCMP` implementation was copied
only to `/tmp` and built with `Bout=1`. It passed 100,000 comparisons and
100,000 interval checks. A dedicated regression produced zero corrected errors
and 100,000 errors when `rb` removal was intentionally omitted. The clean repo
contains only an opaque adapter contract and masked-input algebra; its
plaintext reference backend is test-only composition oracle code.

Old sources actually consulted were `vendor/ezpc_fss/pubdiv.{h,cpp}`,
`group_element.h`, `dcf.cpp`, `cmd/llama-scmp-audit/main.cpp`,
`tools/llama_scmp128_ffi.cpp`, and `tools/final_filter.cpp`. Zero old C++ source
lines or old drivers/controllers were copied into this repository. The LLAMA
algorithm remains external; the old BFV position path is retired. Paper
modified = no. B final choice, short strings, and PHASE 5 payload alignment
remain OPEN.

## PHASE 5B1 — hidden incidence aggregation core

Begin HEAD: bd2c89a11bb2369455e3ab96d6e12c65c435333c; status clean.
Implements only F2 posting hit -> Z/128Z B2A -> local-record F. PARTIAL REUSE
remains the migration decision. New protocol designed: no. Paper modified: no.

The DO uses independent record capacity D=nextPow2(M), zero for empty M,
and a crypto/rand random injection. T=sum(group.PadWidth). PartyMatrix holds
only D/T and column-major coefficient shares. Every zero/nonzero coefficient
gets fresh sharing. The old public u[phi(s)] adapter is absent. A single
scalar-vector triple per posting replaces DT scalar-triple objects; chunked
execution accumulates directly into F. Static A is reusable; triples are not.
The default public chunk limit is 64, configurable by NewAggregator.

Old algorithms referenced: ring_beaver::b2a_z128_party,
bucket::aggregate_shared, beaver::mul_shared_scalar_vectors, and
update::shared_update. Source lines copied from old implementation: 0.
No old Rust dependency graph, plaintext_u/support_index, leaking u rows,
party_states_for_postings_with_identity, or full StaticPerm was copied.

Verification: exhaustive Z128 local operations; four Boolean-share cases plus
100,000 random B2A cases; single-party distribution regression (4096 setups
per party, all 128 marginal values seen, no readable row-equality/unit-column
signal); recursive online object-graph check; one-time/chunk/order guards.
These distribution tests supplement the independent uniform-mask argument;
they are not claimed as a standalone cryptographic proof.

Full MusicBrainz source is the raw 20260905-002519 area COPY file. q=4,
code-point offsets, posting tiers unchanged. Uses the existing full-test kB
bytes 01..20 (hex). No full persistent party index was generated.
120071 records, 644 short records excluded from normal q-chunk queries,
119427 normal queries. Real bucket trials use fresh triples and check ALL D
coordinates, including all-zero, all-real-one, dummy-only, all-one,
duplicate-only, and random hits:

| bucket selection by T | ID | T | M | D | trials | errors |
|---|---:|---:|---:|---:|---:|---:|
| p50 | 3682 | 68 | 32 | 32 | 1000 | 0 |
| p95 | 260 | 352 | 162 | 256 | 1000 | 0 |
| p99 | 10425 | 1072 | 672 | 1024 | 1000 | 0 |
| duplicate | 4844 | 8 | 4 | 4 | 1000 | 0 |

Query scan preserves repeated non-overlapping chunk occurrences. Counts are
per raw area row, not deduplicated name. Wire below is incidence-only,
2*sum_h(T_h+D_h*T_h); B2A adds 4*sum_h(T_h).

| metric | p50 | p95 | p99 | max |
|---|---:|---:|---:|---:|
| r | 2 | 5 | 6 | 14 |
| sum D*T | 89088 | 30194432 | 136296960 | 290775040 |
| incidence wire bytes | 178872 | 60409848 | 272631704 | 581629696 |

Bucket 9963 occurs in 130 queries (0.108853%). Top-ten union is 10009 queries
(8.380852%). Top-ten IDs/query counts: 9963/130, 7640/878, 3648/167,
11448/4740, 15173/736, 13007/861, 7596/860, 4578/874, 8820/484, 11503/541.
Thus expensive buckets are a material workload cost, not merely unreachable
worst cases. B final choice remains OPEN.

Benchmark: 10 warmup + 50 measured per row, real Go B2A/vector-Beaver algebra
for BOTH clouds, in-memory batched masked openings. Timings are measured
online stage sums, excluding triple generation, heap sampling and plaintext
verification. They are NOT network/two-process E2E latency. Communication is
exact one-byte-per-Z128 payload accounting, not triple size or measured TCP.

| T percentile | chunk | B2A us p50/p95 | A*x us p50/p95 | x->F us p50/p95 |
|---|---:|---:|---:|---:|
| p50 | 32 | 1.389 / 2.799 | 22.688 / 32.964 | 24.001 / 35.763 |
| p50 | 64 | 1.308 / 2.994 | 23.299 / 48.132 | 24.731 / 50.033 |
| p50 | 128 | 1.138 / 1.759 | 21.737 / 33.004 | 22.840 / 34.115 |
| p50 | 256 | 1.118 / 1.684 | 22.115 / 25.820 | 23.215 / 26.913 |
| p95 | 32 | 3.029 / 8.090 | 595.124 / 740.892 | 598.073 / 743.502 |
| p95 | 64 | 3.004 / 4.116 | 550.183 / 678.173 | 553.727 / 681.365 |
| p95 | 128 | 2.974 / 6.047 | 561.376 / 681.379 | 564.644 / 684.564 |
| p95 | 256 | 2.929 / 5.353 | 546.136 / 650.116 | 548.798 / 652.945 |
| p99 | 32 | 9.437 / 14.006 | 7204.583 / 9653.708 | 7213.107 / 9664.911 |
| p99 | 64 | 10.434 / 18.687 | 7258.555 / 7872.485 | 7269.345 / 7881.392 |
| p99 | 128 | 9.485 / 18.140 | 7216.562 / 8862.300 | 7226.363 / 8872.841 |
| p99 | 256 | 10.316 / 19.357 | 7539.754 / 9059.496 | 7558.863 / 9068.562 |

Default 64 favors the heavy p99 sample's tail (lowest p95 in both sweeps)
with bounded working memory; no universal/network optimum is claimed.
At chunk=64, x->F latency p50/p95/p99 in ms is:
3682: 0.024731/0.050033/0.096441;
260: 0.553727/0.681365/0.925913;
10425: 7.269345/7.881392/7.965211.

Separate accounting, both parties, bytes per invocation:

| bucket | static A | offline B2A+vector triples | online x->F |
|---|---:|---:|---:|
| 3682 | 4352 | 9248 | 4760 |
| 260 | 180224 | 363264 | 182336 |
| 10425 | 2195456 | 4399488 | 2201888 |
| 9963 | 270336000 | 540804000 | 270435000 |

Formulas: static=2DT, offline=4DT+8T, online=2DT+6T. Offline bytes describe
consumed randomness, not simultaneously resident chunk storage. Heap samples
include trusted raw/logical data and GC retention. At chunk=64 sampled peak
heaps were 47446480 / 85383952 / 96121864 bytes for p50/p95/p99; increases
over pre-benchmark heaps were 1104112 / 38863088 / 47577032 bytes.

Hot bucket 9963: T=16500, M=4661, D=8192, P=135168000. Live-storage estimate
279514752 bytes was below 12 GiB, and ordinary-bucket throughput made one
invocation reasonable. Actually measured once with chunk=64: B2A 0.158671 ms,
A*x 919.513481 ms, online sum 919.672152 ms; wall including preprocessing
1.850909670 s. All-one input checked all coordinates: 0 errors. Sampled heap
peak 541530664 bytes; whole experiment max RSS 542860 KiB; no swap.

Reproduce: PMEQ_INCIDENCE_EXPERIMENT=1 go test ./internal/indexbuild
-run '^TestFullIncidenceExperiment$' -count=1 -timeout=20m -v.
gofmt, go test ./..., go vet ./... and git diff --check pass. No concurrency
was introduced; race is not a gate and was not rerun.

Deferred, unchanged interface: F -> z -> global alignment -> Keep[gamma] ->
independently DO-generated per-record Payload[gamma], same Global LayoutID.
Posting KappaJoinShare/BucketJoinShare remain potentially redundant and are
not removed. F->z, permutation, C, Keep, compaction, routing and payload
implementation: no. New cryptographic protocol: no. Paper changed: no.
