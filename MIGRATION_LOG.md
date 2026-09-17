# PMEQ Migration Audit Log

## PHASE 5B3 — alignment state compaction and preprocessing freeze

Begin HEAD 75a4d9e6d5eeeb8747aaf29cb6dc8f153fa2b362; status clean.
No aggregation mathematics changed: hidden incidence, F->z, DO gamma/pi,
two-stage permutation, C, Keep, payload, Anchor B=65536 and the finalized tiers
4/16/64/256/1024/4096/8192/16384 are unchanged.

Per bucket, crypto/rand generates a fresh 32-byte static rhoSeed. AES-256-CTR
uses that seed as key, IV ASCII "PMEQ-RHO-PRG-V1!", little-endian uint32 stream
words, and descending Fisher-Yates with rejection of words below 2^32 mod bound.
CS0 receives only LayoutID/BucketID/rhoSeed; CS1 only LayoutID/BucketID/sigma[]uint32.
DO sets sigma[rho[i]]=pi[i]. All permutation coordinates, including DO pi/gamma,
now use uint32; local loop indices/lengths and record IDs are not coordinates.
CS0 lazily expands only the accessed invocation's rho[]uint32. The seed is
party-local representation, not a secret shared with CS1. Security uses the
cryptographic PRG assumption; 256 bits do not information-theoretically sample N!.

N=120071, nonempty Anchor buckets=53383. Comparable factor-data bytes:

| representation | CS0/bucket | CS1/bucket | combined/bucket | CS0 total | CS1 total | combined total |
|---|---:|---:|---:|---:|---:|---:|
| old []int factors | 960568 | 960568 | 1921136 | 51278001544 | 51278001544 | 102556003088 |
| new seed / []uint32 | 32 | 480284 | 480316 | 1708256 | 25639000772 | 25640709028 |

Reduction=3.999733509x. These figures exclude metadata/headers/allocator/map
overhead consistently. On this Go runtime sizeof(Stage0)=50 and sizeof(Stage1)=48;
including these structs and sigma backing data gives 25644232306 bytes, still
excluding allocator rounding and lookup containers. The remaining ~25.64 GB is
not claimed to fit the experiment RAM budget; no full factor table was allocated.
The coordinator holds selected party objects and loads accessed sigma only.

Correctness: 100000 fresh random pi/rho pairs, lengths randomly selected from
1..256 except 10 full-N=120071 cases, passed permutation validity, deterministic
seed expansion and sigma[rho[i]]=pi[i] with zero errors. Independent unbuffered
AES-CTR expansion and a fixed N=16 KAT freeze stream/endianness/rejection details.
Static factor reuse with fresh masks passed, including nonzero dynamic inputs.
Reflect audits check exact CS0/CS1 fields and uint32 coordinate types; there is
no peer factor/mask/pi/gamma in either static party object. These are correctness
and structural regressions, not a claim of cryptographic proof by testing.

Full PHASE5B2 regression rerun: 1000 seeded random normal MusicBrainz queries
plus p50/p95/p99 workload representatives; F/z/Y/C/Keep/payload all zero errors.
HMAC/DPF/incidence/Beaver/permutation are real; SCMP remains the explicitly
test-only composition reference, with PHASE5B2's unchanged validated native
LLAMA component. Full run 263.82s; max RSS=1302540 KiB, no swaps. PHASE5B2
permutation tests were rerun. Test pool registries consumed 1003 distinct query
tickets per party; this does NOT mean all 1003 queries' correlated materials
were simultaneously preallocated in RAM. Trusted test preprocessing simulates
offline packets before the online stages, with no online party DO/raw-DB call.

N=120071 benchmark, 2 warmups + 10 measured, sequential per-query occurrences:

| r | expansion ms p50/p95 | online excluding expansion ms p50/p95 | paired total ms p50/p95 | online bytes |
|---|---:|---:|---:|---:|
| 1 | .367863 / .402022 | .374752 / .570924 | .734766 / .952874 | 240142 |
| 2 | .836360 / 1.093395 | .793969 / 1.036237 | 1.650156 / 2.079847 | 480284 |
| 4 | 1.711339 / 1.779306 | 1.753419 / 1.924717 | 3.463046 / 3.670367 | 960568 |
| 6 | 2.672767 / 2.848462 | 2.477459 / 2.781451 | 5.151430 / 5.485716 | 1440852 |

Quantiles use ceil((n-1)*p); paired totals are computed per sample before sorting.
This is measured local work of both parties with in-memory messages, not TCP/E2E.
Expansion is online local compute and is included by the existing Message2 wrapper.
Temporary rho backing=480284 bytes. Per-invocation measured additional HeapAlloc
and TotalAlloc both=980008 bytes; no GC ran inside any measured window. The
temporary peak includes rho plus opening/output arrays; excludes already-existing
sigma, input shares and one-time preprocessing. Sequential r=1/2/4/6 keeps this
increment constant. Memory sampling/forced pre-window GC are outside timings.
Isolated benchmark process max RSS=90368 KiB. No full-table memory claim is made.

PoolConfig.PreprocessingPoolSize=Q_pool is explicit with no frozen/default value.
One query packet contains r one-time sub-invocations and final Keep material.
PartyPool is a lifecycle registry (not serialization/material storage): offline
Provision -> Seal -> online Consume. Reuse, unknown IDs, online refill and budget
overflow are tested. Existing correlated packets keep their own one-use guards.
PoolStorage=Q_pool*S_offline for equal-capacity packets, sum_i S_offline(i) for
heterogeneous packets. OfflineShape keeps PHASE5B2's aggregation byte formula;
PHASE4 material is added separately if budgeting the complete Anchor chain.

STATIC: payload shares, LayoutID, DO-only gamma, bucket A shares, rhoSeed/sigma,
outsourced index/DPF evaluation state. Query DPF keys are still query-generated.
ONE-TIME: SCMP masks/keys, B2A and incidence Beaver triples, permutation masks,
final Keep threshold material. Current Keep has no additional Keep Beaver triples;
any such future triples must also be one-time. No unlimited-query/no-preprocessing
claim is made. Exhaustion requires another offline epoch, never query-time DO.

PHASE5 = SEALED: aggregation correctness, hidden posting mapping, aligned
Keep/payload, quantified static storage, explicit finite one-time model, and
no query-time DO/raw DB access all pass. No new protocol, bit packing, persistent
format, symmetric second direction, Candidate Compaction or Target routing.
Paper modified=NO. Short-string completeness remains OPEN.

Reproduce: go test ./internal/aggregation -run 'TestSeed|TestCompact|TestOfflinePool|TestStaticCompact' -count=1 -v;
PMEQ_AGG_FULL=1 go test ./internal/aggregation -run 'TestReal1000Queries|TestPermutation120071Benchmark' -count=1 -timeout=30m -v.
Final validation: gofmt clean; go test ./... PASS; go vet ./... PASS;
git diff --check PASS. No new concurrency; race was not required or rerun.

## PHASE 5B2 — complete Anchor record aggregation

Begin HEAD a39c25a1fea24b5e2ba6394771b94eaa071b5370; status clean.
AnchorBucketBits=16 / B=65536 is now frozen. Both base indexes use posting
tiers 4/16/64/256/1024/4096/8192/16384. Uniform stays experiment baseline only.
Full raw recalculation: Anchor real/padded=906584/1961824 (2.163974x), groups
110115, nonempty=53383; Target real/padded=480945/1317260 (2.738899x), groups
310331, nonempty=64902 at target bits=16. Target width remains a separate
parameter. Anchor max same-record/same-qgram occurrences=2, attained by
"land" in "Falkland Islands"; hence filtered F<=2<64. Max query r/C=14.

`internal/aggregation` adds offline, one-use masked SCMP composition, separate
rho/sigma party states, the old two-stage masked-scatter algebra, local C,
Keep, and independently generated global payload under LayoutID. N=120071.
z is converted F2->Z128 before alignment, avoiding N-wide conversion.
No old leaking adapter, BigState posting rows, StaticPerm combined state or
old controller was copied. Existing incidence mathematics is unchanged.
Reference: old src/bin/permutation_agg_proto.rs build_static/run_perm_online;
SCMP: vendor/ezpc_fss/pubdiv.cpp, dcf.cpp and tools/llama_scmp128_ffi.cpp.
New Go code reexpresses the existing equations; zero old source lines or
C++ primitive sources were copied into the clean repository.

Correctness: 1000 seeded random normal queries plus p50/p95/p99 workload
queries on the full tiered Anchor index. Real HMAC/DPF/Beaver are used;
SCMP is explicitly TEST ORACLE FOR COMPOSITION ONLY. F,z,Y,C,Keep and payload
coordinates all checked, zero errors. Synthetic tests cover repeats, duplicate
postings, dummy slots, cross-bucket records, no candidates, multiple candidates,
tau=0, lambda=1 and lambda=r. Native unmodified LLAMA independently passed
100000 comparisons: corrected errors=0; omitted-rb errors=49788. Native Keep
batch N=120071 x 5 rounds also had zero errors. Native sources in /tmp were
byte-compared to the read-only old repository. No native algorithm was edited.

Final measured query components (ms), both clouds' local work; native SCMP
rows use the median of 5 independent component runs at the actual wire count:

| workload query | x->F | F->z | z B2A | permutation | C sum | C->Keep | sum |
|---|---:|---:|---:|---:|---:|---:|---:|
| p50 Kozushima (Kōzushima) | .274452 | .076062 | .003361 | .734700 | .242421 | 63.644457 | 64.975453 |
| p95 Negrilla de Palencia | 169.295278 | 3.500107 | .068516 | 2.809816 | .638434 | 63.644457 | 239.956608 |
| p99 Saint-Pierre-d'Oléron | 450.060250 | 4.856601 | .089408 | 2.208225 | .493100 | 63.644457 | 521.352041 |

SUM OF MEASURED COMPONENTS, not monolithic or two-process E2E latency.
Query percentiles select workloads by intrinsic P, not latency percentiles.
SCMP reference timings are excluded. Go component measurements include
in-memory masked exchanges; native comparison includes local masked opening,
both Eval calls and rb correction. No network/RTT timing is claimed.

| query | r | sum D | sum T | sum DT | static A bytes | offline total bytes | online bytes |
|---|---:|---:|---:|---:|---:|---:|---:|
| p50 | 2 | 160 | 332 | 35968 | 71936 | 70120013 | 795320 |
| p95 | 5 | 6560 | 8700 | 25342848 | 50685696 | 177262158 | 52218120 |
| p99 | 5 | 9616 | 9780 | 68338560 | 136677120 | 351013902 | 138234360 |

Offline totals separate Beaver, permutation correlations and external SCMP
keys/masks, as detailed in internal/aggregation/README.md. Native key codec is
284 bytes per key per cloud. Native offline KeyGen medians: F p50=.131830ms,
p95=4.470490ms, p99=6.271160ms; Keep=82.289800ms. These are SCMP component
preprocessing times, not total DO preprocessing times.

N=120071 permutation r=1/2/4/6: online .520367/1.056507/2.103846/3.144846ms;
correlated preprocessing 1.348055/3.326704/6.087911/8.397106ms;
online bytes 240142/480284/960568/1440852, correlated bytes
720426/1440852/2881704/4322556. Each is a real local component invocation.
Full 1000-query correctness run max RSS=1314148 KiB, swaps=0. Separate native
SCMP max RSS=79508 KiB; these are separate processes, not a combined peak.
Representative Go heap samples=749169504/716164168/475993560 bytes, not a
continuous peak profiler. Full static incidence estimate=1521004240 bytes;
global payload arrays=11526816 bytes, including Go alignment padding.

Important storage limitation: eager rho/sigma arrays for every nonempty bucket
would total 102556003088 bytes, so this full permutation table was NOT built.
Only provisioned accessed invocations are materialized. The component supports
offline provisioned packets; no claim of a ready all-bucket resident pool is
made and no query-time dealer service was added. Per bucket factors=1921136
bytes. No further full-table performance expansion was attempted.

Posting KappaJoinShare/BucketJoinShare have no online production consumer and
are DEPRECATED / REDUNDANT, retained for later cleanup. Paper modified=NO.
Compaction and Target routing not started. No new aggregation protocol.

Reproduce Go: PMEQ_AGG_STATS=1 go test ./internal/indexbuild -run TestAggregation -v;
PMEQ_AGG_FULL=1 go test ./internal/aggregation -count=1 -timeout=30m -v.
Native audit harness /tmp/phase5b2-scmp.cpp includes the unchanged old FFI source
from /tmp/phase5a-dmpf; build with g++ -O3 -std=c++17 -march=native -maes
-msse2 -msse4.1 -mpclmul, pubdiv/dcf/prng and cryptoTools Defines/Log/AES/PRNG
sources, -ffunction-sections -fdata-sections -Wl,--gc-sections -pthread.
Runs: /tmp/phase5b2-scmp 100000 1; batch sizes 160,6560,9616,120071 each 5 runs.
Additional native regression enumerated all 64 x 14 value/threshold pairs
repeatedly for 100000 comparisons, including F=1 at threshold=1.
Final gofmt, go test ./..., go vet ./... and git diff --check PASS.
No concurrency was introduced; race was not rerun and is not a gate.

## PHASE 0 record

- Old repository: `/home/tenggn/projects/new-pmeq`
- Old repository status: read-only reference
- Snapshot: `/home/tenggn/projects/PMEQ_SNAPSHOT_PRE_ANCHOR_AGG_20260915T190526+0800/source.tar`
- Actual verified SHA256: `a456dec8a84236b333c043b7ce68033b6418f6c6ac8e2ca494858b62f66792a0`
- Expected SHA256: `a456dec8a84236b333c043b7ce68033b6418f6c6ac8e2ca494858b62f66792a0`
- New repository: `/home/tenggn/projects/clean_pmeq`
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

## PHASE 6 — Exact-K secure candidate compaction (2026-09-16)

Begin HEAD 8b9f675e45e3c3c5317f42e9df9aaa3fee6c3f84, status clean.
Read-only old source audit recovered candidate-compaction-input -> isolated
secure-candidate-permute-bench -> two party layers -> shuffled Keep opening ->
local extraction. Routing selection is N-slot dummy replacement, not compaction;
its coordinators and compacted KHPRF experiments do not define a production
exact-K chain. Full findings, including benchmark PRNG/Keep-byte/inherited-FD
issues, are in results/phase6-audit.md. Mathematical scheme reusable=YES.
No protocol requirement exposes original gamma, plaintext IDs or peer shares.

Migrated the existing masked-scatter equations to the current product group,
using one fresh permutation pair for all fields and independent masks by domain.
Party-local one-use packet handles bind LayoutID/CompactionID/shape/stage and
release N-sized state after extraction. Existing PartyPool integration is tested.
`CompactedCandidates` retains exactly K Ring64 ID/scalar kappa/XOR bucket shares
in fresh shuffled order. Additional compaction leakage=K with fixed public N.
No new compaction protocol, plaintext serialization shuffle or online dealer.

Kept PHASE5 production implementation sealed; extended its test harness through
compaction and added an opt-in test adapter to the existing external LLAMA
backend. Native KeyGen remains offline; Eval uses one party key only, with rb
removed once by existing PHASE4/5 callers. All external builds write to /tmp;
old source, data and paper remain untouched. Ordinary test builds still expose
no unsafe reference SCMP as a production implementation.

Validation and measurements: results/phase6-results.md; raw experiment logs are
recorded alongside it. K distribution reuses the actual 1000 cryptographic-query
outputs. Compaction benchmark runs 10 warmups plus 50 measured fresh packets per
distinct K. Output shares are excluded from server-to-server communication.
PHASE5=SEALED; query-time DO/raw DB=no; KHPRF/Target filtering started=no;
paper modified=NO. Work stops at secret candidate payloads.

Final PHASE6 evidence: 1000 seed-502 native-LLAMA real queries plus three
PHASE5 workload quantiles passed with zero errors. K min/p50/p90/p95/p99/max =
1/5/151/431/2843/4780. All eight distinct benchmark K values
0,1,5,8,64,431,512,2843 completed 10 warmups + 50 measurements each.
Full-N zero/singleton/all/sparse/dense repeated correctness and fresh-shuffle
regressions pass. gofmt, go test ./..., go vet ./..., native-tag vet,
git diff --check and focused race checks pass. Candidate Compaction complete=YES.


## PHASE 7 — private Target routing (2026-09-17)

Begin HEAD 24f863d8ef057fb37f8f0fa427f85f36e2a59420, status clean.
Target width audit found a parameterized builder, last full validated PSMJ
materialization at bits=8 and later bits=16 layout-only statistics. Integration
uses explicit Target bits=8, Anchor bits=16; Target B final choice=OPEN.
PHASE6 gains width metadata and an explicit-width offline mask constructor;
its legacy 16-bit default and shuffle equations remain unchanged. PHASE5
production logic remains SEALED. BucketDomain preserves the targetcrypto scalar
value/no-struct security gate and performs all routing XOR/width checks.

Added Query User-only fresh point/bucket token generation and codecs, one-party
routing Prepare/Finish and exact bucket-message encoding. J_u is evaluated once
per candidate; Y_u stays local. Output keeps Anchor RecordID shares once and
binds candidate indices to CompactionID. Repeated occurrences, short queries,
K=0, wrong bindings/widths, fresh compaction ordering and worker counts are tested.
Old full-Y combine/RoutingTag/retired DPF/CW paths were audited, not migrated.

The complete 310331-group/1317260-padded-slot PSMJ was materialized at bits=8.
A separate 100000 equal + 100000 unequal suite passed (same join/different word,
different join/same word, both different). The final native real-query run uses
Anchor seed 502 and a seed-707 shuffled normal alias catalog for unrelated
negative cases, plus positive and repeated real aliases. Tokens are produced
before Anchor execution; Query User makes no later call. Results/commands and
sampling details are recorded in results/phase7-audit.md and phase7-results.md.
No expensive queries are rerun for distributions. The initial partial query run
was replaced to make the negative sampler explicitly seeded; its completed
100k group checks are retained separately and its partial queries are not counted.

Worker sweep covers 1/4/8/16 at (431,5) and (2843,5); host recommendation=16.
The 35 distinct grid points use K={1,5,64,431,512,2843,4780}, r={1,2,5,7,16},
with the two selected sweep rows reused. Every point has 2 warmups+10 samples.
This grid combines independent marginals, not real joint-query percentiles.
Full grid max-by-max state is 6807280 bytes, so the case was actually run.
Only bucket messages count as server-server traffic; Y and local index reads do
not. Query User bytes, serialized opening bytes and internal state are separate.

PHASE5=SEALED; Candidate Compaction=COMPLETE; full Y never reconstructed in
production; Target Private Equality/Position/Aggregation started=no;
query-time DO/raw DB=no; paper modified=NO. Work stops at private routing.

Final PHASE7 results: final seed-502/707 native execution completed 1003 queries
(1000 normal + three PHASE5 workload quantiles), positive=248, negative=755,
repeated=59, candidate-occurrence pairs=466105, pairs with existing PSMJ groups=2554,
errors=0. K min/p50/p90/p95/p99/max remains 1/5/151/431/2843/4780.
Target r min/p50/p90/p95/p99/max=1/2/4/5/7/16; 4047 short names excluded and counted.
100k equal/100k unequal checks passed. All 35 grid points and the worker sweep
passed. Ordinary tests, full race (including existing 100k suites, no short
mode), vet, native-tag vet, gofmt and diff checks passed. Private Routing
complete=YES. Final code/metadata were migrated byte-identically from the
isolated validation copy to the specified repository before commit.

## PHASE 7B — final Target index layout

Begin HEAD `3afa024328d60d86396c97ebfa3947e3a8daf3ba`; clean. Old repository
read-only. One commit: `phase 7: finalize target index layout`. Paper modified=NO.

**TargetBucketBits=16; B=65536; Target B final choice=FROZEN; PSMJ=SEALED.**
Anchor bits remain independently16. No PHASE5, compaction, routing, KHPRF,
Option4, logical group, group-point, padding, or Position algebra was changed.
Production changes are final artifact serialization/validation, a fixed-width
Target builder wrapper, and a manifest-bound routing entry point. Existing
experimental constructors remain available for historical tests.

PHASE7 did NOT persist detailed workload rows. This phase restores them by the
same seeded native full-chain replay, recording actual fresh compaction outputs.
All 1003 queries/466105 routes and positive/negative/repeat/present-pair aggregates
match prior evidence; original randomized CompactionIDs/order were not recoverable
and are not falsely claimed to have been recovered. Plaintext trace is test-only.

Same logical groups/k_T sweep k8/10/12/14/15/16: total padded slots=1317260 at
every width. k15→k16 reduces query p95/p99 comparisons by50.46%/49.93% and
slots by50.21%/49.92%, with only449918 extra bytes/party (899836 both) and one
additional public bucket-ID bit. k14→k16 adds679252 bytes/party. This satisfies
the user's selection rule. All distributions and independent projection
assumptions are in results/phase7b-results.md and companion CSVs.

Final Build: logical/crypto11.172237082s; sharing/padding15.42065327s;
in-memory total26.592892175s. Build sampled heap peak306432264 bytes, process
build-end RSS high-water323956 KiB, swap0. Each final PSMJ file is29204994 bytes.
Full materialization/codec roundtrip and all310331 points/480945 real slots/
836315 dummy slots pass, plus10000 random samples of each category. Maximum
real group16, existing8-tier ladder unchanged. Party schema allow-list passes.
Final routing against persisted PSMJ files:1003 queries/466105 routes, errors0.

The existing PHASE5 offline payload API provisions120071 final-width tuples,
5043028 bytes/party including the new codec header. KJoin definition unchanged;
all payloads reconstructed correctly in the trusted audit. Its fresh LayoutID
requires matching PHASE5 DealerLayout/alignment; no old coordinate state is
relabelled. No persistent Anchor alignment artifact is claimed by this phase.
Artifacts are local under artifacts/phase7b; large party-share .bin files are
ignored by git, public manifests/hashes and evidence are committed. Each cloud
receives only its own files. No plaintext oracle trace enters party state.

PE source migrated=0. Existing standalone validated PE benchmark was rerun 5
times at 100000 comparisons with0 errors; no query compute latency is extrapolated
from its single batch size. Communication and real LLAMA Position estimates
are explicitly projections, not Target integrated measurements.

gofmt, go test ./..., go vet ./..., native-tag vet, git diff --check: PASS.
Additional race checks for new artifact packages/indexbuild/routing: PASS.
PHASE5=SEALED; Candidate Compaction=COMPLETE; Private Routing=COMPLETE.
Target Private Equality/Target Position/Target Aggregation started=no.

## PHASE8 — Target private equality

Begin HEAD e22a54ecbceb048c774d9130f26ce3bd9c7e8e2b; clean. One commit:
`phase 8: add target private equality`. Old repository read-only; paper unchanged.

Target bits16/B65536/Q4/8 tiers, PSMJ, PHASE5/6/7 and KHPRF semantics unchanged.
`internal/targetpe` loads hash-bound sealed PSMJ and global payload lineage;
no Target index rebuild or raw DB access exists in production. The native test
restores the SAME final offline DealerLayout before existing Alignment calls,
closing the PHASE7B lineage gap without relabelling old Keep coordinates.
All65536 bucket structures are audited without comparing secret T values.

Option4 locally computes D0=Y0-T0 and D1=T1-Y1, canonical32-byte encodings.
The initial shares1 XOR bit(E0) and bit(E1) directly represent bitwise equality;
old input adapter required=NO. No input message. A255-gate/8-round AND tree uses
packed uint64 F2 lanes in the existing f2beaver package; scalar and packed paths
share one Finish formula and party0 d&e convention. No new Beaver protocol.
Query packet consumption is one-time across copied handles; upper-bound
capacity packets consume actual prefixes and burn unused material. No online DO.

Output is secret group MatchShares with route offsets/counts, all query/layout/
compaction/index bindings, occurrences and Anchor ID shares. No peer E/D/Y/T or
plaintext hit is output. Canonical identity/zero and malformed inputs are tested.
Correctness:100000 equal+100000 unequal,0 false negatives/positives;
102400 packed/scalar lanes;100000 old/current differential comparisons,0 errors.

Actual complete native replay:1003 queries,466105 routes,2209949 comparisons;
463551 zero-match routes,2554 one-match routes,0 multi-match routes,0 errors.
G min0,p50=49,p90=1908,p95=5745,p99=50754,max180227, derived from this replay.
All hit statistics are trusted-test-only. Full Y and Match remain unopened in
production. Canonical Candidate Discovery/Target Position/Aggregation/ID output
are not started. See results/phase8-results.md for timings, worker sweep,
communication, memory, artifact assertions and security simulation.

W=ceil(G/64);255W triple words;6120W bytes/party offline,12240W combined.
Online actual payload=8160W plus992 bytes framing for G>0; G=0 sends nothing.
Savings over PHASE7B adapter projection=64G bytes. Input packing is included in
current PE compute; old standalone reference excluded that cost. Benchmarks are
component sums, not TCP E2E.10 warmup/50 measured, max5/20. Default workers1
because Boolean computation is about2% of total; faster packed configurations
are reported separately, without attributing shared-host D/encoding variation
to worker scaling. No standalone primitive normalization is sold as query latency.

gofmt, go test ./..., go vet ./..., go test -race -timeout=60m ./...,
native-tag vet and git diff --check PASS. PHASE5=SEALED, Compaction=COMPLETE,
Routing=COMPLETE, PSMJ=SEALED, Target Private Equality=COMPLETE.
Paper modified=NO.

## PHASE9 — Target Position Filtering

Begin bd84b29eec8911e2dc64c1118623dbb4529b3d15, clean. Anchor Position audit found
its existing interface reusable: trusted offline eta/rho and SCMP keys, initial
masked L/R+1 bounds, Ring32 reduction, real LLAMA EvalPosition with local rb
correction, followed by existing F2 Beaver layers. Target initial QueryToken
previously lacked this material; the authorized Query User API now supplies it
before Anchor, with no subsequent Query User or DO contact.

Full area_alias domain remains compatible with Bin7/Bout1: maximum position62,
indexed rune length66, query occurrence position60; 4047 short rows remain OPEN.
No sealed PSMJ or prior protocol mathematics changed. Production loads the same
hash-validated files and checks lineage and output group layout before expanding
Match shares locally across all physical slots. It evaluates Position on real
and dummy slots, then Match AND Position AND Validity, outputting secret posting
hits. Streaming chunks cap transient arrays at1024 slots and preserve physical
slot order for the next phase; no record incidence/aggregation is performed.

The original PHASE8 real replay gained optional test hooks so PHASE9 consumes
actual Target PE results, never oracle-created Match. Native boundary and sealed
composition tests cover clamping, dummy validity, unmatched groups, repeated
occurrences, one-time capacity, zero output and coherence guards. The full native
replay and benchmark evidence are in results/phase9-results.md and raw logs.
The old repository is read-only; all external builds run under /tmp. Paper NO.

PHASE9 final validation: 1003 queries, 466105 routes, 2209949 group comparisons,
9380900 physical slots, 4144 posting hits, 751 zero-hit queries, errors=0. All1003
S values match PHASE7B element-by-element. S min/p50/p90/p95/p99/max =
0/212/8032/24444/215484/764768. Native component benchmarks and ordinary/native
race checks PASS; gofmt, go test, go vet and diff checks PASS.
Target Position complete=YES; group Match and posting Hit stay secret in production.
Target Aggregation/Candidate ID Generation/final recovery remain unstarted.


## PHASE10B — Target record aggregation and candidate-pair shares

Begin HEAD33e0dd3, clean, physical/Git top-level verified exactly
`/home/tenggn/projects/clean_pmeq`. Sealed PSMJ/payload lengths and SHA256 verified
before changes; obsolete-path search empty. No alternate repository created or
used; backup and old repository not modified. Old Target aggregation/output was
an equation reference only; no old runtime/harness was copied.

Human review freezes PARTIAL REUSE: fixed join-local D26,lambda=r-tau with
0<=tau<r, Ring64 IDs, retained secret PHASE8 Match, F/z/C/Keep, fixed26K secret
pair output, no second compaction/count opening, short completeness OPEN.

Implementation reuses clean incidence and comparison equations. A separate local
coefficient decoder permits26-row matrices without changing PHASE5's power-of-two
PrepareLayout or any sealed Anchor mathematics. Ring64 uses existing additive
Beaver/B2A equations in the required ring. Original PHASE9 Output cleared its PE
input; the new single-consumption retained-Match handoff closes that interface
gap without repeating PE. The historical3x7-bit ID representation is not migrated.

Full offline sidecar generation and independent reconstruction audit cover65536
buckets,310331 groups,1317260 slots,34248760 coefficients and8068606 Ring64
payloads,0 errors. Max aliases26/max multiplicity3/short rows4047. Per-party
incidence34248760 bytes, TargetID64548848 bytes, total framed100301133 bytes.
Original PSMJ bytes/hashes remain unchanged. The own-file loader checks all
public ordered widths and paired sidecar generation binding.

Replay policy correction was explicitly approved after finding149 historical
Tau>=r_target cases: preserve historical Tau/Position, reject those149 at the
new aggregation gate, and validate pairs for854. The1003 upstream routes/slots
remain unchanged. A first integration attempt caught cleared retained Match;
that interface was fixed before the successful evidence run. No partial run is
counted as1003-query completion. All final evidence, metrics and commands are in
results/phase10b-results.md and companion raw files.

Final recovery/PHASE11 runner/PHASE12 E2E are not implemented. No plaintext shortcut,
new aggregation protocol, Target index rebuild, query-time DO or paper change.


Final hardening adds public K/S/G capacity prefixes for the same fixed r class,
with unused capacity burned by the query claim. A new PHASE5 comparison-prefix
adapter changes no comparison mathematics or existing Anchor calls. Native/race
prefix tests cover r1/r16 and K0. Both sidecar-generation hashes bind the online
transcript, and both declared sidecar lengths must match the sealed dimensions.
After these additions the final source was frozen and the complete real replay
and representative benchmarks rerun; preliminary runs are not added to the1003
query count. The normal build's GoFiles explicitly exclude phase10audit hooks.


Memory-evidence correction: the replay's frame-size sampling threshold leaves
small queries unsampled; zero Heap entries are explicitly missing observations,
not zero memory. Supplemental native small/mean representatives sample before
and after each invocation as well. The report separates replay sampling coverage
from unconditional representative measurements. The mean-S representative is
chosen from actual accepted historical queries, never a synthetic K/r product.

Final metadata hardening pins LoadSidecar to the exact manifest digest retained
by the actual PHASE8 PartyIndex. The negative regression changes manifest bytes
while preserving IndexID and parsed semantics; it is rejected before sidecar I/O.
The positive regression loads all buckets of the existing own-party artifact.
This final guard does not change the replay/benchmark algebra, data or timers;
those runs used the same verified manifest bytes. Ordinary/native/race/vet checks
are rerun on this final source; full replay and benchmark evidence precede only
this metadata guard.

Final gates PASS: gofmt, go test ./..., go vet ./..., full
go test -race -timeout=60m ./..., native aggregation race tests and integration-tag
vet, git diff --check and empty obsolete-path git grep. Full replay is1003
upstream/149 threshold rejections/854 pair validations,1510 oracle pairs;
false positives/false negatives/duplicates/wrong AnchorID/wrong TargetID all0.
Target Aggregation complete=YES; Candidate ID Generation complete=YES.
Final pair count and Target IDs opened to clouds=NO. Final recovery=no.
