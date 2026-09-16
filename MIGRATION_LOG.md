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
