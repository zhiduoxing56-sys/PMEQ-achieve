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
