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
