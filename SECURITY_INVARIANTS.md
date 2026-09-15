# PMEQ Security Invariants

## Single-party security boundary

Neither cloud acting alone may obtain:

- plaintext searchable value;
- plaintext record ID;
- plaintext Position;
- JoinID;
- complete kappa;
- complete Target stored group key;
- posting-to-record correspondence;
- gamma;
- complete permutation;
- the other party's share;
- final candidate identity.

The following are prohibited:

- query-time raw DB access;
- query-time production oracle access;
- plaintext candidate shortcuts;
- plaintext Posting production storage.

## Frozen permitted leakage

Only the following leakage is currently permitted:

- public system parameters;
- `L_pad`;
- K from exact-K compaction.

No other leakage may be treated as permitted unless it is explicitly frozen by a reviewed specification decision.

## Required stage audits

**Correctness PASS does not imply security PASS.**

Every production stage must separately pass:

1. correctness test;
2. single-party API/state/view audit.

At minimum, the single-party audit must examine:

- function parameters;
- return values;
- local persistent state;
- local temporary state;
- logs;
- debug output;
- serialized files;
- caches;
- index schema;
- message transcript;
- length information;
- explicit identifiers;
- derivable correspondence.

If any item permits CS0 or CS1 acting alone to recover prohibited information, the stage is a **security FAIL**.

## Authorized reconstruction boundary

The foundational `internal/reconstruct` package is an explicit authorized
reconstruction boundary. A share type must not provide its own reconstruction
method. Once a CS-facing package exists, it must not import
`internal/reconstruct`; this import boundary is part of every subsequent
single-party API/state/view audit.

## DPF role and package boundaries

The 128-bit Anchor DPF evaluation boundary accepts one cloud's opaque `Key` and
one public `Point` and returns only that cloud's `share.BitShare`. A cloud object
must not hold the query alpha, the peer key, or the peer root seed.

`internal/dpf128/internal/core` is a compiler-enforced nested Go `internal`
boundary: packages outside the `internal/dpf128` subtree cannot import its key
constructors or protocol fields. `internal/dpf128/gen` is different: it is a
policy-separated trusted generator package, not a compiler-enforced cloud
boundary. Every future CS-facing package is forbidden from importing
`pmeq/internal/dpf128/gen`; this rule must be enforced by import-graph regression
tests when such a package is introduced.

The DPF key has no wire encoding in PHASE 2D. Production code must not log or
format its root seed, correction words, or final correction bit. Passing the
structural party-view audit is not a proof of the underlying DPF security,
which additionally relies on the stated AES-based PRG assumption and on CS0
and CS1 remaining non-colluding.

## Target routing boundary (PHASE 3B)

**Target stored representation.** The Target stored group key is the additive
Ristretto255 point share pair `T = T0 + T1`. Each party's production state holds
only its own canonical 32-byte encoding. `Enc(T0) XOR Enc(T1)` has no protocol
meaning.

The following are prohibited in production:

- reconstructing, opening, revealing, combining, or reserializing a full target
  point or a full target scalar;
- any exported `Recover*`, `Open*`, `Reveal*`, `Peer*`, or `Secret*` entry point
  on a share type;
- exposing `Enc(Y0 - T0)` or `Enc(T1 - Y1)` outside the party that computed it
  before the PHASE 8 equality protocol consumes it;
- public, unkeyed derivation of a Target join or q-gram value.

**Master key boundary.** `k_T` is a 256-bit secret held only by the DO and an
authorized Query User. The `targetcrypto.MasterKey` type deliberately offers no
serialization, no formatting method, and no logging surface. The all-zero value
is rejected so that an unset key cannot silently reach production. `k_T` is used
only as an HMAC key; it is never a plain hash message field.

**Trusted build boundary.** `DeriveTargetGroupPoint` returns a complete group
point and is therefore a trusted data-owner build-time helper. A future
cloud-facing package must not import it, must not import `MasterKey`, and must
not import `FullEval`. This must be enforced by an import-graph regression test
when the first cloud-facing package is introduced.

**Fresh sharing per posting occurrence.** A record's `kappa_J` and its `beta_J`
secret are the same plaintext secret in every posting occurrence of that record.
Nevertheless, every posting occurrence must obtain a **fresh, independently
sampled** party-local share of each of them. Reusing a party-local share across
occurrences is a **SECURITY FAIL**: a single cloud would recover the
posting-to-record correspondence from share equality alone. This rule binds
PHASE 3C IndexOutsource and is not satisfied by sampling once per record.

**Query-time rerandomization.** Selected `kappa_J` and `beta_J` shares must be
rerandomized per query before they are consumed:

```text
kappa'_J0 = kappa_J0 + rho ,  kappa'_J1 = kappa_J1 - rho        (Z_l)
beta'_J0  = beta_J0 XOR rho_b , beta'_J1 = beta_J1 XOR rho_b    (F_2^k)
```

with fresh `rho` / `rho_b` per query and per candidate. Without this, a cloud
can link the same candidate across queries by local-share equality. A secure
shuffle does **not** provide this automatically; PHASE 6 compaction and PHASE 7
selection must each state explicitly that they rerandomize.

**Structural policy.** Production share types are plain value types, not
structs, so that no share type can grow a second party's state. The package
`internal/targetcrypto` declares no production struct type and holds no
third-party dependency beyond the Ristretto255 implementation.
