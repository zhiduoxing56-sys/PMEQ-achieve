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
