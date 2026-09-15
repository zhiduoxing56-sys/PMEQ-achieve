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
