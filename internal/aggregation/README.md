# Anchor record aggregation

`internal/incidence` is unchanged: F2 hits -> Z128 B2A -> scalar-vector Beaver
-> local F. This package continues F -> F2 z -> Z128 z -> hidden permutation
-> local C -> F2 Keep -> aligned payload. Z128 means Z/128Z. Anchor bits=16.

Offline DO APIs: GeneratePayload fixes LayoutID/gamma and directly shares each
raw record's ID/KJoin/JoinBucket once. Existing incidence.PrepareLayout and
ShareIncidence fix local coordinates and A. DealerLayout.Alignment embeds
these coordinates, completes pi and splits rho/sigma. Neither cloud gets the
DealerLayout. PreprocessPermutation/PreprocessComparison create one-use
packets. The authorized user, not clouds, receives BoundMask.

Online APIs are single-party: ComparisonParty.Prepare/Finish, PermPrep1.Message1,
Stage0.Message2, Stage1.Finish, CountParty.Add, AlignOutput. Opening helpers
combine only masked messages. Comparison uses the external LLAMA SCMPBackend,
Bin=7/Bout=1; raw eval output has key.rb removed. F threshold=1; Keep threshold
lambda=r-tau with 1<=r<=14 and 0<=tau<r. The reference backend exists ONLY in
`_test.go`, is unsafe for cloud use, and is not performance evidence.

z is B2A-converted before alignment: 4D bytes rather than converting N_global
entries afterwards. The reused old permutation is arithmetic Z128. Static
rho/sigma may be reused, but correlated a/b/c vectors may not. Future
compaction/selection must rerandomize static payload before external release.
Posting routing fields are never consumed by aggregation.

Both-party payload accounting, N=120071, Dsum=sum D_h, P=sum D_h*T_h,
Tsum=sum T_h, r query occurrences:

- static A: 2P bytes for accessed invocations (deduplicate for static reuse);
  rho/sigma: 16Nr bytes on this 64-bit runtime; global payload: 96N bytes
  including Go struct padding, 84N logical field bytes.
- one-time Beaver: 4P+8Tsum+6Dsum; permutation correlations: 6Nr.
- external SCMP codec: 284 bytes/key/party; including input-mask shares and
  user bound masks: 570(Dsum+N)+(r+1) offline bytes.
- online: 2P+6Tsum+6Dsum+2Nr+2N+2(r+1), including a masked threshold byte sent
  to each cloud per batch. These are protocol payload counts, not measured
  TCP traffic or an implemented persistent format.

The offline pool may provision selected buckets before a query. Tests simulate
this lifecycle in a trusted coordinator and exclude dealer work from online
timings. No online method uses dealer mapping or raw records. Eager full
rho/sigma arrays for all 53383 buckets would be 102556003088 bytes; this pool
is not materialized. This is a storage limit, not hidden by per-query timings.

Full test: PMEQ_AGG_FULL=1 go test ./internal/aggregation -v -timeout=30m.
PMEQ_AGG_ONLY_BENCH=1 skips the 1000 random queries, retaining the three actual
workload-quantile queries. Native SCMP is measured separately; sums of these
measurements are not monolithic E2E timings.
