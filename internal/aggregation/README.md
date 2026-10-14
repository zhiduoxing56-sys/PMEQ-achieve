# Anchor record aggregation

`internal/incidence` is unchanged: F2 hits -> Z128 B2A -> scalar-vector Beaver
-> local F. This package continues F -> F2 z -> Z128 z -> hidden permutation
-> local C -> F2 Keep -> aligned payload. Z128 means Z/128Z. Anchor bits=16.

Offline DO APIs: GeneratePayload fixes LayoutID/gamma and directly shares each
raw record's ID/KJoin/JoinBucket once. Existing incidence.PrepareLayout and
ShareIncidence fix local coordinates and A. DealerLayout.Alignment embeds
these coordinates, completes pi and splits rhoSeed/sigma. Neither cloud gets the
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
rhoSeed/sigma may be reused, but correlated a/b/c vectors may not. Future
compaction/selection must rerandomize static payload before external release.
Posting routing fields are never consumed by aggregation.

Both-party payload accounting, N=120071, Dsum=sum D_h, P=sum D_h*T_h,
Tsum=sum T_h, r query occurrences:

- static A: 2P bytes for accessed invocations (deduplicate for static reuse);
  rhoSeed/sigma: (32+4N)r factor bytes; global payload: 96N bytes
  including Go struct padding, 84N logical field bytes.
- one-time Beaver: 4P+8Tsum+6Dsum; permutation correlations: 6Nr.
- external SCMP codec: 284 bytes/key/party; including input-mask shares and
  user bound masks: 570(Dsum+N)+(r+1) offline bytes.
- online: 2P+6Tsum+6Dsum+2Nr+2N+2(r+1), including a masked threshold byte sent
  to each cloud per batch. These are protocol payload counts, not measured
  TCP traffic or an implemented persistent format.

The offline pool may provision selected buckets before a query. Tests simulate
this lifecycle in a trusted coordinator and exclude dealer work from online
timings. No online method uses dealer mapping or raw records. Stage0 has only
LayoutID/BucketID/rhoSeed[32], Stage1 LayoutID/BucketID/sigma[]uint32. Seed
expansion uses AES-256-CTR, fixed IV "PMEQ-RHO-PRG-V1!", LE32 words and unbiased
descending Fisher-Yates. The seed is CS0-local, not shared. ExpandedStage0 is
invocation-local scratch. Existing Message2 lazily expands automatically; an
explicit Expand separates expansion timing from online masked scatter.

All 53383 buckets require 1708256 CS0 seed bytes and 25639000772 CS1 sigma
bytes: 25640709028 total versus 102556003088 before. No eager full-table RAM
claim or persistence is made. All permutation coordinates, including DO pi/gamma,
are uint32; int is used only for lengths/loop/slice indexing.

PoolConfig.PreprocessingPoolSize=Q_pool has no default/frozen value. PartyPool
is the one-use lifecycle registry: offline Provision -> Seal -> online Consume;
unknown/repeated IDs or online refill fail. It is not a material serializer;
actual correlated packets remain party-local typed objects. One packet covers
one complete query, including r sub-invocations and final Keep. For equal packet
capacity, PoolStorage=Q_pool*S_offline; heterogeneous packets sum their sizes.
OfflineShape computes aggregation material only; add PHASE4 offline material
separately if the larger pool covers filtering too. Current Keep is SCMP and
has no additional Keep Beaver triples. Static state never enters pool accounting.
Exhaustion requires another offline epoch; unlimited queries are not promised.

Full test: PMEQ_AGG_FULL=1 go test ./internal/aggregation -v -timeout=30m.
PMEQ_AGG_ONLY_BENCH=1 skips the 1000 random queries, retaining the three actual
workload-quantile queries. Native SCMP is measured separately; sums of these
measurements are not monolithic E2E timings.
