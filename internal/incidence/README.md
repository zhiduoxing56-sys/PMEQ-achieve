# Hidden incidence component

This package implements only `F2 posting hit -> Z128 hit -> local-record F`.
`Z128` is Z/128Z. `PrepareLayout`, `ShareIncidence`, `Preprocess`, and `Split`
are trusted offline functions using crypto/rand. No Rust dependencies are used.

Each cloud separately calls BeginB2A/Finish, then NewAggregator with a public
chunk-size limit, BeginChunk/FinishChunk, and Result. OpenMasked models the
single batch exchange for each multiplication layer/chunk; its arguments are
masked messages only. Production online methods never take both parties'
input, coefficient, or triple shares. One-time preprocessing must be delivered
before online execution. The experiment generates it just before timing each
chunk and excludes that generation from the online component sum.

For one posting, open d=x-a and e=A[:,s]-b. Party 0 produces
`c0+d*b0+e*a0+d*e`; party 1 produces `c1+d*b1+e*a1`. Their sum is x*A[:,s].
Sum these products directly into F. Dummy columns reconstruct to zero; repeat
postings contribute separately to the same coordinate. Counts are modulo 128;
integer interpretations require a bound below 128.

Let P=D*T. Byte counts below are payload bytes, both parties combined:

- static A: 2P;
- one-time B2A triples: 6T;
- one-time vector triples: 2T+4P;
- online B2A opening: 4T;
- online vector openings: 2T+2P.

Total x->F traffic is 6T+2P, with one B2A opening plus ceil(T/chunk) vector
openings. No serialization/RPC framing is implemented. Only O(chunk*D) live
vector triples/opening buffers are needed; F has D entries and static A has P.
No DT scalar-triple objects or DT intermediate products are allocated.

Legacy references (algorithm reuse; zero old source lines copied):
`ring_beaver::b2a_z128_party`, `bucket::aggregate_shared`,
`beaver::mul_shared_scalar_vectors`, `update::shared_update`.
The old `PartyRingBigStatePreGen.u` posting adapter, plaintext_u,
support_index, and full StaticPerm are not migrated.

Run `PMEQ_INCIDENCE_EXPERIMENT=1 go test ./internal/indexbuild
-run '^TestFullIncidenceExperiment$' -count=1 -timeout=20m -v` for the full raw
MusicBrainz query scan, 1000 trials per selected real bucket, and chunk sweep.
Bucket percentiles are selected by physical T, ties by BucketID; D is measured
for that actual bucket, not inferred from an independent percentile. Each
benchmark uses 10 warmups and 50 measured invocations with fresh triples.
Times are sums of measured online local stages for BOTH clouds and in-memory
masked openings, excluding offline generation and plaintext verification.
They are not network/two-process end-to-end latency. Heap samples include
trusted raw/logical data and GC retention; they are not party-only live storage.
