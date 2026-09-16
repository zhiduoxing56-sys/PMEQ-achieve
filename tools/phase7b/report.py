#!/usr/bin/env python3
"""Render trusted experiment outputs; never used by either cloud runtime."""
import csv,gzip,json,math,re,statistics,sys
from pathlib import Path
root=Path(sys.argv[1]); results=root/'results'; results.mkdir(exist_ok=True)
layouts=json.loads(Path(sys.argv[2]).read_text())
loads=json.loads(Path(sys.argv[3]).read_text())
artifact=Path(sys.argv[4])
pe=[json.loads(x) for x in Path(sys.argv[5]).read_text().splitlines()]
assert len(pe)==5 and all(x['errors']==0 and x['bits']==256 and x['equalities']==100000 for x in pe)
report=json.loads((artifact/'build-audit.json').read_text())
route=json.loads((artifact/'route-audit.json').read_text())
assert route['Queries']==1003 and route['Routes']==466105 and route['Errors']==0
manifest=json.loads((artifact/'manifest.json').read_text())
assert manifest['TargetBucketBits']==16
ps=[0,.5,.9,.95,.99,1]
def dist(a):
 a=sorted(a);return [a[0] if p==0 else a[math.ceil(len(a)*p)-1] for p in ps]
def cells(a):return ' | '.join(f'{x:.4f}' if isinstance(x,float) else str(x) for x in a)
def table(cols,rows):return '| '+' | '.join(cols)+' |\n| '+' | '.join(['---']*len(cols))+' |\n'+''.join('| '+cells(row)+' |\n' for row in rows)
bucketrows=[];storagerows=[];loadrows=[];projectionrows=[];shortrows=[]
for layout,row in zip(layouts,loads):
 k=layout['Bits'];assert k==row['Bits'];b=layout['Buckets'];q=row['Queries'];assert len(q)==1003 and sum(x['Routes'] for x in q)==466105
 for field in ['Groups','Slots','Joins']:
  bucketrows.append([k,field,*dist([x[field] for x in b])])
 for field in ['Routes','GroupComparisons','TouchedSlots','DistinctBuckets','Reuse']:
  loadrows.append([k,field,*dist([x[field] for x in q]),sum(x[field] for x in q)])
 nonempty=sum(x['Groups']>0 for x in b);size=70+14*nonempty+36*310331+13*1317260
 storagerows.append([k,1<<k,nonempty,310331,480945,1317260,836315,1317260/480945,70+14*nonempty,size,size])
 for field,fun in [
  ('PE_AND_tree_online_bytes',lambda x:8160*math.ceil(x['GroupComparisons']/64) if x['GroupComparisons'] else 0),
  ('PE_Option4_input_share_bytes',lambda x:64*x['GroupComparisons']),
  ('PE_total_online_bytes',lambda x:8160*math.ceil(x['GroupComparisons']/64)+64*x['GroupComparisons'] if x['GroupComparisons'] else 0),
  ('Position_SCMP_local_ms',lambda x:x['TouchedSlots']*70.615/116991),
  ('Position_SCMP_keys_bytes_both',lambda x:1136*x['TouchedSlots']),
  ('Position_masked_open_bytes_both',lambda x:4*(x['TouchedSlots']+x['Routes']))]:
  d=dist([fun(x) for x in q]);projectionrows.append([k,field,d[1],d[3],d[4]])
 g=dist([x['GroupComparisons'] for x in q]);s=dist([x['TouchedSlots'] for x in q]);shortrows.append([k,g[1],g[3],g[4],s[1],s[3],s[4]])
with (results/'phase7b-query-loads.csv').open('w') as f:
 w=csv.writer(f,lineterminator="\n");w.writerow(['TargetBucketBits',*loads[0]['Queries'][0].keys()]);
 for row in loads:
  for q in row['Queries']:w.writerow([row['Bits'],*q.values()])
for name,cols,rows in [
 ('buckets',['bits','field','min','p50','p90','p95','p99','max'],bucketrows),
 ('storage',['bits','B','nonempty','groups','real','padded','dummy','padding_ratio','header_bytes','CS0_bytes','CS1_bytes'],storagerows),
 ('query-summary',['bits','field','min','p50','p90','p95','p99','max','sum'],loadrows),
 ('projections',['bits','field','p50','p95','p99'],projectionrows)]:
 with (results/f'phase7b-{name}.csv').open('w') as f:
  w=csv.writer(f,lineterminator="\n");w.writerow(cols);w.writerows(rows)

rate=statistics.median(sum(x['party_compute_ns']) for x in pe)/100000
q15=loads[4]['Queries'];q16=loads[5]['Queries']
gains={field:[1-dist([x[field] for x in q16])[i]/dist([x[field] for x in q15])[i] for i in [3,4]] for field in ['GroupComparisons','TouchedSlots']}
assert all(x>.3 for v in gains.values() for x in v) # evidence-driven recommendation guard
text='''# PHASE 7B — final Target layout and materialization

Begin HEAD: `3afa024328d60d86396c97ebfa3947e3a8daf3ba`, clean.
This report belongs to the single `phase 7: finalize target index layout` commit.
Old repository read only. Paper modified=NO.

## Workload provenance and scope

PHASE7 saved aggregate logs, **not a 1003-query detailed trace**. PHASE7B restored
its deterministic query definitions by replaying the SAME native complete chain:
seed502 normal Anchor selection/tau, seed707 alias catalog, the same positive,
negative and repeated-occurrence selection, and the same three workload queries.
This is a fresh full-chain replay, not a recovered original cryptographic transcript:
CompactionIDs and candidate order are freshly randomized. The saved test-only
`phase7b-workload.jsonl.gz` records actual replay compaction outputs in their order,
Anchor string/tau, Target string, occurrences and candidate join values. It must
NEVER be deployed to either cloud. No independent percentile product is used.
All 1003 queries, 466105 routes, 248 positives, 755 negatives, 59 repeated queries
and 2554 present-group pairs match PHASE7 aggregate evidence exactly.

Six layouts use the same PHASE7 test k_T, same 310331 logical groups and unchanged
clean builder tier logic. Target widths are independent of Anchor bits=16.
The sweep uses buildLogical ONCE, recalculates each bucket through canonical APIs,
and runs the current tier metadata builder for every width. It does not allocate
six sets of fresh party shares; the selected final layout is fully materialized.

## Bucket statistics

Quantiles throughout are nearest rank ceil(p*n), with min/max explicit.
Bucket quantiles include ALL B buckets, including empty buckets. `Joins` is the
number of distinct join values in that bucket, computed inside the trusted audit.

'''
text+=table(['bits','field','min','p50','p90','p95','p99','max'],bucketrows)
text+='\n## Actual joint query workloads\n\nEvery occurrence and every candidate contributes independently, including repeated\nbucket accesses. `DistinctBuckets` counts accessed IDs, including an empty bucket.\n`Reuse=Routes/DistinctBuckets`. The sum of distinct counts is per-query summed,\nnot a global deduplicated count; sum of reuse factors is descriptive only.\n\n'
text+=table(['bits','field','min','p50','p90','p95','p99','max','sum'],loadrows)
text+='\nBucket data may be cached on repeated access, but a different route has a different\nprivate comparison input. Cache reuse cannot eliminate its equality evaluations.\n\n## Static storage and leakage\n\n'
text+=table(['bits','B','nonempty','groups','real','padded','dummy','padding ratio','header bytes/party','CS0 bytes','CS1 bytes'],storagerows)
text+='''
Index binary v1 has a 70-byte fixed header, 14 bytes per NONEMPTY bucket,
36 bytes per group (local point32 + PadWidth4), and 13 bytes per padded slot
(Ring64 ID8 + Ring32 position4 + F2 validity1). The exact file size is
`70 + 14*nonempty + 36*groups + 13*slots`; public JSON manifests are separate.
A sparse directory is used; empty bucket headers are not serialized.
Each party's layout has identical size. All six rows use the same concrete v1
encoding formula; final k=16 lengths are measured and round-tripped on disk.
The six layouts are NOT all claimed to have been serialized/materialized.

k14→k15 adds 229334 bytes/party; k15→k16 adds 449918 bytes/party.
k14→k16 adds **679252 bytes/party, 1358504 bytes for both (1.296 MiB)**.
Padding ratio is padded/real=2.738899; dummy/real=1.738899 (173.8899% overhead).
The public bucket ID reveals respectively 8/10/12/14/15/16 bits of keyed access
pattern. Larger widths distinguish finer buckets. This states the leakage;
it does not assign an abstract privacy value to the additional bits.

## PE projection boundary

**PROJECTED FROM VALIDATED PE BENCHMARK — NOT INTEGRATED MEASUREMENT.**
The old standalone `boolean_equality_audit` was already available under /tmp;
its source hash matches the read-only old source:
`1eefbb407b9e1cfdaa5e9ac6553f3bd3d69957c2f9ec76d52424020a6f33357d`.
Five reruns at 256 bits, 100000 comparisons, one worker/party, all errors=0.
It has 255 AND gates and 8 Boolean rounds. Raw outputs are saved in
`phase7b-pe-reference.jsonl`. No PE source or runtime was migrated.
'''
text+=f'\nMedian both-party local work normalized by batch size: **{rate:.6f} ns/comparison**.\n'
text+='''This is a normalization of a single batch size, not a proven linear latency model.
Therefore **query PE compute latency is deliberately not extrapolated**.
Option4 point subtraction/canonical encoding, routing, input sharing, network
latency, and memory effects are not included in that local primitive number.

For the explicit hypothetical policy of ONE bit-sliced batch per query, with G
comparisons, Boolean openings send `8160*ceil(G/64)` bytes in both directions.
The future private-input share adapter adds `64*G` bytes. The benchmark's 100000
comparison tree sent 12754080 bytes total; the adapter is separate. The projection
table gives both parts and their sum. Different per-bucket batching changes the
rounding overhead. These are projected wire payloads, not current routing traffic.

## Position projection boundary

**PROJECTION FROM EXISTING REAL LLAMA BENCHMARK — NOT INTEGRATED MEASUREMENT.**
Read-only `results/target_position_real_benchmark.csv`: Villesse, workers=1,
30 runs, skip_invalid=0, slots=116991, SCMP evals=233982, errors=0,
`pos_scmp_ms=70.615`. Source merge uses max(CS0,CS1) local duration; normalization
is 0.603593 us/slot (two comparisons), not the sum of the two servers.
This projects only local interval SCMP work, not a completed Target Position
Filter or its Boolean conjunctions. Historical smaller cases have different
normalized rates, so the estimate is a workload sizing model, not a latency promise.

Current verified Bin7/Bout1 key material is 284 bytes/comparison/party
(also preserved from PHASE5 native component evidence). Two bounds give
568 bytes/slot/party, 1136 bytes/slot for both. For independent masked lower/upper
positions and one threshold pair per route, compact 7-bit-as-byte openings are
`4*(S+R)` bytes both directions (S=touched slots, R=routes), excluding framing.
The threshold-sharing/batching policy is an explicit projection assumption;
no Target opening codec or Position runtime is implemented this phase.

'''
text+=table(['bits','projected quantity','p50','p95','p99'],projectionrows)
text+='\n## Recommendation\n\n**RECOMMENDED TargetBucketBits=16, B=65536.**\n\n'
text+=table(['bits','G p50','G p95','G p99','S p50','S p95','S p99'],shortrows)
text+=f"\nk15→k16 reduces query p95/p99 GroupComparisons by {gains['GroupComparisons'][0]:.2%}/{gains['GroupComparisons'][1]:.2%}, and TouchedSlots by {gains['TouchedSlots'][0]:.2%}/{gains['TouchedSlots'][1]:.2%}.\n"
text+='''The primitive work/communication and Position sizing projections fall accordingly,
while total extra index data is only 899836 bytes for both parties. It reveals
one additional bucket-ID bit relative to k15. This meets the requested selection
rule. No width above16 was examined.

## Final materialization, integrity and reconstruction

'''
text+=f"Logical build+crypto: **{report['BuildStats']['LogicalBuildTime']/1e9:.6f}s**; sharing/padding: **{report['BuildStats']['SharingPadTime']/1e9:.6f}s**; in-memory Build: **{report['BuildWallSeconds']:.6f}s**.\n\n"
text+=f"Build sampled heap peak (10ms): **{report['BuildHeapPeakSampled10ms']} bytes**.\n"
status=report['BuildProcStatus']
for label in ['VmHWM','VmRSS','VmSwap']:
 text+=f"Build-end {label}: **{re.search(r'^'+label+r':\s*(.*)$',status,re.M)[1]}**.\n"
text+=f"\nBuild plus file encoding, full byte-for-byte codec roundtrip and manifest write: **{report['MaterializeAndEncodeSeconds']:.6f}s**; this explicitly includes codec validation work.\n"
text+='''The /usr/bin/time log additionally reports the whole test process RSS, including
later trusted oracle validation, separately from the build-end high-water above.
No process swaps were reported. These measurements ran alongside the necessary
native workload replay, not on an isolated idle host.

All 310331 group points and all 480945 real + 836315 dummy slots reconstructed
correctly. Additionally sampled WITHOUT replacement 10000 real slots, 10000 dummy
slots and 10000 groups; all passed. Every group's stored bucket was independently
checked through canonical KBucketJoin XOR KBucketWord; maximum real group=16.
The tier ladder remains 4/16/64/256/1024/4096/8192/16384; only4 and16 are used.
The exact party schema allow-list and full binary roundtrip passed. Party files
contain only local shares, PadWidth and public bucket metadata, never plaintext
join IDs, qgrams, full T, or peer shares.

Final artifact directory: `artifacts/phase7b/`. Public manifest contains IndexID,
version1, Q4, independent Anchor/Target widths, all8 tiers, dimensions, file
lengths and SHA256 digests. Large .bin files are present locally and git-ignored;
manifests, hashes, experiment code and audit evidence are committed.
Each cloud receives ONLY its respective cs0/cs1 file, never the whole directory.

`BuildFinalTarget` has no width argument. `targetrouting.LoadIndex` loads and
validates the final manifest into an opaque BoundIndex; its Prepare method uses
that bound width, rejecting old8-bit token/payload bindings. Generic Build and
routing primitives remain available for historical controlled experiments.
No caller-selectable width is accepted by the final artifact entry points.

120071 global payload tuples were freshly provisioned through the existing
PHASE5 GeneratePayload API at the final width. Every reconstructed KJoin and
BucketJoin was audited; KJoin's definition is unchanged. Their v1 codec uses
46 header bytes +42N=5043028 bytes/party; LayoutID and IndexID are bound in the
header, with separate payload-manifest hashes. This is a NEW offline LayoutID;
it must be provisioned with its matching PHASE5 alignment using the existing
DealerLayout mechanism, and must never be attached to old Keep/gamma state.
No previously persisted PHASE5 alignment was available or relabelled, and no
PHASE5 online protocol was modified. The audit regenerates and validates this
payload material, not a full persistent Anchor alignment artifact.

The 1003-query final regression selects these shares in the saved replay's
candidate order, retains its CompactionID association, generates final-width user
tokens, and executes the unchanged party-local routing and bucket opening.
All **466105 routes** pass bucket/Y/share association oracles; the **2554** pairs
whose group exists point to the actual materialized bucket. Absent groups are
checked as negative routes, not incorrectly claimed to exist in the index.
K=0 and wrong-width rejection also pass. Full Y/T reconstruction occurs ONLY
inside the trusted test oracle; neither production party reconstructs either.

## Gates and frozen status

`gofmt`, `go test ./...`, `go vet ./...`, `git diff --check`: PASS.
Additional race tests for indexbuild/targetartifact/targetrouting: PASS.
No production concurrency was added; the memory sampler is test-only.
The four engineering documents are updated. Paper modified=NO.

TargetBucketBits=16; Target B final choice=FROZEN; PSMJ=SEALED.
PHASE5=SEALED; Candidate Compaction=COMPLETE; Private Routing=COMPLETE.
Target Private Equality/Position/Aggregation started=no.
'''
(results/'phase7b-results.md').write_text(text)
print(table(['bits','G p50','G p95','G p99','S p50','S p95','S p99'],shortrows))
