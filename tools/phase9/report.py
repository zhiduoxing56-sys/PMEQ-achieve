"""Render actual PHASE9 native replay/measurement logs; fail on incomplete gates."""
import csv, gzip, json, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
real = pathlib.Path('/tmp/phase9-real-final.log').read_text()
bench = pathlib.Path('/tmp/phase9-bench-final.log').read_text()
for name in ['real-final', 'bench-final', 'go-test', 'race']:
    raw = pathlib.Path('/tmp/phase9-'+name+'.log').read_text()
    assert 'FAIL' not in raw and ('PASS' in raw or 'ok  ' in raw), name
assert 'Exit status: 0' in real and 'Exit status: 0' in bench
full_rss = int(re.search(r'Maximum resident set size \(kbytes\): (\d+)', real)[1])
line = next(l for l in real.splitlines() if 'TARGET_POSITION queries=' in l)
values = dict(re.findall(r'(\w+)=(\d+)', line))
counts = json.loads(pathlib.Path('/tmp/phase9-counts.json').read_text())
loads = next(x['Queries'] for x in json.load(gzip.open(root/'results/phase7b-loads.json.gz')) if x['Bits']==16)
assert counts == [x['TouchedSlots'] for x in loads]
assert int(values['queries']) == 1003 and int(values['routes']) == 466105
assert int(values['groups']) == 2209949 and int(values['physical_slots']) == sum(counts)
assert int(values['errors']) == 0
qs = [json.loads(l) for l in gzip.open(root/'results/phase7b-workload.jsonl.gz')]
repeated = sum(len(set(w['QGram'] for w in q['Words'])) < len(q['Words']) for q in qs)
rows = []
pattern = r'POSITION_BENCH S=(\d+) warmup=(\d+) measured=(\d+) p50_ms=\[([^]]+)\] p95_ms=\[([^]]+)\] (.*)'
for match in re.finditer(pattern, bench):
    s,w,n,med,hi,rest=match.groups()
    row = {'S':int(s),'warmup':int(w),'measured':int(n)}
    row.update({k:int(v) for k,v in re.findall(r'(\w+)=(\d+)',rest)})
    for k,m,h in zip('ABCDEFG',med.split(),hi.split()):
        row[k+'_p50']=float(m);row[k+'_p95']=float(h)
    qi=counts.index(row['S']);row['query']=qi;row['r']=len(qs[qi]['Words'])
    row['RSS_KiB']=int(re.search(r'POSITION_MEMORY S='+s+r' VmRSS:\s+(\d+)',bench)[1])
    row['HWM_KiB']=int(re.search(r'POSITION_MEMORY S='+s+r' VmHWM:\s+(\d+)',bench)[1])
    assert row['scmp_offline_party']==578*row['S'] and row['beaver_offline_party']==6*row['S']
    assert row['online_scmp']==16*row['S'] and row['online_and']==8*row['S']
    rows.append(row)
assert len(rows)==4
with (root/'results/phase9-bench.csv').open('w') as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator='\n');w.writeheader();w.writerows(rows)
(root/'results/phase9-query-slots.json').write_text(json.dumps(counts)+'\n')
def table(headers, data):
    return '\n'.join(['| '+' | '.join(headers)+' |','| '+' | '.join(['---']*len(headers))+' |']+['| '+' | '.join(map(str,r))+' |' for r in data])
timings=table(['S']+[k+' ms p50/p95' for k in 'ABCDEFG'],[[r['S']]+[f"{r[k+'_p50']:.3f}/{r[k+'_p95']:.3f}" for k in 'ABCDEFG'] for r in rows])
bytes_table=table(['S','r','SCMP/party','Beaver/party','body both','SCMP online both','AND online both','framing both','total online'],[[r['S'],r['r'],r['scmp_offline_party'],r['beaver_offline_party'],1168*r['S'],r['online_scmp'],r['online_and'],r['framing'],24*r['S']+r['framing']] for r in rows])
memory=table(['S','HitShares both bytes','sampled heap delta bytes','RSS KiB','HWM KiB'],[[r['S'],2*r['S'],r['heap_delta'],r['RSS_KiB'],r['HWM_KiB']] for r in rows])
ordered=sorted(counts)
pct=lambda p:ordered[(len(ordered)*p+99)//100-1]
dist=table(['quantity','min','p50','p90','p95','p99','max'],[[name]+[scale*x for x in [ordered[0],pct(50),pct(90),pct(95),pct(99),ordered[-1]]] for name,scale in [('S',1),('SCMP comparisons',2),('F2 ANDs',2)]])
report=f'''# PHASE9 — Target Position Filtering

Begin HEAD `bd84b29eec8911e2dc64c1118623dbb4529b3d15`, clean.
One authorized commit: `phase 9: add target position filtering`.
Old repository read-only. PHASE7B sealed files and all mathematical/index
parameters unchanged. No paper file changed.

## PHASE4 reuse audit

Anchor Position reusable=YES. QueryToken extension=YES.
The traced chain is anchorquery.MakeOccurrence -> UserPreprocessing.ConsumeBounds
-> PartyQuery masked bounds; trusted anchorfilter.Preprocess -> per-party rho,
Lower/Upper opaque SCMP keys and rb; ReducePosition -> masked p+rho opening ->
anchorfilter.EvalPosition -> local rb removal -> interval XOR -> F2 Beaver.
The Anchor ComposeHits coordinator calls Match AND Validity then AND Position;
Target uses the specified equivalent association Match AND Position then AND
Validity. Both use the existing f2beaver Mask/Finish and its sole party0 d&e term.
The helper BatchAND itself is a trusted harness that creates triples, so production
Target uses preallocated PartyBatch slices and party-local calls instead.

Target calls the SAME PHASE4 EvalPosition, not a reimplemented comparator or rb
formula. The timed backend only delegates Eval to existing scmpnative.Backend.
The C++ bridge and LLAMA source are unchanged. The active bridge calls
phase6_keygen/keyGenSCMP, with sysRandomSeed initialization; rho/eta and Beaver
material use Go crypto/rand. Historical seeded test wrappers are not this path.
Ordinary unit tests label their
insecure oracle comparator explicitly; it is never used in native performance
or the complete real replay.

## Initial token and offline lifecycle

QueryToken retains Manifest/QueryID/Party/Words. It adds Position[r], with each
PositionToken = PID[16], Ltilde(uint32), RplusTilde(uint32). OccurrenceID/Position
remain the already public PHASE7 occurrence fields. No tau, unmasked bound,
qgram, query string, kT or peer share is added. Query User holds per-occurrence
UserPreprocessing(PID,eta_L,eta_R), masks bounds before Anchor starts, then offline.

Each party's one-time Q_pool occurrence has PID, Bin7, rho_L/rho_R arrays, Lower/
Upper SCMPKeyShare arrays (opaque keys plus cached local rb), and two F2 triple
batches. Preprocess belongs to the trusted offline boundary, never called by
cloud Begin/Next/Accept. Capacity may upper-bound the actual public slot workload.
Unused capacity burns; copied packets share the single-use guard. Repeated bucket
accesses and repeated occurrences use distinct key/triple entries. The trusted
replay provisions from saved public workload capacities BEFORE initial tokens;
production can reserve public upper bounds without learning secret Match.

## Full-data bounds and correctness algebra

Full area_alias scan: records67896, indexed63849, short4047; maximum real posting
position62, maximum indexed rune length66, maximum normal qchunk position60.
Every sealed reconstructed slot position (including dummy zero) also satisfies
0<=p<=62. q=4 complete nonoverlapping code-point chunks preserve repeats.
Short strings remain OPEN; the new Position-token API returns explicit
ErrShortTarget rather than silently entering the normal qgram path. No fallback.

PHASE4 Upos=62, Bin7/Bout1: L=max(0,pQ-tau), R=min(62,pQ+tau), with PHASE4's
uint32 overflow saturation. For accepted pQ<=62, L/R in[0,62], R+1 in[1,63],
so both semantic differences lie in[-63,62], inside signed7 bits. Masked ring
values can span[0,127]; they are not plaintext signed positions. Full supported
uint32 tau clamping is retained. Actual saved tau family spans0..5; native tests
cover0/1/2/62/maxUint32 and all database positions0..62 at boundary query positions.
No automatic Bin expansion or new position semantics.

PosOK = correctedSCMP(p>=L) XOR correctedSCMP(p>=R+1).
A = GroupMatchSlot AND PosOK; Hit = A AND Validity.
All physical slots, real/dummy and matched/unmatched, execute2 SCMP comparisons
and2 fresh Beaver ANDs. No secret-dependent pruning occurs. Group share replication
is local. The native boundary/composition tests and complete trusted oracle cover
matched/failed positions, unmatched groups, dummy zero positions, repeats,
duplicate postings, boundaries and tau extremes. Errors=0.

## Sealed input and output coherence

The existing PHASE8 loader checks IndexID/version/Q4/TargetBucketBits16/tiers,
own PSMJ and payload hashes, and trusted final alignment lineage. The full65536
bucket public structure digest is retained. Target Begin also rejects mismatched
manifest/LayoutID/QueryID/CompactionID, wrong occurrence/route/group offsets,
missing Position tokens, wrong PID/party/capacity or reused packets. Online frames
bind the manifest/lineage/query/compaction/structure/route order and token PIDs.

TargetPostingHits = Manifest, LayoutID, CompactionID, QueryID, K,
Occurrences[r], AnchorRecordIDShare[K], Routes[] and HitShares[S].
Each route contains CandidateIndex, OccurrenceID, BucketID, SlotOffset, SlotCount,
Groups[] of GroupOrdinal, PadWidth, SlotRelativeOffset. HitShares follow exactly
route -> sealed group ordinal -> physical slot order. No sort/compaction/dummy
removal, target record ID, group identity or posting-record incidence is output.
This preserves the next-stage association without implementing aggregation.

## Full native MusicBrainz replay

Same1003 saved real queries, same Anchor seed/family and final PHASE8 lineage.
Actual Anchor -> Anchor Position -> Aggregation -> Keep -> fresh Compaction ->
Private Routing -> sealed PSMJ lookup -> Target PE -> Target Position -> Validity.
No oracle-created Match inputs and no query-time Target index rebuild.

Queries={values['queries']}; routes={values['routes']}; group comparisons={values['groups']};
physical slots={values['physical_slots']}; real Target hits={values['hits']};
zero-hit queries={values['zero_hit_queries']}; errors=0.
Whole-chain process peak RSS={full_rss} KiB, swaps=0 (includes upstream phases).
All hit statistics are trusted-test-only reconstruction. Production never opens
Match, PosOK, Validity or Hit. The saved trace has{repeated} repeated-qchunk queries.
Each of1003 S values was recomputed in this replay and compared element-by-element
against PHASE7B TouchedSlots, not merely against the reported percentiles.

{dist}

## Real LLAMA component measurements

Intel Core i9-14900HX,32 logical CPUs, Go1.27.1, linux/amd64. Concurrent replay/
race workloads share the host; no isolated-host or TCP E2E latency claim.
Both parties' local times are summed. Representatives are actual saved queries
chosen by S (not independent K/r percentiles); their actual routing and Target PE
produce the benchmark Match inputs. Repeated isolated Position trials use fresh
keys/triples and fresh masked bounds. No test comparator generates timing data.
10 warmup/50 measured for p50/p95/p99; max5 warmup/20 measured.

A=public slot/output-structure expansion and masked-position body processing.
B=real LLAMA Eval calls. C=remaining PHASE4 EvalPosition, including rb correction,
conversion/allocation and timing-wrapper overhead. D=Match AND Position body
processing. E=Validity AND body processing. F=final HitShare writes.
G=per-trial A+B+C+D+E+F before taking percentiles. Offline generation, initial
token generation, static artifact load and frame-header/session housekeeping
are outside this component sum. This is explicitly a component sum, not full
transport/runtime wall time; communication accounting includes actual headers.

{timings}

## Offline and online bytes

Each serialized LLAMA key is284 bytes. Current party material also stores a
cached local rb byte per comparison and uint32 rho per comparison. Thus SCMP
key/mask body=2*(284+1+4)*S=578S bytes/party. Two scalar F2 triple shares cost6S
bytes/party. One-time body total=584S/party,1168S combined. Capacity overreservation
costs its reserved S, not only used slots. The table reports exact-size bodies.
Additional public field data: PID16+Bin1 per occurrence and lineage(40)+party1
per party packet; thus body plus these fields is584S+17r+41 per party. The Go
packet has no offline wire codec; slice/allocator/mutex overhead is not claimed
as serialized bytes and is reflected in RSS. Query User preprocessing has24r
bytes of PID/eta fields; initial Position token adds24r bytes per cloud before
framing. These are separate from the server-server online bytes.

Each party emits two uint32 masked-position shares per slot:8S,16S combined.
Each AND layer emits two1-byte F2 opening shares per party:4S combined;
two layers=8S. Online payload=24S both. Each nonempty route chunk has3 sequential
exchanges,6 messages,57-byte header each:342 bytes/chunk, where chunk count is
sum_routes ceil(route.SlotCount/1024). Empty routes emit no messages. Headers
are counted from actual codec output. Bucket reads and retained HitShares are
NOT server-server communication.

{bytes_table}

## Memory

Only final HitShares[S] and public route/group output layout persist at query
scale. Position, Match replication, A and validity buffers are bounded by a
1024-slot route chunk; there are no four full-S intermediate predicate arrays.
Consumed/unused one-time material is released after output. Static PSMJ remains
unchanged at29204994 bytes/party. The memory below is a dual-party test process.
Heap delta is sampled after protocol phases and every1024 messages, maximum
across trials including warmup relative to post-preprocessing allocation; it is
not a continuous heap high-water. The existing native adapter copies serialized
key bytes during each Eval, so cumulative allocations pending GC can exceed
the live chunk buffers; a small live chunk is not a small heap-delta guarantee.
RSS includes static fixtures and Q_pool material;
HWM is cumulative process high-water, not a per-server incremental bound.

{memory}

## Single-party security and completion

CSu sees existing public beta/layout dimensions, its Match/Position/Validity shares,
its SCMP/Beaver material, masked openings and its Hit shares. Same PHASE4
trusted-dealer, semi-honest noncolluding assumptions apply. Fresh independent
rho/eta hide opened positions/bounds; SCMP output masking/correction follows
that existing primitive; fresh triples hide both AND openings. Public replication
and chunk scheduling add no secret branch. No plaintext match/predicate/validity/
hit, join value, qgram, target record identity or posting-record relation is
exposed. The leakage remains prior public access pattern/dimensions, including S.
This is not a claim of malicious security or hidden accessed buckets.

Gofmt, go test ./..., go vet ./..., go test -race -timeout=60m ./...,
native correctness, native-tag vet and git diff --check PASS.

Target B=65536; PSMJ=SEALED; Private Routing=COMPLETE;
Target Private Equality=COMPLETE; Target Position complete=YES.
Production group Match opened=NO; posting Hit opened=NO.
Target Aggregation started=no; Candidate ID Generation started=no;
final recovery started=no; query-time DO=no;
query-time Query User after initial token=no; paper modified=no.
'''
(root/'results/phase9-results.md').write_text(report)
print('Rendered actual replay and',len(rows),'benchmark rows')
