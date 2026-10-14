#!/usr/bin/env python3
"""Summarize saved integrated-runner evidence; no execution or raw-data access."""
import json, math, statistics
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
R=ROOT/'results'

def quantiles(values,ps=(50,90,95,99,100)):
    v=sorted(values)
    return [statistics.mean(v)]+[v[max(0,math.ceil(len(v)*p/100)-1)] for p in ps]
def table(rows,ps=(50,90,95,99,100)):
    out=['| quantity | mean | '+' | '.join('max' if p==100 else f'p{p}' for p in ps)+' |','| '+' | '.join(['---']*(2+len(ps)))+' |']
    for name,v in rows:
        out.append('| '+name+' | '+' | '.join(f'{x:,.6f}' if isinstance(x,float) else f'{x:,}' for x in quantiles(v,ps))+' |')
    return '\n'.join(out)
def resource(name):
    return '\n'.join(l.strip() for l in (R/name).read_text().splitlines() if any(s in l for s in ['Maximum resident set size','Swaps:','Elapsed (wall clock)']))
def main():
    rows=json.loads((R/'phase11-queries.json').read_text());valid=[q for q in rows if not q['Rejected']];rejected=[q for q in rows if q['Rejected']]
    assert len(rows)==1003 and len(valid)==854 and len(rejected)==149 and sum(q['Pairs'] for q in valid)==1510
    bench=json.loads((R/'phase11-benchmarks.json').read_text());assert len(bench)==4
    reference=json.loads((R/'phase10b-queries.json').read_text())
    required=[]
    for q in valid:
        rt=reference[q['Query']]['R']
        numerator=q['Metrics']['UserToCloud'][0]-122-66*rt
        assert numerator%2352==0
        ra=numerator//2352
        assert 1<=ra<=14 and 1<=rt<=16
        user={'AnchorPosition':8*ra,'AnchorAggregation':ra+1,'Compaction':0,'TargetPE':0,'TargetPosition':8*rt,'TargetAggregation':2}
        required.append({'Query':q['Query'],'UserMasks':user,'RequiredFields':{k:v+user[k] for k,v in q['Offline'].items()}})
    (R/'phase11-offline-required.json').write_text(json.dumps(required,separators=(',',':'))+'\n')
    for b in bench:assert len(b['Samples'])==30 and b['Warmup']==10
    static=json.loads((R/'phase11-static.json').read_text())
    metadata=sum((ROOT/p).stat().st_size for p in ['artifacts/phase7b/manifest.json','artifacts/phase7b/payload-manifest.json','artifacts/phase10b/manifest.json'])
    static['Public sealed manifests']=[metadata,metadata]
    ms=[q['Metrics'] for q in valid]
    for m in ms:
        assert m['CloudToUser']==[86+442*m['K']]*2 and m['PeakHeap']>0 and m['LocalE2E']>=m['Token']+m['Cloud']+m['Recovery']
    text=['''# PHASE11 — Candidate Discovery integrated local E2E

AUTHORITATIVE REPO = `/home/tenggn/projects/clean_pmeq`.
Begin HEAD c67336ed04c1ca26438ea2003333863c1b19e895, clean.

## Boundary and supported domain

The production entry point is `discovery.RunLocal(ctx, Query, UserKeys,
UserPacket, [2]*Static, [2]*PartyPacket, SCMPBackend)` returning CandidatePairs,
Metrics and error. Query has Anchor/Target strings and independent TauAnchor/
TauTarget. `discovery.Provision` is a separate TRUSTED OFFLINE operation and
must complete before RunLocal. There is no online refill or dealer callback.
The canonical runner is a Go API; the native replay test is its caller, not its
implementation. It does not call test functions or a reference comparator.

Normal input uses complete nonoverlapping q=4 Unicode chunks, 0<=tau_i<r_i,
lambda_i=r_i-tau_i, Anchor r1..14 and Target r1..16 (existing audited bounds).
Incomplete tails are dropped by the existing token rule; repeated chunks remain
separate occurrences. No tau clamping or query rewriting occurs. Queries with
fewer than four usable characters are rejected; short-string completeness
remains OPEN (Anchor644, Target4047), with no fallback.

Each party receives only its own static objects, packet, encoded user token and
byte-message endpoint. It runs existing real DPF/LLAMA/Beaver/permutation/
compaction/routing/PE/Position/Target aggregation components. PHASE11 adds
orchestration and codecs, not new cryptography or stage optimization. The
original ComposeHits/BatchAND test coordinators are not used online: their
existing party-local Mask/Open/Finish steps consume preprovisioned triples.

## Authorized Query User recovery

CandidatePairs = {QueryID, []Pair{AnchorRecordID,TargetRecordID}}.
Only the user's `candidatequery.Recover(expectedBinding, cs0Bytes, cs1Bytes)`
reconstructs Keep=Keep0 XOR Keep1, AnchorID=ID0+ID1 mod2^64 and TargetID likewise.
Keep1 appends a pair; Keep0 REQUIRES both IDs zero. Duplicates fail closed,
without silently deduplicating. Expected IndexID/manifest, LayoutID,
CompactionID, QueryID, sender role, D26, K and exact lengths are checked.
Authenticated role channels are an assumption; these codecs are not a MAC.

Every cloud output is fixed26K slots, candidate-major then ordinal order.
The result codec is magic8+party1+manifest21+three lineage IDs48+K4+D4 =86
header bytes, followed by17 bytes/slot (Keep1, AnchorID8, TargetID8). Cloud-side
arrays are neither sorted nor compacted again. Only the user learns the final
pair cardinality. Full strings, exact edit-distance verification and application
record fetching are outside Candidate Discovery.

## Real correctness

149/149 historical invalid Target thresholds reject at the runner entrance,
before token generation, provisioning consumption or any cloud message. The
854 valid queries execute the complete real chain, including initial tokens and
final user recovery. Raw strings are used only in separate trusted setup/oracle
code; no oracle-constructed Keep, compaction, routing, Match, Hit or pair input
enters the production runner. The independent oracle computes positional qchunk
matches directly from original area and area_alias strings.

1510 recovered pairs total; FP=0, FN=0, duplicate pairs=0, wrong AnchorID=0,
wrong TargetID=0. Each valid query also preserves its PHASE10 K/G/S workload.
Unlike PHASE10's upstream diagnostic replay, PHASE11 rejects149 before Anchor;
its executed route/slot totals therefore cover854 only. Rejected cases are not
imputed as empty successful answers. Tests additionally cover malformed outputs,
masked nonzero IDs, swapped parties, wrong query bindings, Ring64 wraparound,
K0/K1, duplicate results, packet-copy one-use guards and byte codecs.

## Valid real workload

Mean is primary. Quantiles use nearest rank ceil(n*p)-1. All distributions below
cover854 accepted queries unless explicitly stated otherwise.
''']
    text.append(table([(n,[m[k] for m in ms]) for n,k in [('K','K'),('routes','Routes'),('groups','Groups'),('Target physical slots','Slots')]]+[('Recovered real pairs',[q['Pairs'] for q in valid])]))
    text.append(f"Executed totals: routes={sum(m['Routes'] for m in ms):,}, groups={sum(m['Groups'] for m in ms):,}, slots={sum(m['Slots'] for m in ms):,}.")
    text.append('''## Integrated timings, milliseconds

INTEGRATED LOCAL E2E WALL TIME is one outer time.Now/time.Since around initial
user token generation, concurrent cloud processing and final user recovery.
It includes encoded local channel traffic, output encoding and scheduling; it
excludes offline provisioning, index construction and the external oracle.
Token generation includes actual DPF generation and Target token masking/codec.
Recovery includes decoding the user's saved token binding and both output messages.
Cloud phase times include exchanges/waits and use the maximum party duration per
stage. They are supplemental stage measurements, not an E2E definition. The
outer wall is measured independently and is never replaced by their sum.
Heap sampling at10ms and initial/final boundaries instruments the same process.
This is not network/TCP/distributed-deployment latency. Historical component
sums retain their original SUM OF MEASURED COMPONENTS label.
''')
    stages=['Token','Anchor','Compaction','Routing','TargetPE','TargetPosition','TargetAggregation','OutputEncoding','Recovery','Cloud','LocalE2E']
    text.append(table([(k if k!='LocalE2E' else 'INTEGRATED LOCAL E2E WALL TIME',[m[k]/1e6 for m in ms]) for k in stages]))
    text.append('## Representative repeated real-query E2E')
    text.append('Workload metric is Target physical slots S. Choose nearest actual mean S and nearest-rank p50/p95/p99 among854 valid queries. Each repeat uses fresh full-protocol material prepared before the outer timer. Static state is reused. All runs use the same production RunLocal entry point and compare the final result to the independent oracle. All four cases use10 warmup/30 measured invocations.')
    for label,b in zip(['mean workload','p50 workload','p95 workload','p99 workload'],bench):
        text.append(f"{label}: historical query {b['Query']}, K={b['K']}, S={b['Slots']}; warmup={b['Warmup']}, measured={b['Measured']}.")
        text.append(table([('INTEGRATED LOCAL E2E WALL TIME ms',[m['LocalE2E']/1e6 for m in b['Samples']])],(50,95,99)))
    text.append('''## Online communication, encoded application bytes

All values count actual byte slice lengths, not Go object memory. Both initial
user tokens are encoded and decoded; all online cloud messages traverse byte
channels. A37-byte query/packet/sequence/role envelope binds each cloud message,
including one-way permutation/compaction steps (the opposite party sends an
empty envelope). Existing Target framing remains inside this envelope. Local
index reads, internal arrays, random generation and offline material are excluded.
No network transport headers are included. One initial token per cloud has
122+2352*r_anchor+66*r_target bytes with the fixed DPF key encoding.
''')
    comm=[('QueryUser → CS0',[m['UserToCloud'][0] for m in ms]),('QueryUser → CS1',[m['UserToCloud'][1] for m in ms]),('CS0 ↔ CS1',[m['ServerBytes'] for m in ms]),('CS0 → QueryUser',[m['CloudToUser'][0] for m in ms]),('CS1 → QueryUser',[m['CloudToUser'][1] for m in ms])]
    total=[sum(m['UserToCloud'])+m['ServerBytes']+sum(m['CloudToUser']) for m in ms]
    text.append(table(comm+[('Total online encoded bytes',total)]))
    text.append('## One-time offline Q_pool material, both parties plus user masks')
    text.append('Preprocessing is provisioned before query execution. All required stage-correlated body fields are counted separately below, using actual opaque SCMP key lengths. These are compact field-volume accounts, not an offline wire codec or resident-memory estimate; packet IDs, public class metadata, registries and allocator overhead are excluded. Raw replay Offline fields count both clouds. The table additionally includes required user secret masks: Anchor Position8*r_anchor bytes, Anchor aggregation r_anchor+1 bytes, Target Position8*r_target bytes and Target aggregation2 bytes. These follow actual uint32 position-mask and byte aggregation-mask representations. The exact per-query expanded accounting is saved in phase11-offline-required.json. Compaction includes both fresh permutation arrays and six43-byte tuple masks per global coordinate. Anchor Position includes both SCMP/rho fields and both F2 triple layers. Anchor Aggregation includes Hit/z B2A, chunked incidence triples, comparisons and global permutation masks. Target stages use their existing field accounts. Reusable static state is excluded. No query-time dealer/refill is called. The replay reserves exact saved public workload capacities offline; the existing Target protocols also support larger public capacity classes. A heterogeneous Q_pool costs the sum of its packet classes, not a percentile multiplied by pool length.')
    offline=list(valid[0]['Offline'])
    text.append(table([(k,[q['RequiredFields'][k] for q in required]) for k in offline]+[('Total one-time field material',[sum(q['RequiredFields'].values()) for q in required])]))
    timing=json.loads((R/'phase11-offline-timing.json').read_text())
    text.append('## Separate offline/setup timing samples')
    text.append(f"Existing BSMJ IndexOutsource materialization measured separately: {timing['BSMJMaterialization']/1e6:,.6f} ms. Complete trusted fixture setup including raw oracle loading and sealed-file validation: {timing['SetupIncludingOracle']/1e6:,.6f} ms. Neither enters online E2E. PSMJ construction was not rerun.")
    text.append('One separately measured offline sample per representative query follows; these are setup/provisioning samples, not an854-query offline-latency distribution. Reusable static extensions and one-time material are separated.')
    timing_table=['| historical query | reusable static extension ms | one-time provisioning ms |','| --- | ---: | ---: |']
    for sample in timing['Samples']:
        timing_table.append(f"| {sample['Query']} | {sample['StaticExtension']/1e6:,.6f} | {sample['OneTimeProvision']/1e6:,.6f} |")
    text.append("\n".join(timing_table))
    text.append('## Static storage, bytes')
    text.append('PSMJ, global payload and Target aggregation are the original hash-verified sealed files, unchanged. The inherited Anchor implementation has no persistent index/alignment codec: the existing trusted IndexOutsource builder materializes BSMJ once for execution, outside every online timer. Each tested bucket incidence/alignment is provisioned offline before the query; repeated benchmarks reuse it. The full-domain Anchor figures below are exact semantic field counts, not a claim that all25.6GB of sigma factors were loaded or persisted. No index was rebuilt merely to obtain this table, and PSMJ was never rebuilt. Public sealed manifest file sizes are listed separately. Go descriptors, maps, slice headers and in-memory Anchor shape metadata are not mixed with field bytes. User master keys64 bytes are user-only, not cloud static state.')
    static_table=['| static item | CS0 | CS1 | combined |','| --- | ---: | ---: | ---: |']
    for name,v in static.items():static_table.append(f'| {name} | {v[0]:,} | {v[1]:,} | {sum(v):,} |')
    sums=[sum(v[i] for v in static.values()) for i in range(2)]
    static_table.append(f'| Total listed fields/files | {sums[0]:,} | {sums[1]:,} | {sum(sums):,} |')
    text.append('\n'.join(static_table))
    text.append('## Integrated memory')
    text.append(table([('Integrated peak sampled heap bytes',[m['PeakHeap'] for m in ms])]))
    text.append('Each observation is the peak sampled heap across one complete integrated invocation. No individual-stage peaks are summed. Process RSS below includes trusted offline setup, native code, both clouds and the raw comparison oracle; it is not per-cloud production RSS. Sampling every10ms is a sampled peak, not a proof of continuous peak-live memory.')
    for title,file in [('One-pass process','phase11-real.txt'),('Repeated-benchmark process','phase11-benchmark.txt')]:text.append(title+'\n\n```text\n'+resource(file)+'\n```')
    text.append('## NETWORK PAYLOAD LOWER BOUND')
    text.append('Ideal serialization of measured total ONLINE application bytes at the stated aggregate bottleneck bandwidth; no preprocessing, disk reads, TCP/Ethernet overhead, RTT, congestion or protocol round delays. The single aggregate-bottleneck assumption matters: independent full-duplex links may overlap. These are not actual network latency measurements.')
    text.append(table([(f'{gbps} Gbps, ms',[b*8/(gbps*1e6) for b in total]) for gbps in [1,10,25]],(95,99)))
    text.append('''## Single-party security and validation

Existing trusted DO, authorized honest Query User, semi-honest noncolluding cloud
assumptions are retained. Neither cloud state contains the user's master keys,
raw query strings, plaintext incidence mappings, peer state, or user masks.
Isolation here is at the party API boundary: this local prototype process hosts
both workers and the user, not separate OS security domains. The coordinator
routes encoded MASKED openings only. Each cloud owns one
packet guard; copying packet handles cannot regenerate or reuse material.
The Query User is offline after initial token emission until final recovery.
The final user result is not sent back to either cloud. No full Y, GroupMatch,
posting Hit, Target Keep, Target ID or final pair count is opened to clouds.
The existing shuffled Anchor Keep opening/allowed K leakage remains unchanged.
No test-only phase10audit build is used by the PHASE11 runner or replay.

Run from `/home/tenggn/projects/clean_pmeq`:

```sh
GOCACHE=/tmp/phase11-cache /tmp/go/bin/go test ./...
GOCACHE=/tmp/phase11-cache /tmp/go/bin/go vet ./...
GOCACHE=/tmp/phase11-cache /tmp/go/bin/go test -race -timeout=60m ./...
PMEQ_PHASE11=1 CGO_LDFLAGS='-L/tmp/phase6-native -lphase6scmp -lcrypto -pthread' GOCACHE=/tmp/phase11-cache /tmp/go/bin/go test -tags phase6native ./internal/discovery -run '^TestIntegratedReal$' -count=1 -timeout=90m -v
PMEQ_PHASE11_BENCH=1 CGO_LDFLAGS='-L/tmp/phase6-native -lphase6scmp -lcrypto -pthread' GOCACHE=/tmp/phase11-cache /tmp/go/bin/go test -tags phase6native ./internal/discovery -run '^TestIntegratedRepeated$' -count=1 -timeout=90m -v
PMEQ_PHASE11_OFFLINE=1 CGO_LDFLAGS='-L/tmp/phase6-native -lphase6scmp -lcrypto -pthread' GOCACHE=/tmp/phase11-cache /tmp/go/bin/go test -tags phase6native ./internal/discovery -run '^TestOfflineTiming$' -count=1 -timeout=30m -v
python3 tools/summarize_phase11.py
```

All final checks and exact resource outputs are in companion logs.

CANDIDATE DISCOVERY E2E = COMPLETE for the supported normal query domain.
Historical invalid queries rejected=149/149; valid real queries correct=854/854.
Short-string completeness=OPEN; full-string exact verification implemented=NO.
Query-time DO=NO; paper modified=NO; alternate repository created=NO;
obsolete repository used=NO; backup modified=NO.
''')
    (R/'phase11-results.md').write_text('\n\n'.join(text))
    print('854 valid /149 rejected /1510 pairs; mean E2E ms',statistics.mean(m['LocalE2E']/1e6 for m in ms))
if __name__=='__main__':main()
