#!/usr/bin/env python3
"""Summarize saved PHASE10B test evidence; never executes a query or reads raw DB."""
import json
import math
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / 'results'
STAGES = ['Hit B2A', 'Incidence / F', 'F→z', 'z B2A', 'C local sum',
          'C→Keep', 'GroupMatch→Ring64', 'Group Target ID selection',
          'Representative recurrence', 'Representative→Ring64',
          'Across-occurrence ID selection', 'Keep→Ring64', 'Anchor ID mask',
          'Target ID mask', 'Output descriptor write']


def summary(values, percentiles=(50, 90, 95, 99, 100)):
    values = sorted(values)
    return [statistics.mean(values)] + [values[max(0, math.ceil(len(values)*p/100)-1)] for p in percentiles]


def fmt(v):
    return f'{v:,.6f}' if isinstance(v, float) else f'{v:,}'


def table(items, percentiles=(50, 90, 95, 99, 100)):
    heads = ['quantity', 'mean'] + ['max' if p == 100 else f'p{p}' for p in percentiles]
    out = ['| ' + ' | '.join(heads) + ' |', '| ' + ' | '.join(['---']*len(heads)) + ' |']
    for name, values in items:
        out.append('| ' + name + ' | ' + ' | '.join(fmt(x) for x in summary(values, percentiles)) + ' |')
    return '\n'.join(out)


def resource_lines(file):
    return '\n'.join(line.strip() for line in file.read_text().splitlines()
                     if any(x in line for x in ('Maximum resident set size', 'Swaps:', 'Elapsed (wall clock)')))


def main():
    rows = json.loads((RESULTS / 'phase10b-queries.json').read_text())
    bench = json.loads((RESULTS / 'phase10b-benchmarks.json').read_text())
    assert len(bench)==4
    memory_bench = json.loads((RESULTS / 'phase10b-memory-benchmarks.json').read_text())
    assert len(memory_bench)==2
    bench[0]=memory_bench[0]
    bench.append(memory_bench[1])
    for b in bench:
        assert len(b['Samples'])==(20 if b['S']>500000 else 50)
        assert all(x['Heap']>0 for x in b['Samples'])
    valid = [r for r in rows if not r['Rejected']]
    rejected = [r for r in rows if r['Rejected']]
    sampled = [r for r in valid if r['Heap']>0]
    assert len(rows) == 1003 and len(valid) == 854 and len(rejected) == 149
    assert sum(r['K']*r['R'] for r in rows) == 466105
    assert sum(r['S'] for r in rows) == 9380900
    assert sum(r['G'] for r in rows) == 2209949
    for r in valid:
        s, g, m, z = r['S'], r['G'], 26*r['K'], 26*r['K']*r['R']
        assert r['Offline']['Z128'] == 112*s+6*z
        assert r['Offline']['SCMP'] == 572*(z+m)
        assert r['Offline']['Ring64'] == 48*(27*g+2*z+3*m)
        assert r['Offline']['F2'] == 6*z
        assert r['Retained'] == 34*m
        body = 58*s+864*g+74*z+98*m if r['K'] else 0
        assert r['Online'] >= body and (r['Online']-body) % 74 == 0
    totalpairs = sum(r['Pairs'] for r in valid)
    text = ['''# PHASE10B — Target aggregation and fixed-domain candidate pairs

AUTHORITATIVE REPO = `/home/tenggn/projects/clean_pmeq`.
Begin HEAD `33e0dd3`, clean. No alternate repository or backup was modified.
PHASE5 and original PSMJ remain sealed; bucket widths16/q4/tiers unchanged.

## Contract and sidecar audit

DTarget=26 for every Anchor candidate. Trusted DO assigns ascending numeric
alias-ID ranks within each join, including short strings. No actual nalias,
join value, or ordinal→ID map enters a cloud. Initial token validation requires
1<=r<=16 and 0<=tau<r,lambda=r-tau. Both threshold masks are prepared before the
initial query; clouds do not receive plaintext lambda.

The sidecar manifest binds original IndexID, original manifest-byte SHA256,
version1/Q4/width16/tiers through that sealed manifest, full ordered structure,
D26/multiplicity3, both sidecar hashes and lengths. Each party file is
PMEQTG01 + party + IndexID + manifest digest; then every bucket's ordered widths,
column-major incidence shares, group-major26 Ring64 payload shares. Group/slot
prefixes use PadWidth, never bucket.LPad. Both sidecar-generation hashes also
bind every online transcript. Load checks all 65536 buckets and pins the digest
to the exact manifest bytes actually loaded by PHASE8, before sidecar I/O.

Full raw audit: maximum aliases per join26, maximum group/record multiplicity3,
short Target rows4047. Build/order audit:65536 buckets,310331 groups,1317260
physical slots,480945 real slots,0 errors. Independent oracle reads ALL 34248760
coefficients and 8068606 payloads,0 errors; both parties exhibit all128 coefficient
marginals. Those tests supplement the independent-mask security argument.

| static field | bytes/party | both parties |
| --- | ---: | ---: |
| incidence,26×1317260 | 34,248,760 | 68,497,520 |
| Target ID,310331×26×8 | 64,548,848 | 129,097,696 |
| framing and ordered widths | 1,503,525 | 3,007,050 |
| complete sidecar | 100,301,133 | 200,602,266 |

Large sidecar binaries are local ignored artifacts; manifest and audit are
tracked. Original PSMJ/payload hashes were verified unchanged. The loader gets
only its own file and the trusted manifests, never a peer file.

## Algebra and output

F[c,h,u]=sum_s E_beta[u,s]*Hit[c,h,s] mod128; F<=3.
z=[F>=1]; C[c,u]=sum_h z[c,h,u]<=16; Keep=[C>=r-tau].
Hit/z conversions and64-posting scalar-vector incidence reuse the existing
clean primitives; comparisons use real LLAMA Bin7/Bout1 with rb removed.
No full26×S intermediate product array or global Target permutation exists.

ID_h[c,u]=sum_g Match[c,h,g]*Payload[g,u] in Ring64, using retained PHASE8 Match,
not rerun PE. Payload refers to ordinal u within that group's join even when
that alias lacks the group's qgram. Rep=z_h AND NOT(seen); seen XOR=rep, for
all r1..16. SelectedID=sum_h rep_h*ID_h. Final AnchorID=Keep*AnchorID[c] and
TargetID=Keep*SelectedID. Every conversion/multiplication uses fresh material.
Ring64 B2A is b0+b1-2*b0*b1, not reinterpretation of3x7-bit limb shares.

Output is CandidatePairShares{Manifest,LayoutID,CompactionID,QueryID,K,DTarget26,
PairKeepShares,AnchorIDShares,TargetIDShares}. All three arrays have26K entries,
candidate then ordinal order. Inactive IDs reconstruct to0. No second compaction,
final count opening, plaintext ID, or Query User recovery is implemented.

## Correctness scope

The approved replay policy preserves all 1003 historical queries/Tau values.
149 fail tau_target<r_target and are explicit aggregation rejection cases.
854 execute pair generation; rejected queries are NOT counted as zero-pair
answers. All1003 still execute actual Anchor filtering/aggregation/compaction,
routing, Target PE and Position:466105 routes,2209949 groups,9380900 slots.
Aggregation never consumes oracle-created Hit or Match.

The opt-in trusted phase10audit build checks every F,z,C,Keep,rep,SelectedID,
and both masked IDs. An independent raw-string qgram/position oracle checks the
final signature-filter candidate pair set, before any future full edit-distance
verification/retrieval. It is not a claim that full EJSM string verification is
implemented. False positives=0; false negatives=0; duplicate pairs=0;
wrong AnchorID=0; wrong TargetID=0, for all 854 accepted queries.

Synthetic and native boundaries cover K0/K1, r1/r16, lambda1/lambda-r, aliases0/1/26,
repeated occurrences, three postings per record, dummy/zero-hit records, high
Ring64 IDs/wraparound, one-use/reordered/misbound messages. Correctness audits
are separate from the single-party security review.
''', f'Accepted queries return {totalpairs:,} oracle pairs in total. Pair cardinalities below are TRUSTED TEST statistics only.\n',
            table([('oracle pairs (854 accepted)', [r['Pairs'] for r in valid])]),
            '\n## Workload sizes — all 1003 historical queries\n',
            table([(key, [r[key] for r in rows]) for key in ('K','R','G','S')] +
                  [('routes K*r', [r['K']*r['R'] for r in rows]), ('public domain26K', [26*r['K'] for r in rows])]),
            '\n## Accepted workload and cost accounting —854 executed aggregation queries\n',
            table([(key, [r[key] for r in valid]) for key in ('K','R','G','S')]),
            '''
Let M=26K, Z=26Kr, S=physical slots and G=group comparisons.
All cost figures below combine BOTH parties unless explicitly per-party.

- Z128 one-time body=112S+6Z: Hit B2A6S, scalar-vector triples106S, z B2A6Z.
- SCMP body=572(Z+M):284-byte native key + cached rb1 + Z128 mask1 per party
  per comparison. Actual key byte lengths are counted during preprocessing.
- Ring64 body=48(27G+2Z+3M), fresh24-byte local triple shares per party.
- F2 representative body=6Z.
- Online masked body=58S+864G+74Z+98M. This uses scalar-vector incidence;
  historical scalar-per-coefficient estimates do not apply.
- Online framing=74*(9+B+H+r+ceil(Z/4096)), where B=sum_routes ceil(T/64),
  H=sum_routes ceil(groupCount/64). K0 sends no messages. Actual encoded outgoing
  lengths are measured, and unit tests cross-check the exact formula.
- Retained output fields=34M both/17M per party. Output write means descriptor
  transfer into the in-memory result; field writes occur in masking stages.
  There is no output network/disk serializer or recovery implementation.

Offline body excludes user mask metadata(two bytes), packet IDs/shape/lineage,
registries, slice headers and allocator overhead. It is not a wire codec or a
resident-memory claim. Offline K/S/G upper-capacity packets are supported for a chosen r class;
unused capacity burns. Reported experiments provision exact measured shapes.
No online refill is permitted. For a finite pool,
reserved body is the SUM of actual packet classes, not a percentile times Q_pool.
Static sidecars and retained output are NOT server-server traffic.
''',
            table([('offline correlated body bytes', [sum(r['Offline'].values()) for r in valid]),
                   ('online encoded bytes', [r['Online'] for r in valid]),
                   ('retained output field bytes', [r['Retained'] for r in valid])]),
            '\n## Actual replay component times, ms —854 heterogeneous queries\n',
            table([(name,[r['Stages'][i]/1e6 for r in valid]) for i,name in enumerate(STAGES)] +
                  [('SUM OF MEASURED COMPONENTS',[sum(r['Stages'])/1e6 for r in valid])]),
            '''
These are actual summed local times for both clouds, excluding Exchange waits,
heap sampling in Exchange, trusted audit callbacks and offline provisioning.
They are heterogeneous workload statistics, not repeated-trial latency quantiles
or TCP/E2E. Concurrent benchmarks/race checks share the host.

## Representative native repeated measurements

The fixture builder reuses the existing PHASE9 saved-real-workload routing/PE
benchmark setup. The first four points are S p50/p95/p99/max within the 854
valid-threshold queries. The fifth is the actual workload nearest their mean S.
The p50 case was remeasured with unconditional start/end heap sampling and
replaces its earlier missing-heap measurement. Larger cases retain the final
representative run. Each listed point has its own complete fresh-packet trials. It evaluates real PE
and Position to produce the aggregation inputs; no oracle Hit is injected.
These component fixtures restore saved candidate payload associations in the
trusted harness, unlike the separate actual full-chain correctness replay.
Each repeated aggregation trial provisions fresh SCMP/Beaver material and masked
bounds. PE/Position input preparation and preprocessing are outside timings.
Each trial reconstructs the same masked pair output. No old5.659ms sample is reused.
''']
    for b in bench:
        samples = b['Samples']
        text.append(f"\nS={b['S']:,}, K={b['K']}, r={b['R']}, tau={b['Tau']}; "
                    f"{b['Warmups']} warmups + {len(samples)} measured fresh packets. Times in ms.\n")
        text.append(table([(name,[s['Stages'][i]/1e6 for s in samples]) for i,name in enumerate(STAGES)] +
                          [('SUM OF MEASURED COMPONENTS',[sum(s['Stages'])/1e6 for s in samples])], (50,95,99)))
        text.append(f"\nOffline body both={sum(b['Offline'].values()):,} bytes; online both="
                    f"{samples[0]['Online']:,} bytes; retained fields both={34*26*b['K']:,} bytes.\n")
        text.append(table([('sampled heap bytes',[s['Heap'] for s in samples]),
                           ('sampled heap delta bytes',[s['HeapDelta'] for s in samples])]))
    text += ['\n## Memory\n', f'Replay coverage: {len(sampled)} of854 queries had a frame above the sampling threshold. The remaining {len(valid)-len(sampled)} are UNSAMPLED, not zero-heap observations. The following replay statistics cover only the sampled subset. Small and mean-workload representatives above use unconditional start/end sampling.\n', table([('sampled-subset heap bytes',[r['Heap'] for r in sampled]),
                                   ('sampled-subset heap delta bytes',[r['HeapDelta'] for r in sampled])]),
             '''
Heap is the dual-party trusted process, not per-cloud RSS. Baselines are sampled
post-preprocessing; repeated benchmarks additionally force GC before that sample.
Replay heap is sampled on masked frames larger than4096 bytes; supplemental
small/mean benchmarks also sample unconditionally before and after execution. Deltas can include GC
retention and upstream objects; they are sampled observations, not continuous
peak-live measurements. Incidence streams64 slots, group payload products64
groups, across-occurrence selection4096 fields; no 26×S product matrix exists.
Full F/z/ID occurrence vectors are bounded by26Kr; one-time material and static
sidecars are separately accounted. Peak RSS includes the upstream chain/oracle
and is not an incremental production-party footprint.
''', '\nFull replay process:\n\n```text\n'+resource_lines(RESULTS/'phase10b-real.txt')+'\n```\n',
             '\nRepeated benchmark process:\n\n```text\n'+resource_lines(RESULTS/'phase10b-benchmark.txt')+'\n```\n',
             '\nSupplemental small/mean benchmark process:\n\n```text\n'+resource_lines(RESULTS/'phase10b-memory-benchmark.txt')+'\n```\n',
             '''
## Historical comparison

Historical Villesse: K488,r3,116991 slots,p95 aggregation5.659ms is reference
only. It used a variable actual-nalias domain, preprocessing reused outside the
benchmark loop, no final Ring64 pair selection, a harness not demonstrating
production-party isolation, and different ID representation. Current measurements
use fixed26, fresh one-time packets, separate party-local Run calls and complete
Ring64 selection/masking. No numerical speedup against incompatible scopes is claimed.

## Single-party security audit

Production Run takes one sidecar, one Match/Hit set, one packet, masked threshold
and an Exchange accepting framed masked messages only. It has no raw DB, DO,
preprocessing, reconstruction, derivation-key, peer object or logging dependency.
Party state contains own dense coefficient/ID shares only. Runtime shapes depend
on existing K/r/bucket access/public widths and fixed26, never actual nalias or
secret predicates. All fields of zero are fresh masked shares. Packet copies
share one claim guard, streamed ranges are disjoint, final ID masks refresh both
active and inactive outputs. Fresh SCMP/Beaver masks make each message simulatable
under the existing trusted-dealer/semi-honest noncolluding assumptions.

No cloud reconstructs posting→record mapping, nalias, joinID, Target ID,z,Keep,
representative or final pair count. Direct GroupMatch reuse never exposes Match.
Production output has exactly26K entries and no final count field. Privacy is
relative to existing public leakage, which can itself imply empty results. The normal
build has no audit sink; the phase10audit instrument is trusted test-only and
must not be deployed. Tests examine imports/calls, output schema, private party
fields, duplicate packets, frame binding, every static coefficient and native
algebra. Distribution/schema tests support, but do not replace, the masking
argument. No malicious-security or hidden-bucket-pattern claim is made.

## Validation and reproduction

All distribution quantiles use nearest rank (ceil(n*p)-1); means are arithmetic.
The final metadata-only hardening pins the sidecar to PHASE8's loaded manifest.
Its negative substitution test and positive full own-file load pass; final
ordinary/native/race/vet checks cover this guard. Saved full-chain/benchmark
measurements precede only this guard and used the same verified manifest bytes.

Run from `/home/tenggn/projects/clean_pmeq`. Go cache is writable under /tmp;
external unmodified LLAMA library is /tmp/phase6-native/libphase6scmp.a. The
current bridge invokes keyGenSCMP; initialization uses sysRandomSeed, not the
historical seeded benchmark wrappers. Source builds, if needed, use the existing
tools/build_phase6_native.sh and remain under /tmp.

```sh
GOCACHE=/tmp/phase8-cache /tmp/go/bin/go test ./...
GOCACHE=/tmp/phase8-cache /tmp/go/bin/go vet ./...
GOCACHE=/tmp/phase8-cache /tmp/go/bin/go test -race -timeout=60m ./...
PMEQ_AGG_FULL=1 CGO_LDFLAGS='-L/tmp/phase6-native -lphase6scmp -lcrypto -pthread' GOCACHE=/tmp/phase8-cache /tmp/go/bin/go test -tags 'phase10integration phase9integration phase6native phase10audit' ./internal/aggregation -run '^TestReal1000Queries$' -count=1 -timeout=90m -v
PMEQ_TARGET_AGG_BENCH=1 CGO_LDFLAGS='-L/tmp/phase6-native -lphase6scmp -lcrypto -pthread' GOCACHE=/tmp/phase8-cache /tmp/go/bin/go test -tags phase6native ./internal/targetposition -run '^TestPhase10NativeBenchmarks$' -count=1 -timeout=60m -v
PMEQ_TARGET_AGG_BENCH=1 PMEQ_TARGET_AGG_BENCH_SCOPE=small_mean CGO_LDFLAGS='-L/tmp/phase6-native -lphase6scmp -lcrypto -pthread' GOCACHE=/tmp/phase8-cache /tmp/go/bin/go test -tags phase6native ./internal/targetposition -run '^TestPhase10NativeBenchmarks$' -count=1 -timeout=30m -v
python3 tools/summarize_phase10b.py
```

Sidecar builder test is opt-in PMEQ_TARGET_SIDECARS=1 and uses exclusive-create
for artifact files to prevent silent replacement. Existing sidecars can be
independently re-audited with TestEverySidecarCoefficientAndPayload.
Final ordinary/native/race/vet/gofmt/diff and obsolete-path checks are recorded
in the companion validation logs and migration log.

Target Aggregation complete=YES; Candidate ID Generation complete=YES.
Final pair count opened to clouds=NO; Target IDs opened to clouds=NO.
Query User recovery started=no; short-string completeness=OPEN.
Query-time DO=no; paper modified=no; alternate repository created=NO;
obsolete repository used=NO; backup modified=NO.
''']
    (RESULTS/'phase10b-results.md').write_text('\n'.join(text))
    print(f'1003 upstream / {len(valid)} accepted / {len(rejected)} rejected; oracle pairs={totalpairs}')


if __name__ == '__main__':
    main()
