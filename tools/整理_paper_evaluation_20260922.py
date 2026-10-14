#!/usr/bin/env python3
"""Read-only derivation from retained PMEQ measurements; no test/benchmark execution.
Writes exclusively into a new paper-evaluation directory and refuses overwrites.
Database-scale CSVs are referenced, never recalculated or copied. Stdlib only.
"""
import bisect
import csv
import gzip
import hashlib
import io
import json
import math
import statistics as st
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'results/paper-evaluation-20260922'
CAL = 'results/timing-calibration-20260920'
DB = 'results/database-scalability-analysis-20260922'
MIB = 1024**2
STAGES = ['Token','Anchor','Compaction','Routing','TargetPE','TargetPosition','TargetAggregation','OutputEncoding','Recovery']
PARTS = ['Filter','HitB2A','Incidence','FCompare','ZB2A','Alignment','Count','Keep','Other']
OFFLINE = ['AnchorPosition','AnchorAggregation','Compaction','TargetPE','TargetPosition','TargetAggregation']
FILES, INPUTS, CONFLICTS = {}, {}, []

def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''): h.update(chunk)
    return h.hexdigest()

def read(path):
    p = ROOT/path
    b = p.read_bytes()
    INPUTS[path] = hashlib.sha256(b).hexdigest()
    return b

def js(path): return json.loads(read(path))
def jl(path): return [json.loads(x) for x in read(path).splitlines()]
def cr(path): return list(csv.DictReader(io.StringIO(read(path).decode())))
def doc(path, text):
    assert path not in FILES
    FILES[path] = text.strip()+'\n'
def jout(path, data): doc(path, json.dumps(data, ensure_ascii=False, indent=2))
def cout(path, rows):
    assert rows
    f=io.StringIO(); w=csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator='\n')
    w.writeheader(); w.writerows(rows); doc(path, f.getvalue())
def quant(v,p):
    v=sorted(v); a=(len(v)-1)*p; i=math.floor(a)
    return v[i]+(v[min(i+1,len(v)-1)]-v[i])*(a-i)
def stats(v):
    assert v and all(math.isfinite(x) for x in v)
    return {'mean':st.mean(v),'median':quant(v,.5),'P95':quant(v,.95),'P99':quant(v,.99),'min':min(v),'max':max(v)}
def ranks(v):
    out=[0.0]*len(v); order=sorted(range(len(v)),key=v.__getitem__); i=0
    while i<len(v):
        j=i+1
        while j<len(v) and v[order[j]]==v[order[i]]: j+=1
        for k in range(i,j): out[order[k]]=(i+j-1)/2+1
        i=j
    return out

def pearson(x,y):
    a,b=st.mean(x),st.mean(y); xx=[z-a for z in x]; yy=[z-b for z in y]
    den=math.sqrt(sum(z*z for z in xx)*sum(z*z for z in yy))
    assert den>0
    return sum(u*v for u,v in zip(xx,yy))/den

def corr(rows,x,y):
    a=[r[x] for r in rows]; b=[r[y] for r in rows]
    return {'x':x,'y':y,'Pearson_r':pearson(a,b),'Spearman_rho':pearson(ranks(a),ranks(b)),'n':len(rows)}

def git(*args): return subprocess.check_output(['git',*args],cwd=ROOT,text=True)
def table(rows, fields):
    def f(v): return f'{v:.6f}' if isinstance(v,float) else str(v)
    return '| '+' | '.join(fields)+' |\n|'+ '|'.join(['---']*len(fields))+'|\n'+'\n'.join('| '+' | '.join(f(r[k]) for k in fields)+' |' for r in rows)

def main():
    if OUT.exists(): raise SystemExit('Refusing to overwrite existing output directory: '+str(OUT))
    # Freeze original source and scale-directory bytes before deriving anything.
    sources=sorted([p for p in (ROOT/'internal').rglob('*') if p.is_file()]+[p for p in (ROOT/'tools').rglob('*') if p.is_file() and '__pycache__' not in p.parts]+[ROOT/'go.mod',ROOT/'go.sum',ROOT/'CURRENT_SPEC.md',ROOT/'PRODUCTION_CHAIN.md',ROOT/'SECURITY_INVARIANTS.md'])
    source_hash={str(p.relative_to(ROOT)):sha(p) for p in sources}
    db_hash={str(p.relative_to(ROOT)):sha(p) for p in (ROOT/DB).rglob('*') if p.is_file()}
    for name,args in [('git-head.txt',('rev-parse','HEAD')),('git-status-short.txt',('status','--short')),('git-diff-stat.txt',('diff','--stat')),('git-diff.patch',('diff','--binary'))]: doc('provenance/'+name,git(*args))
    jout('provenance/source-sha256.json',source_hash)
    script=str(Path(__file__).relative_to(ROOT)); jout('provenance/statistics-script-sha256.json',{script:sha(Path(__file__))})
    jout('provenance/database-scale-protection-before.json',db_hash)
    env=js(CAL+'/environment.json')
    matches={k:source_hash.get(k, sha(ROOT/k) if (ROOT/k).is_file() else None)==v for k,v in env['source_sha256'].items()}
    assert all(matches.values()), 'Current calibration source mismatch'
    manifest=js('artifacts/phase7b/manifest.json'); payload=js('artifacts/phase7b/payload-manifest.json'); side=js('artifacts/phase10b/manifest.json')
    assert (manifest['Q'],manifest['AnchorBucketBits'],manifest['TargetBucketBits'],side['DTarget'],payload['N'])==(4,16,16,26,120071)
    assert manifest['Tiers']==[4,16,64,256,1024,4096,8192,16384]
    assert 'anchorfilter.Preprocess(t, 7, cb)' in (ROOT/'internal/discovery/offline.go').read_text()
    assert 'keyGenSCMP(bin,1,' in (ROOT/'tools/phase6_scmp_bridge.cpp').read_text()
    params={'q':4,'AnchorBucketBits':16,'TargetBucketBits':16,'Tiers':manifest['Tiers'],'SCMPBin':7,'SCMPBout':1,'TargetRecordDomain':26,'NAnchor':payload['N'],'runtime_env_at_measurement':env['runtime_env'],'evidence':['artifacts/phase7b/manifest.json','artifacts/phase10b/manifest.json','internal/discovery/offline.go','tools/phase6_scmp_bridge.cpp']}
    jout('provenance/frozen-parameters.json',params)
    for name,data in [('target-manifest.json',manifest),('payload-manifest.json',payload),('target-aggregation-manifest.json',side)]: jout('provenance/'+name,data)
    # Actual binary hashes, including the current retained formal binaries (not executed).
    binaries=set((ROOT/'artifacts/phase7b').glob('*.bin'))|set((ROOT/'artifacts/phase10b').glob('*.bin'))
    binaries.add(Path(env['binary']))
    binaries.add(ROOT/'artifacts/n-domain-regression-pilot-runtime/native/libphase6scmp.a')
    for base in [ROOT/'artifacts',ROOT/'results']:
        for pat in ['*runtime*/*.test','*runtime*/native/*.a','*runtime*/native/*.so']:
            binaries.update(base.glob(pat))
    bh={str(p.relative_to(ROOT)): {'sha256':sha(p),'bytes':p.stat().st_size} for p in sorted(binaries)}
    assert bh[str(Path(env['binary']).relative_to(ROOT))]['sha256']==env['binary_sha256']
    for name,h in env['input_sha256'].items(): assert sha(ROOT/name)==h, name
    for i in [0,1]:
        for name,h in [(f'artifacts/phase7b/cs{i}.psmj.bin',manifest['PartySHA256'][i]),(f'artifacts/phase7b/cs{i}.payload.bin',payload['SHA256'][i]),(f'artifacts/phase10b/cs{i}.aggregation.bin',side['PartySHA256'][i])]: assert bh[name]['sha256']==h
    jout('provenance/binary-sha256.json',bh)
    rawdir=Path('/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump')
    raw={}
    for name,h in env['raw_sha256'].items():
        p=rawdir/name
        raw[name]={'path':str(p),'exists':p.is_file(),'historical_sha256':h}
        if p.is_file():
            raw[name].update(sha256=sha(p),bytes=p.stat().st_size)
            assert raw[name]['sha256']==h
        else: raw[name]['current_verification']='无法确认：当前路径不可读/不存在'
    size=js('results/n-domain-regression-pilot-20260920/regression-100-summary.json')
    jout('provenance/dataset.json',{'raw_files':raw,'AnchorInput':size['AnchorInput'],'TargetInput':size['TargetInput'],'source':'results/n-domain-regression-pilot-20260920/regression-100-summary.json','measurement_environment':env,'note':'规模数字引用既有100%回归；未重建/扫描构造数据库。'})
    # Input alignment and fail-closed deterministic-field verification.
    trace=[json.loads(x) for x in gzip.decompress(read('results/phase7b-workload.jsonl.gz')).splitlines()]
    trace={x['Query']:x for x in trace}; assert len(trace)==1003
    runs=[]; allrows=[]; verifications=[]
    errcols=['FP','FN','duplicate','wrong_AnchorID','wrong_TargetID']
    correctness=[]
    for n in [1,2,3]:
        path=f'{CAL}/run-{n}/work/results/phase11-queries.json'; rawrows=js(path)
        byid={x['Query']:x for x in rawrows}; assert len(byid)==len(rawrows)==1003
        assert set(byid)==set(trace)
        verification=js(f'{CAL}/run-{n}/verification.json'); verifications.append(verification)
        verified={int(x['query']):x for x in cr(f'{CAL}/run-{n}/verified-queries.csv')}
        legal={q:r for q,r in byid.items() if not r['Rejected']}; assert len(legal)==854 and len(verified)==854
        assert set(verified)==set(legal)==set(verification['matched_query_ids'])
        assert verification['valid_queries']==854 and verification['invalid_rejected']==149 and verification['pairs']==1510
        assert all(x==0 for x in verification['errors'].values())
        log=read(f'{CAL}/run-{n}/run.log').decode(); assert 'valid=854 pairs=1510 FP=0 FN=0 duplicate=0 wrongAnchor=0 wrongTarget=0' in log
        for q,r in byid.items():
            t=trace[q]; ra=len(t['Anchor'])//4; rt=len(t['Target'])//4
            assert r['Rejected']==not_valid(t,ra,rt)
            if r['Rejected']: continue
            m=r['Metrics']; v=verified[q]
            assert all(int(v[k])==0 for k in errcols)
            for f,g in [('Pairs','final_pairs')]: assert r[f]==int(v[g])
            assert int(v['oracle_pairs'])==r['Pairs']
            for a,b in [('K','K'),('Routes','routes'),('Groups','groups'),('Slots','target_slots'),('LocalE2E','local_e2e_ns'),('ServerBytes','intercloud_bytes')]: assert m[a]==int(v[b])
            assert int(v['N'])==120071 and int(v['tau_anchor'])==t['Tau'] and int(v['tau_target'])==t['Tau']
            assert v['anchor']==t['Anchor'] and v['target']==t['Target']
            assert m['UserToCloud']==[int(v['user_cs0_bytes']),int(v['user_cs1_bytes'])]
            assert m['CloudToUser']==[int(v['cs0_user_bytes']),int(v['cs1_user_bytes'])]
            assert int(v['total_bytes'])==sum(m['UserToCloud'])+m['ServerBytes']+sum(m['CloudToUser'])
            assert m['UserToCloud']==[122+2352*ra+66*rt]*2
            assert sum(m['AnchorParts'].values())==m['Anchor']
            assert m['AnchorParts'] in m['AnchorPartyParts']
            assert max(sum(p.values()) for p in m['AnchorPartyParts'])==m['Anchor']
            assert r['Offline']['AnchorPosition']%1168==0
            ar={'run':n,'QueryID':q,**{k:m[k] for k in STAGES+['Cloud','LocalE2E']},**{f'AnchorParts.{k}':m['AnchorParts'][k] for k in PARTS}}
            allrows.append(ar)
        assert sum(r['Pairs'] for r in legal.values())==1510
        correctness.append({'run':n,'total_trace':1003,'invalid_queries':149,'valid_queries':854,'candidate_pairs':1510,'false_positive_vs_plaintext_candidate_oracle':0,'false_negative_vs_plaintext_candidate_oracle':0,'duplicate_pairs':0,'anchor_id_errors':0,'target_id_errors':0})
        runs.append(byid)
    assert all(set(q for q,r in a.items() if r['Rejected'])==set(q for q,r in runs[0].items() if r['Rejected']) for a in runs)
    qids=sorted(q for q,r in runs[0].items() if not r['Rejected'])
    workload=[]; chain=[]; e2e=[]; token=[]; off=[]; aligned=[]
    for q in qids:
        rr=[r[q] for r in runs]; mm=[r['Metrics'] for r in rr]; m=mm[0]
        for a in rr[1:]:
            assert a['Pairs']==rr[0]['Pairs'] and a['Offline']==rr[0]['Offline']
            assert all(a['Metrics'][k]==m[k] for k in ['K','Routes','Groups','Slots','UserToCloud','CloudToUser','ServerBytes'])
        w={'QueryID':q,'AnchorSlots':rr[0]['Offline']['AnchorPosition']//1168,'K':m['K'],'Routes':m['Routes'],'TargetGroups':m['Groups'],'TargetSlots':m['Slots'],'CandidatePairs':rr[0]['Pairs']}
        chain.append({'QueryID':q,'NAnchor':120071,**{k:v for k,v in w.items() if k!='QueryID'}})
        times={k:st.median([x[k] for x in mm])/1e6 for k in STAGES+['Cloud','LocalE2E']}
        parts={k:st.median([x['AnchorParts'][k] for x in mm])/1e6 for k in PARTS}
        comm=sum(m['UserToCloud'])+m['ServerBytes']+sum(m['CloudToUser'])
        row={**w,**times,**parts,'OnlineCommunicationBytes':comm,'OnlineCommunicationMiB':comm/MIB}
        row['TargetStageSum']=sum(row[k] for k in ['Routing','TargetPE','TargetPosition','TargetAggregation'])
        row['TargetProcessingStageSum']=sum(row[k] for k in ['TargetPE','TargetPosition','TargetAggregation'])
        workload.append(row)
        e2e.append({'QueryID':q,**{f'run_{i+1}_latency_ms':mm[i]['LocalE2E']/1e6 for i in range(3)},'median_latency_ms':times['LocalE2E'],'communication_bytes':comm,'communication_MiB':comm/MIB,**{k:w[k] for k in ['K','Routes','TargetGroups','TargetSlots','CandidatePairs']}})
        token.append({'QueryID':q,'TokenTimeMedianMs':times['Token'],'TokenBytesCloud0':m['UserToCloud'][0],'TokenBytesCloud1':m['UserToCloud'][1],'TotalUserToCloudBytes':sum(m['UserToCloud']),'rAnchor':len(trace[q]['Anchor'])//4,'rTarget':len(trace[q]['Target'])//4})
        off.append({'QueryID':q,**rr[0]['Offline']})
    cout('correctness/correctness-summary.csv',correctness)
    cout('correctness/query-filter-chain.csv',chain)
    cout('correctness/filter-summary.csv',[{'metric':k,'n':854,**stats([r[k] for r in chain])} for k in ['AnchorSlots','K','Routes','TargetGroups','TargetSlots','CandidatePairs']])
    cout('workload/workload-query-level.csv',workload)
    cout('e2e/e2e-three-runs-query-level-ns.csv',allrows)
    cout('e2e/e2e-query-level.csv',e2e)
    cout('token-offline-existing/token-query-level.csv',token)
    cout('token-offline-existing/offline-volume-query-level.csv',off)
    run_summary=[]
    for n,byid in enumerate(runs,1):
        lat=stats([byid[q]['Metrics']['LocalE2E']/1e6 for q in qids]); meancomm=st.mean([r['communication_bytes'] for r in e2e])
        run_summary.append({'run':n,**{f'{k}_latency_ms':v for k,v in lat.items()},'mean_communication_bytes':meancomm,'mean_communication_MiB':meancomm/MIB})
    cout('e2e/e2e-three-runs.csv',run_summary)
    stable=stats([r['LocalE2E'] for r in workload]); comms=stats([r['communication_bytes'] for r in e2e])
    cout('e2e/e2e-query-median-summary.csv',[{'metric':'LocalE2E','unit':'ms','n':854,**stable},{'metric':'OnlineCommunication','unit':'bytes','n':854,**comms},{'metric':'OnlineCommunication','unit':'MiB','n':854,**{k:v/MIB for k,v in comms.items()}}])
    for path,keys in [('e2e/e2e-stage-summary.csv',STAGES),('e2e/anchor-stage-summary.csv',PARTS)]:
        cout(path,[{'stage':k,'unit':'ms','n':854,**stats([r[k] for r in workload])} for k in keys])
    cout('token-offline-existing/token-summary.csv',[{'metric':k,'unit':u,'n':854,**stats([r[k] for r in token])} for k,u in [('TokenTimeMedianMs','ms'),('TokenBytesCloud0','bytes'),('TokenBytesCloud1','bytes'),('TotalUserToCloudBytes','bytes')]])
    cout('token-offline-existing/offline-volume-summary.csv',[{'material':k,'unit':u,'n':854,**stats([r[k]/den for r in off])} for k in OFFLINE for u,den in [('bytes',1),('MiB',MIB)]])
    requests=[('K','Routing'),('K','TargetStageSum'),('TargetSlots','LocalE2E'),('TargetSlots','TargetProcessingStageSum'),('AnchorSlots','Anchor'),('AnchorSlots','Filter'),('Routes','Routing'),('Routes','TargetProcessingStageSum')]
    requests+= [(k,t) for k in ['K','Routes','TargetGroups','TargetSlots'] for t in ['TargetStageSum','TargetProcessingStageSum'] if (k,t) not in requests]
    correlations=[corr(workload,*p) for p in requests]; cout('workload/workload-correlation.csv',correlations)
    # Equal quantile edges collapse ties; identical x never split into different bins.
    bins=[]
    for x,ys in [('K',['TargetStageSum']),('TargetSlots',['LocalE2E','TargetStageSum'])]:
        edges=sorted(set(quant([r[x] for r in workload],j/10) for j in range(1,10)))
        groups={}
        for r in workload: groups.setdefault(bisect.bisect_left(edges,r[x]),[]).append(r)
        for y in ys:
            for i,(_,group) in enumerate(sorted(groups.items()),1):
                bins.append({'variable':x,'latency_metric':y,'bin':i,'query_count':len(group),'x_min':min(r[x] for r in group),'x_max':max(r[x] for r in group),'x_median':quant([r[x] for r in group],.5),'latency_median':quant([r[y] for r in group],.5),'latency_P25':quant([r[y] for r in group],.25),'latency_P75':quant([r[y] for r in group],.75),'latency_unit':'ms'})
    cout('workload/workload-binned.csv',bins)
    tails=[]
    for y in ['LocalE2E','TargetStageSum']:
        for p in [.95,.99]:
            selected={r['QueryID'] for r in workload if r[y]>=quant([r[y] for r in workload],p)}
            for x in ['K','Routes','TargetGroups','TargetSlots']:
                high={r['QueryID'] for r in workload if r[x]>=quant([r[x] for r in workload],p)}
                overlap=len(selected&high)
                tails.append({'latency_metric':y,'quantile':p,'work_variable':x,'latency_tail_count':len(selected),'work_tail_count':len(high),'overlap_count':overlap,'latency_tail_overlap_fraction':overlap/len(selected),'tail_work_median':quant([r[x] for r in workload if r['QueryID'] in selected],.5),'all_work_median':quant([r[x] for r in workload],.5)})
    cout('workload/tail-overlap.csv',tails)
    cout('workload/tail-queries.csv',[r for r in workload if r['LocalE2E']>=quant([x['LocalE2E'] for x in workload],.95) or r['TargetStageSum']>=quant([x['TargetStageSum'] for x in workload],.95)])
    # Exact-K inputs only: no phase6 or keep samples enter this table.
    genv=js('results/global-scale-environment.json')
    gmatches={k:sha(ROOT/k)==v for k,v in genv['source_sha256'].items()}
    assert [k for k,v in gmatches.items() if not v]==['internal/discovery/cloud.go']
    cloud=(ROOT/'internal/discovery/cloud.go').read_text()
    old=cloud.replace('\tn := len(st.payload.Slots)\n\tcount := aggregation.NewCount(st.payload.LayoutID, n)','\tcount := aggregation.NewCount(st.payload.LayoutID, aggregation.CandidateCount)').replace('aggregation.DecodeShuffleForDomain(peer, n)','aggregation.DecodeShuffle(peer)').replace('aggregation.DecodeKeepOpeningForDomain(s.send(ko.Encode()), n)','aggregation.DecodeKeepOpening(s.send(ko.Encode()))').replace('candidatequery.EncodeSharesForDomain(st.party, pairs, n)','candidatequery.EncodeShares(st.party, pairs)')
    assert hashlib.sha256(old.encode()).hexdigest()==genv['source_sha256']['internal/discovery/cloud.go']
    assert bh['artifacts/n-domain-regression-pilot-runtime/native/libphase6scmp.a']['sha256']==genv['native_library_sha256']
    exact=[]; exraw=[]; legacy=cr('results/global-scale-summary.csv'); diffs=[]
    for n in [120071,250000,500000,1000000]:
        for tier in ['median','p95','max']:
            path=f'results/global-scale-exact_k-{n}-{tier}.jsonl'; samples=jl(path)
            assert len(samples)==60 and [r['Iteration'] for r in samples]==list(range(60))
            for r in samples:
                assert r['Warmup']==(r['Iteration']<10) and r['N']==n and r['Operator']=='exact_k' and r['Distribution']==tier and r['Status']=='ok'
                assert r['Sent']==r['Received'][::-1] and r['Rounds']==[3,3]
            measured=[r for r in samples if not r['Warmup']]; assert len(measured)==50
            assert len({r['K'] for r in measured})==len({sum(r['Sent']) for r in measured})==1
            ss=stats([r['Milliseconds'] for r in measured]); wire=sum(measured[0]['Sent'])
            row={'N':n,'KLevel':tier,'ActualK':measured[0]['K'],'MeanMs':ss['mean'],'MedianMs':ss['median'],'P95Ms':ss['P95'],'P99Ms':ss['P99'],'OnlineCommunicationBytes':wire,'OnlineCommunicationMiB':wire/MIB,'PeakHeapBytes':max(r['PeakHeapBytes'] for r in measured),'PeakRSSBytes':max(r['PeakRSSBytes'] for r in measured),'WarmupIterations':10,'MeasuredIterations':50}
            exact.append(row)
            for r in measured: exraw.append({'Source':path,'N':n,'KLevel':tier,'Iteration':r['Iteration'],'ActualK':r['K'],'Milliseconds':r['Milliseconds'],'OnlineCommunicationBytes':sum(r['Sent']),'PeakHeapBytes':r['PeakHeapBytes'],'PeakRSSBytes':r['PeakRSSBytes']})
            l=next(r for r in legacy if r['operator']=='exact_k' and int(r['N'])==n and r['distribution']==tier)
            assert math.isclose(float(l['mean_ms']),row['MeanMs'],abs_tol=1e-8)
            assert int(l['communication_bytes'])==wire
            for key,oldkey in [('MedianMs','p50_ms'),('P95Ms','p95_ms'),('P99Ms','p99_ms')]:
                diffs.append({'N':n,'KLevel':tier,'metric':key,'old_nearest_rank':float(l[oldkey]),'new_linear':row[key],'reason':'quantile convention; not raw-data disagreement'})
    cout('exact-k/exact-k-summary.csv',exact); cout('exact-k/exact-k-measured-samples.csv',exraw)
    cout('exact-k/exact-k-by-N.csv',[{k:r[k] for k in ['N','KLevel','ActualK','MeanMs','MedianMs','P95Ms','P99Ms','OnlineCommunicationMiB']} for r in exact])
    cout('provenance/quantile-convention-differences.csv',diffs)
    jout('provenance/version-verification.json',{'calibration_source_files':matches,'exact_k_recorded_files':gmatches,'exact_k_cloud_difference':'Reversing only runParty N-domain changes reproduces recorded SHA256; used endpoint/send/compare unchanged.','raw_parameters_checked':params,'native_matches_global_scale':True})
    # Provision evidence: registration only for 20-80%; no scale aggregations produced.
    provision_paths=[]
    for s in [20,40,60,80]:
        p=f'results/database-scalability-formal-20260920/scale-{s}/round-1/queries.jsonl'
        with (ROOT/p).open() as f: first=json.loads(next(f))
        assert 'ProvisionNS' in first
        provision_paths.append(p)
    regression_path='results/n-domain-regression-pilot-20260920/regression-100-queries.jsonl'
    regression=jl(regression_path); regression=[r for r in regression if r.get('Metrics',{}).get('LocalE2E',0)>0]
    assert len(regression)==854
    provision_stats=stats([r['ProvisionNS']/1e6 for r in regression])
    jout('token-offline-existing/provision-regression-100-summary.json',{'source':regression_path,'field':'ProvisionNS','n':854,'unit':'ms','status':'existing regression evidence, not the three-run calibrated online main result',**provision_stats})
    create_docs(workload,bins,correlations,tails,stable,comms,run_summary,exact,token,off,provision_stats,provision_paths)
    # Preserve exact input hashes plus registration hashes for canonical scale artifacts.
    for p in ['setup-time.csv','storage.csv','audit-v2.md','dataset-scale.csv']:
        INPUTS[DB+'/'+p]=db_hash[DB+'/'+p]
    jout('provenance/input-sha256.json',INPUTS)
    jout('provenance/derivation-map.json',{
        'correctness/':'calibration run-1..3 phase11-queries.json + verified-queries.csv + verification.json + run.log; no synthetic new oracle results',
        'workload/':'calibration aligned by Query; deterministic equality checked; stage-wise median(ns)/1e6; Offline.AnchorPosition/1168 exact integer; ties averaged for Spearman',
        'e2e/':'same calibration raw Metrics; individual runs and 854 query medians are separate populations',
        'token-offline-existing/':'same calibration Offline/UserToCloud/Token plus phase7b-workload qchunk lengths; regression ProvisionNS only separately labeled; formal scale ProvisionNS referenced only',
        'exact-k/':'12 exact_k JSONL cells, only Warmup=false; 50 samples each; peak fields max across measured iterations',
        'database-scale-reference.md':'existing canonical directory reference only, no CSV copied or recomputed',
        'outsourcing-assessment.md':'canonical setup/storage/audit-v2 + previous audit evidence; no scale aggregation',
        'scripts':script})
    doc('provenance/README.md','''# 文件级现场冻结

“当前论文实验版本由实际文件级哈希和输入 manifest 确定，git HEAD 只能作为辅助标识。”

source-sha256.json覆盖当前internal全部文件、tools非缓存文件、go.mod/go.sum及规格文件，包括未提交文件；git-diff.patch额外保留跟踪文件差异，不为clean修改工程。git-status在输出创建前记录，已包含本轮新增整理脚本。
binary-sha256.json记录当前保留实验二进制、native库和sealed binaries，未执行它们；校准运行时build info/环境在dataset.json。文件哈希冻结不是复制全部巨型二进制；原路径仍需保留。
input-sha256.json给出衍生输入，dataset.json给出数据路径、记录规模、现时与运行时哈希，三个manifest保存语义内容并由原文件哈希绑定。当前实现源码对校准172个记录文件逐项验证；Exact-K cloud.go差异核验见version-verification.json。
本轮只执行标准库统计脚本，脚本哈希见statistics-script-sha256.json；仅Git只读命令，无Go test/benchmark。正式数据库规模目录逐文件前后哈希核对，不复制数据表、不重新统计。
输出sha256见output-sha256.json（排除自身避免递归）；输入保护复核见preservation.json。所有源码和读取的原始结果结束时重新哈希验证。
''')
    # Verify immutable inputs before emitting a new directory.
    assert all(sha(ROOT/p)==h for p,h in source_hash.items())
    assert all(sha(ROOT/p)==h for p,h in INPUTS.items())
    assert all(sha(ROOT/p)==h for p,h in db_hash.items())
    jout('provenance/preservation.json',{'verified_utc':datetime.now(timezone.utc).isoformat(),'source_files_unchanged':len(source_hash),'read_inputs_unchanged':len(INPUTS),'database_scale_directory_files_unchanged':len(db_hash),'database_scale_new_files':False,'protocol_or_parameter_changes':False,'experiments_or_tests_run':False,'old_results_overwritten':False})
    jout('validation.json',{'status':'passed','query_id_alignment':True,'total_trace_per_run':1003,'invalid_per_run':149,'valid_per_run':854,'pairs_per_run':1510,'error_counts_zero_verified':True,'deterministic_workload_communication_offline_equal_three_runs':True,'AnchorSlots_exact_division_1168':True,'AnchorParts_same_slower_party_verified':True,'token_length_formula_verified':True,'exact_k_cells':12,'exact_k_warmups_per_cell':10,'exact_k_measured_per_cell':50,'database_scale_recomputed':False,'quantile':'(n-1)p linear interpolation','stage_query_medians_need_not_add_to_outer_median':True})
    jout('provenance/output-sha256.json',{p:hashlib.sha256(v.encode()).hexdigest() for p,v in sorted(FILES.items())})
    OUT.mkdir()
    for path,content in FILES.items():
        p=OUT/path; p.parent.mkdir(parents=True,exist_ok=True)
        with p.open('x') as f:f.write(content)
    print(json.dumps({'directory':str(OUT),'files':len(FILES),'stable_e2e':stable,'run_mean_average_ms':st.mean(r['mean_latency_ms'] for r in run_summary),'communication':comms,'token_median_query_mean_ms':st.mean(r['TokenTimeMedianMs'] for r in token),'offline_raw_body_mean_bytes':st.mean(sum(r[k] for k in OFFLINE) for r in off),'correlations':correlations},ensure_ascii=False,indent=2))

def not_valid(t,ra,rt): return ra<1 or rt<1 or t['Tau']<0 or t['Tau']>=ra or t['Tau']>=rt

def create_docs(workload,bins,correlations,tails,stable,comms,run_summary,exact,token,off,provision_stats,provision_paths):
    doc('source-of-truth.md','''# 论文实验唯一事实源索引

|实验|唯一主事实源及本轮衍生数据|
|---|---|
|1 正确性与过滤效果|results/timing-calibration-20260920/ + 本目录correctness/|
|2 数据库规模扩展性|results/database-scalability-analysis-20260922/；以audit-v2.md及最新CSV为准，本轮不重新计算、不复制|
|3 查询工作负载敏感性|results/timing-calibration-20260920/ + 本目录workload/|
|4 100%完整数据候选发现|results/timing-calibration-20260920/ + 本目录e2e/|
|5 Token与离线已有结果|校准原始Metrics.Token/UserToCloud/Offline + token-offline-existing/；正式规模ProvisionNS仅登记引用，100%regression ProvisionNS单独标注|
|6B Exact-K|results/global-scale-exact_k-*原始JSONL + 现有global-scale汇总用于交叉核验 + 本目录exact-k/统一分位数|
|6A 聚合|当前AnchorParts/历史incidence/当前Keep子算子仅辅助；完整受控机制实验尚缺|
|6C Route+Target|本目录workload/为当前真实工作量事实源，受控联合实验尚缺；是否需要另补见route-target-assessment.md|
|7 方案对比|尚无正式基线；不把布局uniform baseline等当对比协议|

所有相对results路径均相对工程根目录。原始结构化记录优先；本轮输出提供统一统计口径，不覆盖旧报告。数据库规模唯一入口见database-scale-reference.md。
历史约583ms只作历史资产；历史Target bits8及Phase7B成本投影、旧Rust PE、Phase6组件通信都禁止进入当前主性能数据。100%全静态失败部分查询不进入任何本轮统计。100%校准不拼接20%～80%曲线。
''')
    doc('database-scale-reference.md','''# 数据库规模：仅引用

唯一事实源：`results/database-scalability-analysis-20260922/`。
最新审计：`results/database-scalability-analysis-20260922/audit-v2.md`。
最新论文表：`results/database-scalability-analysis-20260922/paper-data.csv`。
图数据仍从该目录的dataset-scale.csv、query-time.csv、query-time-runs.csv、communication.csv、setup-time.csv、storage.csv、workload.csv读取；summary.md为对应说明。

1. 四档20%/40%/60%/80%均完成3×854正式查询（引用既有audit-v2结论，本轮不重新统计）。
2. 100%不进入规模曲线。
3. 最新CSV的`_mb`字段实际表示MiB=bytes/1024²；容量展示GiB=bytes/1024³。
4. 旧十进制MB/GB表与新MiB/GiB禁止混用。
5. 所谓索引构造时间只包含已有明确计时边界的BSMJ与PSMJ构造组件，不能擅自改名完整数据外包时间；total_build_time_s不是全OutSource wall-clock。
6. 静态容量是状态容量核算，不等同于进程RSS。
7. 本轮没有生成第二套规模CSV，没有复制原表；该目录前后全文件哈希保护见provenance/。
''')
    doc('correctness/correctness-notes.md','''# 正确性与过滤链

correctness-summary.csv每行是一轮独立完整回放，不把三轮当3009种不同查询：每轮1003条，149条非法、854条合法、1510个候选对，五类错误均零。
依据：calibration各run-N/work/results/phase11-queries.json、verified-queries.csv、verification.json、run.log；脚本逐Query核对。原始测试internal/discovery/real_native_test.go:TestIntegratedReal先Validate，再让非法输入调用RunLocal入口并要求ErrDomain；发生在token/离线材料消耗及云端消息之前。合法输入逐查询执行真实链路，以独立原始字符串fixture.oracle得到候选pair集合，检查重复/多余pair、集合长度、ID和参考工作量。不在本轮重新执行oracle或协议。

误报/漏报仅表示“安全候选发现结果与可信明文候选发现oracle的差异”。1510是每轮854个合法查询恢复的CandidatePairs总数，不是完成最终编辑距离验证的EJSM结果。终点是Candidate Discovery，非法查询不当空答案计入性能分布。

query-filter-chain.csv每条合法查询一行：NAnchor=120071，其他确定性字段三轮一致。AnchorSlots使用原始Offline.AnchorPosition/1168：每slot两次SCMP，每次两云各284-byte key+1-byte rb，共2*(2*284+2)，另16-byte rho、12-byte两层F2 AND材料，共1168。来源internal/anchorfilter/filter.go:Preprocess、internal/discovery/offline.go:counter/Provision及results/phase7b-reference/phase5b2-scmp-f95.txt的固定Bin7 key长度。脚本对每轮每条执行余数为零检查，失败立即报错；没有取整掩盖错误。
这是按occurrence累计物理slot访问（重复bucket按实际访问次数计），不是distinct slots。不可对加过user masks的phase11-offline-required.json直接套用。filter-summary用854逻辑查询、(n-1)p线性分位数，不把压缩比例命名精确率或召回率。
''')
    mean_runs=st.mean(r['mean_latency_ms'] for r in run_summary)
    doc('e2e/e2e-boundary.md',f'''# 当前100%候选发现计时边界

依据internal/discovery/local.go:RunLocal：start在generate之前，LocalE2E在candidatequery.RecoverForDomain之后。包含Token generation、Token内部DPF生成、token编码与解码、两云在线协议计算、本地Go channel通信等待、CandidatePairs用户端恢复及LocalE2E内其他协调/统计开销。
不包含index construction、prepareStatic、Provision、oracle、文件写盘及最终完整字符串编辑距离验证。验证和首次heap采样在计时外；计时中发生的调度、分配、GC等待仍属于wall时间。两云是同进程goroutine，经本地Go channels传帧；不包含真实广域网/TCP RTT，通信bytes也不含网络链路头。

三轮完整回放平均值分别见e2e-three-runs.csv，三轮均值平均 **{mean_runs:.6f} ms**（约237.614ms）。每Query三轮中位数后再取854查询均值则为 **{stable['mean']:.6f} ms**，是另一种统计量，二者不能互换标签。历史约583ms不进入主结果。
原始三轮逐查询ns完整保留于e2e-three-runs-query-level-ns.csv（本轮复制的是校准测量字段，不是规模实验）。各次完整原JSON继续保留。e2e-query-level.csv提供三次延迟和查询中位数。通信三轮相同，按854逻辑查询统计。

STAGES原名：Token、Anchor、Compaction、Routing、TargetPE、TargetPosition、TargetAggregation、OutputEncoding、Recovery。Cloud与LocalE2E为独立外层计时，另保留于workload和三轮ns表。Anchor是完整Anchor阶段，Filter仅其子项，禁止改名。
AnchorParts原名：Filter、HitB2A、Incidence、FCompare、ZB2A、Alignment、Count、Keep、Other。原始每次AnchorParts来自同一较慢云，本轮校验其确为AnchorPartyParts其中一组，且其和等于Anchor并为两云较大总和。**没有逐分项取两云max**。
本轮对每个字段各自取三轮中位数；因此这些中位数之和不要求等于Anchor中位数，各主阶段和也不要求等于LocalE2E。TargetStageSum=Routing+TargetPE+TargetPosition+TargetAggregation；TargetProcessingStageSum=TargetPE+TargetPosition+TargetAggregation，均为“sum of measured stage timings”，不是独立wall-clock计时点。

完整数据模式加载sealed Target并复用BSMJ；每查询计时外准备所需Anchor incidence/alignment、fresh Provision。正式规模全bucket驻留方式不同，故不能将这里100%放入20%～80%规模曲线。
''')
    bintrend=[]
    for x,y in [('K','TargetStageSum'),('TargetSlots','LocalE2E'),('TargetSlots','TargetStageSum')]:
        b=[r for r in bins if r['variable']==x and r['latency_metric']==y]
        increases=sum(a['latency_median']<=z['latency_median'] for a,z in zip(b,b[1:]))
        bintrend.append({'x':x,'latency':y,'bins':len(b),'nondecreasing_transitions':increases,'transitions':len(b)-1,'first_bin_median_ms':b[0]['latency_median'],'last_bin_median_ms':b[-1]['latency_median']})
    doc('workload/workload-ranking.md','''# 工作量主图选择

样本为854个Query的三轮逐字段中位数。Pearson为原值线性相关，Spearman使用并列值平均秩，无离群值剔除或log转换。

'''+table(correlations,['x','y','Pearson_r','Spearman_rho','n'])+'\n\n分箱趋势：\n\n'+table(bintrend,list(bintrend[0]))+'''

建议两种主图自变量为 **TargetSlots与K**：TargetSlots代表实际目标处理量，和Target阶段和呈很强相关；K代表候选驱动规模，虽相关性弱于Routes/Groups/Slots，仍显示清晰候选规模分层。以TargetSlots→TargetStageSum作机制工作量主图，K→TargetStageSum作候选驱动补充主图；TargetSlots→LocalE2E单列展示Anchor/Compaction等额外开销，不能期待和Target阶段一样严格单调。
Routes、TargetGroups对Target阶段的相关系数也很高；不删除这些数据，数值保留于correlation.csv。选择K而非再放一个高度相关的目标工作量坐标，旨在覆盖候选数量和实际访问量两个概念，并非声称K预测能力最佳。AnchorSlots→Anchor/Filter保留辅助图。

分箱按(n-1)p产生十分位边界，合并重复边界，使用右闭箱（bisect_left），相同x不拆到不同箱，空箱不输出，故K可能少于10箱且样本不等量。所有箱的count和为854；P25/P75也是线性插值。延迟单位ms，workload-query-level.csv所有原名时间列均为ms。该表Filter就是AnchorParts.Filter；相关表使用Filter标识，非整个Anchor。
''')
    relevant=[r for r in correlations if r['y']=='TargetStageSum' and r['x'] in ['K','Routes','TargetGroups','TargetSlots']]
    slotcorr=next(r for r in relevant if r['x']=='TargetSlots')
    assert slotcorr['Pearson_r']>.95 and slotcorr['Spearman_rho']>.95
    targettails=[r for r in tails if r['work_variable']=='TargetSlots']
    doc('route-target-assessment.md','''# Route+Target补测必要性评估

事实源：workload/workload-query-level.csv（校准三轮逐Query中位数）、workload-correlation.csv、workload-binned.csv、tail-overlap.csv。TargetStageSum包含Routing、TargetPE、TargetPosition、TargetAggregation，是“sum of measured stage timings”。

'''+table(relevant,['x','y','Pearson_r','Spearman_rho','n'])+'\n\n'+table(bintrend,list(bintrend[0]))+'\n\nTargetSlots长尾重合：\n\n'+table(targettails,['latency_metric','quantile','latency_tail_count','work_tail_count','overlap_count','latency_tail_overlap_fraction'])+'''

K、Routes、Groups、Slots与目标阶段均呈正相关，Routes/Groups/Slots的Pearson约0.9995、Spearman约0.989～0.990。TargetSlots的P95高工作量集合覆盖目标阶段P95全部43条，P99覆盖全部9条；这支持“在该真实查询集合中，候选驱动目标处理开销随实际处理量增加而呈明显增长趋势”的描述。并非每一对相邻查询延迟严格有序，不能把相关性写成因果或恒定单位成本。

端到端P95长尾只有26/43与TargetSlots的P95重合，端到端P99为9/9；因此**目标处理长尾的关联证据很强，但不能声称所有E2E长尾均由Target量解释**。Anchor工作量、固定域Keep/Compaction、调度等阶段需同时看分段数据；本轮没有做因果归因。

854条真实查询已足以支撑限定在此数据集、冻结参数和本地运行条件下的上述经验趋势，不必为了这句话另跑受控微基准。当前仍不支持独立改变K且固定routes/groups/slots的边际成本、独立变量因果效应、未观察到的高密度K/N、不同布局/网络条件外推；若论文需要这些更强论证，再补固定其他量的联合区间受控实验。

【真实工作负载敏感性已足够，Route+Target受控微基准可选】
''')
    doc('token-offline-existing/provision-existing.md',f'''# 已有Provision证据（不运行新实验）

Provision是总的离线材料准备时间，不是Token时间；当前DPF key生成发生在Token路径。不能用ProvisionNS拆出DPF Gen、SCMP KeyGen、pure Exact-K correlated preprocessing。

20%～80%正式记录各scale-S/round-1、2、3/queries.jsonl保存ProvisionNS，来源internal/discovery/database_scalability_native_test.go:formalScale在dbProvision调用前后取时间。以下只是字段存在检查和路径登记，**本轮不重新汇总这些规模值、不生成第二套规模CSV**：

'''+ '\n'.join('- `'+p.replace('round-1','round-{1,2,3}')+'`' for p in provision_paths)+f'''

100%既有完整回归（不是失败的100%全驻留部分记录）`results/n-domain-regression-pilot-20260920/regression-100-queries.jsonl`有854条ProvisionNS。本轮独立整理于provision-regression-100-summary.json：mean={provision_stats['mean']:.6f}ms，median={provision_stats['median']:.6f}ms，P95={provision_stats['P95']:.6f}ms，P99={provision_stats['P99']:.6f}ms。它是既有单遍回归的离线总准备时间，不能标成三轮校准的离线统计，也不进入主在线结果。

历史`results/phase11-offline-timing.json/txt`由TestOfflineTiming为q292/82/382/538各测一次，仍可查阅但不是854查询离线分布。global-scale的OfflineMilliseconds还包含合成输入/GeneratePayload等，不能解释成Exact-K纯preprocessing。

本轮offline-volume-query-level.csv保存校准原始Offline六类bytes，三轮逐查询相等；summary同时给bytes和MiB。它是两云一次性字段体积，排除用户mask增补、packet元数据/注册表/allocator，不是完整pool磁盘大小，不是在线通信或RSS。不要把历史phase11-offline-required.json（额外加入user masks）的总数与本表混用。
''')
    doc('token-offline-existing/missing-offline-benchmark.md','''# 未测独立生成时间

- standalone DPF Gen：已有internal/dpf128/benchmark_test.go:BenchmarkGen入口，未找到可作当前正式数值的独立结果；TokenTime包括它但不能拆分。
- standalone SCMP KeyGen/material generation：当前真实后端生成材料，但已有体积与Provision总计不能分解出其时间。
- pure Exact-K correlated permutation preprocessing：已有266N字节体积；global-scale OfflineMilliseconds包含输入fixture生成，不是纯预处理时间。

本轮均未运行。若继续原实验5独立生成时间要求，这三项为小型分项测量，建议放同一离线专项；不需重跑854查询完整链路。单独DPF matching/EvalBucket辅助图则无当前主论证的必要，可选。
''')
    doc('exact-k/exact-k-notes.md','''# Exact-K正式算子结果

原始12格results/global-scale-exact_k-{N}-{median,p95,max}.jsonl；每格10预热+50正式，完整Iteration 0..59、Warmup、Status、N/K、双向通信/3轮交互均校验。统计排除预热；通信=sum(Sent[0:2])，不再加Received。峰值为50次正式记录PeakHeapBytes/PeakRSSBytes的最大值，与现有汇总口径一致。
KLevel为既有median/p95/max候选比例档名，ActualK为每格真实K，不因本轮改用线性分位数而重选K或更改实验参数。N为120071/250000/500000/1000000。exact-k-by-N为同12点长表供绘图，measured-samples保留600条正式观测及原始来源路径。

每格所有延迟分位数本轮使用(n-1)p线性插值；旧global-scale表nearest-rank保留，差异列在provenance/quantile-convention-differences.csv。均值与通信与旧汇总一致。旧Phase6数据不进入本表。
当前结果对应当前Exact-K算子：global-scale测试/compaction/codec等记录哈希匹配；cloud.go差异仅runParty N域适配，反向恢复后匹配旧哈希，算子使用的endpoint/send/compare不变；详细核验见provenance/version-verification.json。

PeakHeap/PeakRSS是两云同一进程整体采样，10ms与边界采样，包含准备材料、benchmark输入和运行时；不是单云、不是增量、也非连续采样保证的真实绝对峰值。资源txt中的进程生命周期maximum RSS是另一口径，未混入此表。online计时排除offline准备、输入构造、计时前GC及正确性检查；不能把它称完整查询E2E。没有从OfflineMilliseconds提取纯Exact-K材料生成时间。
''')
    doc('outsourcing-assessment.md','''# 是否补完整OutSource

唯一规模事实源仍为results/database-scalability-analysis-20260922/：setup-time.csv、storage.csv、dataset-scale.csv及audit-v2.md；本轮只引用，不重算、不复制这些表。

|内容|当前证据/口径|
|---|---|
|BSMJ构造时间|setup-time.csv的anchor_build_time_s，计时indexbuild.Build|
|PSMJ构造时间|setup-time.csv的target_build_time_s，计时BuildFinalTarget|
|payload构造|已在原正式scale-S/static.json的scale.PayloadBuildNS保存，前轮审计已确认；不属于setup-time.csv总时间|
|sidecar构造|原正式static.json的scale.SidecarBuildNS，前轮审计确认|
|Anchor静态辅助构造|原正式static.json的static_construction_ns，前轮审计确认；不在索引时间总计|
|两云静态容量|storage.csv的逐云/合计bytes、GiB；BSMJ/incidence/alignment语义字段+Target sealed bytes，不是RSS|
|padding amplification|dataset-scale.csv有各索引real postings/padded slots；指标定义padded/real，前轮审计有核算证据；本轮不生成新规模数值|
|统一完整OutSource wall-clock|没有统一外层计时覆盖全部构造、编码、准备/交付|
|完整DO→CS实际wire bytes|缺完整序列化交付/实测通信记录；不能拿静态容量直接改名wire|

依据还包括results/experiment-completion-audit-20260922.md及internal/discovery/database_regression_pilot_native_test.go:dbBuild、database_scalability_native_test.go:formalStatic/formalScale。每档一次构造、三轮在线复用；不能写成构造也重复三次。

**若论文只写“index construction cost + static storage overhead”：现有数据足够，可取消完整OutSource补测。**索引cost严格限定setup-time.csv原边界，静态storage严格限定accounting，payload/sidecar/辅助状态作为已测组件说明，不合成未测完整wall time。建议采用这一已被证据支持的口径，不因重命名而声称完成外包实验。

**若论文一定保留“complete data outsourcing cost”：仍需补统一OutSource外层wall-clock及完整DO→CS实际wire bytes。**必须明确是否含序列化、装载、辅助状态和交付，并记录重复次数/环境；已有组件之和不包含计时缝隙，实际静态field容量也不是wire。该强口径未完成，本轮未补测。
''')
    doc('remaining-experiments.md','''# 最小剩余实验（没有启动）

|候选|状态|理由/范围|
|---|---|---|
|A 独立离线材料生成时间|【必须补】|若完成既定实验5，补standalone DPF Gen、SCMP material generation、pure Exact-K correlated permutation三个分项，可合为一个小型离线专项；现有Token/Provision总体不可分解|
|B 当前完整安全记录聚合受控微基准|【必须补】|冻结实验6A主体仍缺；历史B2A/incidence和当前Keep/Anchor分段不能替代完整聚合随T/D/DT变化曲线|
|C Route+Target联合受控微基准|【可选】|854真实工作量已呈很强相关和目标长尾重合，足以支撑限定真实数据的增长趋势；仅独立变量边际效应、因果/外推论证需要补|
|D 完整OutSource wall-clock/wire|【已有数据足够，可取消】|针对建议采用的“index construction cost + static storage overhead”口径；若坚持完整OutSource标题则升级为【必须补】，当前没有完成该强口径|
|E 方案对比基线|【必须补】|若完成七组计划中的实验7，需先实现/适配所选基线再测；目前没有正式对比结果，是仍缺的大型实验，本轮暂不开始|
|F 可选DPF matching/Eval辅助微基准|【可选】|不是解释当前端到端或目标处理趋势的必需图；不能与A中为了完成实验5而需要的DPF Gen分项混淆|

不需要重跑：实验1正确性、20%～80%在线三轮、实验3真实工作负载、100%校准三轮、Exact-K四档。100%全静态正式扩展失败不列入冻结20%～80%规模计划的必补项；不使用其部分查询。
实际最小新运行集合为一个离线生成专项（3分项）、一个完整聚合微基准专项，以及后续方案对比。Route+Target和完整OutSource依上述论文论证范围可以取消；这是口径建议，不是声称它们已经被受控/完整测量。
''')
    doc('provenance/statistical-notes.md','''# 统计与衍生字段规范

时间原始ns，当前展示ms=ns/10^6；global-scale原生Milliseconds直接使用。bytes保留原值，MiB=bytes/1024²，GiB=bytes/1024³；禁止十进制MB/GB混入。所有本轮新表分位数(n−1)p线性插值；旧nearest-rank报告保留不覆盖。
三轮按QueryID对齐：每轮独立分布与854查询逐字段中位数分布分别保留。确定性工作量/通信/Offline必须三轮完全一致，否则报错而不是平均。非法149只进入拒绝统计。
工作量、通信及三轮中位数表均n=854；Exact-K每格正式n=50，不包含10预热。Pearson原值，Spearman并列值平均秩；不剔除离群点、不预先log变换。P95/P99 tail集合使用大于等于插值阈值，重合率分母为延迟tail数；不属于准确率或因果解释比例。
每个stage先按Query取三轮中位数，TargetStageSum再相加；这是sum of measured stage timings，不等于“每轮先加再取中位数”，不等于任何外层wall。AnchorParts每次来源同一较慢云，跨轮每项分别取中位数，故总和不再强制等于Anchor中位数。
''')
    doc('provenance/conflicts.md','''# 与既有报告的对照

当前校准三轮结构化结果仍为854合法/149拒绝/1510 pairs，每轮日志和verification一致。Exact-K均值和通信与既有global-scale-summary.csv逐格核对一致，未发现这些主数值冲突。
旧global-scale分位数nearest-rank与本轮线性插值不同，详细对照quantile-convention-differences.csv，属于统计定义差异，不是改动原始数据。历史约583ms不与当前约237.614ms合并或计算加速比。
“每轮均值再平均”与“每Query三轮中位数后平均”是不同总体定义；两者均保留，后者不能改称237.614ms。Anchor各分项中位数和不必等于Anchor中位数，不能视作数据错误。
原始Offline体积不包含历史phase11-offline-required.json补入的用户mask，不直接比较两个总数。旧审计将Route+Target列为待补；本轮有854查询相关性证据后判断受控补测可选，详见assessment，不是篡改历史审计。
数据库规模既有报告没有在本轮重新复算；其数值一致性沿用audit-v2.md，不能声称本轮重验规模统计。无法确认的历史环境归因维持“无法确认”。
''')
    doc('README.md',f'''# PMEQ论文性能结果集（2026-09-22）

本目录由`tools/整理_paper_evaluation_20260922.py`读取已有结构化测量生成。仅做冻结、验证和统计；未运行benchmark/test、未改协议/参数、未重建数据库、未删除/覆盖旧结果。原始输入与脚本/源码/二进制/参数哈希见provenance/。脚本拒绝已有输出目录，避免覆盖。

## 当前完成状态

正确性、四档规模在线查询、真实工作负载、100%在线候选发现、Token体积/时间、Exact-K均已有可写作/作图数据。Token/离线仍缺独立生成时间，完整聚合机制仍缺当前受控实验；方案对比尚未开始。Route+Target真实工作量证据已足够，其受控实验可选；以索引构造+静态容量口径写作则不需完整OutSource补测。剩余不是重跑整套实验：先一个离线专项含3小分项，再一个聚合微基准；大型缺口是实验7基线实现与测量。若坚持完整OutSource强口径，还有该专项缺口。

## 当前核心口径

100%正式在线候选发现用三轮独立完整校准：每轮854合法、149拒绝、1510 CandidatePairs，三轮均值平均{mean_runs:.6f}ms。工作负载/分布/阶段图使用每Query三轮中位数，854个中位数的均值为{stable['mean']:.6f}ms，中位数{stable['median']:.6f}ms，P95={stable['P95']:.6f}ms，P99={stable['P99']:.6f}ms；不同于三轮均值平均。
平均在线通信{comms['mean']:.6f}bytes={comms['mean']/MIB:.6f}MiB，三轮逐查询一致。两云双向总发送量已在ServerBytes计一次，不再乘2。输出终点为CandidatePairs用户端恢复，不含最终字符串编辑距离验证。
Exact-K使用global-scale-exact_k的4个N×3个K档，每格10预热+50正式；本轮统一线性分位数，旧Phase6不进入新表。

## 未来图表输入映射

|未来图/表|直接读取|
|---|---|
|正确性结论|correctness/correctness-summary.csv（每轮一行，不重复计逻辑查询）|
|过滤链/压缩工作量|correctness/query-filter-chain.csv、filter-summary.csv|
|规模记录/发布项/padding|既有results/database-scalability-analysis-20260922/dataset-scale.csv|
|规模查询延迟与三轮|同既有目录query-time.csv、query-time-runs.csv|
|规模通信、索引构造、静态容量|同既有目录communication.csv、setup-time.csv、storage.csv|
|规模工作量及论文总表|同既有目录workload.csv、paper-data.csv；audit-v2.md为最新审计|
|K/TargetSlots敏感性散点与分箱|workload/workload-query-level.csv、workload-binned.csv；相关性见workload-correlation.csv|
|长尾工作量对照|workload/tail-overlap.csv、tail-queries.csv|
|100%三轮延迟|e2e/e2e-three-runs.csv|
|100%查询分布/通信|e2e/e2e-query-level.csv、e2e-query-median-summary.csv|
|主阶段/Anchor子阶段|e2e/e2e-stage-summary.csv、anchor-stage-summary.csv|
|Token时间/大小|token-offline-existing/token-query-level.csv、token-summary.csv|
|离线六类字段体积|token-offline-existing/offline-volume-query-level.csv、offline-volume-summary.csv|
|Exact-K随N、K变化|exact-k/exact-k-by-N.csv、exact-k-summary.csv；600正式样本见exact-k-measured-samples.csv|

数据库规模只引用既有目录，无第二套规模CSV。100%按查询准备Anchor辅助状态与正式全bucket驻留不同，不拼成第五档。

## 单位、分位数与语义

所有新表分位数统一(n−1)p线性插值，旧nearest-rank文档不覆盖。时间ms，e2e-three-runs-query-level-ns.csv例外明确为ns；workload中原计时点名字不改，时间列均ms。通信保留bytes并展示MiB=bytes/1024²。规模旧十进制MB/GB不进入本轮，最新`_mb`字段含义沿用MiB；静态GiB不是RSS。
主阶段Token/Anchor/Compaction/Routing/TargetPE/TargetPosition/TargetAggregation/OutputEncoding/Recovery均为原计时字段；Anchor不能改名Filter。TargetStageSum及TargetProcessingStageSum仅“sum of measured stage timings”；不能视作独立wall-clock。每字段中位数之和无需等于LocalE2E。Anchor分项每次来自同一较慢云，未独立max；详见e2e-boundary.md。
149非法只参与拒绝正确性；五类错误为相对plaintext candidate oracle，不是最终编辑距离真实匹配错误。相关性不作因果解释；分箱重复边界合并，箱数约10。Pearson原值、Spearman并列平均秩。

## 历史隔离

禁止混入历史583ms、Target bits8、旧Rust PE、Phase7B组件投影、旧Phase6计时/逻辑通信、1003条含非法仍做上游处理的旧工作量、100%全静态失败部分记录、pilot/smoke。当前regression-100 Provision仅单独补充已有离线证据，不替代三轮在线校准。Exact-K峰值内存为双云同进程整体采样，非单云增量。

## 最终简表

|实验|状态|
|---|---|
|实验1 正确性|【完成，可直接写论文】|
|实验2 数据库规模|【完成，只差画图】|
|实验3 工作负载|【完成，只差画图】|
|实验4 100%端到端|【完成，只差画图】|
|实验5 Token/离线|【已有主体数据，仍缺少量实验】|
|实验6A 聚合|【需要补实验】|
|实验6B Exact-K|【完成，只差画图】|
|实验6C Route+Target|【完成，只差画图】|
|实验7 方案对比|【暂未开始】|

实验2完成状态限已确认索引构造/静态容量/在线三轮；不暗示完整OutSource已测。实验6C完成状态限真实工作负载敏感性论证；不暗示受控联合微基准已执行。后续最小补测及条件见remaining-experiments.md。
''')

if __name__=='__main__': main()
