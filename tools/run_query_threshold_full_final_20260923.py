"""Run and audit both maximal legal threshold query sets."""
import csv
import gzip
import hashlib
import json
import os
from pathlib import Path
import shlex
import statistics
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'results/query-threshold-full-final-20260923'
RAW = Path('/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump')
GO = ROOT/'artifacts/n-domain-regression-pilot-runtime/go/bin/go'
MODCACHE = ROOT/'artifacts/n-domain-regression-pilot-runtime/modcache'
NATIVE = ROOT/'artifacts/n-domain-regression-pilot-runtime/native'


def digest(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda:f.read(4*1024*1024),b''):h.update(block)
    return h.hexdigest()


def write(name,s):
    with (OUT/name).open('x',encoding='utf-8') as f:f.write(s)


def readcsv(name):
    with (OUT/name).open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))


def writecsv(name,rows):
    with (OUT/name).open('x',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)


def query_sets():
    with gzip.open(ROOT/'results/phase7b-workload.jsonl.gz','rt',encoding='utf-8') as f: trace=[json.loads(line) for line in f]
    refs=json.loads((ROOT/'results/phase10b-queries.json').read_text())
    assert len(trace)==len(refs)==1003
    legal=[]
    for q in trace:
        if refs[q['Query']]['Rejected']:continue
        ar,tr=len(q['Anchor'])//4,len(q['Target'])//4
        assert q['Tau']<ar and q['Tau']<tr and ar<=14 and tr<=16
        legal.append(dict(query_id=q['Query'],anchor=q['Anchor'],target=q['Target'],original_tau=q['Tau'],anchor_signatures=ar,target_signatures=tr))
    assert len(legal)==854 and len({q['query_id'] for q in legal})==854
    a=sorted((q for q in legal if q['anchor_signatures']>=4 and q['target_signatures']>=2),key=lambda x:x['query_id'])
    t=sorted((q for q in legal if q['target_signatures']>=4 and q['anchor_signatures']>=2),key=lambda x:x['query_id'])
    for side,rows in (('anchor',a),('target',t)):
        for q in rows:
            for tau in range(4):
                at,gt=(tau,1) if side=='anchor' else (1,tau)
                assert at<q['anchor_signatures'] and gt<q['target_signatures']
    assert len(a)==69 and len(t)==152
    return [dict(label='AnchorThresholdSet',original_query_count=854,query_count=len(a),q=4,bucket_bits=16,queries=a),dict(label='TargetThresholdSet',original_query_count=854,query_count=len(t),q=4,bucket_bits=16,queries=t)]


def expected_cases(sets):
    cases=[]
    for side,s in zip(('anchor','target'),sets):
        for q in s['queries']:
            for tau in range(4):
                at,gt=(tau,1) if side=='anchor' else (1,tau)
                cases.append(dict(case_id=len(cases),query_id=q['query_id'],variation_side=side,anchor_r=q['anchor_signatures'],target_r=q['target_signatures'],anchor_tau=at,target_tau=gt))
    return cases


def merge_shards():
    for name in ('candidate-raw.csv','correctness.csv'):
        rows=[]
        for i in range(4):
            with (OUT/'shards'/str(i)/name).open(newline='',encoding='utf-8') as f:rows.extend(csv.DictReader(f))
        rows.sort(key=lambda r:(int(r['case_id']),int(r['trial']) if name=='candidate-raw.csv' else 0))
        writecsv(name,rows)


def audit(sets,cases):
    raw=readcsv('candidate-raw.csv'); checks=readcsv('correctness.csv')
    assert len(cases)==4*(69+152)==884
    assert len(raw)==3*len(cases)==2652 and len(checks)==len(cases)
    by={}; packets=set(); cb={}
    for row in raw:
        key=(int(row['case_id']),int(row['trial']))
        assert key not in by and 0<=key[0]<len(cases) and key[1] in (1,2,3)
        c=cases[key[0]]
        assert all(str(row[k])==str(c[k]) for k in c)
        assert int(row['candidate_discovery_ns'])>0
        assert int(row['online_bytes'])==sum(int(row[k]) for k in ('user_to_cloud_bytes','cs_to_cs_bytes','cloud_to_user_bytes'))
        assert int(row['candidate_pair_count'])==int(row['oracle_pairs'])
        assert all(int(row[k])==0 for k in ('missing_candidate','extra_candidate','duplicate_candidate','wrong_anchor_id','wrong_target_id'))
        assert row['packet_id_sha256'] not in packets
        packets.add(row['packet_id_sha256'])
        by[key]=row
    assert by.keys()=={(i,j) for i in range(len(cases)) for j in (1,2,3)}
    for row in checks:
        i=int(row['case_id']);assert i not in cb and 0<=i<len(cases)
        c=cases[i];assert all(str(row[k])==str(c[k]) for k in c)
        assert row['all_three_equal_oracle']=='true'
        assert all(int(row[k])==0 for k in ('missing_candidate','extra_candidate','duplicate_candidate','wrong_anchor_id','wrong_target_id'))
        assert all(int(row[f'trial{j}_pairs'])==int(row['oracle_pairs']) for j in (1,2,3))
        cb[i]=row
    assert cb.keys()==set(range(len(cases)))
    med=[]
    for c in cases:
        rows=[by[c['case_id'],j] for j in (1,2,3)]
        assert len({r['pair_sha256'] for r in rows})==1
        assert rows[0]['pair_sha256']==cb[c['case_id']]['oracle_pair_sha256']
        med.append(dict(**c,candidate_discovery_ms=statistics.median(int(r['candidate_discovery_ns']) for r in rows)/1e6,
                        online_bytes=statistics.median(int(r['online_bytes']) for r in rows),K=statistics.median(int(r['K']) for r in rows),
                        route_count=statistics.median(int(r['route_count']) for r in rows),target_slots=statistics.median(int(r['target_slots']) for r in rows),
                        candidate_pair_count=statistics.median(int(r['candidate_pair_count']) for r in rows)))
    writecsv('query-medians.csv',med)
    summary=[]
    for side,s in zip(('anchor','target'),sets):
        expected_ids={q['query_id'] for q in s['queries']}
        assert len(expected_ids)==s['query_count']
        for tau in range(4):
            vals=[r for r in med if r['variation_side']==side and (r['anchor_tau'] if side=='anchor' else r['target_tau'])==tau]
            assert len(vals)==s['query_count'] and {r['query_id'] for r in vals}==expected_ids
            base=dict(variation_side=side,anchor_tau=tau if side=='anchor' else 1,target_tau=tau if side=='target' else 1,query_count=len(vals))
            summary.append(dict(**base,mean_candidate_discovery_ms=statistics.mean(r['candidate_discovery_ms'] for r in vals),
                mean_online_mib=statistics.mean(r['online_bytes'] for r in vals)/(2**20),mean_K=statistics.mean(r['K'] for r in vals),
                mean_route_count=statistics.mean(r['route_count'] for r in vals),mean_target_slots=statistics.mean(r['target_slots'] for r in vals),
                mean_candidate_pair_count=statistics.mean(r['candidate_pair_count'] for r in vals)))
    writecsv('summary.csv',summary)
    return summary,sum(int(r['oracle_pairs'])==0 for r in checks)


def main():
    assert not OUT.exists(),f'Refusing to overwrite {OUT}'
    assert GO.is_file() and MODCACHE.is_dir() and (NATIVE/'libphase6scmp.a').is_file()
    formal=json.loads((ROOT/'results/database-scalability-formal-20260920/environment.json').read_text())
    rawhash={n:digest(RAW/n) for n in ('area','area_alias')}
    assert rawhash==formal['raw_sha256']
    sets=query_sets();cases=expected_cases(sets)
    print(f"PREFLIGHT original_query_count=854 anchor_threshold_query_count={sets[0]['query_count']} target_threshold_query_count={sets[1]['query_count']}",flush=True)
    OUT.mkdir(mode=0o700)
    for name,s in zip(('anchor-query-set.json','target-query-set.json'),sets):write(name,json.dumps(s,indent=2,ensure_ascii=False)+'\n')
    with tempfile.TemporaryDirectory(prefix='pmeq-threshold-full-') as temp:
        rt=Path(temp)
        for n in ('cache','gopath','tmp'):(rt/n).mkdir()
        env={k:v for k,v in os.environ.items() if not k.startswith(('PMEQ_','GO','CGO'))}
        env.update(GOROOT=str(GO.parents[1]),GOMODCACHE=str(MODCACHE),GOPATH=str(rt/'gopath'),GOCACHE=str(rt/'cache'),GOTMPDIR=str(rt/'tmp'),TMPDIR=str(rt/'tmp'),GOPROXY='off',GOSUMDB='off',GOTOOLCHAIN='local',GOENV='off',GOFLAGS='',GOMAXPROCS='8',GOGC='100',GOMEMLIMIT='off',GODEBUG='',CGO_ENABLED='1',CGO_CFLAGS='',CGO_CPPFLAGS='',CGO_CXXFLAGS='',CGO_LDFLAGS=f'-L{NATIVE} -lphase6scmp -lcrypto -pthread',PMEQ_THRESHOLD_FULL_ROOT=str(OUT),PMEQ_THRESHOLD_FULL_SHARD_COUNT='4')
        binary=rt/'threshold-full.test'
        build=[str(GO),'test','-tags','phase6native','-c','-o',str(binary),'./internal/discovery']
        run=[str(binary),'-test.run=^TestThresholdFullFinalCandidateDiscovery$','-test.count=1','-test.v','-test.timeout=12h']
        write('run-command.txt','Entry point: python3 tools/run_query_threshold_full_final_20260923.py\nBuild: '+shlex.join(build)+'\nRun per shard: '+shlex.join(run)+'\nShard env: PMEQ_THRESHOLD_FULL_SHARD_COUNT=4; PMEQ_THRESHOLD_FULL_SHARD_INDEX=0,1,2,3; query_id modulo 4; GOMAXPROCS=8 per shard\n')
        with (OUT/'build.log').open('x') as log:b=subprocess.run(build,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
        if b.returncode:raise RuntimeError('build failed; see build.log')
        (OUT/'shards').mkdir()
        with (OUT/'run.log').open('x') as log:
            log.write('BEGIN threshold full candidate discovery\n');log.flush()
            children=[]
            for i in range(4):
                dest=OUT/'shards'/str(i);dest.mkdir()
                shenv=dict(env,PMEQ_THRESHOLD_FULL_OUTPUT=str(dest),PMEQ_THRESHOLD_FULL_SHARD_INDEX=str(i))
                h=(dest/'run.log').open('x')
                children.append((i,subprocess.Popen(run,cwd=ROOT/'internal/discovery',env=shenv,stdout=h,stderr=subprocess.STDOUT),h))
            failed=[]
            for i,p,h in children:
                code=p.wait();h.close();log.write(f'shard {i} exit={code}\n');log.flush()
                if code:failed.append(i)
            if failed:raise RuntimeError(f'shards failed: {failed}; see shards/*/run.log')
            merge_shards();log.write('END; merged raw records\n');log.flush()
        summary,zeros=audit(sets,cases)
        files=['anchor-query-set.json','target-query-set.json','candidate-raw.csv','query-medians.csv','summary.csv','correctness.csv','run-command.txt','build.log','run.log']
        sources=['internal/discovery/threshold_full_final_native_test.go','internal/discovery/threshold_candidate_experiment_native_test.go','internal/discovery/real_native_test.go','internal/discovery/signature_candidate_experiment_native_test.go','internal/discovery/token.go','internal/discovery/local.go','internal/discovery/offline.go','internal/anchorfilter/filter.go','tools/run_query_threshold_full_final_20260923.py','results/phase7b-workload.jsonl.gz','results/phase10b-queries.json','artifacts/phase7b/manifest.json','artifacts/phase7b/payload-manifest.json','artifacts/phase10b/manifest.json']
        prov=dict(status='passed',original_query_count=854,anchor_threshold_query_count=69,target_threshold_query_count=152,case_count=884,formal_run_count=2652,zero_candidate_cases=zeros,selection='all original legal queries satisfying side-specific r bounds; no sampling',timing_boundary='Metrics.Cloud + Metrics.Recovery',raw_database_sha256=rawhash,source_sha256={s:digest(ROOT/s) for s in sources},output_sha256={s:digest(OUT/s) for s in files},binary_sha256=digest(binary),shard_rule='query_id modulo 4',shard_count=4)
        write('provenance.json',json.dumps(prov,indent=2,ensure_ascii=False)+'\n')
        write('notes.md','# 编辑距离阈值对 PMEQ 候选发现性能影响：正式全量实验\n\n原始正式合法查询 854 条；AnchorThresholdSet 69 条，TargetThresholdSet 152 条。分别采用全部满足本侧四档阈值合法性条件的查询，不抽样、不取交集。\n\n固定 q=4、B=2^16，保持正式索引和协议。每个查询配置三轮，每轮重新 Provision 并由 RunLocal 生成新 token；计时从两云取得 token 到用户恢复候选记录对，采用 Metrics.Cloud + Metrics.Recovery。明文候选集合按每个阈值配置重新计算并逐轮核对。\n\n统计先取逐查询三轮中位数，再对同档完整查询集求平均。两侧查询集不同，仅比较各组内部的阈值变化。\n\n自动审计通过：884 个查询配置，2652 次完整运行；全部正确，无缺失、额外、重复或静默跳过。零候选配置按原样保留，实际数量见 provenance.json。\n')
        print('AUDIT PASSED: 854 original, 69 anchor, 152 target, 884 cases, 2652 runs, all correct',flush=True)
        print(json.dumps(summary,ensure_ascii=False),flush=True)

if __name__=='__main__':main()
