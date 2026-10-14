"""Recover mechanism data from immutable formal raw results; refuse existing outputs."""
import csv
import hashlib
import json
from pathlib import Path
import statistics

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'results/paper-mechanism-supplement-final-20260924'
PLOT=OUT/'plot-data'
SCALE=ROOT/'results/database-scalability-formal-20260920'
ANALYSIS=ROOT/'results/database-scalability-analysis-20260922'
THRESH=ROOT/'results/query-threshold-full-final-20260923'
SIGN=ROOT/'results/query-signature-full-final-20260923'
SCALES=(20,40,60,80)
GI=2**30


def readcsv(p):
    with p.open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))


def savecsv(p,rows):
    assert rows and not p.exists(),p
    with p.open('x',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def check_close(a,b,eps=1e-6):
    assert abs(float(a)-float(b))<=eps,(a,b)


def index_data():
    records=[];store=[];con=[]
    prev_times={int(r['scale_pct']):r for r in readcsv(ANALYSIS/'setup-time.csv')}
    prev_storage={int(r['scale_pct']):r for r in readcsv(ANALYSIS/'storage.csv')}
    prev_post={int(r['scale_pct']):r for r in readcsv(ANALYSIS/'dataset-scale.csv')}
    for scale in SCALES:
        s=json.loads((SCALE/f'scale-{scale}'/'static.json').read_text())['scale']
        b,p,t=(int(s[k]) for k in ('AnchorBuildNS','TargetBuildNS','IndexBuildNS'))
        assert abs(b+p-t)<=1
        assert int(s['AnchorIndex']['PaddedSlots'])==int(prev_post[scale]['bsmj_padded_slots'])
        assert int(s['TargetIndex']['PaddedSlots'])==int(prev_post[scale]['psmj_padded_slots'])
        check_close(b/1e9,prev_times[scale]['anchor_build_time_s'],1e-9)
        check_close(p/1e9,prev_times[scale]['target_build_time_s'],1e-9)
        check_close(t/1e9,prev_times[scale]['total_build_time_s'],1e-9)
        d=s['Static'];assert set(d)=={'BSMJ semantic fields','PSMJ sealed bytes','Anchor alignment full-domain factors','Anchor incidence full-domain fields','Global payload sealed bytes','Target aggregation sealed bytes','Public manifests'}
        bbytes=sum(d['BSMJ semantic fields']);pbytes=sum(d['PSMJ sealed bytes'])
        auxbytes=sum(sum(v) for k,v in d.items() if k not in ('BSMJ semantic fields','PSMJ sealed bytes'))
        totalbytes=sum(sum(v) for v in d.values())
        assert bbytes+pbytes+auxbytes==totalbytes==int(prev_storage[scale]['total_static_bytes'])
        check_close(totalbytes/GI,prev_storage[scale]['total_static_gib'],1e-12)
        records.append(dict(scale=scale,trial=1,anchor_records=s['AnchorInput']['UsableRows'],target_records=s['TargetInput']['UsableRows'],
            bsmj_construction_ms=b/1e6,psmj_construction_ms=p/1e6,shared_auxiliary_ms='',total_construction_ms=t/1e6,
            bsmj_padded_postings=s['AnchorIndex']['PaddedSlots'],psmj_padded_postings=s['TargetIndex']['PaddedSlots']))
        con.append(dict(scale=scale,measurement_count=1,mean_bsmj_construction_ms=b/1e6,median_bsmj_construction_ms=b/1e6,
            mean_psmj_construction_ms=p/1e6,median_psmj_construction_ms=p/1e6,mean_total_construction_ms=t/1e6,median_total_construction_ms=t/1e6,
            bsmj_padded_postings=s['AnchorIndex']['PaddedSlots'],psmj_padded_postings=s['TargetIndex']['PaddedSlots']))
        store.append(dict(scale=scale,bsmj_storage_gib=bbytes/GI,psmj_storage_gib=pbytes/GI,shared_aux_storage_gib=auxbytes/GI,total_static_storage_gib=totalbytes/GI,
            bsmj_storage_bytes=bbytes,psmj_storage_bytes=pbytes,shared_aux_storage_bytes=auxbytes,total_static_storage_bytes=totalbytes))
    savecsv(OUT/'index-construction-raw.csv',records)
    savecsv(OUT/'index-construction-summary.csv',con)
    savecsv(OUT/'index-storage-summary.csv',store)
    savecsv(PLOT/'index-construction-plot.csv',[dict(scale=r['scale'],bsmj_construction_ms=r['mean_bsmj_construction_ms'],psmj_construction_ms=r['mean_psmj_construction_ms'],total_construction_ms=r['mean_total_construction_ms']) for r in con])
    savecsv(PLOT/'index-storage-plot.csv',[{k:r[k] for k in ('scale','total_static_storage_gib','bsmj_storage_gib','psmj_storage_gib','shared_aux_storage_gib')} for r in store])
    return con,store


def scale_queries():
    summary=[];all_medians=[]
    old_times={int(r['scale_pct']):float(r['three_run_mean_ms']) for r in readcsv(ANALYSIS/'query-time-summary.csv')}
    old_bytes={int(r['scale_pct']):r for r in readcsv(ANALYSIS/'communication.csv')}
    old_work={int(r['scale_pct']):r for r in readcsv(ANALYSIS/'workload.csv')}
    fields={'candidate_discovery_ms':('Cloud_ns','Recovery_ns'),'anchor_processing_ms':('Anchor_ns',),
            'candidate_compaction_ms':('Compaction_ns',),'private_routing_ms':('Routing_ns',),
            'target_index_matching_ms':('TargetPE_ns',),'target_position_filtering_ms':('TargetPosition_ns',),
            'target_record_aggregation_ms':('TargetAggregation_ns',)}
    for scale in SCALES:
        by={};all_rows=[]
        for trial in (1,2,3):
            rows=readcsv(SCALE/f'scale-{scale}'/f'round-{trial}'/'queries.csv')
            assert len(rows)==854
            ids=set()
            for row in rows:
                q=int(row['query']);assert q not in ids and 0<=q<1003;ids.add(q)
                assert int(row['scale'])==scale and int(row['round'])==trial
                assert all(int(row[k])==0 for k in ('FP','FN','duplicates','wrong_AnchorID','wrong_TargetID'))
                assert int(row['final_pairs'])==int(row['oracle_pairs'])
                assert int(row['total_online_bytes'])==sum(int(row[k]) for k in ('user_cs0_bytes','user_cs1_bytes','cs0_user_bytes','cs1_user_bytes','intercloud_bytes'))
                by.setdefault(q,[]).append(row);all_rows.append(row)
        assert len(by)==854 and all(len(v)==3 for v in by.values())
        got=[]
        for q,rows in sorted(by.items()):
            assert [int(r['round']) for r in rows]==[1,2,3]
            keys=('anchor_query','target_query','tau_anchor','tau_target','N','K','routes','groups','target_slots','final_pairs','oracle_pairs','total_online_bytes')
            assert all(tuple(r[k] for k in keys)==tuple(rows[0][k] for k in keys) for r in rows[1:])
            med=dict(scale=scale,query_id=q)
            for name,cols in fields.items():med[name]=statistics.median(sum(int(r[c]) for c in cols) for r in rows)/1e6
            med['target_stage_ms']=med['target_index_matching_ms']+med['target_position_filtering_ms']+med['target_record_aggregation_ms']
            for name,col in (('online_bytes','total_online_bytes'),('K','K'),('route_count','routes'),('target_slots','target_slots'),('candidate_pair_count','final_pairs')):
                med[name]=statistics.median(int(r[col]) for r in rows)
            got.append(med)
        all_medians.extend(got)
        check_close(statistics.mean(int(r['local_e2e_ns']) for r in all_rows)/1e6,old_times[scale],1e-6)
        check_close(statistics.mean(r['online_bytes'] for r in got),old_bytes[scale]['total_online_bytes'],1e-6)
        check_close(statistics.mean(r['K'] for r in got),old_work[scale]['K_mean'],1e-9)
        check_close(statistics.mean(r['route_count'] for r in got),old_work[scale]['routes_mean'],1e-9)
        check_close(statistics.mean(r['target_slots'] for r in got),old_work[scale]['target_slots_mean'],1e-9)
        assert len({r['query_id'] for r in got})==854
        means={f'mean_{key}':statistics.mean(r[key] for r in got) for key in ('candidate_discovery_ms','K','route_count','target_slots','candidate_pair_count','anchor_processing_ms','candidate_compaction_ms','private_routing_ms','target_index_matching_ms','target_position_filtering_ms','target_record_aggregation_ms','target_stage_ms')}
        summary.append(dict(scale=scale,query_count=854,mean_online_mib=statistics.mean(r['online_bytes'] for r in got)/(2**20),**means))
    savecsv(OUT/'scale-query-mechanism-query-medians.csv',all_medians)
    savecsv(OUT/'scale-query-mechanism-summary.csv',summary)
    savecsv(PLOT/'database-scale-query-plot.csv',[dict(scale=r['scale'],candidate_discovery_ms=r['mean_candidate_discovery_ms'],online_mib=r['mean_online_mib'],mean_K=r['mean_K'],mean_route_count=r['mean_route_count'],mean_target_slots=r['mean_target_slots'],mean_anchor_processing_ms=r['mean_anchor_processing_ms'],mean_candidate_compaction_ms=r['mean_candidate_compaction_ms'],mean_target_stage_ms=r['mean_target_stage_ms']) for r in summary])
    return summary


def threshold():
    source=readcsv(THRESH/'candidate-raw.csv');official=readcsv(THRESH/'summary.csv')
    sets={side:json.loads((THRESH/f'{side}-query-set.json').read_text()) for side in ('anchor','target')}
    by={}
    for r in source:
        key=(r['variation_side'],int(r['anchor_tau']),int(r['target_tau']),int(r['query_id']))
        assert all(int(r[k])==0 for k in ('missing_candidate','extra_candidate','duplicate_candidate'))
        by.setdefault(key,[]).append(r)
    assert len(by)==4*(69+152)
    med=[]
    for (side,at,gt,q),rows in by.items():
        assert sorted(int(r['trial']) for r in rows)==[1,2,3]
        assert len({r['pair_sha256'] for r in rows})==1
        med.append(dict(variation_side=side,tau_delta=at,tau_gamma=gt,query_id=q,
            candidate_discovery_ms=statistics.median(int(r['candidate_discovery_ns']) for r in rows)/1e6,
            online_bytes=statistics.median(int(r['online_bytes']) for r in rows),K=statistics.median(int(r['K']) for r in rows),
            route_count=statistics.median(int(r['route_count']) for r in rows),target_slots=statistics.median(int(r['target_slots']) for r in rows)))
    summary=[]
    for side in ('anchor','target'):
        ids={int(q['query_id']) for q in sets[side]['queries']}
        for tau in range(4):
            at,gt=(tau,1) if side=='anchor' else (1,tau)
            rows=[r for r in med if (r['variation_side'],r['tau_delta'],r['tau_gamma'])==(side,at,gt)]
            assert len(rows)==len(ids) and {r['query_id'] for r in rows}==ids
            result=dict(variation_side=side,tau_delta=at,tau_gamma=gt,query_count=len(rows),
                mean_candidate_discovery_ms=statistics.mean(r['candidate_discovery_ms'] for r in rows),
                mean_online_mib=statistics.mean(r['online_bytes'] for r in rows)/(2**20),mean_K=statistics.mean(r['K'] for r in rows),
                mean_route_count=statistics.mean(r['route_count'] for r in rows),mean_target_slots=statistics.mean(r['target_slots'] for r in rows))
            old=next(o for o in official if (o['variation_side'],int(o['anchor_tau']),int(o['target_tau']))==(side,at,gt))
            for a,b in (('mean_candidate_discovery_ms','mean_candidate_discovery_ms'),('mean_online_mib','mean_online_mib'),('mean_K','mean_K'),('mean_route_count','mean_route_count'),('mean_target_slots','mean_target_slots')):check_close(result[a],old[b],1e-9)
            summary.append(result)
    savecsv(OUT/'threshold-mechanism-summary.csv',summary)
    for side in ('anchor','target'):
        rows=[r for r in summary if r['variation_side']==side]
        key='tau_delta' if side=='anchor' else 'tau_gamma'
        savecsv(PLOT/f'threshold-{side}-plot.csv',[{key:r[key],'candidate_discovery_ms':r['mean_candidate_discovery_ms'],'online_mib':r['mean_online_mib'],'mean_K':r['mean_K'],'mean_route_count':r['mean_route_count'],'mean_target_slots':r['mean_target_slots']} for r in rows])
    return summary


def signature():
    source=readcsv(SIGN/'candidate-raw.csv');official=readcsv(SIGN/'candidate-summary.csv')
    by={}
    for r in source:
        key=(r['variation_side'],int(r['anchor_r']),int(r['target_r']),r['source_id'])
        assert all(int(r[k])==0 for k in ('FP','FN','duplicates'))
        by.setdefault(key,[]).append(r)
    assert len(by)==8*644
    med=[]
    for (side,ar,tr,source_id),rows in by.items():
        assert sorted(int(r['trial']) for r in rows)==[1,2,3]
        med.append(dict(variation_side=side,r_delta=ar,r_gamma=tr,source_id=source_id,
            candidate_discovery_ms=statistics.median(int(r['candidate_discovery_ns']) for r in rows)/1e6,
            online_bytes=statistics.median(int(r['online_bytes']) for r in rows),K=statistics.median(int(r['K']) for r in rows),
            route_count=statistics.median(int(r['route_count']) for r in rows),target_slots=statistics.median(int(r['target_slots']) for r in rows)))
    summary=[]
    for side in ('anchor','target'):
        expected=None
        for n in (2,3,4,6):
            ar,tr=(n,4) if side=='anchor' else (4,n)
            rows=[r for r in med if (r['variation_side'],r['r_delta'],r['r_gamma'])==(side,ar,tr)]
            ids={r['source_id'] for r in rows}
            assert len(rows)==len(ids)==644
            if expected is None:expected=ids
            else:assert ids==expected
            result=dict(variation_side=side,r_delta=ar,r_gamma=tr,query_count=644,
                mean_candidate_discovery_ms=statistics.mean(r['candidate_discovery_ms'] for r in rows),
                mean_online_mib=statistics.mean(r['online_bytes'] for r in rows)/(2**20),mean_K=statistics.mean(r['K'] for r in rows),
                mean_route_count=statistics.mean(r['route_count'] for r in rows),mean_target_slots=statistics.mean(r['target_slots'] for r in rows))
            old=next(o for o in official if (o['variation_side'],int(o['anchor_r']),int(o['target_r']))==(side,ar,tr))
            for k in ('mean_candidate_discovery_ms','mean_online_mib','mean_K','mean_route_count','mean_target_slots'):check_close(result[k],old[k],1e-9)
            summary.append(result)
    savecsv(OUT/'signature-mechanism-summary.csv',summary)
    for side in ('anchor','target'):
        rows=[r for r in summary if r['variation_side']==side]
        savecsv(PLOT/f'signature-{side}-plot.csv',[dict(r=r['r_delta'] if side=='anchor' else r['r_gamma'],candidate_discovery_ms=r['mean_candidate_discovery_ms'],online_mib=r['mean_online_mib'],mean_K=r['mean_K'],mean_route_count=r['mean_route_count'],mean_target_slots=r['mean_target_slots']) for r in rows])
    return summary


def main():
    assert OUT.is_dir() and PLOT.is_dir() and (OUT/'audit.md').is_file()
    index_data();scale_queries();threshold();signature()
    inputs=[ANALYSIS/'setup-time.csv',ANALYSIS/'storage.csv',ANALYSIS/'dataset-scale.csv',THRESH/'candidate-raw.csv',SIGN/'candidate-raw.csv']
    inputs += [SCALE/f'scale-{s}'/'static.json' for s in SCALES]
    inputs += [SCALE/f'scale-{s}'/f'round-{trial}'/'queries.csv' for s in SCALES for trial in (1,2,3)]
    outputs=[p for p in OUT.rglob('*.csv')]
    write=OUT/'provenance.json'
    assert not write.exists()
    write.write_text(json.dumps(dict(status='passed',input_sha256={str(p.relative_to(ROOT)):sha(p) for p in inputs},output_sha256={str(p.relative_to(OUT)):sha(p) for p in outputs},source_sha256=sha(Path(__file__))),indent=2,ensure_ascii=False)+'\n')
    print('Recovered and audited all mechanism CSVs:',len(outputs),'CSV files')

if __name__=='__main__':main()
