"""Reconcile independent paper baselines using saved raw measurements only."""
import csv
import gzip
import hashlib
import json
from pathlib import Path
import statistics

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'results/paper-evaluation-reconciliation-20260924'
PAPER=ROOT/'results/paper-evaluation-20260922'
BUCKET=ROOT/'results/bucket-count-candidate-20260923'
SIGN=ROOT/'results/query-signature-full-final-20260923'
MECH=ROOT/'results/paper-mechanism-supplement-final-20260924'


def rows(p):
    with p.open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))


def savecsv(name,items):
    assert items
    with (OUT/name).open('x',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(items[0]));w.writeheader();w.writerows(items)


def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def close(a,b,eps=1e-9):assert abs(float(a)-float(b))<=eps,(a,b)


def timing():
    cal=rows(PAPER/'e2e/e2e-three-runs-query-level-ns.csv')
    bucket=rows(BUCKET/'candidate-raw.csv')
    work=rows(PAPER/'workload/workload-query-level.csv')
    assert len(cal)==len(bucket)==2562 and len(work)==854
    workload={int(r['QueryID']):r for r in work}
    cby={};bby={}
    for r in cal:cby.setdefault(int(r['QueryID']),[]).append(r)
    for r in bucket:
        assert r['bucket_bits']=='16' and r['bucket_count']=='65536'
        bby.setdefault(int(r['query_id']),[]).append(r)
    assert cby.keys()==bby.keys()==workload.keys() and len(cby)==854
    comparison=[]
    for q in sorted(cby):
        a=sorted(cby[q],key=lambda r:int(r['run']))
        b=sorted(bby[q],key=lambda r:int(r['trial']))
        assert [int(r['run']) for r in a]==[1,2,3]
        assert [int(r['trial']) for r in b]==[1,2,3]
        w=workload[q]
        assert len({(r['K'],r['routes'],r['groups'],r['target_slots'],r['final_pairs'],r['total_online_bytes']) for r in b})==1
        for bk,wk in (('K','K'),('routes','Routes'),('groups','TargetGroups'),('target_slots','TargetSlots'),('final_pairs','CandidatePairs'),('total_online_bytes','OnlineCommunicationBytes')):
            assert int(b[0][bk])==int(w[wk]),(q,bk)
        cm=statistics.median(int(r['LocalE2E']) for r in a)/1e6
        bm=statistics.median(int(r['local_e2e_ns']) for r in b)/1e6
        comparison.append(dict(query_id=q,calibration_query_median_ms=cm,bucket_default_query_median_ms=bm,
            bucket_minus_calibration_ms=bm-cm,online_bytes=int(b[0]['total_online_bytes']),K=int(b[0]['K']),
            route_count=int(b[0]['routes']),target_slots=int(b[0]['target_slots']),candidate_pair_count=int(b[0]['final_pairs'])))
    savecsv('timing-baseline-paired-queries.csv',comparison)
    cal_all=statistics.mean(int(r['LocalE2E']) for r in cal)/1e6
    buck_all=statistics.mean(int(r['local_e2e_ns']) for r in bucket)/1e6
    cal_med=statistics.mean(r['calibration_query_median_ms'] for r in comparison)
    buck_med=statistics.mean(r['bucket_default_query_median_ms'] for r in comparison)
    close(cal_all,237.61399350897736,1e-9)
    close(buck_med,256.0945157412178,1e-9)
    summary=[dict(dataset='calibration_854',timing_boundary='RunLocal.LocalE2E',query_count=854,trials_per_query=3,
                  mean_all_trials_ms=cal_all,mean_query_median_ms=cal_med,mean_online_mib=statistics.mean(r['online_bytes'] for r in comparison)/(2**20),
                  binary_sha256=json.loads((PAPER/'provenance/binary-sha256.json').read_text())['artifacts/n-domain-regression-pilot-runtime/database-regression-pilot.test']['sha256']),
             dict(dataset='bucket_default_B65536',timing_boundary='RunLocal.LocalE2E',query_count=854,trials_per_query=3,
                  mean_all_trials_ms=buck_all,mean_query_median_ms=buck_med,mean_online_mib=statistics.mean(r['online_bytes'] for r in comparison)/(2**20),
                  binary_sha256=json.loads((BUCKET/'provenance.json').read_text())['binary_sha256'])]
    savecsv('timing-baseline-summary.csv',summary)
    return summary


def signature():
    raw=rows(SIGN/'candidate-raw.csv')
    groups={}
    for r in raw:
        if int(r['anchor_r'])==4 and int(r['target_r'])==4:
            groups.setdefault(r['source_id'],{}).setdefault(r['variation_side'],[]).append(r)
    assert len(groups)==644
    comparison=[]
    for source_id,sides in sorted(groups.items()):
        assert sides.keys()=={'anchor','target'}
        a=sorted(sides['anchor'],key=lambda r:int(r['trial']))
        t=sorted(sides['target'],key=lambda r:int(r['trial']))
        assert [int(r['trial']) for r in a]==[1,2,3] and [int(r['trial']) for r in t]==[1,2,3]
        invariant=('online_bytes','K','route_count','target_slots','candidate_pair_count','pair_sha256')
        assert len({tuple(r[k] for k in invariant) for r in a+t})==1,source_id
        am=statistics.median(int(r['candidate_discovery_ns']) for r in a)/1e6
        tm=statistics.median(int(r['candidate_discovery_ns']) for r in t)/1e6
        pooled=statistics.median(int(r['candidate_discovery_ns']) for r in a+t)/1e6
        comparison.append(dict(source_id=source_id,anchor_three_trial_median_ms=am,target_three_trial_median_ms=tm,
            unified_equal_weight_query_ms=(am+tm)/2,pooled_six_trial_median_ms=pooled,
            online_bytes=int(a[0]['online_bytes']),K=int(a[0]['K']),route_count=int(a[0]['route_count']),
            target_slots=int(a[0]['target_slots']),candidate_pair_count=int(a[0]['candidate_pair_count'])))
    savecsv('signature-common-baseline-query.csv',comparison)
    baseline=dict(r_delta=4,r_gamma=4,query_count=644,
        anchor_independent_ms=statistics.mean(r['anchor_three_trial_median_ms'] for r in comparison),
        target_independent_ms=statistics.mean(r['target_three_trial_median_ms'] for r in comparison),
        unified_equal_weight_ms=statistics.mean(r['unified_equal_weight_query_ms'] for r in comparison),
        pooled_six_trial_median_ms=statistics.mean(r['pooled_six_trial_median_ms'] for r in comparison),
        mean_online_mib=statistics.mean(r['online_bytes'] for r in comparison)/(2**20),mean_K=statistics.mean(r['K'] for r in comparison),
        mean_route_count=statistics.mean(r['route_count'] for r in comparison),mean_target_slots=statistics.mean(r['target_slots'] for r in comparison))
    savecsv('signature-common-baseline-summary.csv',[baseline])
    official=rows(SIGN/'candidate-summary.csv')
    close(baseline['anchor_independent_ms'],next(float(r['mean_candidate_discovery_ms']) for r in official if r['variation_side']=='anchor' and r['anchor_r']=='4'),1e-9)
    close(baseline['target_independent_ms'],next(float(r['mean_candidate_discovery_ms']) for r in official if r['variation_side']=='target' and r['target_r']=='4'),1e-9)
    for side in ('anchor','target'):
        source=rows(MECH/f'plot-data/signature-{side}-plot.csv')
        out=[]
        for r in source:
            x=dict(r)
            x['baseline_method']='original_three_trial_query_median'
            if int(r['r'])==4:
                x['candidate_discovery_ms']=baseline['unified_equal_weight_ms']
                x['baseline_method']='mean_of_two_independent_query_medians'
            out.append(x)
        savecsv(f'signature-{side}-plot-common-baseline.csv',out)
    return baseline


def offline():
    with (ROOT/'results/n-domain-regression-pilot-20260920/regression-100-queries.jsonl').open(encoding='utf-8') as f:
        rec=[json.loads(line) for line in f]
    assert len(rec)==854 and len({r['Query'] for r in rec})==854
    assert all(r['Scale']==100 and r['N']==120071 and r['ProvisionNS']>0 for r in rec)
    provision=statistics.mean(r['ProvisionNS'] for r in rec)/1e6
    vol=rows(PAPER/'token-offline-existing/offline-volume-query-level.csv')
    assert len(vol)==854 and len({int(r['QueryID']) for r in vol})==854
    cols=('AnchorPosition','AnchorAggregation','Compaction','TargetPE','TargetPosition','TargetAggregation')
    material=statistics.mean(sum(int(r[k]) for k in cols) for r in vol)
    close(provision,865.8194586194379,1e-9)
    close(material/(2**20),135.837354,1e-6)
    table=[dict(metric='full_Provision',mean_time_ms=provision,mean_material_mib='',actual_network_mib='',query_count=854,measurement='one_pass_existing_regression',note='fresh one-use material; total preparation includes components not independently timed'),
           dict(metric='six_offline_material_fields',mean_time_ms='',mean_material_mib=material/(2**20),actual_network_mib='',query_count=854,measurement='three_run_calibration_fields',note='semantic field volume; not serialized dealer-to-cloud wire')]
    savecsv('offline-default-small-table.csv',table)
    return provision,material/(2**20)


def main():
    assert OUT.is_dir() and not any(OUT.iterdir())
    timing();signature();offline()
    sources=[PAPER/'e2e/e2e-three-runs-query-level-ns.csv',PAPER/'workload/workload-query-level.csv',BUCKET/'candidate-raw.csv',SIGN/'candidate-raw.csv',PAPER/'token-offline-existing/offline-volume-query-level.csv',ROOT/'results/n-domain-regression-pilot-20260920/regression-100-queries.jsonl']
    (OUT/'provenance.json').write_text(json.dumps(dict(status='passed',input_sha256={str(p.relative_to(ROOT)):digest(p) for p in sources},output_sha256={p.name:digest(p) for p in OUT.glob('*.csv')},source_sha256=digest(Path(__file__))),indent=2,ensure_ascii=False)+'\n')
    print('Reconciled timing, signature baseline, and offline evidence')

if __name__=='__main__':main()
