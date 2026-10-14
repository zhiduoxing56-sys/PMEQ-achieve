import csv,json,statistics,collections,hashlib,subprocess
from pathlib import Path
P=Path(__file__).resolve().parent
def write_csv(name,rows):
    keys=list(dict.fromkeys(k for r in rows for k in r))
    with (P/name).open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=keys);w.writeheader();w.writerows(rows)
def main():
    raw=[json.loads(x) for x in (P/'performance-raw.jsonl').read_text().splitlines()]
    if (P/'full-secure-raw.jsonl').exists():raw += [json.loads(x) for x in (P/'full-secure-raw.jsonl').read_text().splitlines()]
    if (P/'ring-sum-raw.jsonl').exists():raw += [json.loads(x) for x in (P/'ring-sum-raw.jsonl').read_text().splitlines()]
    if (P/'hybrid-raw.jsonl').exists():raw += [json.loads(x) for x in (P/'hybrid-raw.jsonl').read_text().splitlines()]
    if (P/'matched-raw.jsonl').exists():raw += [json.loads(x) for x in (P/'matched-raw.jsonl').read_text().splitlines()]
    for name in ['grouped-raw.jsonl','grouped-sum-raw.jsonl','large-shuffle-raw.jsonl','grouped-matched-raw.jsonl','offline-bank-raw.jsonl','larger-raw.jsonl']:
        if (P/name).exists():raw += [json.loads(x) for x in (P/name).read_text().splitlines()]
    # Preserve every executed observation, including preliminary v1 runs.
    rows=[];seen=set()
    for r in raw:
        r=dict(r);r.setdefault('kernel_version','v1');r.setdefault('experiment_version','preliminary-sequential')
        if 'process_wall_s' in r and 'fixture_s_excluded' in r:r['harness_wall_minus_fixture_s']=r['process_wall_s']-r['fixture_s_excluded']
        r['fast_decoder_verified']=False if r['requested_method'].startswith('linear') else 'N/A'
        r['measure_scope']='C++ logical two-party kernels; socketpair; interleaved measured dealer generation; reference decoder'
        r['offline_delivery_time_s']='';r['deployed_end_to_end_s']='';r['application_bytes_only']=True
        r['offline_material_scope']='Actual generated serialized material; physical cloud delivery not measured; unconsumed capacity bank reported separately'
        r['user_framing_scope']='37-byte experiment header per frame, no IP/TLS headers; body length/M provided by trusted harness, production framing pending'
        if r['requested_method']=='full':r['measure_scope']='Transfer diagnostic only: unmasked synthetic IDs; NOT the secure A baseline';r['secure_baseline']=False
        else:r['secure_baseline']=r['record_type']!='offline_only_measured'
        if r['record_type']=='offline_only_measured':r['measure_scope']=r['scope'];r['offline_material_scope']='Full public-capacity bank actually written/fsynced locally, but not consumed in online run'
        key=(r.get('experiment_version'),r['requested_method'],r['L'],r['N'],r['M'],r['trial'])
        r['independent_sample_for_median']=r.get('experiment_version') in ['v2-pinned4','v3-matched-serial','v4-large-serial','v5-grouped-matched','v7-larger-sparse'] and key not in seen
        if r.get('experiment_version') in ['v2-pinned4','v3-matched-serial','v4-large-serial','v5-grouped-matched','v7-larger-sparse']:seen.add(key)
        r['physical_cloud_processes']=False
        r['end_to_end_scope']='Measured stage subtotal including material generation; not a deployed wall-clock end-to-end run. process_wall_s includes fixture/oracle/launcher.'
        r['psmj_executed']=False;rows.append(r)
    # The requested fast scheme has no invented timing observation.
    plan=json.loads((P/'benchmark-plan.json').read_text())
    seen_fast=set()
    for method,L,N,M,trial,scope in plan['jobs']:
        if method=='linear-B' and (L,N,M,trial) not in seen_fast:
            seen_fast.add((L,N,M,trial));rows.append(dict(requested_method='linear-C-paper-fast',L=L,N=N,K=L//N,M=M,trial=trial,record_type='not_executed',status='BLOCKED_THEOREM25_FAST_DECODER',fast_decoder_verified=False,measure_scope='No fast decoder runtime measured',psmj_executed=False))
    write_csv('performance.csv',rows)
    groups=collections.defaultdict(list)
    for r in rows:
        if r.get('independent_sample_for_median') and r['record_type']=='measured' and r['status'].startswith('PASS'):
            groups[(r['experiment_version'],r['requested_method'],r['L'],r['N'],r['M'])].append(r)
    medians=[]
    metrics=['offline_s','prepare_s','encode_s','decode_s','online_s','end_to_end_with_measured_offline_s','harness_wall_minus_fixture_s','cloud_local_s','cloud_transport_s','transport_s','fixture_s_excluded','process_wall_s','material_bytes','cloud_bytes','user_bytes','peak_rss_bytes','frames']
    for (version,method,L,N,M),rs in sorted(groups.items()):
        d=dict(method=method,L=L,N=N,K=L//N,M=M,runs=len(rs),complete_five=len(rs)==5,record_type='median_measured',experiment_version=version)
        for k in metrics:
            vals=[x[k] for x in rs if k in x]
            if vals:d[k]=statistics.median(vals)
        medians.append(d)
    write_csv('performance-medians.csv',[r for r in medians if r['experiment_version']=='v2-pinned4'])
    write_csv('performance-matched-medians.csv',[r for r in medians if r['experiment_version'] in ['v3-matched-serial','v5-grouped-matched']])
    write_csv('performance-large-shuffle-medians.csv',[r for r in medians if r['experiment_version']=='v4-large-serial'])
    write_csv('performance-larger-medians.csv',[r for r in medians if r['experiment_version']=='v7-larger-sparse'])
    banks=collections.defaultdict(list)
    for r in raw:
        if r.get('experiment_version')=='v6-offline-bank':banks[(r['L'],r['N'],r['T'])].append(r)
    bank_medians=[]
    for (L,N,T),rs in sorted(banks.items()):
        b=dict(L=L,N=N,K=L//N,T=T,runs=len(rs),record_type='offline_only_median_measured')
        for k in ['offline_file_generation_s','fsync_s','offline_s','material_bytes','file_bytes_with_headers','peak_rss_bytes','verification_s_excluded']:b[k]=statistics.median(r[k] for r in rs)
        bank_medians.append(b)
    write_csv('performance-offline-bank-medians.csv',bank_medians)
    formulas=[]
    for L,N in [(100000,100000),(1000000,1000000),(6001215,6001215),(60012150,6001215)]:
        for M in [0,1,2,10,100,1000]:
            K=L//N
            formulas.extend([
                dict(method='full',L=L,N=N,K=K,M=M,record_type='theoretical_payload_formula',cloud_payload_bytes=0,user_payload_bytes=34*L,material_payload_bytes=0),
                dict(method='full-secure',L=L,N=N,K=K,M=M,record_type='theoretical_payload_formula',cloud_payload_bytes=64*L+2*((L+7)//8)+16,user_payload_bytes=34*L,material_payload_bytes=112*L+2*((L+7)//8)),
                dict(method='shuffle-pair-projection',L=L,N=N,K=K,M=M,record_type='theoretical_payload_formula',cloud_payload_bytes=36*L,user_payload_bytes=32*M,material_payload_bytes=110*L),
                dict(method='linear-B-reserved',L=L,N=N,K=K,M=M,record_type='theoretical_payload_formula',cloud_payload_bytes=(2*((L+7)//8)+16+(68*L+4032*((K+63)//64) if M else 0)),user_payload_bytes=68*M,material_payload_bytes=16*L+2*((L+7)//8)+102*L+6048*((K+63)//64)+16*N,note='Fully reserved fresh GF triples even for M0, static state cold-start included; headers and batching padding excluded'),
                dict(method='linear-hybrid-reserved',L=L,N=N,K=K,M=M,record_type='theoretical_payload_formula',cloud_payload_bytes=2*((L+7)//8)+16+(32*L+2*((L+7)//8)+4032*((K+63)//64) if M else 0),user_payload_bytes=68*M,material_payload_bytes=80*L+4*((L+7)//8)+16*N+6048*((K+63)//64),note='Fresh count daBits, independent target-aware masks, GF64 anchor triples; all L reserved even M0; headers and batching padding excluded'),
                dict(method='linear-grouped-reserved-T1000',L=L,N=N,K=K,M=M,T=1000,record_type='theoretical_payload_formula',cloud_payload_bytes=2*((L+7)//8)+16+(2*((L+7)//8)+136*K*M+4032*((K+63)//64) if M else 0),user_payload_bytes=68*M,material_payload_bytes=32*L+4*((L+7)//8)+16*N+204*K*1000+6048*((K+63)//64),note='Full target-aware mask bank plus 2KTmax GF129 triples reserved offline; actual measured consumption uses 2KM; no Mc opened'),
                dict(method='grouped-sum1',L=L,N=N,K=K,M=M,record_type='theoretical_payload_formula',cloud_payload_bytes=4*((L+7)//8)+16+68*K+4032*((K+63)//64) if M==1 else '',user_payload_bytes=34 if M==1 else '',material_payload_bytes=32*L+4*((L+7)//8)+16*N+102*K+6048*((K+63)//64) if M==1 else '',note='M1 local sums with K GF129 products; client gets no slot index'),
                dict(method='sum1-B',L=L,N=N,K=K,M=M,record_type='theoretical_payload_formula',user_payload_bytes=34 if M==1 else '',note='Only valid for M1; same full masking as linear-B'),
                dict(method='ring-sum1',L=L,N=N,K=K,M=M,record_type='theoretical_payload_formula',cloud_payload_bytes=64*L+2*((L+7)//8)+16 if M==1 else '',user_payload_bytes=32 if M==1 else '',material_payload_bytes=112*L+2*((L+7)//8) if M==1 else '',note='Only valid for M1; daBit count/B2A, two Ring64 Beaver masks, local sums; no field conversion'),
            ])
    write_csv('theoretical-costs.csv',formulas)
    expected={(method,L,N,M,trial) for method,L,N,M,trial,scope in plan['jobs']}
    expected.update(('full-secure',L,N,M,trial) for method,L,N,M,trial,scope in plan['jobs'] if method=='full')
    expected.update(('ring-sum1',L,N,1,trial) for L,N in [(100000,100000),(1000000,1000000),(6001215,6001215),(60012150,6001215)] for trial in range(5))
    expected.update(('linear-hybrid',L,N,M,trial) for method,L,N,M,trial,scope in plan['jobs'] if method=='linear-B')
    expected.update(('linear-grouped',L,N,M,trial) for method,L,N,M,trial,scope in plan['jobs'] if method=='linear-B')
    expected.update(('grouped-sum1',L,N,1,trial) for L,N in [(100000,100000),(1000000,1000000),(6001215,6001215),(60012150,6001215)] for trial in range(5))
    final=[r for r in raw if r.get('experiment_version')=='v2-pinned4'];keys={(r['requested_method'],r['L'],r['N'],r['M'],r['trial']) for r in final}
    matched=[r for r in raw if r.get('experiment_version')=='v3-matched-serial']
    large=[r for r in raw if r.get('experiment_version')=='v4-large-serial'];gm=[r for r in raw if r.get('experiment_version')=='v5-grouped-matched'];larger=[r for r in raw if r.get('experiment_version')=='v7-larger-sparse']
    audit=dict(raw_records=len(raw),v2_records=len(final),unique_v2_jobs=len(keys),same_seed_extra_records=len(final)-len(keys),expected_jobs=len(expected),missing_jobs=sorted(expected-keys),failed=[r for r in final+matched if r['record_type']=='failed'],resource_skipped=sum(r['record_type']=='not_executed' for r in final),complete_five_groups=sum(r['complete_five'] for r in medians if r['experiment_version']=='v2-pinned4'),measured_records=sum(r['record_type']=='measured' for r in final),independent_v2_measured_records=sum(r.get('independent_sample_for_median',False) and r['record_type']=='measured' and r.get('experiment_version')=='v2-pinned4' for r in rows),matched_expected_jobs=45,matched_measured_records=sum(r['record_type']=='measured' for r in matched),matched_complete_five_groups=sum(r['complete_five'] for r in medians if r['experiment_version']=='v3-matched-serial'),fast_decoder=False)
    large_keys={(r['L'],r['N'],r['M'],r['trial']) for r in large if r['record_type']=='measured'}
    originally_skipped={(r['L'],r['N'],r['M'],r['trial']) for r in final if r['record_type']=='not_executed' and r['requested_method']=='shuffle'}
    audit.update(large_shuffle_expected_jobs=40,large_shuffle_measured_records=sum(r['record_type']=='measured' for r in large),large_shuffle_complete_five_groups=sum(r['complete_five'] for r in medians if r['experiment_version']=='v4-large-serial'),grouped_matched_expected_jobs=55,grouped_matched_measured_records=sum(r['record_type']=='measured' for r in gm),remaining_unmeasured_original_shuffles=sorted(originally_skipped-large_keys),offline_bank_expected_jobs=20,offline_bank_measured_records=sum(len(x) for x in banks.values()),larger_expected_jobs=10,larger_measured_records=sum(r['record_type']=='measured' for r in larger))
    audit['failed'] += [r for r in large+gm+larger if r['record_type']=='failed']
    (P/'benchmark-audit.json').write_text(json.dumps(audit,indent=2));print(json.dumps({k:v for k,v in audit.items() if k!='failed'},ensure_ascii=False))
if __name__=='__main__':main()
