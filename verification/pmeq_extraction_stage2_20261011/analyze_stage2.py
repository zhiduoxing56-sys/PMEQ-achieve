#!/usr/bin/env python3
"""Independent byte/count checks and explicitly separated experimental tables."""
import pathlib,json,csv,statistics,collections,hashlib,platform,subprocess
p=pathlib.Path(__file__).resolve().parent
rows=[];groups=collections.defaultdict(list)
for line in (p/'physical-performance-raw.jsonl').read_text().splitlines():
 r=json.loads(line);L,M=r['L'],r['M'];B=(L+7)//8;C=(L+4095)//4096;method=r['method'];masked=r['masked_input'];assert r['status']=='PASS'
 assert r['user_bytes']==r['user_file_bytes']
 if method=='shuffle':
  assert r['material_bytes']==104*L+6*B
  assert r['cloud_bytes']==32*L+4*B+148*C
  assert r['user_bytes']==32*M+144
 else:
  assert r['material_bytes']==(16 if masked else 80)*L+2*B
  assert r['cloud_bytes']==2*B+16+37*(2*C+2)+(0 if masked or M==0 else 32*L+74*C)
  h=(L-1).bit_length()
  expected=144 if M==0 else (34*L+144 if method=='full' else (176 if M==1 else 32*(h+1)+8*M+144))
  assert r['user_bytes']==expected
 r['boundary']='raw-ID' if not masked else 'masked-ID/fresh-daBit-count';r['version']='v2-branch-only';r['reserved_material_bytes']=r['material_bytes'];rows.append(r)
for line in [s for path in [p/'final-performance-raw.jsonl',p/'final-v5-performance-raw.jsonl'] for s in path.read_text().splitlines()]:
 r=json.loads(line);L,M=r['L'],r['M'];B=(L+7)//8;C=(L+4095)//4096;method=r['method'];assert r['status']=='PASS'
 assert r['user_bytes']==r['user_file_bytes'];perm=32*L+4*B+74*C+74
 if method in ('shuffle','raw-optimal-shuffle'):assert r['cloud_bytes']==perm
 elif method=='sre':assert r['cloud_bytes']==(90 if M<=3 else perm+90)
 else:assert r['cloud_bytes']==90
 expected=144 if M==0 else (32*L+2*B+144 if method=='full' else (176 if method=='sre' and M==1 else (32*((L-1).bit_length()+1)+8*M+144 if method=='sre' and M<=3 else 32*M+144)))
 assert r['user_bytes']==expected,(L,M,method,r['user_bytes'],expected)
 assert r['fallback_preprocessing']['material_bytes']==104*L+6*B
 assert r['selector_preprocessing']['material_bytes']==80*L+2*B
 assert r['selector_prefix']['cloud_bytes']==32*L+2*B+238
 assert r['reserved_material_bytes']==(0 if method=='full' else 104*L+6*B)
 assert r['full_pipeline_cloud_bytes']==r['cloud_bytes']+(0 if method=='raw-optimal-shuffle' else r['selector_prefix']['cloud_bytes'])
 assert abs(r['full_pipeline_cold_s']-(r['full_pipeline_online_s']+r['offline_s']+(0 if method=='raw-optimal-shuffle' else r['selector_preprocessing']['offline_s'])))<1e-9
 r['boundary']='raw-ID/direct-permutation' if method=='raw-optimal-shuffle' else 'masked-ID/reuse-count';r['version']=('final-v5' if r['experiment_version'].endswith('v5') else 'final-v4')+'/full-fallback-reservation';rows.append(r)
for line in (p/'raw-adaptive-performance-raw.jsonl').read_text().splitlines():
 r=json.loads(line);L,M=r['L'],r['M'];B=(L+7)//8;C=(L+4095)//4096;method=r['method'];perm=32*L+4*B+74*C+74
 assert r['status']=='PASS' and r['user_bytes']==r['user_file_bytes']
 if method=='shuffle':
  assert r['cloud_bytes']==perm and r['reserved_material_bytes']==104*L+6*B
 elif method=='full':
  assert r['cloud_bytes']==32*L+2*B+238 and r['reserved_material_bytes']==80*L+2*B
 else:
  assert r['cloud_bytes']==(32*L+2*B+238 if M<=3 else perm+2*B+164)
  assert r['reserved_material_bytes']==184*L+8*B
 expected=32*L+2*B+144 if method=='full' else (32*((L-1).bit_length()+1)+8*M+144 if method=='sre' and M in (2,3) else 176 if method=='sre' and M==1 else 32*M+144)
 assert r['user_bytes']==expected
 assert len(r['offline_banks'])==(2 if method=='sre' else 1)
 r['boundary']='raw-ID/direct-full-stage';r['version']='final-v5/raw-adaptive-full-reservation';rows.append(r)
for line in (p/'grouped-performance-raw.jsonl').read_text().splitlines():
 r=json.loads(line);L,K,N,M=r['L'],r['K'],r['N'],r['M'];B=(L+7)//8;C=(L+4095)//4096;h=(L-1).bit_length()+1;perm=32*L+4*B+74*C+74
 assert r['status']=='PASS' and r['user_bytes']==r['user_file_bytes'] and K*N==L
 if r['method']=='shuffle':
  assert r['cloud_bytes']==perm and r['reserved_material_bytes']==104*L+6*B
 else:
  assert r['reserved_material_bytes']==152*L+8*B+48*K*h+16
  expected=(2*B+164 if M==0 else 16*L+2*B+32*K*(1 if M==1 else h)+312 if M<=3 else perm+2*B+164)
  assert r['cloud_bytes']==expected,(L,K,M,r['cloud_bytes'],expected)
 expected=144 if not M else (176 if r['method']=='sre' and M==1 else 32*h+8*M+144 if r['method']=='sre' and M<=3 else 32*M+144)
 assert r['user_bytes']==expected
 r['boundary']='raw-ID/grouped-anchor/direct-full-stage';r['version']='grouped-ring/full-adaptive-reservation';rows.append(r)
for line in (p/'grouped-full-baseline-raw.jsonl').read_text().splitlines():
 r=json.loads(line);L,M=r['L'],r['M'];B=(L+7)//8
 assert r['status']=='PASS' and r['method']=='full'
 assert r['user_bytes']==r['user_file_bytes']==(144 if not M else 32*L+2*B+144)
 assert r['cloud_bytes']==(2*B+164 if not M else 32*L+2*B+238)
 assert r['reserved_material_bytes']==80*L+2*B
 assert r['matched_grouped_input_generator_and_seed']
 r['boundary']='raw-ID/grouped-anchor/direct-full-stage';r['version']='grouped-ring/full-adaptive-reservation';rows.append(r)
for r in json.loads((p/'strict-private-performance.json').read_text()):
 L,K,N,M=r['L'],r['K'],r['N'],r['M'];B=(L+7)//8;C=(L+4095)//4096;h=(L-1).bit_length()+1;perm=32*L+4*B+74*C+74
 assert r['status']=='PASS' and r['user_bytes']==r['user_file_bytes'] and L==K*N
 assert r['private_256bit_fresh_owner_seed'] and r['offline_preprocessing_before_input_available']
 expected_wire=perm if r['method']=='shuffle' else 32*L+2*B+238 if r['method']=='full' else 16*L+2*B+32*K*h+312
 expected_mat=104*L+6*B if r['method']=='shuffle' else 80*L+2*B if r['method']=='full' else 152*L+8*B+48*K*h+16
 assert r['cloud_bytes']==expected_wire and r['reserved_material_bytes']==expected_mat
 assert r['user_bytes']==(32*L+2*B+144 if r['method']=='full' else 32*M+144 if r['method']=='shuffle' else 32*h+8*M+144)
 assert abs(r['strict_protocol_wall_s']-(r['cloud_wall_s']+r['client_process_wall_s']-r['user_validation_s_excluded']))<1e-8
 assert abs(r['strict_cold_protocol_s']-r['offline_s']-r['strict_protocol_wall_s'])<1e-8
 r['end_to_end_cold_return_s']=r['offline_s']+r['online_return_wall_s']
 r['boundary']='raw-ID/grouped-anchor/private-input/strict-clock';r['version']='strict-private-grouped-clock';rows.append(r)
for r in rows:
 if 'offline_banks' in r:
  r['reserved_material_file_bytes']=sum(x['material_file_bytes'] for x in r['offline_banks'])
  assert r['reserved_material_file_bytes']>=r['reserved_material_bytes']
 if r['version']=='strict-private-grouped-clock':
  folder=p/'strict-private-benchmark'/f"{r['trial']}-{r['method']}"
  files=[f for prefix in ['count','select','anchor','shuffle'] for f in folder.glob(prefix+'*.bin')]
  r['reserved_material_file_bytes']=sum(f.stat().st_size for f in files)
  assert r['reserved_material_file_bytes']-56*len(files)==r['reserved_material_bytes']
 groups[(r['version'],r['boundary'],r['L'],r['M'],r['method'])].append(r)
metrics=['cloud_cpu_s','cloud_wall_s','count_s','selector_s','encode_s','cloud_io_s','cloud_transport_s','cloud_bytes','reserved_material_bytes','offline_s','user_bytes','user_decode_s','user_validation_s_excluded','cloud_peak_rss_max_bytes','cloud_peak_rss_sum_bytes','client_peak_rss_bytes','online_return_wall_s','end_to_end_cold_return_s','offline_peak_rss_bytes','full_pipeline_cloud_bytes','full_pipeline_online_s','full_pipeline_reserved_material_bytes','full_pipeline_cold_s','private_file_bridge_s','strict_protocol_wall_s','strict_cold_protocol_s','client_process_wall_s','harness_wall_including_client_and_oracle_s']
columns=['version','boundary','L','K','N','M','method','trial','seed','status']+metrics
metrics.append('reserved_material_file_bytes');columns.append('reserved_material_file_bytes')
with (p/'performance.csv').open('w') as f:
 w=csv.DictWriter(f,fieldnames=columns,extrasaction='ignore');w.writeheader();w.writerows(rows)
med=[]
for key,v in groups.items():
 assert len(v)==5 and sorted(x['trial'] for x in v)==list(range(5)),(key,len(v))
 q=dict(zip(['version','boundary','L','M','method'],key),trials=5)
 for k in metrics:
  if all(k in x for x in v):q[k]=statistics.median(x[k] for x in v)
 med.append(q)
with (p/'performance-medians.csv').open('w') as f:
 w=csv.DictWriter(f,fieldnames=['version','boundary','L','M','method','trials']+metrics,extrasaction='ignore');w.writeheader();w.writerows(med)
(p/'performance-audit.json').write_text(json.dumps({'status':'PASS_INDEPENDENT_BYTE_FORMULAS_AND_FIVE_TRIALS','rows':len(rows),'groups':len(groups),'all_present_metrics_are_measured_not_extrapolated':True,'missing_metrics':'v2 offline peak RSS not instrumented; network offline delivery and WAN/TLS absent; blank cells never treated as zero','network_delivery_and_WAN_not_measured':True},indent=2)+'\n')
(p/'environment.json').write_text(json.dumps({'platform':platform.platform(),'python':platform.python_version(),'cpu_model':next(s.split(':',1)[1].strip() for s in pathlib.Path('/proc/cpuinfo').read_text().splitlines() if s.startswith('model name')),'compiler':subprocess.check_output(['g++','--version'],text=True).splitlines()[0],'openssl':subprocess.check_output(['openssl','version'],text=True).strip(),'mem_total_kib':int(next(s.split()[1] for s in pathlib.Path('/proc/meminfo').read_text().splitlines() if s.startswith('MemTotal:')))},indent=2)+'\n')
# Small-methods A/B optimization comparisons, kept out of primary large-scale table.
v=json.loads((p/'optimization-ab-results.json').read_text());ab=[]
for version in sorted(set(x['version'] for x in v)):
 a=[x for x in v if x['version']==version];assert len(a)==5
 ab.append(dict(version=version,trials=5,**{k:statistics.median(x[k] for x in a) for k in ['encode_s','cloud_bytes','cloud_cpu_s','online_return_wall_s','user_decode_s','cloud_peak_rss_max_bytes']}))
(p/'optimization-medians.json').write_text(json.dumps(ab,indent=2)+'\n')
print('AUDIT PASS',len(rows),'actual rows',len(groups),'five-trial groups')
