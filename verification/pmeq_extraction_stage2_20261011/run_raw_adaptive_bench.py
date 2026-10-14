#!/usr/bin/env python3
"""Fair complete extraction boundary: XOR Keep + original two Ring64 IDs.
M unknown to preprocessing. Final v5 adaptive branch includes both banks.
"""
import pathlib,os,time,json,hashlib,shutil
import role_driver as d
from run_final_bench import certificate
P=pathlib.Path(__file__).resolve().parent
def main():
 root=P/'raw-adaptive-work';root.mkdir(exist_ok=True);jobs=[(L,M,t) for L,M in [(6001215,2),(60012150,2),(1000000,1000)] for t in range(5)]
 raw=P/'raw-adaptive-performance-raw.jsonl';done=set()
 if raw.exists():
  for line in raw.read_text().splitlines():
   r=json.loads(line);done.add((r['L'],r['M'],r['trial'],r['method']))
 binary_sha=hashlib.sha256(d.EXE.read_bytes()).hexdigest()
 (P/'raw-adaptive-benchmark-plan.json').write_text(json.dumps({'jobs':jobs,'binary_sha256':binary_sha,'five_independent_trials':True,'input_boundary':'post5(1) XOR Keep and raw Ring64 IDs','both_banks_reserved_before_query':True,'cloud_cpus':[0,2],'dealer_cpu':6,'client_cpu':4,'large_cloud_VM_limit_bytes':10<<30,'large_dealer_VM_limit_bytes':18<<30,'minimum_available_memory_bytes':32<<30,'disk_guard': '320*L + 5GiB'},indent=2)+'\n')
 with raw.open('a',buffering=1) as log:
  for L,M,trial in jobs:
   if all((L,M,trial,m) in done for m in ['sre','full','shuffle']):continue
   folder=root/f'{L}-{M}-{trial}'
   if folder.exists():shutil.rmtree(folder)
   folder.mkdir();os.chmod(folder,0o700)
   avail=int(next(s.split()[1] for s in pathlib.Path('/proc/meminfo').read_text().splitlines() if s.startswith('MemAvailable:')))*1024
   assert L<10000000 or avail>32<<30
   assert shutil.disk_usage(folder).free>320*L+(5<<30)
   seed=202610112100+L*37+M*1009+trial*100000000
   key=folder/'DO-only.key';key.write_bytes(hashlib.sha256(f'performance-only-DO:{seed}'.encode()).digest());os.chmod(key,0o600);binding=hashlib.sha256(key.read_bytes()+b'query-independent-ticket').hexdigest();prep=[]
   for kind,args in [('selector',['prep',folder,L,key,0,binding,0]),('shuffle',['prep-shuffle',folder,L,key,binding])]:
    start=time.monotonic();v=d.run(args,timeout=240,preexec_fn=d.limits(6,(18 if L>10000000 and kind=='shuffle' else 4)<<30));gen=time.monotonic()-start;stats=json.loads(v.stdout.decode().splitlines()[-1]);files=[f for f in folder.glob('*.bin') if f.name.startswith(('count','select') if kind=='selector' else ('shuffle',))];sync=d.fsync_files(files)
    prep.append(dict(kind=kind,offline_s=gen+sync,offline_generation_s=gen,fsync_s=sync,material_bytes=sum(f.stat().st_size-56 for f in files),material_file_bytes=sum(f.stat().st_size for f in files),certificates=certificate(files),**stats))
   finished=time.time()
   fixturekey=folder/'fixture-only.key';fixturekey.write_bytes(hashlib.sha256(f'performance-only-fixture:{seed}'.encode()).digest());os.chmod(fixturekey,0o600);start=time.monotonic();d.run(['inputs',folder,L,M,fixturekey,0,binding,0],timeout=240,preexec_fn=d.limits(6));fixture=time.monotonic()-start
   order=['sre','full','shuffle'];order=order[trial%3:]+order[:trial%3]
   for method in order:
    if (L,M,trial,method) in done:continue
    dst=folder/method;dst.mkdir()
    for f in folder.glob('*.bin'):os.link(f,dst/f.name)
    r=d.execute(dst,method,timeout=360,adaptive=method=='sre',memory_limit_bytes=(10 if L>10000000 and (method=='shuffle' or M>3) else 4)<<30)
    banks=prep if method=='sre' else [prep[1] if method=='shuffle' else prep[0]]
    r.update(L=L,M=M,trial=trial,seed=seed,experiment_version='stage2-v5-raw-full-adaptive',binary_sha256=binary_sha,input_boundary='post5(1) XOR Keep plus raw dynamic Ring64 IDs',masked_input=False,all_preprocessing_finished_unix=finished,query_fixture_after_preprocessing=True,fixture_s_excluded=fixture,
     offline_s=sum(b['offline_s'] for b in banks),reserved_material_bytes=sum(b['material_bytes'] for b in banks),offline_peak_rss_bytes=max(b['offline_peak_rss_bytes'] for b in banks),offline_banks=banks,all_branch_preprocessing_included=True,offline_network_delivery_s=None,network='AF_UNIX; no WAN/TLS',public_performance_seed_not_production_secret=True,paired_counterfactual_instances=True)
    r['end_to_end_cold_return_s']=r['offline_s']+r['online_return_wall_s'];log.write(json.dumps(r)+'\n');done.add((L,M,trial,method))
    print('DONE',L,M,trial,method,'online',round(r['online_return_wall_s'],6),'cold',round(r['end_to_end_cold_return_s'],6),'bytes',r['cloud_bytes'],r['user_bytes'],'material',r['reserved_material_bytes'],flush=True);shutil.rmtree(dst)
   shutil.rmtree(folder)
 print('COMPLETE',len(done),'RAW FULL-ADAPTIVE BENCHMARK ROWS',flush=True)
if __name__=='__main__':main()
