#!/usr/bin/env python3
import pathlib,os,time,json,hashlib,shutil
import role_driver as d
from run_final_bench import certificate
P=pathlib.Path(__file__).resolve().parent
def main():
 root=P/'grouped-full-baseline-work';root.mkdir(exist_ok=True);jobs=[(K,N,M,t) for K,N,M in [(1,6001215,1),(2,6001215,2)] for t in range(5)];raw=P/'grouped-full-baseline-raw.jsonl';done=set()
 if raw.exists():
  for line in raw.read_text().splitlines():
   r=json.loads(line);done.add((r['K'],r['N'],r['M'],r['trial'],r['method']))
 sha=hashlib.sha256(d.EXE.read_bytes()).hexdigest();(P/'grouped-workload-full-supplement-plan.json').write_text(json.dumps({'jobs':jobs,'binary_sha256':sha,'input_boundary':'original grouped-anchor raw shares after5(1)','cloud_cpus':[0,2],'dealer_cpu':6,'user_cpu':4,'available_memory_guard_bytes':32<<30,'disk_guard':'320L+5GiB','private_capacity_tests':'grouped-tests-v2-results.json'},indent=2)+'\n')
 with raw.open('a',buffering=1) as log:
  for K,N,M,trial in jobs:
   L=K*N
   if all((K,N,M,trial,m) in done for m in ['full']):continue
   folder=root/f'{K}-{N}-{M}-{trial}'
   if folder.exists():shutil.rmtree(folder)
   folder.mkdir();os.chmod(folder,0o700)
   avail=int(next(s.split()[1] for s in pathlib.Path('/proc/meminfo').read_text().splitlines() if s.startswith('MemAvailable:')))*1024
   assert L<10000000 or avail>32<<30
   assert shutil.disk_usage(folder).free>320*L+(5<<30)
   seed=202610112400+L*37+M*1009+trial*100000000
   key=folder/'DO-only.key';key.write_bytes(hashlib.sha256(f'performance-only-DO:{seed}'.encode()).digest());os.chmod(key,0o600);binding=hashlib.sha256(key.read_bytes()+b'grouped-query-independent-ticket').hexdigest();prep=[]
   for kind,args in [('full',['prep',folder,L,key,0,binding,0])]:
    start=time.monotonic();v=d.run(args,timeout=240,preexec_fn=d.limits(6,(18 if L>10000000 and kind=='shuffle' else 4)<<30));gen=time.monotonic()-start;stats=json.loads(v.stdout.decode().splitlines()[-1]);files=[f for f in folder.glob('*.bin') if f.name.startswith(('count','select'))];sync=d.fsync_files(files)
    prep.append(dict(kind=kind,offline_s=gen+sync,generation_wall_s=gen,fsync_s=sync,material_bytes=sum(f.stat().st_size-56 for f in files),material_file_bytes=sum(f.stat().st_size for f in files),certificates=certificate(files),**stats))
   finished=time.time();fixturekey=folder/'fixture-only.key';fixturekey.write_bytes(hashlib.sha256(f'performance-only-fixture:{seed}'.encode()).digest());os.chmod(fixturekey,0o600);start=time.monotonic();d.run(['inputs-grouped',folder,L,N,M,fixturekey,binding,0],timeout=240,preexec_fn=d.limits(6));fixture=time.monotonic()-start;os.environ['SRE_GROUP_N']=str(N)
   order=['full']
   for method in order:
    if (K,N,M,trial,method) in done:continue
    dst=folder/method;dst.mkdir()
    for f in folder.glob('*.bin'):os.link(f,dst/f.name)
    r=d.execute(dst,method,timeout=360,adaptive=method=='sre',memory_limit_bytes=(10 if L>10000000 and (method=='shuffle' or M>3) else 4)<<30)
    banks=prep
    r.update(L=L,K=K,N=N,M=M,trial=trial,seed=seed,experiment_version='stage2-grouped-input-full-baseline',binary_sha256=sha,input_boundary='post5(1) grouped raw Ring64 anchor, dynamic raw Ring64 target and XOR Keep',masked_input=False,all_preprocessing_finished_unix=finished,query_fixture_after_preprocessing=True,fixture_s_excluded=fixture,
     offline_s=sum(b['offline_s'] for b in banks),reserved_material_bytes=sum(b['material_bytes'] for b in banks),offline_peak_rss_bytes=max(b['offline_peak_rss_bytes'] for b in banks),offline_banks=banks,all_branch_preprocessing_included=True,offline_network_delivery_s=None,network='AF_UNIX; no WAN/TLS',public_performance_seed_not_production_secret=True,paired_counterfactual_instances=True,matched_grouped_input_generator_and_seed=True)
    r['end_to_end_cold_return_s']=r['offline_s']+r['online_return_wall_s'];log.write(json.dumps(r)+'\n');done.add((K,N,M,trial,method));print('DONE',K,N,M,trial,method,'online',round(r['online_return_wall_s'],6),'cold',round(r['end_to_end_cold_return_s'],6),'bytes',r['cloud_bytes'],r['user_bytes'],'material',r['reserved_material_bytes'],flush=True);shutil.rmtree(dst)
   shutil.rmtree(folder)
 print('COMPLETE',len(done),'GROUPED-INPUT FULL-RETURN BASELINE ROWS',flush=True)
if __name__=='__main__':main()
