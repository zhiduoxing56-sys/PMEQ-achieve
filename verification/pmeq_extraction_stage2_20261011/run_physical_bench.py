#!/usr/bin/env python3
import pathlib,os,time,json,hashlib,shutil,subprocess,resource
import role_driver as d
P=pathlib.Path(__file__).resolve().parent
def main():
 jobs=[]
 # Four real sizes, small paths; additional native integration is separate.
 for L in [100000,1000000,6001215]:
  for M in [0,1,2,3]:
   for trial in range(5):
    for masked in [False,True]:jobs.append((L,M,trial,masked))
 # Strict 18 GiB dealer / 4 GiB per-cloud guard at the largest required L.
 # To bound disk churn, compare all three methods for M=2, five trials.
 for trial in range(5):jobs.append((60012150,2,trial,False))
 meta=dict(status='PLANNED',five_independent_trials=True,jobs=jobs,cloud_cpu_pins=[0,2],client_cpu_pin=4,dealer_cpu_pin=6,
  cloud_limit_bytes=4<<30,largest_dealer_limit_bytes=18<<30,largest_dealer_guard_bytes=256*60012150,
  minimum_available_memory_bytes=24<<30,max_single_trial_disk_bytes=220*60012150,
  public_fixture_seed_base=202610110500,scope='Physical two cloud processes, complete offline files generated and fsynced before online; local AF_UNIX and user files, not WAN')
 (P/'physical-benchmark-plan.json').write_text(json.dumps(meta,indent=2)+'\n')
 raw=P/'physical-performance-raw.jsonl';done=set()
 if raw.exists():
  for line in raw.read_text().splitlines():
   r=json.loads(line)
   if r['status']=='PASS':done.add((r['L'],r['M'],r['trial'],r['masked_input'],r['method']))
 root=P/'physical-work';root.mkdir(exist_ok=True)
 with raw.open('a',buffering=1) as out:
  for L,M,trial,masked in jobs:
   if all((L,M,trial,masked,m) in done for m in ['sre','full','shuffle']):continue
   seed=202610110500+L*37+M*1009+trial*100000000+int(masked)*4000000000
   group=root/f'{L}-{M}-{trial}-{int(masked)}'
   if group.exists():shutil.rmtree(group)
   group.mkdir();os.chmod(group,0o700);kp=group/'DO-only.key';kp.write_bytes(hashlib.sha256(f'performance-only:{seed}'.encode()).digest());os.chmod(kp,0o600)
   binding=hashlib.sha256(kp.read_bytes()+b'query-binding').hexdigest()
   t=time.monotonic();d.run(['inputs',group,L,M,kp,int(masked),binding,0],timeout=240,preexec_fn=d.limits(6));fixture=time.monotonic()-t
   order=['sre','full','shuffle'];order=order[trial%3:]+order[:trial%3]
   for method in order:
    if (L,M,trial,masked,method) in done:continue
    dest=group/method;dest.mkdir()
    for f in group.glob('*.bin'):os.link(f,dest/f.name)
    if L>10000000:
     avail=int(next(x.split()[1] for x in pathlib.Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))*1024
     assert avail>24<<30,(avail,'unsafe available memory')
    start=time.monotonic()
    if method=='shuffle':args=['prep-shuffle',dest,L,kp,binding]
    else:args=['prep',dest,L,kp,int(masked),binding,0]
    dealer_limit=18<<30 if L>10000000 and method=='shuffle' else 4<<30
    d.run(args,timeout=240,preexec_fn=d.limits(6,dealer_limit))
    gen=time.monotonic()-start
    files=[f for f in dest.glob('*.bin') if f.name.startswith(('count','select','shuffle'))]
    sync=d.fsync_files(files);filebytes=sum(f.stat().st_size for f in files)
    cert={f.name:dict(bytes=f.stat().st_size,sha256='') for f in files}
    # Full hashes computed as a separate excluded evidence check, streamed.
    verify_start=time.monotonic()
    for f in files:
     h=hashlib.sha256()
     with f.open('rb') as fh:
      while b:=fh.read(8<<20):h.update(b)
     cert[f.name]['sha256']=h.hexdigest()
    verify=time.monotonic()-verify_start
    cloud_limit=10<<30 if method=='shuffle' and L>10000000 else 4<<30
    result=d.execute(dest,method,timeout=240,memory_limit_bytes=cloud_limit)
    result.update(L=L,M=M,trial=trial,seed=seed,masked_input=masked,experiment_version='stage2-physical-v2',
     input_boundary='already Keep-masked Ring64 IDs' if masked else 'raw dynamic Ring64 IDs plus XOR Keep',
     material_bytes=filebytes-56*len(files),material_file_bytes=filebytes,material_certificates=cert,
     offline_generation_s=gen,fsync_s=sync,offline_s=gen+sync,offline_files_consumed_online=True,
     offline_delivery_network_s=None,fixture_s_excluded=fixture,material_hashing_s_excluded=verify,
     end_to_end_cold_return_s=gen+sync+result['online_return_wall_s'],
     user_channel='separate final stdout file for each cloud',application_bytes_only=True,public_performance_seed_not_production_secret=True,
     branch_scope='M<=3 only; reserved fallback bank is NOT included here',cpu_pins=[0,2,4,6],cloud_limit_bytes=cloud_limit,dealer_limit_bytes=dealer_limit)
    out.write(json.dumps(result)+'\n');done.add((L,M,trial,masked,method))
    print('DONE',L,M,trial,int(masked),method,result['status'],'online',round(result['online_return_wall_s'],4),'offline',round(gen+sync,4),flush=True)
    shutil.rmtree(dest)
   shutil.rmtree(group)
 print('COMPLETE',len(done),'physical benchmarks',flush=True)
if __name__=='__main__':main()
