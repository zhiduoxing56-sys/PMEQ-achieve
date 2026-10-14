#!/usr/bin/env python3
"""Paired count-reuse benchmarks; secure input preparation is separately charged.
No plaintext-derived count or payload is given to a cloud. A real two-party
selector exports its own local count shares and masked private intermediate.
"""
import pathlib,os,json,time,hashlib,shutil,struct
import role_driver as d
P=pathlib.Path(__file__).resolve().parent

def certificate(files):
 out={}
 for f in files:
  h=hashlib.sha256()
  with f.open('rb') as x:
   while b:=x.read(8<<20):h.update(b)
  out[f.name]={'bytes':f.stat().st_size,'sha256':h.hexdigest()}
 return out

def bridge(src,dst,L):
 # Each file is transformed independently, never reconstructed. Private
 # intermediate full-return layout: header72, packed Keep, paired records.
 for p in (0,1):
  cp=src/f'count-output{p}.bin';h=bytearray(cp.read_bytes()[:56]);h[49]=4
  shutil.copyfile(cp,dst/f'count{p}.bin')
  with (src/f'user{p}.bin').open('rb') as f,(dst/f'input{p}.bin').open('wb') as g:
   q=f.read(72);assert struct.unpack('<QQ',q[56:])[1]==12
   bits=f.read((L+7)//8);g.write(h)
   for at in range(0,L,4096):
    n=min(4096,L-at);g.write(bits[at//8:(at+n+7)//8]);v=f.read(16*n);assert len(v)==16*n;g.write(v)
   assert not f.read(1)
 shutil.copyfile(src/'expected.bin',dst/'expected.bin')

def main():
 root=P/'final-benchmark-work';root.mkdir(exist_ok=True)
 jobs=[(L,M,t) for L,M in [(1000000,1),(1000000,2),(1000000,3),(6001215,1),(6001215,2),(6001215,3),(60012150,2),(3123216,1),(35238024,667)] for t in range(5)]
 raw=P/'final-performance-raw.jsonl';done=set()
 if raw.exists():
  for line in raw.read_text().splitlines():
   r=json.loads(line);done.add((r['L'],r['M'],r['trial'],r['method']))
 sha=hashlib.sha256(d.EXE.read_bytes()).hexdigest()
 (P/'final-benchmark-plan.json').write_text(json.dumps({'jobs':jobs,'version':'final-count-reuse','binary_sha256':sha,'cloud_cpus':[0,2],'dealer_cpu':6,'user_cpu':4,'available_memory_guard_bytes':32<<30,'large_cloud_VM_limit_bytes':10<<30,'large_dealer_VM_limit_bytes':18<<30,'scope':'real AF_UNIX; warm local files; reserved full fallback included; public reproducible fixture seeds'},indent=2)+'\n')
 with raw.open('a',buffering=1) as log:
  for L,M,trial in jobs:
   if all((L,M,trial,m) in done for m in ('sre','full','shuffle','raw-optimal-shuffle')):continue
   group=root/f'{L}-{M}-{trial}'
   if group.exists():shutil.rmtree(group)
   group.mkdir();os.chmod(group,0o700)
   if L>10000000:
    avail=int(next(s.split()[1] for s in pathlib.Path('/proc/meminfo').read_text().splitlines() if s.startswith('MemAvailable:')))*1024
    assert avail>32<<30,(avail,'memory guard')
   seed=202610110900+L*37+M*1009+trial*100000000
   key=group/'DO-only.key';key.write_bytes(hashlib.sha256(f'performance-only:{seed}'.encode()).digest());os.chmod(key,0o600)
   binding=hashlib.sha256(key.read_bytes()+b'final-query-binding').hexdigest()
   start=time.monotonic();d.run(['inputs',group,L,M,key,0,binding,0],timeout=240,preexec_fn=d.limits(6));fixture=time.monotonic()-start
   prep=[]
   # ALL branch banks complete before the first cloud process.
   for kind,args in [('selector',['prep',group,L,key,0,binding,0]),('shuffle',['prep-shuffle',group,L,key,binding])]:
    start=time.monotonic();v=d.run(args,timeout=240,preexec_fn=d.limits(6,(18 if L>10000000 and kind=='shuffle' else 4)<<30))
    elapsed=time.monotonic()-start;stats=json.loads(v.stdout.decode().splitlines()[-1])
    files=[f for f in group.glob('*.bin') if f.name.startswith(('count','select') if kind=='selector' else ('shuffle',))]
    sync=d.fsync_files(files);cert=certificate(files)
    prep.append(dict(kind=kind,offline_s=elapsed+sync,generation_wall_s=elapsed,fsync_s=sync,material_file_bytes=sum(f.stat().st_size for f in files),material_bytes=sum(f.stat().st_size-56 for f in files),certificates=cert,**stats))
   selector,perm=prep
   prefix=group/'prefix';prefix.mkdir()
   for f in group.glob('*.bin'):os.link(f,prefix/f.name)
   p=d.execute(prefix,'full',timeout=240,export_count=True,validate=False)
   bdir=group/'masked';bdir.mkdir();start=time.monotonic();bridge(prefix,bdir,L);bridge_s=time.monotonic()-start
   common=dict(L=L,M=M,trial=trial,seed=seed,binary_sha256=sha,public_performance_seed_not_production_secret=True,all_branch_preprocessing_completed_before_clouds=True,
    selector_prefix=p,selector_preprocessing=selector,fallback_preprocessing=perm,fixture_s_excluded=fixture,private_file_bridge_s=bridge_s,
    count_source='actual two-party selector local Ring count; never reconstructed by test fixture',source_prefix_M_already_public=True,
    input_boundary='Keep-masked Ring64 IDs plus local sum of Ring Keep',application_bytes_only=True,user_channel='separate final stdout files',network='AF_UNIX; no WAN/TLS or offline network measurement',
    prefix_private_intermediate_not_QU_result=True,full_pipeline_includes_private_intermediate_file_bridge=True)
   order=['sre','full','shuffle'];order=order[trial%3:]+order[:trial%3]
   for method in order+['raw-optimal-shuffle']:
    if (L,M,trial,method) in done:continue
    dest=group/method;dest.mkdir()
    source=group if method=='raw-optimal-shuffle' else bdir
    for f in source.glob('*.bin'):
     if f.name.startswith(('input','count')) or f.name=='expected.bin':os.link(f,dest/f.name)
    for f in group.glob('shuffle*.bin'):os.link(f,dest/f.name)
    actual='shuffle' if method=='raw-optimal-shuffle' else method
    result=d.execute(dest,actual,timeout=360,adaptive=method=='sre',memory_limit_bytes=(10 if L>10000000 and actual=='shuffle' or L>10000000 and M>3 else 4)<<30)
    result.update(common,method=method,status='PASS',experiment_version='stage2-final-count-reuse-v4')
    result['reserved_material_bytes']=0 if method=='full' else perm['material_bytes']
    result['offline_s']=0 if method=='full' else perm['offline_s']
    result['offline_peak_rss_bytes']=0 if method=='full' else perm['offline_peak_rss_bytes']
    result['end_to_end_cold_return_s']=result['offline_s']+result['online_return_wall_s']
    result['full_pipeline_cloud_bytes']=result['cloud_bytes']+(0 if method=='raw-optimal-shuffle' else p['cloud_bytes'])
    result['full_pipeline_online_s']=result['online_return_wall_s']+(0 if method=='raw-optimal-shuffle' else p['cloud_wall_s']+bridge_s)
    result['full_pipeline_reserved_material_bytes']=result['reserved_material_bytes']+(0 if method=='raw-optimal-shuffle' else selector['material_bytes'])
    result['full_pipeline_cold_s']=result['full_pipeline_online_s']+result['offline_s']+(0 if method=='raw-optimal-shuffle' else selector['offline_s'])
    result['source_prefix_selector_cost_charged']=method!='raw-optimal-shuffle'
    log.write(json.dumps(result)+'\n');done.add((L,M,trial,method))
    print('DONE',L,M,trial,method,'online',round(result['online_return_wall_s'],6),'cold',round(result['end_to_end_cold_return_s'],6),'bytes',result['cloud_bytes'],result['user_bytes'],flush=True)
    shutil.rmtree(dest)
   shutil.rmtree(group)
 print('COMPLETE',len(done),'FINAL FULL-RESERVATION BENCHMARK ROWS',flush=True)
if __name__=='__main__':main()
