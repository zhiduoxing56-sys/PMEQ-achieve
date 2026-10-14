#!/usr/bin/env python3
"""Measured separate cloud processes with a completed offline file bank.

Keys are DO-only files. The two peers receive only their own input/material
paths and one socket endpoint. Final stdout goes to separate user files.
"""
import os,json,time,hashlib,secrets,socket,subprocess,resource,pathlib,shutil
P=pathlib.Path(__file__).resolve().parent
EXE=pathlib.Path(os.environ.get('ROLES_BINARY',str(P/'roles')))
def run(args,**kw):
 r=subprocess.run([str(EXE),*map(str,args)],capture_output=True,**kw)
 if r.returncode:raise RuntimeError(r.stderr.decode())
 return r
def fsync_files(files):
 t=time.monotonic()
 for f in files:
  with f.open('rb') as fh:os.fsync(fh.fileno())
 return time.monotonic()-t
def limits(cpu=None,limit=4<<30):
 def f():
  resource.setrlimit(resource.RLIMIT_AS,(limit,limit))
  if cpu is not None:os.sched_setaffinity(0,{cpu})
 return f
def execute(directory,method,timeout=240,adaptive=False,cpu_pins=(0,2),client_cpu=4,memory_limit_bytes=4<<30,registry=None,export_count=False,validate=True):
 d=pathlib.Path(directory);s=socket.socketpair();procs=[];outputs=[];errors=[]
 started=time.monotonic()
 try:
  for party in [0,1]:
   out=d/f'user{party}.bin';outputs.append(out);of=out.open('wb');err=d/f'cloud{party}.stderr';errors.append(err);ef=err.open('wb')
   if method=='shuffle':args=['shuffle-cloud',d/f'input{party}.bin',d/f'shuffle{party}.bin',s[party].fileno()]
   else:
    args=['cloud',d/f'input{party}.bin',d/f'count{party}.bin',d/f'select{party}.bin',s[party].fileno(),method]
    if adaptive:args.append(d/f'shuffle{party}.bin')
   env=os.environ.copy()
   env['SRE_TICKET_REGISTRY']=str(registry or (d/'consumption-state'))
   if export_count:env['SRE_EXPORT_COUNT_SHARE']=str(d/f'count-output{party}.bin')
   p=subprocess.Popen([str(EXE),*map(str,args)],stdin=subprocess.DEVNULL,stdout=of,stderr=ef,env=env,pass_fds=(s[party].fileno(),),preexec_fn=limits(cpu_pins[party],memory_limit_bytes))
   of.close();ef.close();procs.append(p)
  for ch in s:ch.close()
  for p in procs:
   p.wait(timeout=max(1,timeout-(time.monotonic()-started)))
  wall=time.monotonic()-started
  if any(p.returncode for p in procs):raise RuntimeError('; '.join(e.read_text() for e in errors))
  stats=[]
  for e in errors:
   parts=[json.loads(x) for x in e.read_text().strip().splitlines() if x.startswith('{')]
   v=dict(parts[-1])
   if len(parts)>1:
    for k in ['cloud_bytes','user_bytes','count_s','selector_s','encode_s','input_and_material_io_s','transport_s','frames']:v[k]=sum(x[k] for x in parts)
    v['peak_rss_bytes']=max(x['peak_rss_bytes'] for x in parts)
    v['phase_metrics']=parts
   stats.append(v)
  # User processes receive both final files only after both clouds terminate.
  if validate:
   client_started=time.monotonic()
   client=run(['client',*outputs,d/'expected.bin'],timeout=60,preexec_fn=limits(client_cpu))
   client_wall=time.monotonic()-client_started
   c=json.loads(client.stdout)
  else:
   client_wall=0
   c={'decode_s':0,'validation_s_excluded':0,'client_peak_rss_bytes':0,'status':'PRIVATE_INTERMEDIATE_NOT_SENT_TO_QU'}
  return dict(status='PASS',method=method,physical_cloud_processes=True,owner_online=False,private_AES256_dealer_key_given_to_cloud=False,only_own_state_paths=True,
   harness_wall_including_client_and_oracle_s=time.monotonic()-started,client_process_wall_s=client_wall,strict_protocol_wall_s=wall+client_wall-c['validation_s_excluded'],
   cloud_wall_s=wall,user_decode_s=c['decode_s'],user_validation_s_excluded=c['validation_s_excluded'],online_return_wall_s=wall+c['decode_s'],
   cloud_local_cpu_proxy_s=sum(x['count_s']+x['selector_s']+x['encode_s']-x['transport_s'] for x in stats),cloud_cpu_s=sum(x.get('cloud_cpu_s',0) for x in stats),
   count_s=sum(x['count_s'] for x in stats),selector_s=sum(x['selector_s'] for x in stats),encode_s=sum(x['encode_s'] for x in stats),
   cloud_io_s=sum(x['input_and_material_io_s'] for x in stats),cloud_transport_s=sum(x['transport_s'] for x in stats),cloud_bytes=sum(x['cloud_bytes'] for x in stats),
   user_bytes=sum(x['user_bytes'] for x in stats),user_file_bytes=sum(o.stat().st_size for o in outputs),cloud_peak_rss_max_bytes=max(x['peak_rss_bytes'] for x in stats),
   cloud_peak_rss_sum_bytes=sum(x['peak_rss_bytes'] for x in stats),client_peak_rss_bytes=c['client_peak_rss_bytes'],role_stats=stats,client_stats=c)
 finally:
  for ch in s:ch.close()
  for p in procs:
   if p.poll() is None:p.kill();p.wait()
def make(directory,L,M,masked,seed=None,extra_shuffle=False,private_identifiers=False):
 d=pathlib.Path(directory);d.mkdir(parents=True,exist_ok=False);os.chmod(d,0o700)
 # Reproducible public seed is permitted for isolated performance fixtures;
 # private security cases use secrets and retain DO key under 0600 mode.
 key=secrets.token_bytes(32) if seed is None else hashlib.sha256(f'performance-only:{seed}'.encode()).digest()
 kp=d/'DO-only.key';kp.write_bytes(key);os.chmod(kp,0o600)
 binding=hashlib.sha256(key+b'query-binding').hexdigest()
 t=time.monotonic();run(['inputs-private' if private_identifiers else 'inputs',d,L,M,kp,int(masked),binding,0],timeout=240,preexec_fn=limits(6));fixture=time.monotonic()-t
 t=time.monotonic();run(['prep',d,L,kp,int(masked),binding,0],timeout=240,preexec_fn=limits(6));generation=time.monotonic()-t
 if extra_shuffle:
  t=time.monotonic();run(['prep-shuffle',d,L,kp,binding],timeout=240,preexec_fn=limits(6));generation+=time.monotonic()-t
 files=[f for f in d.glob('*.bin') if f.name.startswith(('count','select','shuffle'))]
 sync=fsync_files(files);byte=sum(f.stat().st_size for f in files)
 material=byte-56*len(files)
 hashes={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in files} if L<=100000 else {}
 return dict(L=L,M=M,masked_input=bool(masked),input_boundary='already Keep-masked Ring64 IDs' if masked else 'raw dynamic Ring64 IDs plus XOR Keep',
  preprocessing_complete_before_clouds=True,offline_generation_and_fsync_s=generation+sync,offline_generation_s=generation,fsync_s=sync,
  material_bytes=material,material_file_bytes=byte,offline_delivered_by_files=True,offline_cloud_delivery_network_measured=False,
  fixture_s_excluded=fixture,private_seed=seed is None,seed=seed,query_binding=binding,material_hashes=hashes)
def smoke(rootname="role-smoke-v2"):
 root=P/rootname;root.mkdir(exist_ok=True);results=[]
 for masked in [False,True]:
  for L,M in [(1,0),(1,1),(2,2),(3,3),(9,0),(9,1),(9,2),(17,3),(65,2),(4097,3)]:
   for trial in range(5):
    d=root/f'{int(masked)}-{L}-{M}-{trial}';meta=make(d,L,M,masked,extra_shuffle=True)
    # Paired alternative protocol instances: material is cloned only for this
    # counterfactual test; each claimed ticket runs exactly once per instance.
    for method in ['sre','full','shuffle']:
     dest=d/method;dest.mkdir()
     for f in d.glob('*.bin'):os.link(f,dest/f.name)
     result=execute(dest,method);result.update(meta,trial=trial,paired_counterfactual_instance=True);results.append(result)
  print('COMPLETE PRIVATE ROLE GRID',int(masked),flush=True)
 (P/(rootname+"-results.json")).write_text(json.dumps(results,indent=2)+'\n')
 print('COMPLETE',len(results),'ROLE TESTS',flush=True)
if __name__=='__main__':smoke()
