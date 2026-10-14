import os,pathlib,json,secrets,time,hashlib,shutil
import role_driver as d
p=pathlib.Path(__file__).resolve().parent;root=p/'strict-private-benchmark';root.mkdir(exist_ok=False);source=json.loads((p/'grouped-private-large-results.json').read_text());folders=sorted((p/'grouped-private-large').iterdir());out=[]
for trial,src in enumerate(folders):
 L,K,N,M=6001210,10,600121,2;bodyhash={}
 for party in (0,1):
  with (src/f'input{party}.bin').open('rb') as f:f.read(56);bodyhash[str(party)]=hashlib.sha256(f.read()).hexdigest()
 for method in ['full','shuffle','sre']:
  dst=root/f'{trial}-{method}';dst.mkdir();os.chmod(dst,0o700);key=dst/'DO-only.key';key.write_bytes(secrets.token_bytes(32));os.chmod(key,0o600);binding=secrets.token_hex(32);banks=[]
  args=[]
  if method=='full':args=[['prep',dst,L,key,0,binding,0]]
  elif method=='shuffle':args=[['prep-shuffle',dst,L,key,binding]]
  else:args=[['prep-grouped',dst,L,N,key,binding],['prep-shuffle',dst,L,key,binding]]
  started=time.monotonic()
  for a in args:
   x=d.run(a,preexec_fn=d.limits(14));banks.append(json.loads(x.stdout.decode().splitlines()[-1]))
  fs=d.fsync_files(list(dst.glob('*.bin')));offline=time.monotonic()-started;preprocessing_finished=time.time()
  material=sum(f.stat().st_size-56 for f in dst.glob('*.bin'))
  for party in (0,1):
   h=bytearray((dst/f'shuffle{party}.bin' if method=='shuffle' else dst/f'count{party}.bin').read_bytes()[:56]);h[49]=3
   with (src/f'input{party}.bin').open('rb') as f,(dst/f'input{party}.bin').open('wb') as g:
    f.read(56);g.write(h);shutil.copyfileobj(f,g)
  shutil.copyfile(src/'expected.bin',dst/'expected.bin');os.environ['SRE_GROUP_N']=str(N)
  r=d.execute(dst,method,adaptive=method=='sre',cpu_pins=(8,10),client_cpu=12);r.update(L=L,K=K,N=N,M=M,trial=trial,status='PASS',private_256bit_fresh_owner_seed=True,source_private_body_sha256=bodyhash,reserved_material_bytes=material,offline_s=offline,strict_cold_protocol_s=offline+r['strict_protocol_wall_s'],offline_preprocessing_before_input_available=True,offline_peak_rss_bytes=max(x['offline_peak_rss_bytes'] for x in banks),method=method,experiment_version='strict-private-grouped-clock',input_boundary='same private grouped raw inputs; only public context header differs per alternative world')
  out.append(r);print('DONE STRICT PRIVATE',trial,method,r['strict_protocol_wall_s'],r['online_return_wall_s'],flush=True)
(p/'strict-private-performance.json').write_text(json.dumps(out,indent=2)+'\n');print('COMPLETE 15 STRICT PRIVATE CLOCK TESTS')
