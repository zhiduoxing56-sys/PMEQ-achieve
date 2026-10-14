import os,pathlib,json,secrets,time,hashlib,shutil
import role_driver as d
p=pathlib.Path(__file__).resolve().parent;root=p/'grouped-tests-v2';root.mkdir(exist_ok=False);out=[]
for trial in range(5):
 for K,N,M,capK in [(0,1,0,0),(1,1,1,1),(2,1,2,2),(3,1,3,3),(1,17,0,2),(1,17,1,2),(1,17,2,2),(2,17,3,3),(3,13,3,5),(2,26,4,3),(2,26,26,3),(1,17,17,1),(241,17,3,243),(2,4097,3,3)]:
  folder=root/secrets.token_hex(12);folder.mkdir();os.chmod(folder,0o700);key=folder/'DO-only.key';key.write_bytes(secrets.token_bytes(32));os.chmod(key,0o600);binding=secrets.token_hex(32)
  d.run(['prep-grouped',folder,capK*N,N,key,binding],preexec_fn=d.limits(14));d.run(['prep-shuffle',folder,capK*N,key,binding],preexec_fn=d.limits(14));d.fsync_files(list(folder.glob('*.bin')));finished=time.time()
  fixture=folder/'fixture-only.key';fixture.write_bytes(secrets.token_bytes(32));os.chmod(fixture,0o600)
  d.run(['inputs-grouped',folder,K*N,N,M,fixture,binding,1],preexec_fn=d.limits(14));os.environ['SRE_GROUP_N']=str(N)
  r=d.execute(folder,'sre',adaptive=True,cpu_pins=(8,10),client_cpu=12);r.update(K=K,N=N,L=K*N,M=M,L_capacity=capK*N,trial=trial,owner_offline_before_fixture=True,private_full64_both_IDs=True);out.append(r)
  if M<=3:
   try:d.execute(folder,'shuffle',cpu_pins=(8,10),client_cpu=12)
   except RuntimeError as e:assert 'already-consumed ticket identity' in str(e)
   else:raise AssertionError('unused fallback not retired')
 print('COMPLETE GROUPED TRIAL',trial,flush=True)
(p/'grouped-tests-v2-results.json').write_text(json.dumps(out,indent=2)+'\n');print('COMPLETE',len(out),'PRIVATE GROUPED CAPACITY/PAIRING TESTS')
