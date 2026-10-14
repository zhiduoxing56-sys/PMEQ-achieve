import os,pathlib,secrets,json,time
import role_driver as d
p=pathlib.Path(__file__).resolve().parent;root=p/'grouped-private-large';root.mkdir(exist_ok=False);out=[];K,N,M=10,600121,2;L=K*N
for trial in range(5):
 folder=root/secrets.token_hex(12);folder.mkdir();os.chmod(folder,0o700);key=folder/'DO-only.key';key.write_bytes(secrets.token_bytes(32));os.chmod(key,0o600);binding=secrets.token_hex(32)
 start=time.monotonic();d.run(['prep-grouped',folder,L,N,key,binding],preexec_fn=d.limits(14));d.run(['prep-shuffle',folder,L,key,binding],preexec_fn=d.limits(14));sync=d.fsync_files(list(folder.glob('*.bin')));offline=time.monotonic()-start;finished=time.time()
 fixture=folder/'fixture-only.key';fixture.write_bytes(secrets.token_bytes(32));os.chmod(fixture,0o600);d.run(['inputs-grouped',folder,L,N,M,fixture,binding,1],preexec_fn=d.limits(14));os.environ['SRE_GROUP_N']=str(N)
 r=d.execute(folder,'sre',adaptive=True,cpu_pins=(8,10),client_cpu=12);r.update(L=L,K=K,N=N,M=M,trial=trial,private_256bit_fresh_owner_seed=True,private_256bit_independent_fixture_seed=True,owner_offline_before_query=True,material_file_bytes=sum(f.stat().st_size for f in folder.glob('*.bin') if f.name.startswith(('count','select','anchor','shuffle'))),offline_generation_and_fsync_s=offline,secret_seed_not_in_cloud_arguments=True);out.append(r);print('COMPLETE PRIVATE LARGE',trial,flush=True)
(p/'grouped-private-large-results.json').write_text(json.dumps(out,indent=2)+'\n');print('COMPLETE 5 PRIVATE SIX-MILLION-SLOT EXECUTIONS')
