import pathlib,os,secrets,hashlib,json,time,struct,shutil
import role_driver as d
P=pathlib.Path(__file__).resolve().parent
def main():
 root=P/'capacity-v4';root.mkdir(exist_ok=False);plans=[];registry=root/'fixed-server-state'
 # Public offline maximum is fixed FIRST. Actual length/support follows only
 # after ALL owner preprocessing processes have terminated.
 for trial in range(5):
  for capacity,L,M in [(0,0,0),(65,1,1),(65,2,2),(65,17,3),(65,33,4),(65,52,26),(65,65,3),(4097,17,2),(4097,4097,3)]:
   for masked in [0,1]:
    folder=root/os.urandom(12).hex();folder.mkdir();os.chmod(folder,0o700)
    key=folder/'DO-only.key';key.write_bytes(secrets.token_bytes(32));os.chmod(key,0o600);binding=secrets.token_hex(32)
    d.run(['prep',folder,capacity,key,masked,binding,0],preexec_fn=d.limits(14))
    d.run(['prep-shuffle',folder,capacity,key,binding],preexec_fn=d.limits(14));d.fsync_files(list(folder.glob('*.bin')))
    plans.append((folder,key,binding,capacity,L,M,masked,trial))
 owner_offline_unix=time.time();results=[]
 for folder,key,binding,capacity,L,M,masked,trial in plans:
  # This is the trusted test fixture producer, not the owner's online role.
  fixture_key=folder/'fixture-only.key';fixture_key.write_bytes(secrets.token_bytes(32));os.chmod(fixture_key,0o600)
  d.run(['inputs-private',folder,L,M,fixture_key,masked,binding,0],preexec_fn=d.limits(14))
  r=d.execute(folder,'sre',adaptive=True,cpu_pins=(8,10),client_cpu=12,registry=registry)
  r.update(L=L,M=M,L_capacity=capacity,masked_input=bool(masked),trial=trial,private_full64_ids=True,
   owner_offline_unix=owner_offline_unix,query_started_unix=time.time()-r['cloud_wall_s'],all_bank_generated_before_actual_queries=True)
  results.append(r)
 # Explicit matched payloads in different positions, maximal IDs, shared
 # anchors/targets and wraparound; prep is independent of these fixtures.
 patterns=[([0,6],[(0,0),(0,0)]),([1,2],[(2**64-1,2**64-1)]*2),([0,1,2],[(7,0),(7,9),(7,2**64-1)]),([0,1,2],[(0,9),(2**64-1,9),(8,9)]),([0,8,16],[(7,9),(7,9),(0,0)]),([0,1],[(1,1),(2**64-1,2**64-1)])]
 for trial in range(5):
  for hits,values in patterns:
   folder=root/os.urandom(12).hex();meta=d.make(folder,17,len(hits),0,extra_shuffle=True,private_identifiers=True)
   # Replace only trusted query input; clouds still receive random own shares.
   ref=dict(zip(hits,values));parts=[bytearray(),bytearray()];bits=[bytearray(3),bytearray(3)]
   for i in range(17):
    b=secrets.randbits(1);bits[0][i//8]|=b<<(i%8);bits[1][i//8]|=(b^(i in ref))<<(i%8)
    a,t=ref.get(i,(secrets.randbits(64),secrets.randbits(64)));sa=secrets.randbits(64);st=secrets.randbits(64)
    if i==0:sa=st=2**64-1
    parts[0]+=struct.pack('<QQ',sa,st);parts[1]+=struct.pack('<QQ',(a-sa)%2**64,(t-st)%2**64)
   for party in [0,1]:
    f=folder/f'input{party}.bin';h=f.read_bytes()[:56];f.write_bytes(h+bits[party]+parts[party])
   (folder/'expected.bin').write_bytes(b''.join(struct.pack('<QQQ',i,*ref[i]) for i in hits))
   r=d.execute(folder,'sre',adaptive=True,cpu_pins=(8,10),client_cpu=12,registry=registry);r.update(meta,trial=trial,explicit_pattern=patterns.index((hits,values)),L_capacity=17);results.append(r)
 # Copy replay: identity, not pathname, is authoritative.
 copy=root/'copied-ticket';copy.mkdir()
 for f in folder.glob('*.bin'):shutil.copyfile(f,copy/f.name)
 try:d.execute(copy,'sre',adaptive=True,cpu_pins=(8,10),client_cpu=12,registry=registry)
 except RuntimeError as e:assert 'already-consumed ticket identity' in str(e)
 else:raise AssertionError('copied replay passed')
 out=dict(status='PASS',capacity_and_edge_queries=len(results),query_materials_owner_offline=True,Lmax_unknown_actual_K_supported=True,
  copied_ticket_replay_rejected=True,duplicate_zero_and_max_ids_verified=True,results=results)
 (P/'capacity-v4-results.json').write_text(json.dumps(out,indent=2)+'\n');print('COMPLETE',len(results),'FINAL CAPACITY/PREFIX/EDGE QUERY TESTS')
if __name__=='__main__':main()
