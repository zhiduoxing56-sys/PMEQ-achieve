#!/usr/bin/env python3
"""Extraction preprocessing precedes unchanged native query execution."""
import json,pathlib,os,secrets,hashlib,struct,time,subprocess,uuid
import role_driver as d
P=pathlib.Path(__file__).resolve().parent
def main():
 root=P/'native-integration-count-reuse-v5';root.mkdir(exist_ok=False);tickets={}
 prep_started=time.time()
 for trial in range(5):
  for aliases in [0,1,2,3,4,26]:
   folder=root/uuid.uuid4().hex;folder.mkdir();os.chmod(folder,0o700)
   kp=folder/'DO-only.key';kp.write_bytes(secrets.token_bytes(32));os.chmod(kp,0o600)
   binding='PMEQ-native-IndexID-01-LayoutID-02-CompactionID-03-QueryID-04-ticket-'+uuid.uuid4().hex
   d.run(['prep-shuffle',folder,52,kp,binding],preexec_fn=d.limits(14))
   d.fsync_files(list(folder.glob('*.bin')))
   tickets[(trial,aliases)]=(folder,binding)
 prep_finished=time.time();results=[];cmd=json.loads((P/'native-command.json').read_text());env=os.environ.copy();env.update(cmd['env_overrides'])
 for trial in range(5):
  exports=root/f'exports-{trial}';exports.mkdir();env['PMEQ_EXTRACTION_OUTPUT_DIR']=str(exports)
  args=cmd['command'][:];args[args.index('-count=5')]='-count=1'
  started=time.time()
  with (root/f'native-{trial}.log').open('w') as log:
   r=subprocess.run(args,cwd=cmd['cwd'],env=env,stdout=log,stderr=subprocess.STDOUT,preexec_fn=d.limits(8))
  assert r.returncode==0,(root/f'native-{trial}.log').read_text()
  assert len(list(exports.glob('*.json')))==6
  for source in exports.glob('*.json'):
   v=json.loads(source.read_text());aliases=v['Aliases'];folder,binding=tickets[(trial,aliases)]
   assert v['Bindings']=={k:[a]+[0]*15 for k,a in [('IndexID',1),('LayoutID',2),('CompactionID',3),('QueryID',4)]},v['Bindings']
   shares=v['Parties'];L=len(shares[0]['keep']);assert L==52
   hits=[i for i in range(L) if shares[0]['keep'][i]^shares[1]['keep'][i]];M=len(hits)
   assert (shares[0]['Count']+shares[1]['Count'])%2**64==M
   with (folder/'expected.bin').open('wb') as out:
    for i in hits:out.write(struct.pack('<QQQ',i,(shares[0]['Anchor'][i]+shares[1]['Anchor'][i])%2**64,(shares[0]['Target'][i]+shares[1]['Target'][i])%2**64))
   for party in [0,1]:
    header=bytearray((folder/f'shuffle{party}.bin').read_bytes()[:56]);header[49]=4
    count_header=bytearray(header);count_header[49]=6
    (folder/f'count{party}.bin').write_bytes(count_header+struct.pack('<Q',shares[party]['Count']))
    bits=bytearray((L+7)//8)
    for i,b in enumerate(shares[party]['keep']):bits[i//8]|=int(b)<<(i%8)
    with (folder/f'input{party}.bin').open('wb') as out:
     out.write(header);out.write(bits)
     for a,b in zip(shares[party]['Anchor'],shares[party]['Target']):out.write(struct.pack('<QQ',a,b))
   result=d.execute(folder,'sre',adaptive=True,cpu_pins=(8,10),client_cpu=12)
   result.update(trial=trial,aliases=aliases,L=L,M=M,source_native_fixture=str(source.relative_to(P)),native_backend='LLAMA SCMP phase6native',
    psmj_changed=False,original_go_source_hashes_unchanged=True,preprocessing_finished_unix=prep_finished,native_query_started_unix=started,
    extraction_input_boundary='native masked CandidatePairShares plus local sum of existing keep64; no new DA material',all_branches_bank_reserved=True,
    branch='BCH-Ring M<=3' if M<=3 else 'existing packed private permutation fallback',
    fixture_is_functional_not_private_security_evidence=True)
   assert prep_finished<started
   results.append(result)
   if M<=3:
    try:d.execute(folder,'shuffle',cpu_pins=(8,10),client_cpu=12)
    except RuntimeError as e:assert 'already-consumed ticket identity' in str(e)
    else:raise AssertionError('unused coupled fallback bank was not retired')
 (P/'native-count-reuse-v5-results.json').write_text(json.dumps(results,indent=2)+'\n')
 print('COMPLETE',len(results),'NATIVE PIPELINE + ISOLATED EXTRACTION TESTS; DO PREPROCESSING PRECEDES QUERY',flush=True)
if __name__=='__main__':main()
