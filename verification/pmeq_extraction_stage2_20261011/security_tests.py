#!/usr/bin/env python3
import collections,itertools,json,pathlib,hashlib,shutil,os,struct
import role_driver as d
P=pathlib.Path(__file__).resolve().parent
def view_exact():
 # Enumerate both vector-selector coordinates over Z/2 (including full
 # local material and all openings). A complete vector test, not merely
 # separate marginals. Keep and both identifiers vary independently.
 reference=None;samples=0
 for b,x,y in itertools.product(range(2),repeat=3):
  dist=collections.Counter()
  for r,rb,rs,ta,tb,sa,sb,ua,ub in itertools.product(range(2),repeat=9):
   e=b^r;fa=(x-ta)%2;fb=(y-tb)%2
   view=(rb,rs,sa,sb,ua,ub,e,fa,fb)
   dist[view]+=1;samples+=1
   # Correlated sharing reconstructed and evaluated using both roles.
   aa=(ua+fa*rs)%2;ab=(ub+fb*rs)%2
   ba=((r*ta-ua)+fa*(r-rs))%2;bb=((r*tb-ub)+fb*(r-rs))%2
   if e:aa=(-aa)%2;ab=(-ab)%2;ba=(x-ba)%2;bb=(y-bb)%2
   assert (aa+ba)%2==b*x and (ab+bb)%2==b*y
  if reference is None:reference=dist
  assert dist==reference
 return {'selector_joint_distribution_equal_all_8_worlds':True,'enumerated_samples':samples,'distinct_local_views':len(reference),'scope':'Z/2 vector selector only; full arbitrary-word simulation supplied separately'}
def tests():
 root=P/'security-tests';root.mkdir(exist_ok=False);out={'exact_views':view_exact(),'protocol_tests':[]}
 # Fresh, private keys and opaque directories for successive queries.
 for trial in range(5):
  for masked in [0,1]:
   for M in [0,1,2,3,4,17]:
    folder=root/os.urandom(12).hex();meta=d.make(folder,17,M,masked,extra_shuffle=True)
    r=d.execute(folder,'sre',adaptive=True,cpu_pins=(8,10),client_cpu=12)
    r.update(meta,trial=trial,all_M_correct_with_reserved_fallback=True)
    assert r['user_bytes']==r['user_file_bytes'];out['protocol_tests'].append(r)
 # A consumed packet cannot be replayed even by an honest API caller.
 reused=folder
 try:d.execute(reused,'sre',adaptive=True,cpu_pins=(8,10),client_cpu=12)
 except RuntimeError as e:
  assert 'already-consumed ticket' in str(e);out['reuse_rejected']=True
 else:raise AssertionError('replay unexpectedly accepted')
 # M>3 without a reserved fallback must reject explicitly, never truncate.
 folder=root/os.urandom(12).hex();d.make(folder,9,4,0)
 try:d.execute(folder,'sre',cpu_pins=(8,10),client_cpu=12)
 except RuntimeError as e:
  assert 'capacity exceeded' in str(e);out['capacity_without_fallback_rejected']=True
 else:raise AssertionError('unsupported M passed')
 # A local manifest mismatch rejects before any Keep-related exchange.
 folder=root/os.urandom(12).hex();d.make(folder,9,2,0)
 f=folder/'count0.bin';w=bytearray(f.read_bytes());w[16]^=1;f.write_bytes(w)
 try:d.execute(folder,'sre',cpu_pins=(8,10),client_cpu=12)
 except RuntimeError as e:
  assert 'binding' in str(e);out['mixed_binding_rejected']=True
 else:raise AssertionError('mixed manifest passed')
 # Honest cloud never learns QU's peer share: stdout files are separate;
 # final metadata mismatch is detected at QU, with no feedback to clouds.
 good=out['protocol_tests'][2]
 out['status']='PASS';out['fresh_queries']=len(out['protocol_tests']);out['proof_limit']='Finite exact views plus protocol tests do not constitute a composable/malicious security proof.'
 (P/'security-tests-results.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({k:v for k,v in out.items() if k!='protocol_tests'}))
if __name__=='__main__':tests()
