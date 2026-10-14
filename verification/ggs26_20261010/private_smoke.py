"""Physical cloud tests with secret 256-bit AES keys; owner-only replay keys.
Unlike public fixed-seed timings, the cloud arguments cannot regenerate masks.
Fixture/preprocessing and the OpenSSL child finish before either cloud starts.
"""
import os,json,subprocess,hashlib,multiprocessing as mp,random
from pathlib import Path
from minimal import decode,U64
import two_process_grouped as g
P=Path(__file__).resolve().parent
class CryptoRandom:
    def __init__(self,key,domain):
        iv=(domain<<64).to_bytes(16,'big');r=subprocess.run(['openssl','enc','-aes-256-ctr','-K',key.hex(),'-iv',iv.hex(),'-nopad'],input=bytes(65536),capture_output=True);assert r.returncode==0
        self.buf=r.stdout;self.at=0
    def getrandbits(self,n):
        size=(n+7)//8;b=self.buf[self.at:self.at+size];assert len(b)==size;self.at+=size;return int.from_bytes(b,'little')&((1<<n)-1)
    def below(self,n):
        while True:
            x=self.getrandbits((n-1).bit_length())
            if x<n:return x
def main():
    folder=P/'private-replay';folder.mkdir(exist_ok=True,mode=0o700);os.chmod(folder,0o700);keyfile=folder/'keys.json'
    if keyfile.exists():keys=json.loads(keyfile.read_text())
    else:
        keys={str(i):os.urandom(32).hex() for i in range(30)};fd=os.open(keyfile,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:json.dump(keys,f)
    ctx=mp.get_context('spawn');rows=[];old_random=random.Random
    for trial in range(5):
        for ci,(N,M,sum_only) in enumerate([(6,0,False),(6,1,False),(6,2,False),(6,3,False),(2,4,False),(6,1,True)]):
            index=trial*6+ci;key=bytes.fromhex(keys[str(index)]);case_label=202610122000+index;rng=CryptoRandom(key,0);K=2;n=K*N
            hits=set()
            while len(hits)<M:hits.add(rng.below(n))
            # Separate, disjoint CTR domains for fixture and GF triples.
            random.Random=lambda s:CryptoRandom(key,1 if s==case_label else 2)
            try:states,_=g.fixture(K,N,hits,n,case_label,sum_only)
            finally:random.Random=old_random
            anchors=[rng.getrandbits(64) for _ in range(K)];targets=[rng.getrandbits(64) for _ in range(N)]
            for p in (0,1):states[p]['anchor']=[];states[p]['target']=[];states[p]['target_prep']=[]
            for a in anchors:
                s=rng.getrandbits(64);states[0]['anchor'].append(s);states[1]['anchor'].append((a-s)&U64)
            for t in targets:
                s=rng.getrandbits(64);states[0]['target'].append(s);states[1]['target'].append(t^s)
            target_rng=CryptoRandom(key,3)
            for i in range(n):
                r=target_rng.getrandbits(1);rb=target_rng.getrandbits(1);rp=target_rng.getrandbits(64);states[0]['target_prep'].append((rb,rp));states[1]['target_prep'].append((r^rb,(targets[i%N] if r else 0)^rp))
            want=[(i,anchors[i//N],targets[i%N]) for i in sorted(hits)];views=g.execute(ctx,states);assert all(v['status']=='OK' and v['M']==M for v in views),views
            s=[int.from_bytes(views[0]['syndrome'][i:i+17],'little')^int.from_bytes(views[1]['syndrome'][i:i+17],'little') for i in range(0,len(views[0]['syndrome']),17)]
            if sum_only:assert s[0]>>128==1 and ((s[0]>>64)&U64,s[0]&U64)==want[0][1:]
            else:assert decode(s,n,M)==want
            row=dict(trial=trial,case_label=case_label,K=K,N=N,M=M,sum_only=sum_only,secret_seed_bits=256,key_commitment=hashlib.sha256(key).hexdigest(),private_seed_given_to_cloud=False,owner_online=False,only_own_state=True,status='PASS',view_hashes=[v['view_sha256'] for v in views]);rows.append(row);print(json.dumps(row),flush=True)
    (P/'private-smoke-results.json').write_text(json.dumps(rows,indent=2));print('COMPLETE 30 PRIVATE AES256 ROLE TESTS',flush=True)
if __name__=='__main__':main()
