"""Five full capacity-T1000 offline file banks per required L, no M input.
Only latest two party artifacts retained; hash/size/sample certificates persist.
"""
import json,subprocess,time,hashlib,os,struct,random
from pathlib import Path
from minimal import mul,U64
P=Path(__file__).resolve().parent
def target(i,N):
    j=i%N;special=[0,U64,7,7,0,123];return special[j] if j<6 else j
def main():
    folder=P/'offline-material';folder.mkdir(exist_ok=True);output=P/'offline-bank-raw.jsonl';rows=[]
    with output.open('w',buffering=1) as log:
        for L,N in [(100000,100000),(1000000,1000000),(6001215,6001215),(60012150,6001215)]:
            for trial in range(5):
                seed=202610120000+trial*100000000+L*37;T=1000;K=L//N;t=time.monotonic()
                r=subprocess.run(['taskset','-c','14','prlimit',f'--as={512*1024**2}',str(P/'offline-bank'),str(L),str(N),str(T),str(seed),str(trial),str(folder)],text=True,capture_output=True,timeout=240);assert r.returncode==0,r.stderr
                row=json.loads(r.stdout.strip().splitlines()[-1]);row.update(M=None,experiment_version='v6-offline-bank',scope='Complete reserved material written to two local files, fsync; no cloud delivery or online bank consumption',cpu_pin=14,process_wall_s=time.monotonic()-t)
                files=[folder/f'cs{p}.bin' for p in (0,1)];t=time.monotonic()
                for path in files:
                    with path.open('r+b') as f:os.fsync(f.fileno())
                row['fsync_s']=time.monotonic()-t;row['offline_s']=row['offline_file_generation_s']+row['fsync_s'];assert sum(f.stat().st_size for f in files)==row['file_bytes_with_headers']
                t=time.monotonic();sha=[]
                for path in files:
                    h=hashlib.sha256()
                    with path.open('rb') as f:
                        while data:=f.read(1024*1024):h.update(data)
                    sha.append(h.hexdigest())
                handles=[f.open('rb') for f in files]
                def read(p,off,n):handles[p].seek(off);a=handles[p].read(n);assert len(a)==n;return a
                static=56;count=static+8*N;target_at=count+8*L+(L+7)//8;bits=target_at+8*L+(L+7)//8;fields=bits+3024*((K+63)//64)
                for i in [0,1,2,N-1,L-1]:
                    j=i%N;z=[struct.unpack('<Q',read(p,static+8*j,8))[0] for p in (0,1)];assert z[0]^z[1]==target(i,N)
                    block=i//4096;off=i%4096;n=min(4096,L-block*4096);bitlen=(n+7)//8
                    for region,is_count in [(count,True),(target_at,False)]:
                        at=region+block*(512+8*4096);rb=[(read(p,at+off//8,1)[0]>>(off%8))&1 for p in (0,1)];v=[struct.unpack('<Q',read(p,at+bitlen+8*off,8))[0] for p in (0,1)]
                        assert (sum(v)&U64)==(rb[0]^rb[1]) if is_count else v[0]^v[1]==(target(i,N) if rb[0]^rb[1] else 0)
                for index in [0,2*K*T-1]:
                    records=[[int.from_bytes(read(p,fields+51*index+17*x,17),'little') for x in range(3)] for p in (0,1)];u,v,w=[records[0][x]^records[1][x] for x in range(3)];assert mul(u,v)==w
                for h in handles:h.close()
                row.update(status='PASS_FULL_RESERVED_BANK_FILES_AND_SAMPLES',sha256=sha,verification_s_excluded=time.monotonic()-t,bank_material_consumed_online=False);rows.append(row);log.write(json.dumps(row)+'\n');print(L,trial,row['offline_s'],flush=True)
    (P/'offline-bank-certificates.json').write_text(json.dumps(rows,indent=2));print('COMPLETE 20 offline bank jobs',flush=True)
if __name__=='__main__':main()
