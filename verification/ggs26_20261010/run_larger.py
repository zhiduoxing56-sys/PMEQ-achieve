"""Evaluated before launch: 2 x 512MiB VM, actual O(N+K) state for M0/M1.
Includes the maximum nonempty MB K/M shape, never the TB TPC-H prefix bank.
"""
import json,subprocess,time,threading,hashlib
from pathlib import Path
P=Path(__file__).resolve().parent
def main():
    shapes=[('linear-grouped',324542880,67896,0),('grouped-sum1',311099472,67896,1)]
    review=[]
    for method,L,N,M in shapes:
        K=L//N
        review.append(dict(method=method,L=L,N=N,K=K,M=M,memory_limit_bytes=512*1024**2,workers=2,explicit_local_array_upper_bound_bytes=100*1024**2,reason_memory_bound='N<68000, at most K weights M1, fixed 4096-slot buffers; no O(L) arrays; checked grouped.cpp/countAll/Fixture',conservative_process_time_estimate_s=200,basis_time='Actual 60M M0/M1 process wall scaling plus 50% margin; estimate, not timing observation',timeout_s=240,shuffle_measured_RSS_scaled_bytes=int(14891044864*L/60012150),decision='Execute five seeded sparse special-case runs only'))
    (P/'larger-execution-preflight.json').write_text(json.dumps(review,indent=2))
    jobs=[(*s,t) for s in shapes for t in range(5)];lock=threading.Lock();bh=hashlib.sha256((P/'grouped').read_bytes()).hexdigest()
    with (P/'larger-raw.jsonl').open('w',buffering=1) as f:
        def worker(index):
            for method,L,N,M,trial in jobs[index::2]:
                seed=202610121000+trial*100000000+L*37+M*101;t=time.monotonic();print('START',method,L,trial,flush=True)
                r=subprocess.run(['taskset','-c',str([0,2][index]),'prlimit',f'--as={512*1024**2}',str(P/'grouped'),method,str(L),str(N),str(M),str(seed),str(trial)],text=True,capture_output=True,timeout=240)
                base=dict(requested_method=method,L=L,N=N,K=L//N,M=M,trial=trial,seed=seed,experiment_version='v7-larger-sparse',scope='Two sparse workers CPU0/2, 512MiB each; guarded large shuffles CPU8/10 and offline-bank CPU14 may run',binary_sha256=bh,cpu_pin=[0,2][index])
                if r.returncode:base.update(record_type='failed',status='EXECUTION_FAILED',stderr=r.stderr)
                else:
                    base.update(json.loads(r.stdout.strip().splitlines()[-1]));base.update(record_type='measured',process_wall_s=time.monotonic()-t);base['end_to_end_with_measured_offline_s']=base['online_s']+base['offline_s'];base['cloud_local_s']=base['prepare_s']+base['encode_s']-base['cloud_transport_s']
                with lock:f.write(json.dumps(base)+'\n');print('DONE',method,L,trial,base['status'],time.monotonic()-t,flush=True)
        ts=[threading.Thread(target=worker,args=(i,)) for i in range(2)]
        for t in ts:t.start()
        for t in ts:t.join()
    print('COMPLETE 10 larger sparse jobs',flush=True)
if __name__=='__main__':main()
