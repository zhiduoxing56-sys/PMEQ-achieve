import json,subprocess,time,threading,hashlib
from pathlib import Path
P=Path(__file__).resolve().parent
def main():
    while 'COMPLETE' not in (P/'full-secure-runner.log').read_text():time.sleep(5)
    jobs=[(L,N,t) for L,N in [(100000,100000),(1000000,1000000),(6001215,6001215),(60012150,6001215)] for t in range(5)];lock=threading.Lock();sha=hashlib.sha256((P/'ring-sum1').read_bytes()).hexdigest()
    with (P/'ring-sum-raw.jsonl').open('w',buffering=1) as output:
        def worker(i):
            cpu=[0,2,4,6][i]
            for L,N,trial in jobs[i::4]:
                seed=202610110000+trial*100000000+L*37+101;cmd=['taskset','-c',str(cpu),'prlimit',f'--as={4*1024**3}',str(P/'ring-sum1'),'ring-sum1',str(L),str(N),'1',str(seed),str(trial)];start=time.monotonic();base=dict(requested_method='ring-sum1',L=L,N=N,K=L//N,M=1,trial=trial,seed=seed,scope='M1_special',experiment_version='v2-pinned4',cpu_pin=cpu,binary_sha256=sha)
                try:
                    r=subprocess.run(cmd,capture_output=True,text=True,timeout=240)
                    if r.returncode:base.update(status='EXECUTION_FAILED',record_type='failed',stderr=r.stderr)
                    else:base.update(json.loads(r.stdout));base.update(record_type='measured',process_wall_s=time.monotonic()-start,kernel_version='v2-ring-sum');base['end_to_end_with_measured_offline_s']=base['online_s']+base['offline_s'];base['cloud_local_s']=base['prepare_s']+base['encode_s']-base['cloud_transport_s']
                except subprocess.TimeoutExpired:base.update(record_type='failed',status='TIMEOUT_240S')
                with lock:output.write(json.dumps(base)+'\n');print('DONE',L,trial,base['status'],flush=True)
        threads=[threading.Thread(target=worker,args=(i,)) for i in range(4)]
        for t in threads:t.start()
        for t in threads:t.join()
    print('COMPLETE 20 ring-sum1 jobs',flush=True)
if __name__=='__main__':main()
