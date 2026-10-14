"""Five independent seeds, same physical CPU pins and limits as other baselines."""
import json,subprocess,threading,time,hashlib
from pathlib import Path
P=Path(__file__).resolve().parent
def main():
    jobs=list(dict.fromkeys(tuple(j[1:5]) for j in json.loads((P/'benchmark-plan.json').read_text())['jobs'] if j[0]=='linear-B'))
    done=set();log=P/'hybrid-raw.jsonl'
    if log.exists():
        for line in log.read_text().splitlines():
            r=json.loads(line);done.add((r['L'],r['N'],r['M'],r['trial']))
    binary_hash=hashlib.sha256((P/'hybrid').read_bytes()).hexdigest();lock=threading.Lock()
    with log.open('a',buffering=1) as output,(P/'hybrid-progress.log').open('a',buffering=1) as progress:
        def worker(index):
            cpu=[0,2,4,6][index]
            for L,N,M,trial in jobs[index::4]:
                if (L,N,M,trial) in done:continue
                seed=202610110000+trial*100000000+L*37+M*101
                cmd=['taskset','-c',str(cpu),'prlimit',f'--as={4*1024**3}',str(P/'hybrid'),'linear-hybrid',str(L),str(N),str(M),str(seed),str(trial)]
                start=time.monotonic()
                with lock:progress.write(f'START L={L} M={M} trial={trial} cpu={cpu}\n')
                base=dict(requested_method='linear-hybrid',L=L,N=N,K=L//N,M=M,trial=trial,seed=seed,scope='same final matrix',experiment_version='v2-pinned4',kernel_version='v2-payload-aware',cpu_pin=cpu,binary_sha256=binary_hash)
                try:
                    r=subprocess.run(cmd,text=True,capture_output=True,timeout=240)
                    if r.returncode:base.update(record_type='failed',status='EXECUTION_FAILED',stderr=r.stderr)
                    else:
                        base.update(json.loads(r.stdout.strip().splitlines()[-1]));base.update(record_type='measured',process_wall_s=time.monotonic()-start,kernel_version='v2-payload-aware');base['end_to_end_with_measured_offline_s']=base['online_s']+base['offline_s'];base['cloud_local_s']=base['prepare_s']+base['encode_s']-base['cloud_transport_s']
                except subprocess.TimeoutExpired:base.update(record_type='failed',status='TIMEOUT_240S',elapsed_wall_s=time.monotonic()-start)
                with lock:output.write(json.dumps(base)+'\n');progress.write(f"DONE L={L} M={M} trial={trial} {base['status']} {time.monotonic()-start:.3f}s\n")
        threads=[threading.Thread(target=worker,args=(i,)) for i in range(4)]
        for t in threads:t.start()
        for t in threads:t.join()
    print('COMPLETE',len(jobs),'payload-aware jobs',flush=True)
if __name__=='__main__':main()
