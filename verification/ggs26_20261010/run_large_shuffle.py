"""Two guarded large workers. Pilot 14.9GB RSS; 18GiB VM each, 8GiB reserve.
Original serial prefix retained. JSON rows state actual worker scope.
"""
import json,subprocess,time,hashlib,threading
from pathlib import Path
P=Path(__file__).resolve().parent
def available():
    for s in Path('/proc/meminfo').read_text().splitlines():
        if s.startswith('MemAvailable:'):return int(s.split()[1])*1024

def main():
    while 'COMPLETE' not in (P/'grouped-sum-runner.log').read_text():time.sleep(5)
    assert available()>44*1024**3,'Need 36GiB worst-case VM plus 8GiB host reserve'
    jobs=[(L,N,M,trial) for L,N,M in [(60012150,6001215,m) for m in [0,1,2,10,100,1000]]+[(35238024,67896,667),(12002430,6001215,2)] for trial in range(5)]
    done=set();out=P/'large-shuffle-raw.jsonl'
    if out.exists():
        for line in out.read_text().splitlines():
            r=json.loads(line);done.add((r['L'],r['N'],r['M'],r['trial']))
    jobs=[j for j in jobs if j not in done];binary=P/'prototype-large';bh=hashlib.sha256(binary.read_bytes()).hexdigest();lock=threading.Lock();active={};stop=threading.Event()
    def watchdog():
        while not stop.wait(1):
            if available()<8*1024**3:
                with lock:
                    for proc in active.values():proc.terminate()
                stop.set();print('HOST RESERVE ABORT',flush=True);return
    monitor=threading.Thread(target=watchdog,daemon=True);monitor.start()
    with out.open('a',buffering=1) as f:
        def worker(index):
            cpu=[8,10][index]
            for L,N,M,trial in jobs[index::2]:
                if stop.is_set():return
                while available()<300*L+8*1024**3:
                    if stop.wait(2):return
                seed=202610110000+trial*100000000+L*37+M*101
                cmd=['taskset','-c',str(cpu),'prlimit',f'--as={18*1024**3}',str(binary),'shuffle',str(L),str(N),str(M),str(seed),str(trial)]
                free=available();t=time.monotonic();print('START',L,M,trial,'cpu',cpu,'available',free,flush=True)
                proc=subprocess.Popen(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                with lock:active[index]=proc
                try:stdout,stderr=proc.communicate(timeout=240)
                except subprocess.TimeoutExpired:proc.kill();stdout,stderr=proc.communicate();stderr+='TIMEOUT 240S'
                with lock:active.pop(index,None)
                base=dict(requested_method='shuffle',L=L,N=N,K=L//N,M=M,trial=trial,seed=seed,experiment_version='v4-large-serial',scope='Guarded extension: 2 workers CPU8/10; 18GiB each; 36GiB VM total; 8GiB reserve; same equations as serial prefix',cpu_pin=cpu,binary_sha256=bh,available_memory_before_bytes=free,memory_limit_bytes=18*1024**3,conservative_guard_bytes=300*L,large_workers=2,background_grouped_active=False)
                if proc.returncode:base.update(record_type='failed',status='EXECUTION_FAILED',stderr=stderr)
                else:
                    base.update(json.loads(stdout.strip().splitlines()[-1]));base.update(record_type='measured',process_wall_s=time.monotonic()-t);base['end_to_end_with_measured_offline_s']=base['online_s']+base['offline_s'];base['cloud_local_s']=base['prepare_s']+base['encode_s']-base['cloud_transport_s']
                with lock:f.write(json.dumps(base)+'\n')
                print('DONE',L,M,trial,base['status'],time.monotonic()-t,flush=True)
                if base['record_type']=='failed':stop.set();return
        ts=[threading.Thread(target=worker,args=(i,)) for i in range(2)]
        for t in ts:t.start()
        for t in ts:t.join()
    stop.set();monitor.join(2)
    print('COMPLETE 40 large shuffle jobs' if all(json.loads(x)['record_type']=='measured' for x in out.read_text().splitlines()) and len(out.read_text().splitlines())==40 else 'INCOMPLETE',flush=True)
if __name__=='__main__':main()
