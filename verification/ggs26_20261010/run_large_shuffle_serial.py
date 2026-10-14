"""Adaptive safe one-large-worker shuffle extension.
24 GiB virtual memory limit, 8 GiB host reserve, 240 s timeout per job.
Pilot command executes only L=60,012,150, M=10, trial=0.
"""
import json,subprocess,time,hashlib,sys
from pathlib import Path
P=Path(__file__).resolve().parent
def available():
    for s in Path('/proc/meminfo').read_text().splitlines():
        if s.startswith('MemAvailable:'):return int(s.split()[1])*1024
def main():
    if 'COMPLETE' not in (P/'matched-runner.log').read_text():raise RuntimeError('Other experiments still running')
    pilot=len(sys.argv)>1 and sys.argv[1]=='pilot';jobs=[(60012150,6001215,10,0)] if pilot else [(L,N,M,trial) for L,N,M in [(60012150,6001215,m) for m in [0,1,2,10,100,1000]]+[(35238024,67896,667),(12002430,6001215,2)] for trial in range(5)]
    done=set();out=P/'large-shuffle-raw.jsonl'
    if out.exists():
        for line in out.read_text().splitlines():
            r=json.loads(line);done.add((r['L'],r['N'],r['M'],r['trial']))
    binary=P/'prototype-large';bh=hashlib.sha256(binary.read_bytes()).hexdigest()
    with out.open('a',buffering=1) as f:
        for L,N,M,trial in jobs:
            if (L,N,M,trial) in done:continue
            free=available();guard=400*L
            if free<guard+8*1024**3:raise RuntimeError(f'Host memory reserve failed: available={free}, guard={guard}')
            seed=202610110000+trial*100000000+L*37+M*101
            cmd=['taskset','-c','8','prlimit',f'--as={24*1024**3}',str(binary),'shuffle',str(L),str(N),str(M),str(seed),str(trial)]
            t=time.monotonic();print('START',L,M,trial,'available',free,flush=True)
            r=subprocess.run(cmd,text=True,capture_output=True,timeout=240)
            bg=(P/'grouped-runner.log').exists() and 'COMPLETE' not in (P/'grouped-runner.log').read_text()
            base=dict(requested_method='shuffle',L=L,N=N,K=L//N,M=M,trial=trial,seed=seed,experiment_version='v4-large-serial',scope='one large shuffle on physical CPU8; 24GiB limit; 8GiB host reserve; grouped suite may occupy 0/2/4/6',cpu_pin=8,binary_sha256=bh,available_memory_before_bytes=free,conservative_guard_bytes=guard,background_grouped_active=bg)
            if r.returncode:base.update(record_type='failed',status='EXECUTION_FAILED',stderr=r.stderr)
            else:
                base.update(json.loads(r.stdout.strip().splitlines()[-1]));base.update(record_type='measured',process_wall_s=time.monotonic()-t);base['end_to_end_with_measured_offline_s']=base['online_s']+base['offline_s'];base['cloud_local_s']=base['prepare_s']+base['encode_s']-base['cloud_transport_s']
            f.write(json.dumps(base)+'\n');print('DONE',L,M,trial,base['status'],time.monotonic()-t,flush=True)
            if base['record_type']=='failed':raise RuntimeError('Pilot/runtime failure; no further large allocation')
    print('PILOT COMPLETE' if pilot else 'COMPLETE 40 large shuffle jobs',flush=True)
if __name__=='__main__':main()
