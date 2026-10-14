"""Serial paired comparison CPU12; two controlled large-shuffle workers active.
All four methods have identical synthetic share boundary, rotated method order.
"""
import json,subprocess,time,hashlib
from pathlib import Path
P=Path(__file__).resolve().parent
def main():
    while 'COMPLETE' not in (P/'grouped-sum-runner.log').read_text():time.sleep(5)
    output=P/'grouped-matched-raw.jsonl';done=set()
    if output.exists():
        for line in output.read_text().splitlines():
            r=json.loads(line);done.add((r['requested_method'],r['L'],r['M'],r['trial']))
    bins={'full-secure':'full-secure','shuffle':'prototype','linear-grouped':'grouped','grouped-sum1':'grouped'}
    with output.open('a',buffering=1) as f:
        for L,M in [(1000000,1),(6001215,1),(1000000,10)]:
            methods=['full-secure','shuffle','linear-grouped']+(['grouped-sum1'] if M==1 else [])
            for trial in range(5):
                order=methods[trial%len(methods):]+methods[:trial%len(methods)]
                for method in order:
                    if (method,L,M,trial) in done:continue
                    seed=202610119000+trial*100000000+L*37+M*101;binary=P/bins[method]
                    bg='COMPLETE' not in (P/'large-shuffle-runner.log').read_text()
                    t=time.monotonic();r=subprocess.run(['taskset','-c','12','prlimit',f'--as={4*1024**3}',str(binary),method,str(L),str(L),str(M),str(seed),str(trial)],capture_output=True,text=True,timeout=240)
                    base=dict(requested_method=method,L=L,N=L,K=1,M=M,trial=trial,seed=seed,experiment_version='v5-grouped-matched',scope='Serial paired method order on CPU12, two guarded large-shuffle workers CPU8/10 may run',cpu_pin=12,background_large_shuffle_active=bg,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
                    if r.returncode:base.update(record_type='failed',status='EXECUTION_FAILED',stderr=r.stderr)
                    else:
                        base.update(json.loads(r.stdout.strip().splitlines()[-1]));base.update(record_type='measured',process_wall_s=time.monotonic()-t);base['end_to_end_with_measured_offline_s']=base['online_s']+base['offline_s'];base['cloud_local_s']=base['prepare_s']+base['encode_s']-base['cloud_transport_s']
                    f.write(json.dumps(base)+'\n');print(method,L,M,trial,base['status'],flush=True)
    print('COMPLETE 55 grouped matched jobs',flush=True)
if __name__=='__main__':main()
