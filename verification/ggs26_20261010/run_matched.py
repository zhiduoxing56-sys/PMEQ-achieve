"""Serial, paired-input comparison after the four-worker matrix finishes.
One physical CPU (8), rotating method order, five fresh seeds per cell.
"""
import json,subprocess,time,hashlib
from pathlib import Path
P=Path(__file__).resolve().parent
def main():
    while 'COMPLETE' not in (P/'hybrid-runner.log').read_text():time.sleep(5)
    out=P/'matched-raw.jsonl';done=set()
    if out.exists():
        for line in out.read_text().splitlines():
            r=json.loads(line);done.add((r['requested_method'],r['L'],r['M'],r['trial']))
    methods=['full-secure','shuffle','linear-hybrid'];bins={'full-secure':'full-secure','shuffle':'prototype','linear-hybrid':'hybrid'}
    with out.open('a',buffering=1) as f:
        for L,M in [(1000000,1),(6001215,1),(1000000,10)]:
            for trial in range(5):
                order=methods[trial%3:]+methods[:trial%3]
                for method in order:
                    if (method,L,M,trial) in done:continue
                    seed=202610116000+trial*100000000+L*37+M*101;binary=P/bins[method]
                    cmd=['taskset','-c','8','prlimit',f'--as={4*1024**3}',str(binary),method,str(L),str(L),str(M),str(seed),str(trial)]
                    t=time.monotonic();r=subprocess.run(cmd,capture_output=True,text=True,timeout=240)
                    base=dict(requested_method=method,L=L,N=L,K=1,M=M,trial=trial,seed=seed,experiment_version='v3-matched-serial',scope='serial paired inputs; CPU8; no other experiment workers',cpu_pin=8,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
                    if r.returncode:base.update(record_type='failed',status='EXECUTION_FAILED',stderr=r.stderr)
                    else:
                        base.update(json.loads(r.stdout.strip().splitlines()[-1]));base.update(record_type='measured',process_wall_s=time.monotonic()-t);base['end_to_end_with_measured_offline_s']=base['online_s']+base['offline_s'];base['cloud_local_s']=base['prepare_s']+base['encode_s']-base['cloud_transport_s']
                    f.write(json.dumps(base)+'\n');print(method,L,M,trial,base['status'],flush=True)
    print('COMPLETE 45 matched jobs',flush=True)
if __name__=='__main__':main()
