"""Sequential, resumable fresh-process benchmarks. No concurrent timings.
Every requested cell has five fixed seeds. Missing/blocked cells are recorded,
never filled by an extrapolated runtime. Large shuffles use a 4 GiB guard.
"""
import csv,json,subprocess,time,hashlib,shutil,platform,resource,threading,os
from pathlib import Path
HERE=Path(__file__).resolve().parent
def main():
    inputs=HERE/'inputs';inputs.mkdir(exist_ok=True)
    sources=[Path('/tmp/pmeq-return-audit-20261010/workload.csv'),Path('/tmp/pmeq-tpch-return-bench-20261010/sf1-workload.csv'),Path('/tmp/pmeq-tpch-return-bench-20261010/sf1-full-string-workload.csv')]
    provenance=[]
    for src in sources:
        if src.exists():
            dest=inputs/src.name;shutil.copyfile(src,dest);provenance.append(dict(source=str(src),copy=str(dest),sha256=hashlib.sha256(src.read_bytes()).hexdigest()))
    (HERE/'workload-provenance.json').write_text(json.dumps(provenance,indent=2))
    jobs=[]
    for L,N in [(100000,100000),(1000000,1000000),(6001215,6001215),(60012150,6001215)]:
        for M in [0,1,2,10,100,1000]:
            for method in ['full','shuffle','linear-B']:
                for trial in range(5):jobs.append((method,L,N,M,trial,'requested'))
        for trial in range(5):jobs.append(('sum1',L,N,1,trial,'M1_special'))
    for L in [100000,1000000]:
        for M in [0,1,10,1000]:
            for trial in range(5):jobs.append(('linear-A',L,L,M,trial,'A_conversion_upper_bound'))
    # Historical plaintext/reference statistics supply workload shapes only;
    # new secure shares and independent positions are generated for every run.
    mb=list(csv.DictReader((inputs/'workload.csv').open()))
    mb_nonempty=[x for x in mb if int(x['M'])>0]
    picks=[mb_nonempty[0],max(mb_nonempty,key=lambda x:int(x['K'])),max(mb_nonempty,key=lambda x:int(x['M']))]
    workloads=[]
    for x in picks:
        L,K,M=int(x['L']),int(x['K']),int(x['M']);workloads.append(dict(source='MusicBrainz historic candidate statistics',query=x['query'],L=L,N=L//K,K=K,M=M,synthetic_positions=True))
    tp=list(csv.DictReader((inputs/'sf1-full-string-workload.csv').open()))
    for x in [tp[0],max(tp,key=lambda x:int(x['K']))]:
        K,M=int(x['K']),int(x['M']);workloads.append(dict(source='TPC-H SF1 full-string plaintext workload',source_part=x['source_part'],L=K*6001215,N=6001215,K=K,M=M,synthetic_positions=True))
    for x in workloads:
        if x['L']>60012150:
            x['run_status']='RESOURCE_REVIEW_ONLY';continue
        for method in ['full','shuffle','linear-B']:
            for trial in range(5):jobs.append((method,x['L'],x['N'],x['M'],trial,'workload_shape'))
    jobs=list(dict.fromkeys(jobs));(HERE/'workloads.json').write_text(json.dumps(workloads,indent=2))
    (HERE/'benchmark-plan.json').write_text(json.dumps(dict(seed_base=202610110000,rounds=5,jobs=jobs,timeout_s=240,memory_limit_bytes=4*1024**3,kernel_version='v2',cpu_pins=[0,2,4,6],workers=4,large_shuffle_workers=1,scope='C++ logical role kernels with actual AF_UNIX application transfers, not isolated cloud processes or WAN; quadratic reference decoder; offline generated interleaved by trusted harness and measured separately; four concurrent pinned physical cores, shared memory/cache contention included'),indent=2))
    log=HERE/'performance-raw.jsonl';done=set()
    if log.exists():
        for line in log.read_text().splitlines():
            x=json.loads(line)
            if x.get('experiment_version')=='v2-pinned4':done.add((x['requested_method'],x['L'],x['N'],x['M'],x['trial']))
    lock=threading.Lock();large_shuffle=threading.Lock()
    with log.open('a',buffering=1) as output,(HERE/'benchmark-progress.log').open('a',buffering=1) as progress:
        def execute(job,cpu):
            method,L,N,M,trial,scope=job
            key=(method,L,N,M,trial)
            if key in done:return
            seed=202610110000+trial*100000000+L*37+M*101
            base=dict(requested_method=method,L=L,N=N,K=L//N,M=M,trial=trial,seed=seed,scope=scope,record_type='measured',experiment_version='v2-pinned4',cpu_pin=cpu)
            if method=='shuffle' and L*400>=4*1024**3:
                base.update(record_type='not_executed',status='RESOURCE_BUDGET_4GIB',estimated_guard_bytes=L*400)
            else:
                cmd=['taskset','-c',str(cpu),'prlimit',f'--as={4*1024**3}',str(HERE/'prototype'),method,str(L),str(N),str(M),str(seed),str(trial)]
                # Only one >1M full-shuffle allocation at a time.
                guard=large_shuffle if method=='shuffle' and L>1000000 else threading.Lock()
                guard.acquire()
                with lock:progress.write(f'START {key} cpu={cpu} {time.time()}\n')
                start=time.monotonic()
                try:
                    r=subprocess.run(cmd,capture_output=True,text=True,timeout=240)
                    if r.returncode or not r.stdout.strip():base.update(status='EXECUTION_FAILED',stderr=r.stderr,stdout=r.stdout,record_type='failed')
                    else:base.update(json.loads(r.stdout.strip().splitlines()[-1]));base['process_wall_s']=time.monotonic()-start;base['end_to_end_with_measured_offline_s']=base['online_s']+base['offline_s'];base['cloud_local_s']=base['prepare_s']+base['encode_s']-base.get('cloud_transport_s',0)
                except subprocess.TimeoutExpired as e:base.update(status='TIMEOUT_240S',record_type='failed',elapsed_wall_s=time.monotonic()-start)
                finally:guard.release()
                with lock:progress.write(f"DONE {key} {base['status']} {time.monotonic()-start:.3f}s\n")
            with lock:output.write(json.dumps(base)+'\n');done.add(key)
        cpus=[0,2,4,6]
        queues=[[] for _ in cpus]
        for i,job in enumerate(jobs):queues[i%4].append(job)
        def worker(i):
            for job in queues[i]:execute(job,cpus[i])
        threads=[threading.Thread(target=worker,args=(i,)) for i in range(4)]
        for t in threads:t.start()
        for t in threads:t.join()
    print('COMPLETE',len(jobs),'jobs',flush=True)
if __name__=='__main__':main()
