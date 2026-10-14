"""Two real spawned cloud processes; all dealer work finishes before spawning.
Each child receives only its own input and offline state. Client sees only M
and final syndromes. Decoder remains explicitly a slow reference.
"""
import multiprocessing as mp, socket, struct, random, json, time, hashlib, os
from pathlib import Path
from minimal import mul, encode, decode, U64

def recv_exact(s,n):
    b=bytearray()
    while len(b)<n:
        x=os.read(s.fileno(),n-len(b))
        if not x:raise RuntimeError('short peer message')
        b.extend(x)
    return bytes(b)

def cloud(p,s,pipe,state):
    seq=0;sent=0;digest=hashlib.sha256();views=[]
    binding=bytes.fromhex(state['binding'])
    def exchange(body):
        nonlocal seq,sent
        header=binding+struct.pack('<IBI',seq,p,len(body))
        frame=header+body;at=0
        while at<len(frame):at+=os.write(s.fileno(),frame[at:])
        sent+=len(frame)
        peer=recv_exact(s,41)
        if peer[:32]!=binding or struct.unpack('<IBI',peer[32:])!=(seq,1-p,len(body)):
            raise RuntimeError('binding / sequence')
        b=recv_exact(s,len(body));digest.update(frame);digest.update(peer+b);seq+=1
        return b
    cursor=0
    def gate(x,y):
        nonlocal cursor
        a,b,c=state['bits'][cursor];cursor+=1
        own=bytes([x^a,y^b]);peer=exchange(own)
        d=own[0]^peer[0];e=own[1]^peer[1]
        return c^(d&b)^(e&a)^((d&e) if p==0 else 0)
    def convert(r):
        carry=0;out=0
        for j in range(64):
            x=(r>>j)&1 if p==0 else 0
            y=(r>>j)&1 if p==1 else 0
            z=x^y;out|=(z^carry)<<j
            if j<63:carry=gate(x,y)^gate(z,carry)
        return out
    try:
        start=time.perf_counter();n=len(state['keep']);acc=0
        own=bytes(b^r[0] for b,r in zip(state['keep'],state['dabits']))
        peer=exchange(own)
        for e,(rb,ra) in zip(bytes(a^b for a,b in zip(own,peer)),state['dabits']):
            acc=(acc+(ra if not e else int(p==0)-ra))&U64
        peer=exchange(struct.pack('<Q',acc));m=(acc+struct.unpack('<Q',peer)[0])&U64
        if m>state['capacity']:
            pipe.send({'status':'CAPACITY_REJECTED','M':m,'sent':sent,'frames':seq});return
        payload=[]
        if m:
            for i in range(n):
                a=convert(state['anchor'][i]);b=convert(state['target'][i])
                payload.append((int(p==0)<<128)|(a<<64)|b)
            own=bytearray()
            for i,(u,v,w) in enumerate(state['fields']):
                own.extend((state['keep'][i]^u).to_bytes(17,'little'))
                own.extend((payload[i]^v).to_bytes(17,'little'))
            peer=exchange(bytes(own));masked=[]
            for i,(u,v,w) in enumerate(state['fields']):
                at=34*i;d=int.from_bytes(own[at:at+17],'little')^int.from_bytes(peer[at:at+17],'little')
                e=int.from_bytes(own[at+17:at+34],'little')^int.from_bytes(peer[at+17:at+34],'little')
                masked.append(w^mul(d,v)^mul(e,u)^(mul(d,e) if p==0 else 0))
            syndrome=encode(masked,m)
        else:syndrome=[]
        message=b''.join(x.to_bytes(17,'little') for x in syndrome)
        pipe.send({'status':'OK','M':m,'syndrome':message,'sent':sent,'frames':seq,
                   'cloud_s':time.perf_counter()-start,'view_sha256':digest.hexdigest(),
                   'only_own_input':True,'triples_used':cursor,'return_bytes':len(message)})
    except Exception as e:pipe.send({'status':'ERROR','error':str(e)})
    finally:s.close();pipe.close()

def fixture(n,hits,capacity,seed):
    rng=random.Random(seed);binding=hashlib.sha256(str(seed).encode()).hexdigest()
    states=[dict(binding=binding,capacity=capacity,keep=[],anchor=[],target=[],bits=[],fields=[],dabits=[]) for _ in (0,1)]
    pairs=[(0,0),(U64,U64),(7,9),(7,10),(8,9),(7,9)]
    expected=[]
    for i in range(n):
        a,b=pairs[i%len(pairs)];k=int(i in hits)
        if k:expected.append((i,a,b))
        ka=rng.getrandbits(1);ar=rng.getrandbits(64);br=rng.getrandbits(64)
        for p in (0,1):
            states[p]['keep'].append(ka if p==0 else ka^k)
            states[p]['anchor'].append(ar if p==0 else (a-ar)&U64)
            states[p]['target'].append(br if p==0 else (b-br)&U64)
        r=rng.getrandbits(1);rb=rng.getrandbits(1);ra=rng.getrandbits(64)
        states[0]['dabits'].append((rb,ra));states[1]['dabits'].append((rb^r,(r-ra)&U64))
        u=rng.getrandbits(129);v=rng.getrandbits(129);w=mul(u,v)
        x,y,z=(rng.getrandbits(129) for _ in range(3))
        states[0]['fields'].append((x,y,z));states[1]['fields'].append((u^x,v^y,w^z))
    for _ in range(n*252):
        a,b=(rng.getrandbits(1) for _ in range(2));x,y,z=(rng.getrandbits(1) for _ in range(3))
        states[0]['bits'].append((x,y,z));states[1]['bits'].append((a^x,b^y,(a&b)^z))
    return states,expected

def run():
    ctx=mp.get_context('spawn');results=[]
    cases=[(9,[]),(9,[0]),(9,[1,8]),(9,[0,2,3,4,5,6]),(4,list(range(4)))]
    for trial in range(5):
        for ci,(n,hits) in enumerate(cases):
            seed=202610110000+100*trial+ci;t=time.perf_counter();states,want=fixture(n,hits,n,seed);offline=time.perf_counter()-t
            a,b=socket.socketpair();pipes=[ctx.Pipe(False) for _ in (0,1)]
            workers=[ctx.Process(target=cloud,args=(p,[a,b][p],pipes[p][1],states[p])) for p in (0,1)]
            # Dealer already finished; children cannot access peer state via spawn.
            for proc in workers:proc.start()
            a.close();b.close()
            for p in (0,1):pipes[p][1].close()
            views=[pipes[p][0].recv() for p in (0,1)]
            for proc in workers:proc.join(30);assert proc.exitcode==0
            assert all(v['status']=='OK' and v['M']==len(hits) for v in views),views
            t=time.perf_counter();s=[int.from_bytes(views[0]['syndrome'][i:i+17],'little')^int.from_bytes(views[1]['syndrome'][i:i+17],'little') for i in range(0,len(views[0]['syndrome']),17)]
            got=decode(s,n,len(hits));assert got==want,(got,want);dec=time.perf_counter()-t
            results.append(dict(seed=seed,n=n,m=len(hits),trial=trial,offline_s=offline,decode_s=dec,cloud_s=[v['cloud_s'] for v in views],cloud_bytes=sum(v['sent'] for v in views),user_bytes=sum(v['return_bytes'] for v in views),view_hashes=[v['view_sha256'] for v in views],status='PASS'))
            print(json.dumps(results[-1]),flush=True)
    # Public capacity rejection happens only after securely opening total M.
    states,want=fixture(4,[0,1,2],2,202610119999);a,b=socket.socketpair();pipes=[ctx.Pipe(False) for _ in (0,1)];workers=[ctx.Process(target=cloud,args=(p,[a,b][p],pipes[p][1],states[p])) for p in (0,1)]
    for proc in workers:proc.start()
    a.close();b.close()
    rejected=[pipes[p][0].recv() for p in (0,1)]
    for proc in workers:proc.join(30);assert proc.exitcode==0
    assert all(v['status']=='CAPACITY_REJECTED' and v['M']==3 for v in rejected)
    Path(__file__).with_name('two-process-results.json').write_text(json.dumps(dict(cases=results,capacity_rejection=rejected,process_start='spawn',dealer_online=False,fast_decoder=False),indent=2))
if __name__=='__main__':run()
