"""Role-isolated hybrid protocol; trusted dealer finishes before cloud spawn.
Fresh target-aware Boolean-mask correlations, GF64 triples, and daBits.
The only decoder used is the explicitly quadratic correctness reference.
"""
import multiprocessing as mp, socket, struct, random, json, hashlib, os
from pathlib import Path
from minimal import encode, decode, U64
from two_process import recv_exact
from field_certificate import square,gcd

def mul64(a,b):
    z=0
    for _ in range(64):
        if b&1:z^=a
        b>>=1;c=a>>63;a=(a<<1)&U64
        if c:a^=27
    return z

def cloud(p,s,pipe,st):
    seq=sent=cursor=0;digest=hashlib.sha256();binding=bytes.fromhex(st['binding'])
    def exchange(body):
        nonlocal seq,sent
        frame=binding+struct.pack('<IBI',seq,p,len(body))+body;at=0
        while at<len(frame):at+=os.write(s.fileno(),frame[at:])
        sent+=len(frame);header=recv_exact(s,41)
        assert header[:32]==binding and struct.unpack('<IBI',header[32:])==(seq,1-p,len(body))
        peer=recv_exact(s,len(body));seq+=1;digest.update(frame+header+peer);return peer
    def gate(x,y):
        nonlocal cursor
        a,b,c=st['bits'][cursor];cursor+=1;own=bytes([x^a,y^b]);peer=exchange(own)
        d=own[0]^peer[0];e=own[1]^peer[1]
        return c^(d&b)^(e&a)^((d&e) if p==0 else 0)
    def convert(r):
        carry=out=0
        for j in range(64):
            x=(r>>j)&1 if p==0 else 0;y=(r>>j)&1 if p==1 else 0;z=x^y
            out|=(z^carry)<<j
            if j<63:carry=gate(x,y)^gate(z,carry)
        return out
    try:
        n=len(st['keep']);own=bytes(b^d[0] for b,d in zip(st['keep'],st['dabits']));peer=exchange(own)
        acc=sum(ra if (a^b)==0 else int(p==0)-ra for a,b,(_,ra) in zip(own,peer,st['dabits']))&U64
        peer=exchange(struct.pack('<Q',acc));m=(acc+struct.unpack('<Q',peer)[0])&U64
        if m>st['capacity']:
            pipe.send(dict(status='CAPACITY_REJECTED',M=m,sent=sent));return
        if m:
            anchors=[convert(a) for a in st['anchor']]
            own=bytes(b^r for b,(r,rp) in zip(st['keep'],st['target_prep']));peer=exchange(own)
            target=[rp^(st['target'][i%st['N']] if (own[i]^peer[i]) else 0) for i,(_,rp) in enumerate(st['target_prep'])]
            own=b''.join(struct.pack('<QQ',st['keep'][i]^u,anchors[i//st['N']]^v) for i,(u,v,w) in enumerate(st['triples']))
            peer=exchange(own);masked=[]
            for i,(u,v,w) in enumerate(st['triples']):
                d,e=struct.unpack_from('<QQ',own,i*16);dp,ep=struct.unpack_from('<QQ',peer,i*16);d^=dp;e^=ep
                a=w^mul64(d,v)^mul64(e,u)^(mul64(d,e) if p==0 else 0)
                masked.append((st['keep'][i]<<128)|(a<<64)|target[i])
            syndrome=encode(masked,m)
        else:syndrome=[]
        pipe.send(dict(status='OK',M=m,syndrome=b''.join(x.to_bytes(17,'little') for x in syndrome),sent=sent,view_sha256=digest.hexdigest(),triples_used=cursor,only_own_state=True))
    except Exception as e:pipe.send(dict(status='ERROR',error=str(e)))
    finally:s.close();pipe.close()

def fixture(K,N,hits,capacity,seed):
    rng=random.Random(seed);binding=hashlib.sha256(str(seed).encode()).hexdigest()
    a=[0,U64,7,7][:K];t=[0,U64,9,9,10,0][:N];n=K*N
    st=[dict(binding=binding,capacity=capacity,N=N,keep=[],anchor=[],target=[],bits=[],triples=[],dabits=[],target_prep=[]) for _ in (0,1)]
    for v in a:
        z=rng.getrandbits(64);st[0]['anchor'].append(z);st[1]['anchor'].append((v-z)&U64)
    for v in t:
        z=rng.getrandbits(64);st[0]['target'].append(z);st[1]['target'].append(v^z)
    for i in range(n):
        b=int(i in hits);z=rng.getrandbits(1);st[0]['keep'].append(z);st[1]['keep'].append(b^z)
        r=rng.getrandbits(1);rb=rng.getrandbits(1);ra=rng.getrandbits(64)
        st[0]['dabits'].append((rb,ra));st[1]['dabits'].append((r^rb,(r-ra)&U64))
        r=rng.getrandbits(1);rb=rng.getrandbits(1);rp=rng.getrandbits(64)
        st[0]['target_prep'].append((rb,rp));st[1]['target_prep'].append((r^rb,(t[i%N] if r else 0)^rp))
        u,v=[rng.getrandbits(64) for _ in range(2)];w=mul64(u,v);us,vs,ws=[rng.getrandbits(64) for _ in range(3)]
        st[0]['triples'].append((us,vs,ws));st[1]['triples'].append((u^us,v^vs,w^ws))
    for _ in range(K*126):
        a0,b0=[rng.getrandbits(1) for _ in range(2)];x,y,z=[rng.getrandbits(1) for _ in range(3)]
        st[0]['bits'].append((x,y,z));st[1]['bits'].append((a0^x,b0^y,(a0&b0)^z))
    want=[(i,a[i//N],t[i%N]) for i in sorted(hits)]
    return st,want

def execute(ctx,states):
    a,b=socket.socketpair();pipes=[ctx.Pipe(False) for _ in (0,1)]
    workers=[ctx.Process(target=cloud,args=(p,[a,b][p],pipes[p][1],states[p])) for p in (0,1)]
    for proc in workers:proc.start()
    a.close();b.close()
    for p in (0,1):pipes[p][1].close()
    views=[pipes[p][0].recv() for p in (0,1)]
    for proc in workers:proc.join(30);assert proc.exitcode==0
    return views

def main():
    f=(1<<64)|27;v=2;check32=None
    for j in range(1,65):
        v=square(v,f)
        if j==32:check32=gcd(v^2,f)
    assert v==2 and check32==1
    (Path(__file__).parent/'field64-certificate.json').write_text(json.dumps(dict(modulus='x^64+x^4+x^3+x+1',irreducible=True,gcd32=check32,final_frobenius=hex(v),method='Rabin'),indent=2))
    ctx=mp.get_context('spawn');rows=[]
    cases=[(2,6,[]),(2,6,[0]),(2,6,[1,7]),(2,6,[0,2,3,6,8,9]),(2,2,list(range(4)))]
    for trial in range(5):
        for ci,(K,N,hits) in enumerate(cases):
            seed=202610114000+trial*100+ci;states,want=fixture(K,N,hits,len(hits),seed);views=execute(ctx,states)
            assert all(v['status']=='OK' and v['M']==len(hits) for v in views),views
            s=[int.from_bytes(views[0]['syndrome'][i:i+17],'little')^int.from_bytes(views[1]['syndrome'][i:i+17],'little') for i in range(0,len(views[0]['syndrome']),17)]
            assert decode(s,K*N,len(hits))==want
            rows.append(dict(K=K,N=N,M=len(hits),trial=trial,seed=seed,status='PASS',cloud_bytes=sum(v['sent'] for v in views),view_hashes=[v['view_sha256'] for v in views]))
            print(json.dumps(rows[-1]),flush=True)
    states,_=fixture(2,2,[0,1,2],2,202610114999);v=execute(ctx,states);assert all(x['status']=='CAPACITY_REJECTED' and x['M']==3 for x in v)
    (Path(__file__).parent/'two-process-hybrid-results.json').write_text(json.dumps(dict(cases=rows,capacity_rejection=v,dealer_online=False,process_start='spawn',fast_decoder=False),indent=2))
    print('HYBRID TWO PROCESS PASS',flush=True)
if __name__=='__main__':main()
