"""True separated clouds for bilinear factoring, offline owner precomputes T.
Own Boolean Keep -> local H weights; never opens per-anchor counts/weights.
Small zero padding serves as independent oracle for C++ restricted FFT.
"""
import multiprocessing as mp,socket,struct,random,json,hashlib,os
from pathlib import Path
from minimal import mul,encode,decode,U64
from two_process import recv_exact
from two_process_hybrid import fixture as base_fixture

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
        n=len(st['keep']);K=len(st['anchor']);N=st['N'];own=bytes(b^d[0] for b,d in zip(st['keep'],st['dabits']));peer=exchange(own)
        acc=sum(ra if (a^b)==0 else int(p==0)-ra for a,b,(_,ra) in zip(own,peer,st['dabits']))&U64
        peer=exchange(struct.pack('<Q',acc));m=(acc+struct.unpack('<Q',peer)[0])&U64
        if m>st['capacity']:
            pipe.send(dict(status='CAPACITY_REJECTED',M=m,sent=sent));return
        if m:
            width=1 if st['sum_only'] else 2*m
            anchors=[convert(a)<<64 for a in st['anchor']]
            own=bytes(b^r for b,(r,rp) in zip(st['keep'],st['target_prep']));peer=exchange(own)
            target=[rp^(st['target'][i%N] if (own[i]^peer[i]) else 0) for i,(_,rp) in enumerate(st['target_prep'])]
            def H(v):
                if st['sum_only']:
                    out=0
                    for x in v:out^=x
                    return [out]
                return encode(v,m)
            syndrome=H([(st['keep'][i]<<128)|target[i] for i in range(n)])
            weights=[H([st['keep'][i] if i//N==c else 0 for i in range(n)]) for c in range(K)]
            triples=[st['fields'][c*2*st['capacity']+row] for c in range(K) for row in range(width)]
            own=b''.join((weights[c][row]^triples[c*width+row][0]).to_bytes(17,'little')+(anchors[c]^triples[c*width+row][1]).to_bytes(17,'little') for c in range(K) for row in range(width));peer=exchange(own)
            for index,(u,v,w) in enumerate(triples):
                at=index*34;d=int.from_bytes(own[at:at+17],'little')^int.from_bytes(peer[at:at+17],'little');e=int.from_bytes(own[at+17:at+34],'little')^int.from_bytes(peer[at+17:at+34],'little')
                product=w^mul(d,v)^mul(e,u)^(mul(d,e) if p==0 else 0);syndrome[index%width]^=product
        else:syndrome=[]
        pipe.send(dict(status='OK',M=m,syndrome=b''.join(x.to_bytes(17,'little') for x in syndrome),sent=sent,view_sha256=digest.hexdigest(),only_own_state=True))
    except Exception as e:pipe.send(dict(status='ERROR',error=str(e)))
    finally:s.close();pipe.close()

def fixture(K,N,hits,T,seed,sum_only=False):
    st,want=base_fixture(K,N,hits,T,seed);rng=random.Random(seed+997)
    for x in st:x.pop('triples');x['fields']=[];x['sum_only']=sum_only
    for _ in range(2*K*T):
        u,v=[rng.getrandbits(129) for _ in range(2)];w=mul(u,v);a,b,c=[rng.getrandbits(129) for _ in range(3)]
        st[0]['fields'].append((a,b,c));st[1]['fields'].append((a^u,b^v,c^w))
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
    ctx=mp.get_context('spawn');rows=[]
    cases=[(2,6,[]),(2,6,[0]),(2,6,[1,7]),(2,6,[0,2,3,6,8,9]),(2,2,list(range(4)))]
    for trial in range(5):
        for ci,(K,N,hits) in enumerate(cases+[(2,6,[7])]):
            sum_only=ci==5;seed=202610118000+trial*100+ci;T=len(hits) if ci==3 else K*N
            states,want=fixture(K,N,hits,T,seed,sum_only);views=execute(ctx,states)
            assert all(v['status']=='OK' and v['M']==len(hits) for v in views),views
            s=[int.from_bytes(views[0]['syndrome'][i:i+17],'little')^int.from_bytes(views[1]['syndrome'][i:i+17],'little') for i in range(0,len(views[0]['syndrome']),17)]
            if sum_only:assert len(s)==1 and s[0]>>128==1 and ((s[0]>>64)&U64,s[0]&U64)==want[0][1:]
            else:assert decode(s,K*N,len(hits))==want
            rows.append(dict(K=K,N=N,M=len(hits),T=T,trial=trial,seed=seed,sum_only=sum_only,status='PASS',cloud_bytes=sum(v['sent'] for v in views),view_hashes=[v['view_sha256'] for v in views]));print(json.dumps(rows[-1]),flush=True)
    states,_=fixture(2,2,[0,1,2],2,202610118999);v=execute(ctx,states);assert all(x['status']=='CAPACITY_REJECTED' and x['M']==3 for x in v)
    (Path(__file__).parent/'two-process-grouped-results.json').write_text(json.dumps(dict(cases=rows,capacity_rejection=v,dealer_online=False,process_start='spawn',fast_decoder=False,material_reserved_before_count=True),indent=2));print('GROUPED TWO PROCESS PASS',flush=True)
if __name__=='__main__':main()
