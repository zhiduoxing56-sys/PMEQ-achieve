"""Exact small oracle. Fast encoder: Def19/Lemma23. Decoder is explicitly
quadratic reference for Theorem18, NOT the fast Theorem25 implementation.
No protocol method receives both raw parties' inputs; trusted harness does.
"""
import random, json, time
from pathlib import Path
ELL=129; MOD=(1<<129)|(1<<5)|1; MASK=(1<<129)-1; U64=(1<<64)-1
def mul(a,b):
    z=0
    while b:
        if b&1:z^=a
        b>>=1;a<<=1
        if a>>129:a^=MOD
    return z
def inv(a):
    if not a:raise ValueError('zero inverse')
    z=1;b=(1<<129)-2
    while b:
        if b&1:z=mul(z,a)
        a=mul(a,a);b>>=1
    return z
def pack(a,b):
    if not 0<=a<=U64 or not 0<=b<=U64:raise ValueError('ID overflow')
    return (1<<128)|(a<<64)|b
def unpack(v):
    if v>>128!=1:raise ValueError('invalid marker')
    return (v>>64)&U64,v&U64
def split(x,rng,bits=129):
    a=rng.getrandbits(bits);return a,x^a
def and_gate(x,y,rng,log):
    # Trusted dealer samples fresh F2 triple; each cloud only masks own inputs.
    a=rng.getrandbits(1);b=rng.getrandbits(1)
    aa=split(a,rng,1);bb=split(b,rng,1);cc=split(a&b,rng,1)
    messages=[(x[p]^aa[p],y[p]^bb[p]) for p in (0,1)]
    d=messages[0][0]^messages[1][0];e=messages[0][1]^messages[1][1]
    log.extend(messages)
    return tuple(cc[p]^(d&bb[p])^(e&aa[p])^((d&e) if p==0 else 0) for p in (0,1))
def ring_to_xor(a,b,rng,log):
    # Add the two private ring shares in a Boolean circuit, modulo 2^64.
    carry=(0,0);out=[0,0]
    for j in range(64):
        x=((a>>j)&1,0);y=(0,(b>>j)&1);t=(x[0]^y[0],x[1]^y[1])
        for p in (0,1):out[p]|=(t[p]^carry[p])<<j
        if j<63:
            u=and_gate(x,y,rng,log);v=and_gate(t,carry,rng,log)
            carry=(u[0]^v[0],u[1]^v[1])
    return tuple(out)
def mask_pair(bit,payload,rng,log):
    u=rng.getrandbits(129);v=rng.getrandbits(129)
    uu=split(u,rng);vv=split(v,rng);ww=split(mul(u,v),rng)
    msgs=[(bit[p]^uu[p],payload[p]^vv[p]) for p in (0,1)]
    d=msgs[0][0]^msgs[1][0];e=msgs[0][1]^msgs[1][1];log.extend(msgs)
    return tuple(ww[p]^mul(d,vv[p])^mul(e,uu[p])^(mul(d,e) if p==0 else 0) for p in (0,1))
def count(bits,rng,log):
    acc=[0,0]
    for bs in bits:
        r=rng.getrandbits(1);rb=split(r,rng,1);ra=rng.getrandbits(64);rr=(ra,(r-ra)&U64)
        msg=(bs[0]^rb[0],bs[1]^rb[1]);e=msg[0]^msg[1];log.append(msg)
        for p in (0,1):acc[p]=(acc[p]+(rr[p] if not e else (int(p==0)-rr[p])))&U64
    log.append(tuple(acc));return sum(acc)&U64
def padd(a,b):
    c=[0]*max(len(a),len(b))
    for i,v in enumerate(a):c[i]^=v
    for i,v in enumerate(b):c[i]^=v
    return trim(c)
def trim(a):
    while len(a)>1 and a[-1]==0:a.pop()
    return a
def pmul(a,b):
    c=[0]*(len(a)+len(b)-1)
    for i,x in enumerate(a):
        for j,y in enumerate(b):c[i+j]^=mul(x,y)
    return trim(c)
def rem(a,b):
    a=a[:];ib=inv(b[-1])
    for i in range(len(a)-1,len(b)-2,-1):
        t=mul(a[i],ib)
        for j,v in enumerate(b):a[i-len(b)+1+j]^=mul(t,v)
    return trim(a[:len(b)-1] or [0])
def gcd(a,b):
    while b!=[0]:a,b=b,rem(a,b)
    z=inv(a[-1]);return [mul(v,z) for v in a]
def peval(f,a):
    v=0
    for x in reversed(f):v=mul(v,a)^x
    return v
def basis(r):
    s=[[0,1]];cs=[];xs=[[1]]
    for k in range((r-1).bit_length()):
        c=peval(s[k],1<<k);cs.append(c)
        sq=[0]*(2*len(s[k])-1)
        for j,x in enumerate(s[k]):sq[2*j]=mul(x,x)
        s.append(padd(sq,[mul(c,x) for x in s[k]]))
    for i in range(1,r):
        k=i.bit_length()-1;xs.append(pmul(xs[i^(1<<k)],s[k]))
    return s,cs,xs
def tfft(values,beta,s,cs):
    # Transposition of f0+S_k(beta)f1 / f0+(S_k(beta)+c_k)f1.
    n=len(values)
    if n==1:return values[:]
    k=n.bit_length()-2;h=n//2
    l=tfft(values[:h],beta,s,cs);r=tfft(values[h:],beta^(1<<k),s,cs)
    a=peval(s[k],beta);u=[x^y for x,y in zip(l,r)]
    return u+[mul(a,x)^mul(cs[k],y) for x,y in zip(u,r)]
def encode(v,capacity):
    if not capacity:return []
    r=1<<(2*capacity-1).bit_length();s,cs,_=basis(r);out=[0]*r;base=1<<(len(v)-1).bit_length()
    for start in range(0,len(v),r):
        block=v[start:start+r]+[0]*max(0,start+r-len(v));t=tfft(block,base^start,s,cs)
        out=[a^b for a,b in zip(out,t)]
    return out[:2*capacity]
def roots(f):
    # Deterministic Berlekamp trace splitting; no scan of L. Slow polynomial
    # arithmetic is deliberate here and excluded from fast-algorithm claims.
    if len(f)==2:return [mul(f[0],inv(f[1]))]
    if len(f)==1:return []
    for bit in range(129):
        term=rem([0,1<<bit],f);tr=[0]
        for _ in range(129):
            tr=padd(tr,term);sq=[0]*(2*len(term)-1)
            for j,v in enumerate(term):sq[2*j]=mul(v,v)
            term=rem(sq,f)
        g=gcd(f,tr)
        if 1<len(g)<len(f):
            # exact quotient
            a=f[:];q=[0]*(len(f)-len(g)+1);ig=inv(g[-1])
            for i in range(len(q)-1,-1,-1):
                q[i]=mul(a[i+len(g)-1],ig)
                for j,v in enumerate(g):a[i+j]^=mul(q[i],v)
            return roots(g)+roots(trim(q))
    raise ValueError('polynomial does not split into distinct field roots')
def decode(s,n,capacity):
    if not s:return []
    _,_,xs=basis(len(s));mom=[]
    for i,x in enumerate(xs):
        v=s[i]
        for j,c in enumerate(x[:-1]):v^=mul(c,mom[j])
        mom.append(v)
    C=[1];B=[1];deg=0;shift=1;b=1
    for k in range(len(mom)):
        d=mom[k]
        for j in range(1,deg+1):d^=mul(C[j],mom[k-j])
        if not d:shift+=1;continue
        old=C[:];scale=mul(d,inv(b));C += [0]*max(0,len(B)+shift-len(C))
        for j,v in enumerate(B):C[j+shift]^=mul(scale,v)
        if 2*deg<=k:deg=k+1-deg;B=old;b=d;shift=1
        else:shift+=1
    if deg>capacity:raise ValueError('capacity')
    if not deg:return []
    locs=roots(list(reversed(C[:deg+1])));P=[0]*deg
    for i in range(deg):
        for j in range(i+1):P[i]^=mul(C[j],mom[i-j])
    derivative=[C[i+1] if (i+1)&1 else 0 for i in range(deg)];base=1<<(n-1).bit_length();out=[]
    for a in locs:
        z=inv(a);v=mul(a,mul(peval(P,z),inv(peval(derivative,z))));idx=a^base
        if idx>=n:raise ValueError('invalid locator')
        out.append((idx,*unpack(v)))
    return sorted(out)
def run():
    rng=random.Random(2026101001);log=[];passed=[]
    for n,hit in [(9,[]),(9,[0]),(9,[0,8]),(17,[0,1,2]),(17,[2,5,9,16])]:
        ref=[];bits=[];payload=[[],[]]
        for i in range(n):
            a,b=[(0,0),(U64,U64),(0,7),(9,7),(9,0)][i%5];r0=rng.getrandbits(64);r1=rng.getrandbits(64)
            aa=ring_to_xor(r0,(a-r0)&U64,rng,log);bb=ring_to_xor(r1,(b-r1)&U64,rng,log)
            pp=((1<<128)|(aa[0]<<64)|bb[0],(aa[1]<<64)|bb[1]);bs=split(int(i in hit),rng,1);bits.append(bs)
            masked=mask_pair(bs,pp,rng,log)
            for p in (0,1):payload[p].append(masked[p])
            if i in hit:ref.append((i,a,b))
        m=count(bits,rng,log);assert m==len(hit)
        syn=[encode(payload[p],m) for p in (0,1)];combined=[a^b for a,b in zip(*syn)]
        got=decode(combined,n,m);assert got==ref,(got,ref);passed.append(dict(n=n,m=m,ok=True))
    for bad in [-1,1<<64]:
        try:pack(bad,0);raise AssertionError('overflow accepted')
        except ValueError:pass
    # Counterexample: arithmetic shares cannot be reinterpreted as XOR shares.
    assert (((1<<64)-1)+2)&U64==1 and (((1<<64)-1)^2)!=1
    for _ in range(30):
        a=rng.getrandbits(129) or 1;assert mul(a,inv(a))==1
    out=dict(seed=2026101001,cases=passed,masked_messages=len(log),status='PASS_SMALL_REFERENCE',fast_decoder=False)
    Path(__file__).with_name('minimal-results.json').write_text(json.dumps(out,indent=2));print(json.dumps(out))
if __name__=='__main__':run()
