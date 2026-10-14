"""Exact small-domain distribution checks, not a replacement for a proof."""
import itertools,collections,json
from pathlib import Path
def count_view(world):
    n=3;mod=8;counts=collections.Counter()
    for r in itertools.product(range(2),repeat=n):
        for rb in itertools.product(range(2),repeat=n):
            for ra in itertools.product(range(mod),repeat=n):
                e=tuple(b^x for b,x in zip(world,r))
                own=sum((v if not k else 1-v) for k,v in zip(e,ra))%mod
                peer=(sum(world)-own)%mod
                counts[(rb,ra,tuple(k^a for k,a in zip(e,rb)),peer)]+=1
    return counts
def gf4(a,b):
    c=0
    for _ in range(2):
        if b&1:c^=a
        b>>=1;a<<=1
        if a&4:a^=7
    return c
def mul_view(x,y):
    view=collections.Counter()
    for u,v,a,b,c in itertools.product(range(4),repeat=5):
        # Own raw x0=y0=0 conditioned fixed; peer masked messages only.
        d=x^u;e=y^v;local=c^gf4(d,b)^gf4(e,a)^gf4(d,e)
        view[(a,b,c,x^u^a,y^v^b,local)]+=1
    return view
def main():
    a=count_view((1,0,0));b=count_view((0,0,1));assert a==b
    c=count_view((1,1,0));d=count_view((1,0,1));assert c==d
    ref=mul_view(0,0)
    for x in range(4):
        for y in range(4):assert mul_view(x,y)==ref
    # Condition on the corrupt cloud's existing P-share and b-share.
    # Its target-aware preprocessing share rb,rP and honest masked message
    # have the same joint law for every full target P and Keep b.
    def target_view(b,P,P0=2,b0=1):
        out=collections.Counter()
        for r,rb,rp in itertools.product(range(2),range(2),range(4)):
            e=b^r;own=b0^rb;peer=e^own;y0=rp^(P0 if e else 0)
            # P influences only the unobserved honest rP-share.
            rp1=rp^(P if r else 0);P1=P^P0
            assert y0^(rp1^(P1 if e else 0))==(P if b else 0)
            out[(rb,rp,peer,y0)]+=1
        return out
    tv=target_view(0,0)
    for b in range(2):
        for P in range(4):assert target_view(b,P)==tv
    # Reusing a mask deterministically exposes differences across queries.
    u=2;x1=0;x2=1;assert (x1^u)^(x2^u)==x1^x2
    out=dict(status='PASS_SMALL_EXACT_DISTRIBUTIONS',count_world_samples=sum(a.values()),count_view_keys=len(a),mask_world_samples=sum(ref.values()),mask_view_keys=len(ref),target_aware_world_samples=sum(tv.values()),target_aware_views_equal=True,count_same_M_different_positions=True,beaver_local_views_equal_all_inputs=True,reused_mask_difference_leak=True,limitation='Small fields only; full protocol simulation and concurrent composition still require proof.')
    Path(__file__).with_name('view-audit.json').write_text(json.dumps(out,indent=2));print(json.dumps(out))
if __name__=='__main__':main()
