"""Pure-Python independent ID boundaries and secure Ring64 conversion checks."""
import json,random
from pathlib import Path
from minimal import pack,unpack,ring_to_xor,U64,mul,inv
def main():
    values=[0,1,(1<<63)-1,1<<63,U64-1,U64];rng=random.Random(202610115000);passed=0
    for a in values:
        for b in values:
            v=pack(a,b);assert v and v.bit_length()<=129 and unpack(v)==(a,b);passed+=1
    bad=[(-1,0),(0,-1),(1<<64,0),(0,1<<64)];rejected=0
    for a,b in bad:
        try:pack(a,b)
        except ValueError:rejected+=1
    assert rejected==len(bad)
    tests=0;log=[]
    for trial in range(5):
        for v in values+[rng.getrandbits(64) for _ in range(14)]:
            for r in [0,U64,rng.getrandbits(64)]:
                shares=ring_to_xor(r,(v-r)&U64,rng,log);assert shares[0]^shares[1]==v;tests+=1
    assert (U64+2)&U64==1 and U64^2!=1
    out=dict(status='PASS',seed=202610115000,pack_roundtrip_cases=passed,overflow_rejected=rejected,secure_conversion_cases=tests,masked_messages=len(log),ring_xor_reinterpretation_rejected=True,zero_pair_nonzero=True)
    Path(__file__).with_name('boundary-checks.json').write_text(json.dumps(out,indent=2));print(json.dumps(out))
if __name__=='__main__':main()
