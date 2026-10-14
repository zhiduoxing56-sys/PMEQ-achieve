"""Deterministic Rabin irreducibility certificate for GF(2^129)."""
import json
from pathlib import Path
def mod(a,b):
    while a.bit_length()>=b.bit_length():a^=b<<(a.bit_length()-b.bit_length())
    return a
def gcd(a,b):
    while b:a,b=b,mod(a,b)
    return a
def square(a,f):
    z=0
    while a:
        j=(a&-a).bit_length()-1;z^=1<<(2*j);a&=a-1
    return mod(z,f)
def main():
    f=(1<<129)|(1<<5)|1;v=2;checks={}
    for j in range(1,130):
        v=square(v,f)
        if j in [3,43]:checks[str(j)]=dict(frobenius_mod_hex=hex(v),gcd=gcd(v^2,f))
    assert v==2 and all(x['gcd']==1 for x in checks.values())
    out=dict(degree=129,degree_prime_divisors=[3,43],modulus='x^129+x^5+1',modulus_hex=hex(f),checks=checks,final_frobenius_mod_hex=hex(v),irreducible=True,method='Rabin: gcd(x^(2^(129/p))-x,f)=1 for p=3,43; x^(2^129)=x mod f')
    Path(__file__).with_name('field-certificate.json').write_text(json.dumps(out,indent=2));print(json.dumps(out))
if __name__=='__main__':main()
