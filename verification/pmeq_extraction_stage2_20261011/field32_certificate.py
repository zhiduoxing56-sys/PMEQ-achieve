import json
from pathlib import Path
f=(1<<32)|0x8d
def rem(a,b):
 while a.bit_length()>=b.bit_length():a^=b<<(a.bit_length()-b.bit_length())
 return a
def square(a):
 z=0
 for k in range(a.bit_length()):z|=((a>>k)&1)<<(2*k)
 return rem(z,f)
def gcd(a,b):
 while b:a,b=b,rem(a,b)
 return a
x=2;v=x;res={}
for k in range(1,33):
 v=square(v)
 if k in [16,32]:res[str(k)]=hex(v)
 if k==16:assert gcd(v^x,f)==1
assert v==x
out=dict(status='PASS_RABIN_IRREDUCIBLE',polynomial='x^32+x^7+x^3+x^2+1',prime_divisors_of_degree=[2],frobenius=res)
Path(__file__).with_name('field32-certificate.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out))
