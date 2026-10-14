"""Only plaintext data, q-gram filtering and publicly reproducible bucket geometry."""
import csv,hashlib,hmac,json,pathlib,struct

BASE=pathlib.Path(__file__).resolve().parents[1]
ROOT=BASE.parent
FULL=ROOT/'imdb_final_dataset'
OLD=ROOT/'imdb_main_join_precheck_20261014'
SEED=20261014
Q_VALUES=[1,2,3,4,5,6,8]
SCALES=[1000,5000,10000]
BUCKET_VALUES=[1024,4096,16384,65536,131072]
TIERS=[4,16,64,256,1024,4096,8192,16384,32768]
KEY_A=hashlib.sha256(b'PUBLIC-PLAINTEXT-BUCKET-ANCHOR|20261014').digest()
KEY_T=hashlib.sha256(b'PUBLIC-PLAINTEXT-BUCKET-TARGET|20261014').digest()

def sha(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(8<<20),b''):h.update(b)
 return h.hexdigest()
def save(path,value):
 p=BASE/path;p.parent.mkdir(parents=True,exist_ok=True)
 p.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
def csvsave(path,items,fields=None):
 p=BASE/path;p.parent.mkdir(parents=True,exist_ok=True)
 if not fields:fields=list(items[0]) if items else []
 with p.open('w',encoding='utf-8-sig',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(items)
def frame(*fields):
 out=b''
 for x in fields:
  b=x.encode('utf-8') if isinstance(x,str) else x
  out+=struct.pack('>I',len(b))+b
 return out
def anchor_hash(word):
 return hmac.new(KEY_A,b'PMEQ-BSMJ-INDEX-V1'+frame('BSMJ','MOVIECAST','aliasTitle','tconst',word),hashlib.sha256).digest()
def join_hash(tc):
 return hmac.new(KEY_T,frame('PMEQ-TARGET-BUCKET-JOIN-V1',struct.pack('>Q',int(tc[2:]))),hashlib.sha256).digest()
def target_word_hash(word):
 return hmac.new(KEY_T,frame('PMEQ-TARGET-BUCKET-WORD-V1','PSMJ','MOVIE','primaryTitle','tconst',word),hashlib.sha256).digest()
def prefix(digest,bits):return int.from_bytes(digest[:3],'big')>>(24-bits)
def power2(n):return 0 if n==0 else 1<<(n-1).bit_length()
def width(n):return next((t for t in TIERS if t>=n),None)
def chunks(s,q):return [(s[p:p+q],p) for p in range(0,len(s)-q+1,q)]
def bit_ids(mask):
 while mask:
  low=mask&-mask;yield low.bit_length()-1;mask^=low
def threshold_mask(hits,threshold,n):
 # Ordinary public integer bitsets, no field multiplication or secret shares.
 planes=[]
 for hit in hits:
  carry=hit;j=0
  while carry:
   if j==len(planes):planes.append(carry);break
   carry,planes[j]=carry&planes[j],planes[j]^carry;j+=1
 all_mask=(1<<n)-1;equal=all_mask;greater=0
 for j in range(max(len(planes),threshold.bit_length())-1,-1,-1):
  plane=planes[j] if j<len(planes) else 0
  if threshold>>j&1:equal&=plane
  else:greater|=equal&plane;equal&=~plane
 return (greater|equal)&all_mask
def bounded_ed(a,b,tau):
 if a==b:return 0
 if abs(len(a)-len(b))>tau:return tau+1
 if len(a)>len(b):a,b=b,a
 inf=tau+1;prev={i:i for i in range(min(len(a),tau)+1)}
 for j,cb in enumerate(b,1):
  cur={0:j} if j<=tau else {}
  for i in range(max(1,j-tau),min(len(a),j+tau)+1):
   cur[i]=min(cur.get(i-1,inf)+1,prev.get(i,inf)+1,prev.get(i-1,inf)+(a[i-1]!=cb),inf)
  if min(cur.values(),default=inf)>tau:return inf
  prev=cur
 return prev.get(len(a),inf)
def direct_score(text,features,tau,q):
 # Independent direct string lookup; does not read the inverted index or labels.
 count=0
 for word,p in features:
  lo=max(0,p-tau);hi=min(len(text)-q,p+tau)
  if hi>=lo and text.find(word,lo,hi+q)>=0:count+=1
 return count
def distribution(values):
 if not values:return dict(count=0,min=0,p50=0,p90=0,p95=0,p99=0,max=0,mean=0)
 a=sorted(values)
 pick=lambda p:a[min(len(a)-1,int((len(a)-1)*p))]
 return dict(count=len(a),min=a[0],p50=pick(.5),p90=pick(.9),p95=pick(.95),p99=pick(.99),max=a[-1],mean=sum(a)/len(a))
