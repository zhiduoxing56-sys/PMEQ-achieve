#include <memory>
// Pointer-free native key codec; Bin=7 or 10, Bout=1. No plaintext evaluator.
// Canonical, pointer-free SCMP encoding. Integers are fixed little-endian;
// dynamically-owned DCF arrays carry explicit u64 lengths.
static void u32put(std::vector<uint8_t>&o,uint32_t x){for(int i=0;i<4;i++)o.push_back(x>>(8*i));} static void u64put(std::vector<uint8_t>&o,uint64_t x){for(int i=0;i<8;i++)o.push_back(x>>(8*i));}
static uint32_t u32get(const std::vector<uint8_t>&b,size_t&p){if(p+4>b.size())throw std::runtime_error("scmp truncation");uint32_t x=0;for(int i=0;i<4;i++)x|=uint32_t(b[p++])<<(8*i);return x;} static uint64_t u64get(const std::vector<uint8_t>&b,size_t&p){if(p+8>b.size())throw std::runtime_error("scmp truncation");uint64_t x=0;for(int i=0;i<8;i++)x|=uint64_t(b[p++])<<(8*i);return x;}
static void geput(std::vector<uint8_t>&o,const GroupElement&g){u32put(o,g.bitsize);u64put(o,g.value);} static GroupElement geget(const std::vector<uint8_t>&b,size_t&p){auto bits=(int)u32get(b,p);auto value=u64get(b,p);if(bits<1||bits>64||(bits<64&&(value>>bits)))throw std::runtime_error("invalid GroupElement");return GroupElement(value,bits);}
static void blockput(std::vector<uint8_t>&o,const block&x){uint64_t v[2];_mm_storeu_si128((__m128i*)v,x);u64put(o,v[0]);u64put(o,v[1]);} static block blockget(const std::vector<uint8_t>&b,size_t&p){auto low=u64get(b,p);auto high=u64get(b,p);return toBlock(high,low);}
static void dcfput(std::vector<uint8_t>&o,const DCFKeyPack&k){u32put(o,k.Bin);u32put(o,k.Bout);u32put(o,k.groupSize);u64put(o,k.Bin+1);for(int i=0;i<=k.Bin;i++)blockput(o,k.k[i]);u64put(o,k.groupSize);for(int i=0;i<k.groupSize;i++)geput(o,k.g[i]);u64put(o,uint64_t(k.Bin)*k.groupSize);for(int i=0;i<k.Bin*k.groupSize;i++)geput(o,k.v[i]);}
static DCFKeyPack dcfget(const std::vector<uint8_t>&b,size_t&p,int expected){int bi=u32get(b,p),bo=u32get(b,p),gs=u32get(b,p);if(bi!=expected||(bi!=6&&bi!=9)||bo!=1||gs!=1)throw std::runtime_error("invalid DCF");if(u64get(b,p)!=(uint64_t)bi+1)throw std::runtime_error("DCF k length");std::unique_ptr<block[]> ownedK(new block[bi+1]);auto*k=ownedK.get();for(int i=0;i<=bi;i++)k[i]=blockget(b,p);if(u64get(b,p)!=(uint64_t)gs)throw std::runtime_error("DCF g length");std::unique_ptr<GroupElement[]> ownedG(new GroupElement[gs]);auto*g=ownedG.get();for(int i=0;i<gs;i++){g[i]=geget(b,p);if(g[i].bitsize!=bo)throw std::runtime_error("DCF g ring");}if(u64get(b,p)!=(uint64_t)bi*gs)throw std::runtime_error("DCF v length");std::unique_ptr<GroupElement[]> ownedV(new GroupElement[bi*gs]);auto*v=ownedV.get();for(int i=0;i<bi*gs;i++){v[i]=geget(b,p);if(v[i].bitsize!=bo)throw std::runtime_error("DCF v ring");}return DCFKeyPack(bi,bo,gs,ownedK.release(),ownedG.release(),ownedV.release());}
static std::vector<uint8_t> serialize_scmp_keypack(const ScmpKeyPack&k){std::vector<uint8_t>o;u32put(o,k.Bin);u32put(o,k.Bout);u32put(o,k.dualDcfKey.Bin);u32put(o,k.dualDcfKey.Bout);u32put(o,k.dualDcfKey.groupSize);dcfput(o,k.dualDcfKey.dcfKey);u64put(o,k.dualDcfKey.groupSize);for(int i=0;i<k.dualDcfKey.groupSize;i++)geput(o,k.dualDcfKey.sb[i]);geput(o,k.rb);return o;}
static ScmpKeyPack deserialize_scmp_keypack(const std::vector<uint8_t>&b){
 size_t p=0;ScmpKeyPack k;
 k.Bin=u32get(b,p);k.Bout=u32get(b,p);
 k.dualDcfKey.Bin=u32get(b,p);k.dualDcfKey.Bout=u32get(b,p);k.dualDcfKey.groupSize=u32get(b,p);
 if((k.Bin!=7&&k.Bin!=10)||k.Bout!=1||k.dualDcfKey.Bin!=k.Bin-1||k.dualDcfKey.Bout!=1||k.dualDcfKey.groupSize!=1)
  throw std::runtime_error("unsupported SCMP shape");
 k.dualDcfKey.dcfKey=dcfget(b,p,k.Bin-1);
 try{
  if(u64get(b,p)!=1)throw std::runtime_error("DualDCF sb length");
  std::unique_ptr<GroupElement[]> sb(new GroupElement[1]);sb[0]=geget(b,p);k.rb=geget(b,p);
  if(sb[0].bitsize!=1||k.rb.bitsize!=1||p!=b.size())throw std::runtime_error("SCMP encoding");
  k.dualDcfKey.sb=sb.release();return k;
 }catch(...){delete[] k.dualDcfKey.dcfKey.k;delete[] k.dualDcfKey.dcfKey.g;delete[] k.dualDcfKey.dcfKey.v;throw;}
}
static void freek(ScmpKeyPack&k){freeDualDCFKeyPack(k.dualDcfKey);}
