// Sole native adapter. Key generation is trusted offline; Eval is party-local.
#include <cstdint>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <mutex>
#include "pubdiv.h"
#include "dcf.h"
#include "cryptoTools/Crypto/PRNG.h"
int32_t bitlength=64;
GroupElement changeBitsize(GroupElement x,int b){return GroupElement(x.value,b);}
GroupElement signedDivide(GroupElement x,GroupElement y){return GroupElement(x.value/y.value,x.bitsize);}
#include "scmp_key_codec.h"
static std::once_flag initFlag;
static std::mutex dealerMutex;
static void initializeDealer(){
 std::call_once(initFlag, []{prng.SetSeed(osuCrypto::sysRandomSeed());setDCFFixedKeyPRG(false);});
}
// Keep the existing C ABI, but never propagate a C++ exception across it.
// KeyGen retries initialization inside its own checked error boundary.
extern "C" void scmp128_init(){try{initializeDealer();}catch(...) {}}
extern "C" int phase6_keygen(unsigned bin,unsigned x,unsigned y,unsigned o,uint8_t*a,uint8_t*b,size_t*na,size_t*nb,uint8_t*ra,uint8_t*rb){
 if((bin!=7&&bin!=10)||o>1||!a||!b||!na||!nb||!ra||!rb)return 0;
 const uint32_t mask=(uint32_t(1)<<bin)-1;
 if(x>mask||y>mask)return 0;
 try{
 std::lock_guard<std::mutex> lock(dealerMutex);
 initializeDealer();
 auto k=keyGenSCMP(bin,1,GroupElement(x,bin),GroupElement(y,bin),GroupElement(o,1));
 auto u=serialize_scmp_keypack(k.first),v=serialize_scmp_keypack(k.second);
 std::pair<DualDCFKeyPack,DualDCFKeyPack> d={k.first.dualDcfKey,k.second.dualDcfKey};
 *ra=k.first.rb.value&1;*rb=k.second.rb.value&1;
 freeDualDCFKeyPackPair(d);
 if(u.size()!=88+28*bin||v.size()!=88+28*bin)return 0;
 memcpy(a,u.data(),u.size());memcpy(b,v.data(),v.size());*na=u.size();*nb=v.size();
 return 1;
 }catch(...){return 0;}
}
extern "C" int scmp128_key_eval(const uint8_t*b,size_t n,int party,int xy,uint32_t x,uint32_t y,uint8_t*out){
 if(!b||!out||(n!=284&&n!=368)||party<0||party>1||xy!=1)return 0;
 try{
 auto k=deserialize_scmp_keypack(std::vector<uint8_t>(b,b+n));
 const uint32_t mask=(uint32_t(1)<<k.Bin)-1;
 if(x>mask||y>mask){freek(k);return 0;}
 auto r=evalSCMP(party,k,GroupElement(x,k.Bin),GroupElement(y,k.Bin));
 freek(k);*out=uint8_t(r.value)&1;return 1;
 }catch(...){return 0;}
}
