// Test adapter to the existing external LLAMA implementation, not a new SCMP.
#include "llama_scmp128_ffi.cpp"
extern "C" int phase6_keygen(unsigned bin,unsigned x,unsigned y,unsigned o,uint8_t*a,uint8_t*b,size_t*na,size_t*nb,uint8_t*ra,uint8_t*rb){
 try{
 auto k=keyGenSCMP(bin,1,GroupElement(x,bin),GroupElement(y,bin),GroupElement(o,1));
 auto u=serialize_scmp_keypack(k.first),v=serialize_scmp_keypack(k.second);
 if(u.size()>4096||v.size()>4096)return 0;
 memcpy(a,u.data(),u.size());memcpy(b,v.data(),v.size());*na=u.size();*nb=v.size();*ra=k.first.rb.value&1;*rb=k.second.rb.value&1;
 std::pair<DualDCFKeyPack,DualDCFKeyPack> d={k.first.dualDcfKey,k.second.dualDcfKey};freeDualDCFKeyPackPair(d);return 1;
 }catch(...){return 0;}
}
