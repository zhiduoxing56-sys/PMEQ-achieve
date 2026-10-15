#!/usr/bin/env bash
set -euo pipefail
# Pinned repaired dependency. Never silently select the retired native library.
build=${PMEQ_SCMP_BUILD:-/tmp/phase6-native}
root=$(cd "$(dirname "$0")/.." && pwd)
if [[ -n ${PMEQ_EXTERNAL_SCMP:-} ]]; then
 echo 'PMEQ_EXTERNAL_SCMP is retired; use the in-project repaired dependency' >&2
 exit 1
fi
external="$root/third_party/ezpc_fss"
mkdir -p "$build"
flags=(-O3 -std=c++17 -maes -msse2 -msse4.1 -mpclmul -w -I"$external" -I"$root/tools")
g++ "${flags[@]}" -c "$root/tools/phase6_scmp_bridge.cpp" -o "$build/bridge.o"
sources=(pubdiv.cpp dcf.cpp prng.cpp cryptoTools/Common/Defines.cpp cryptoTools/Common/Log.cpp cryptoTools/Crypto/AES.cpp cryptoTools/Crypto/PRNG.cpp)
objects=("$build/bridge.o")
for i in "${!sources[@]}"; do
 g++ "${flags[@]}" -c "$external/${sources[$i]}" -o "$build/core$i.o"
 objects+=("$build/core$i.o")
done
ar rcs "$build/libphase6scmp.a" "${objects[@]}"
