#!/usr/bin/env bash
set -euo pipefail
# Read-only external implementation; every build artifact goes under /tmp.
external=${PMEQ_EXTERNAL_SCMP:-/home/tenggn/projects/new-pmeq/dmpf_agg_proto}
build=${PMEQ_SCMP_BUILD:-/tmp/phase6-native}
root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$build"
flags=(-O3 -std=c++17 -maes -msse2 -msse4.1 -mpclmul -w -I"$external/vendor/ezpc_fss" -I"$external/tools")
g++ "${flags[@]}" -c "$root/tools/phase6_scmp_bridge.cpp" -o "$build/bridge.o"
sources=(pubdiv.cpp dcf.cpp prng.cpp cryptoTools/Common/Defines.cpp cryptoTools/Common/Log.cpp cryptoTools/Crypto/AES.cpp cryptoTools/Crypto/PRNG.cpp)
objects=("$build/bridge.o")
for i in "${!sources[@]}"; do
 g++ "${flags[@]}" -c "$external/vendor/ezpc_fss/${sources[$i]}" -o "$build/core$i.o"
 objects+=("$build/core$i.o")
done
ar rcs "$build/libphase6scmp.a" "${objects[@]}"
