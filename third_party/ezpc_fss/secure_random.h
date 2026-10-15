#pragma once
#include <cstdint>
#include <openssl/rand.h>
#include <stdexcept>

// Dealer-private CSPRNG; no seed is exported to either cloud. A masked uniform
// 64-bit word is uniform in Z_(2^bits). Entropy failures abort preprocessing.
inline uint64_t secureRandomWord(int bits) {
    if (bits < 1 || bits > 64) throw std::runtime_error("invalid random ring");
    uint64_t word;
    if (RAND_priv_bytes(reinterpret_cast<unsigned char*>(&word), sizeof(word)) != 1)
        throw std::runtime_error("private entropy unavailable");
    return bits == 64 ? word : word & ((uint64_t(1) << bits) - 1);
}
