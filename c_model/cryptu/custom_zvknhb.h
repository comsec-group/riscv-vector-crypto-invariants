
#include <cstdint>
#include <climits>
#include <cstddef>
#include <type_traits>

// requires custom_zvknha.h for rotate_right, ZVK_SHA_CH and ZVK_SHA_MAJ

// SHA-512
//

#define ZVK_ROR64(X, N) rotate_right<uint64_t>((X), (N))

// sum0(x) = ROTR2(x) ⊕ ROTR13(x) ⊕ ROTR22(x)
#define ZVK_SHA512_SUM0(X) \
  (ZVK_ROR64(X, 28) ^ ZVK_ROR64(X, 34) ^ ZVK_ROR64(X, 39))

// sum1(x) = ROTR6(x) ⊕ ROTR11(x) ⊕ ROTR25(x)
#define ZVK_SHA512_SUM1(X) \
  (ZVK_ROR64(X, 14) ^ ZVK_ROR64(X, 18) ^ ZVK_ROR64(X, 41))

// sig0(x) = ROTR7(x) ⊕ ROTR18(x) ⊕ SHR3 (x)
#define ZVK_SHA512_SIG0(X) \
  (ZVK_ROR64(X, 1) ^ ZVK_ROR64(X, 8) ^ ((X) >> 7))

// sig1(x) = ROTR17(x) ⊕ ROTR19(x) ⊕ SHR10(x)
#define ZVK_SHA512_SIG1(X) \
  (ZVK_ROR64(X, 19) ^ ZVK_ROR64(X, 61) ^ ((X) >> 6))

// Given the schedule words W[t+0], W[t+1], W[t+9], W[t+14], computes
// W[t+16].
#define ZVK_SHA512_SCHEDULE(W14, W9, W1, W0) \
    (ZVK_SHA512_SIG1(W14) + (W9) + ZVK_SHA512_SIG0(W1) + (W0))

// Performs one round of compression (out of the 64 rounds), given the state
// temporaries A,B,C,...,H, and KW, the sum Kt+Wt.
// Updates A,B,C,...,H to their new values. KW is not modified.
//
// Note that some of the logic could be omitted in vshac[ab] since
// some of the variables are dropped in each of those. However removing
// those unnecessary updates reduces the opportunities to share this single
// per-round logic and forces us to move further away from the how the logic
// is expressed in FIPS PUB 180-4.
#define ZVK_SHA512_COMPRESS(A, B, C, D, E, F, G, H, KW) \
  { \
    const uint64_t t1 = (H) + ZVK_SHA512_SUM1(E) + \
                        ZVK_SHA_CH((E), (F), (G)) + (KW); \
    const uint64_t t2 = ZVK_SHA512_SUM0(A) + ZVK_SHA_MAJ((A), (B), (C)); \
    (H) = (G); \
    (G) = (F); \
    (F) = (E); \
    (E) = (D) + t1; \
    (D) = (C); \
    (C) = (B); \
    (B) = (A); \
    (A) = t1 + t2; \
  }
