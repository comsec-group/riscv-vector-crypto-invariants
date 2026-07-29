
#include <cstdint>
#include <climits>
#include <cstddef>
#include <type_traits>

template <typename T>
static inline T rotate_right(T x, std::size_t shiftamt) {
  static_assert(std::is_unsigned<T>::value);
  static constexpr T mask = (8 * sizeof(T)) - 1;
  const std::size_t rshift = shiftamt & mask;
  const std::size_t lshift = (-rshift) & mask;
  return (x << lshift) | (x >> rshift);
}

// Rotates right a uint32_t value by N bits.
//   uint32_t ROR32(uint32_t X, std::size_t N);
#define ZVK_ROR32(X, N) rotate_right<uint32_t>((X), (N))

// sig0(x) = ROTR7(x) ⊕ ROTR18(x) ⊕ SHR3 (x)
#define ZVK_SHA256_SIG0(X) \
  (ZVK_ROR32(X, 7) ^ ZVK_ROR32(X, 18) ^ ((X) >> 3))

// sig1(x) = ROTR17(x) ⊕ ROTR19(x) ⊕ SHR10(x)
#define ZVK_SHA256_SIG1(X)  \
  (ZVK_ROR32(X, 17) ^ ZVK_ROR32(X, 19) ^ ((X) >> 10))

// Given the schedule words W[t+0], W[t+1], W[t+9], W[t+14], computes
// W[t+16].
#define ZVK_SHA256_SCHEDULE(W14, W9, W1, W0) \
    (ZVK_SHA256_SIG1(W14) + (W9) + ZVK_SHA256_SIG0(W1) + (W0))

// Ch(x, y, z) = (xy) ⊕ (~xz) = xy | ~xz
#define ZVK_SHA_CH(X, Y, Z) (((X) & (Y)) ^ ((~(X)) & (Z)))

// Maj(x,y,z)  = (xy) ⊕ (xz) ⊕(yz) = xy | xz | yz
#define ZVK_SHA_MAJ(X, Y, Z) (((X) & (Y)) ^ ((X) & (Z)) ^ ((Y) & (Z)))

// sum0(x) = ROTR2(x) ⊕ ROTR13(x) ⊕ ROTR22(x)
#define ZVK_SHA256_SUM0(X) \
  (ZVK_ROR32(X, 2) ^ ZVK_ROR32(X, 13) ^ ZVK_ROR32(X, 22))

// sum1(x) = ROTR6(x) ⊕ ROTR11(x) ⊕ ROTR25(x)
#define ZVK_SHA256_SUM1(X) \
  (ZVK_ROR32(X, 6) ^ ZVK_ROR32(X, 11) ^ ZVK_ROR32(X, 25))

// Performs one round of compression (out of the 64 rounds), given the state
// temporaries A,B,C,...,H, and KW, the sum Kt+Wt.
// Updates A,B,C,...,H to their new values. KW is not modified.
//
// Note that some of the logic could be omitted in vshac[ab] since
// some of the variables are dropped in each of those. However removing
// those unnecessary updates reduces the opportunities to share this single
// per-round logic and forces us to move further away from the how the logic
// is expressed in FIPS PUB 180-4.
#define ZVK_SHA256_COMPRESS(A, B, C, D, E, F, G, H, KW) \
  { \
    const uint32_t t1 = (H) + ZVK_SHA256_SUM1(E) + \
                        ZVK_SHA_CH((E), (F), (G)) + (KW); \
    const uint32_t t2 = ZVK_SHA256_SUM0(A) + ZVK_SHA_MAJ((A), (B), (C)); \
    (H) = (G); \
    (G) = (F); \
    (F) = (E); \
    (E) = (D) + t1; \
    (D) = (C); \
    (C) = (B); \
    (B) = (A); \
    (A) = t1 + t2; \
  }
