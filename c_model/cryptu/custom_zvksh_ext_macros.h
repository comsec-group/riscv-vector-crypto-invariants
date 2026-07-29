// Helper macros and functions to help implement instructions defined as part of
// the RISC-V Zvksh extension (vectorized SM3).

#include <cstdint>
#include <climits>
#include <cstddef>
#include <type_traits>


// Constraints common to all vsm3* instructions:
//  - Zvksh is enabled
//  - VSEW == 32
//  - EGW (256) <= LMUL * VLEN
//  - No overlap of vd and vs2.
//
// The constraint that vstart and vl are both EGS (8) aligned
// is checked in the VI_ZVK_..._EGU32x8_..._LOOP macros.

// Rotates left an unsigned integer by the given number of bits.
template <typename T>
static inline T rotate_left(T x, std::size_t shiftamt) {
  static_assert(std::is_unsigned<T>::value);
  static constexpr T mask = (8 * sizeof(T)) - 1;
  const std::size_t lshift = shiftamt & mask;
  const std::size_t rshift = (-lshift) & mask;
  return (x << lshift) | (x >> rshift);
}

// Byte swap unsigned int
uint32_t swap_uint32( uint32_t val )
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
}

#define FF1(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define FF2(X, Y, Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))

// Boolean function FF_j - section 4.3. of the IETF draft.
#define ZVKSH_FF(X, Y, Z, J) (((J) <= 15) ? FF1(X, Y, Z) : FF2(X, Y, Z))

#define GG1(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define GG2(X, Y, Z) (((X) & (Y)) | ((~(X)) & (Z)))

// Boolean function GG_j - section 4.3. of the IETF draft.
#define ZVKSH_GG(X, Y, Z, J) (((J) <= 15) ? GG1(X, Y, Z) : GG2(X, Y, Z))

#define T1 0x79CC4519
#define T2 0x7A879D8A

// T_j constant - section 4.2. of the IETF draft.
#define ZVKSH_T(J) (((J) <= 15) ? (T1) : (T2))

// Rotates left a uint32_t value by N bits.
//   uint32_t ROL32(uint32_t X, std::size_t N);
#define ZVK_ROL32(X, N) rotate_left<uint32_t>((X), (N))

// Permutation functions P_0 and P_1 - section 4.4 of the IETF draft.
#define ZVKSH_P0(X) ((X) ^ ZVK_ROL32((X),  9) ^ ZVK_ROL32((X), 17))
#define ZVKSH_P1(X) ((X) ^ ZVK_ROL32((X), 15) ^ ZVK_ROL32((X), 23))


// Per the SM3 spec, the message expansion computes new words Wi as:
//   W[i] = (    P_1( W[i-16] xor W[i-9] xor ( W[i-3] <<< 15 ) )
//           xor ( W[i-13] <<< 7 )
//           xor W[i-6]))
// Using arguments M16 = W[i-16], M9 = W[i-9], etc.,
// where Mk stands for "W[i Minus k]", we define the "W function":
#define ZVKSH_W(M16, M9, M3, M13, M6) \
  (ZVKSH_P1((M16) ^  (M9) ^ ZVK_ROL32((M3), 15)) ^ ZVK_ROL32((M13), 7) ^ (M6))

//require_vsm3_constraints;

// {w7,  w6,  w5,  w4,  w3,  w2,  w1,  w0} <- vs1
// {w15, w14, w13, w12, w11, w10, w9, w8} <- vs2
// Arguments are W[i-16], W[i-9], W[i-13], W[i-6].
// Note that some of the newly computed words are used in later invocations.
#define VSM3_MESSAGE_EXPANSION(w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15, w16, w17, w18, w19, w20, w21, w22, w23) \
{ \
    uint32_t W0 = swap_uint32(w0); \
    uint32_t W1 = swap_uint32(w1); \
    uint32_t W2 = swap_uint32(w2); \
    uint32_t W3 = swap_uint32(w3); \
    uint32_t W4 = swap_uint32(w4); \
    uint32_t W5 = swap_uint32(w5); \
    uint32_t W6 = swap_uint32(w6); \
    uint32_t W7 = swap_uint32(w7); \
    uint32_t W8 = swap_uint32(w8); \
    uint32_t W9 = swap_uint32(w9); \
    uint32_t W10 = swap_uint32(w10); \
    uint32_t W11 = swap_uint32(w11); \
    uint32_t W12 = swap_uint32(w12); \
    uint32_t W13 = swap_uint32(w13); \
    uint32_t W14 = swap_uint32(w14); \
    uint32_t W15 = swap_uint32(w15); \
    const uint32_t t1 = ZVKSH_W((W0),  (W7), (W13),  (W3), (W10)); \
    const uint32_t t2 = ZVKSH_W((W1),  (W8), (W14),  (W4), (W11)); \
    const uint32_t t3 = ZVKSH_W((W2),  (W9), (W15),  (W5), (W12)); \
    const uint32_t t4 = ZVKSH_W((W3), (W10), (t1),  (W6), (W13)); \
    const uint32_t t5 = ZVKSH_W((W4), (W11), (t2),  (W7), (W14)); \
    const uint32_t t6 = ZVKSH_W((W5), (W12), (t3),  (W8), (W15)); \
    const uint32_t t7 = ZVKSH_W((W6), (W13), (t4),  (W9), (t1)); \
    const uint32_t t8 = ZVKSH_W((W7), (W14), (t5), (W10), (t2)); \
    (w16) = swap_uint32(t1); \
    (w17) = swap_uint32(t2); \
    (w18) = swap_uint32(t3); \
    (w19) = swap_uint32(t4); \
    (w20) = swap_uint32(t5); \
    (w21) = swap_uint32(t6); \
    (w22) = swap_uint32(t7); \
    (w23) = swap_uint32(t8); \
};


// {H, G, F, E, D, C, B, A} <- vd
// {_, _, w5, w4, _, _, w1, w0} <- vs2
// {round} <- imm
// output:
// {G1, G2, E1, E2, C1, C2, A1, A2} <- vd_out
#define VSM3_COMPRESSION(Ai, Bi, Ci, Di, Ei, Fi, Gi, Hi, w0, w1, w4, w5, imm, out7, out6, out5, out4, out3, out2, out1, out0) \
    { \
      uint32_t A = swap_uint32(Ai); \
      uint32_t B = swap_uint32(Bi); \
      uint32_t C = swap_uint32(Ci); \
      uint32_t D = swap_uint32(Di); \
      uint32_t E = swap_uint32(Ei); \
      uint32_t F = swap_uint32(Fi); \
      uint32_t G = swap_uint32(Gi); \
      uint32_t H = swap_uint32(Hi); \
      uint32_t W0 = swap_uint32(w0); \
      uint32_t W1 = swap_uint32(w1); \
      uint32_t W4 = swap_uint32(w4); \
      uint32_t W5 = swap_uint32(w5); \
      const uint32_t x0 = W0 ^ W4; \
      const uint32_t x1 = W1 ^ W5; \
      const uint32_t round = imm & 0x1F; \
      uint32_t ss1; \
      uint32_t ss2; \
      uint32_t tt1; \
      uint32_t tt2; \
      uint32_t j; \
      j = 2 * round; \
      ss1 = ZVK_ROL32(ZVK_ROL32(A, 12) + E + ZVK_ROL32(ZVKSH_T(j), j % 32), 7); \
      ss2 = ss1 ^ ZVK_ROL32(A, 12); \
      tt1 = ZVKSH_FF(A, B, C, j) + D + ss2 + x0; \
      tt2 = ZVKSH_GG(E, F, G, j) + H + ss1 + W0; \
      D = C; \
      const uint32_t C1 = ZVK_ROL32(B, 9); \
      B = A; \
      const uint32_t A1 = tt1; \
      H = G; \
      const uint32_t G1 = ZVK_ROL32(F, 19); \
      F = E; \
      const uint32_t E1 = ZVKSH_P0(tt2); \
      j = 2 * round + 1; \
      ss1 = ZVK_ROL32(ZVK_ROL32(A1, 12) + E1 + ZVK_ROL32(ZVKSH_T(j), j % 32), 7); \
      ss2 = ss1 ^ ZVK_ROL32(A1, 12); \
      tt1 = ZVKSH_FF(A1, B, C1, j) + D + ss2 + x1; \
      tt2 = ZVKSH_GG(E1, F, G1, j) + H + ss1 + W1; \
      D = C1; \
      const uint32_t C2 = ZVK_ROL32(B, 9); \
      B = A1; \
      const uint32_t A2 = tt1; \
      H = G1; \
      const uint32_t G2 = ZVK_ROL32(F, 19); \
      F = E1; \
      const uint32_t E2 = ZVKSH_P0(tt2); \
      out7 = swap_uint32(G1); \
      out6 = swap_uint32(G2); \
      out5 = swap_uint32(E1); \
      out4 = swap_uint32(E2); \
      out3 = swap_uint32(C1); \
      out2 = swap_uint32(C2); \
      out1 = swap_uint32(A1); \
      out0 = swap_uint32(A2); \
    };


