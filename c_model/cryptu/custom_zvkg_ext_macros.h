#include <cstdint>
#include <climits>
#include <cstddef>
#include <type_traits>
#include <array>

#include "zvk_ext_macros.h"
using EGU32x4_t = std::array<uint32_t, 4>;

// uint32_t swap_uint32( uint32_t val )
// {
//     val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
//     return (val << 16) | (val >> 16);
// }

void vgmul(uint32_t *vs2_0, uint32_t *vs2_1, uint32_t *vs2_2, uint32_t *vs2_3, uint32_t *vd_0, uint32_t *vd_1, uint32_t *vd_2, uint32_t *vd_3, uint32_t *vd_out_0, uint32_t *vd_out_1, uint32_t *vd_out_2, uint32_t *vd_out_3)
{
    // Loading vectors in little endian (following spikes register conventions)
    // EGU32x4_t Y = {swap_uint32(*vd_0), swap_uint32(*vd_1), swap_uint32(*vd_2), swap_uint32(*vd_3)};
    // EGU32x4_t H = {swap_uint32(*vs2_0), swap_uint32(*vs2_1), swap_uint32(*vs2_2), swap_uint32(*vs2_3)};

    // Testing big endian in hopes to find the bug (not correct according to spike register ordering)
    // EGU32x4_t Y = {*vd_3, *vd_2, *vd_1, *vd_0};
    // EGU32x4_t H = {*vs2_3, *vs2_2, *vs2_1, *vs2_0};

    
    EGU32x4_t Y = {*vd_0, *vd_1, *vd_2, *vd_3};
    EGU32x4_t H = {*vs2_0, *vs2_1, *vs2_2, *vs2_3};
    EGU32x4_t Z = {0, 0, 0, 0};

    EGU32x4_BREV8(Y);
    EGU32x4_BREV8(H);

    for (int bit = 0; bit < 128; bit++) {
        if (EGU32x4_ISSET(Y, bit)) {
        EGU32x4_XOREQ(Z, H);
        }

        bool reduce = EGU32x4_ISSET(H, 127);
        EGU32x4_LSHIFT(H);  // Lef shift by 1
        if (reduce) {
        H[0] ^= 0x87; // Reduce using x^7 + x^2 + x^1 + 1 polynomial
        }
    }
    EGU32x4_BREV8(Z);

    *vd_out_3 = Z[3];
    *vd_out_2 = Z[2];
    *vd_out_1 = Z[1];
    *vd_out_0 = Z[0];
}

void vghsh(uint32_t *vs1_0, uint32_t *vs1_1, uint32_t *vs1_2, uint32_t *vs1_3, uint32_t *vs2_0, uint32_t *vs2_1, uint32_t *vs2_2, uint32_t *vs2_3, uint32_t *vd_0, uint32_t *vd_1, uint32_t *vd_2, uint32_t *vd_3, uint32_t *vd_out_0, uint32_t *vd_out_1, uint32_t *vd_out_2, uint32_t *vd_out_3)
{
    // Loading vectors in little endian (following spikes register conventions)
    // EGU32x4_t Y = {swap_uint32(*vd_0), swap_uint32(*vd_1), swap_uint32(*vd_2), swap_uint32(*vd_3)};
    // EGU32x4_t H = {swap_uint32(*vs2_0), swap_uint32(*vs2_1), swap_uint32(*vs2_2), swap_uint32(*vs2_3)};
    // EGU32x4_t X = {swap_uint32(*vs1_0), swap_uint32(*vs1_1), swap_uint32(*vs1_2), swap_uint32(*vs1_3)};

    // Testing big endian in hopes to find the bug (not correct according to spike register ordering)
    // EGU32x4_t Y = {*vd_3, *vd_2, *vd_1, *vd_0};
    // EGU32x4_t H = {*vs2_3, *vs2_2, *vs2_1, *vs2_0};
    // EGU32x4_t X = {*vs1_3, *vs1_2, *vs1_1, *vs1_0};

    EGU32x4_t Y = {*vd_0, *vd_1, *vd_2, *vd_3};
    EGU32x4_t H = {*vs2_0, *vs2_1, *vs2_2, *vs2_3};
    EGU32x4_t X = {*vs1_0, *vs1_1, *vs1_2, *vs1_3};
    EGU32x4_t Z = {0, 0, 0, 0};

    EGU32x4_BREV8(H);

    // S = brev8(Y ^ X)
    EGU32x4_t S;
    EGU32x4_XOR(S, Y, X);
    EGU32x4_BREV8(S);

    for (int bit = 0; bit < 128; bit++) {
      if (EGU32x4_ISSET(S, bit)) {
        EGU32x4_XOREQ(Z, H);
      }

      const bool reduce = EGU32x4_ISSET(H, 127);
      EGU32x4_LSHIFT(H);  // Left shift by 1.
      if (reduce) {
        H[0] ^= 0x87; // Reduce using x^7 + x^2 + x^1 + 1 polynomial
      }
    }
    EGU32x4_BREV8(Z);

    *vd_out_3 = Z[3];
    *vd_out_2 = Z[2];
    *vd_out_1 = Z[1];
    *vd_out_0 = Z[0];
}