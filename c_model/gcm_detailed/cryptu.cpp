#include <stdio.h>
#include "jasperc.h"


#include "zvk_ext_macros.h"

#pragma C2RTL loop_merge off


enum ara_op_e {
    // Arithmetic and logic instructions
    VADD, VSUB, VADC, VSBC, VRSUB, VMINU, VMIN, VMAXU, VMAX, VREV8, VBREV8, VROL, VROR, VAND, VANDN, VOR, VXOR,
    // Fixed point
    VSADDU, VSADD, VSSUBU, VSSUB, VAADDU, VAADD, VASUBU, VASUB, VSSRL, VSSRA, VNCLIP, VNCLIPU,
    // Shifts,
    VSLL, VSRL, VSRA, VNSRL, VNSRA,
    // Merge
    VMERGE,
    // Scalar moves to VRF
    VMVSX, VFMVSF,
    // Integer Reductions
    VREDSUM, VREDAND, VREDOR, VREDXOR, VREDMINU, VREDMIN, VREDMAXU, VREDMAX, VWREDSUMU, VWREDSUM,
    // Mul/Mul-Add
    VMUL, VMULH, VMULHU, VMULHSU, VMACC, VNMSAC, VMADD, VNMSUB,
    // Fixed point multiplication
    VSMUL,
    // Div
    VDIVU, VDIV, VREMU, VREM,
    // FPU
    VFADD, VFSUB, VFRSUB, VFMUL, VFDIV, VFRDIV, VFMACC, VFNMACC, VFMSAC, VFNMSAC, VFMADD, VFNMADD, VFMSUB,
    VFNMSUB, VFSQRT, VFMIN, VFMAX, VFREC7, VFRSQRT7, VFCLASS, VFSGNJ, VFSGNJN, VFSGNJX, VFCVTXUF, VFCVTXF, VFCVTFXU, VFCVTFX,
    VFCVTRTZXUF, VFCVTRTZXF, VFNCVTRODFF, VFCVTFF,
    // Floating-point reductions
    VFREDUSUM, VFREDOSUM, VFREDMIN, VFREDMAX, VFWREDUSUM, VFWREDOSUM,
    // Floating-point comparison instructions
    VMFEQ, VMFLE, VMFLT, VMFNE, VMFGT, VMFGE,
    // Integer comparison instructions
    VMSEQ, VMSNE, VMSLTU, VMSLT, VMSLEU, VMSLE, VMSGTU, VMSBF, VMSOF, VMSIF, VIOTA, VID, VCPOP, VFIRST, VMSGT,
    // Integer add-with-carry and subtract-with-borrow carry-out instructions
    VMADC, VMSBC,
    // Mask operations
    VMANDNOT, VMAND, VMOR, VMXOR, VMORNOT, VMNAND, VMNOR, VMXNOR,
    // Scalar moves from VRF
    VMVXS, VFMVFS,
    // Slide instructions
    VSLIDEUP, VSLIDEDOWN,
    // Load instructions
    VLE, VLSE, VLXE,
    // Store instructions
    VSE, VSSE, VSXE,
    // AES Key expansion
    VAESK1, VAESK2,
    // AES Encrypt/Decrypt (vec-vec)
    VAESDF_VV, VAESDM_VV, VAESEF_VV, VAESEM_VV,
    // AES Encrypt/Decrypt (vec-scalar)
    VAESDF_VS, VAESDM_VS, VAESEF_VS, VAESEM_VS, VAESZ_VS,
    // AES GCM
    VGMUL, VGHSH,
    // SHA-2
    VSHA2CH, VSHA2CL, VSHA2MS,
    // SM4 key expansion
    VSM4K,
    // SM4 (vec-vec)
    VSM4R_VV,
    // SM4 (vec-scalar)
    VSM4R_VS,
    // SM3
    VSM3ME, VSM3C
  };



using EGU32x4_t = std::array<uint32_t, 4>;

uint32_t swap_uint32( uint32_t val )
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
}

void vgmul(uint32_t *vs2_0, uint32_t *vs2_1, uint32_t *vs2_2, uint32_t *vs2_3, uint32_t *vd_0, uint32_t *vd_1, uint32_t *vd_2, uint32_t *vd_3, uint32_t *vd_out_0, uint32_t *vd_out_1, uint32_t *vd_out_2, uint32_t *vd_out_3)
{
    // Loading vectors in little endian (following spikes register conventions)
    // EGU32x4_t Y = {swap_uint32(*vd_0), swap_uint32(*vd_1), swap_uint32(*vd_2), swap_uint32(*vd_3)};
    // EGU32x4_t H_0 = {swap_uint32(*vs2_0), swap_uint32(*vs2_1), swap_uint32(*vs2_2), swap_uint32(*vs2_3)};

    EGU32x4_t Y = {*vd_0, *vd_1, *vd_2, *vd_3};
    EGU32x4_t H_0 = {*vs2_0, *vs2_1, *vs2_2, *vs2_3};
    EGU32x4_t Z_0 = {0, 0, 0, 0};

    EGU32x4_BREV8(Y);
    EGU32x4_BREV8(H_0);
    
    // Unrolled vgmul loop: preserving Z and H for each bit (0-127)
    EGU32x4_t Z1_1 = Z_0;
    EGU32x4_t H1_1 = H_0;
    if (EGU32x4_ISSET(Y, 0)) {
        EGU32x4_XOREQ(Z1_1, H1_1);
    }
    bool reduce_0 = EGU32x4_ISSET(H1_1, 127);
    EGU32x4_LSHIFT(H1_1);
    if (reduce_0) {
        H1_1[0] ^= 0x87;
    }

    EGU32x4_t Z1_2 = Z1_1;
    EGU32x4_t H1_2 = H1_1;
    if (EGU32x4_ISSET(Y, 1)) {
        EGU32x4_XOREQ(Z1_2, H1_2);
    }
    bool reduce_1 = EGU32x4_ISSET(H1_2, 127);
    EGU32x4_LSHIFT(H1_2);
    if (reduce_1) {
        H1_2[0] ^= 0x87;
    }

    EGU32x4_t Z1_3 = Z1_2;
    EGU32x4_t H1_3 = H1_2;
    if (EGU32x4_ISSET(Y, 2)) {
        EGU32x4_XOREQ(Z1_3, H1_3);
    }
    bool reduce_2 = EGU32x4_ISSET(H1_3, 127);
    EGU32x4_LSHIFT(H1_3);
    if (reduce_2) {
        H1_3[0] ^= 0x87;
    }

    EGU32x4_t Z1_4 = Z1_3;
    EGU32x4_t H1_4 = H1_3;
    if (EGU32x4_ISSET(Y, 3)) {
        EGU32x4_XOREQ(Z1_4, H1_4);
    }
    bool reduce_3 = EGU32x4_ISSET(H1_4, 127);
    EGU32x4_LSHIFT(H1_4);
    if (reduce_3) {
        H1_4[0] ^= 0x87;
    }

    EGU32x4_t Z1_5 = Z1_4;
    EGU32x4_t H1_5 = H1_4;
    if (EGU32x4_ISSET(Y, 4)) {
        EGU32x4_XOREQ(Z1_5, H1_5);
    }
    bool reduce_4 = EGU32x4_ISSET(H1_5, 127);
    EGU32x4_LSHIFT(H1_5);
    if (reduce_4) {
        H1_5[0] ^= 0x87;
    }

    EGU32x4_t Z1_6 = Z1_5;
    EGU32x4_t H1_6 = H1_5;
    if (EGU32x4_ISSET(Y, 5)) {
        EGU32x4_XOREQ(Z1_6, H1_6);
    }
    bool reduce_5 = EGU32x4_ISSET(H1_6, 127);
    EGU32x4_LSHIFT(H1_6);
    if (reduce_5) {
        H1_6[0] ^= 0x87;
    }

    EGU32x4_t Z1_7 = Z1_6;
    EGU32x4_t H1_7 = H1_6;
    if (EGU32x4_ISSET(Y, 6)) {
        EGU32x4_XOREQ(Z1_7, H1_7);
    }
    bool reduce_6 = EGU32x4_ISSET(H1_7, 127);
    EGU32x4_LSHIFT(H1_7);
    if (reduce_6) {
        H1_7[0] ^= 0x87;
    }

    EGU32x4_t Z1_8 = Z1_7;
    EGU32x4_t H1_8 = H1_7;
    if (EGU32x4_ISSET(Y, 7)) {
        EGU32x4_XOREQ(Z1_8, H1_8);
    }
    bool reduce_7 = EGU32x4_ISSET(H1_8, 127);
    EGU32x4_LSHIFT(H1_8);
    if (reduce_7) {
        H1_8[0] ^= 0x87;
    }

    EGU32x4_t Z1_9 = Z1_8;
    EGU32x4_t H1_9 = H1_8;
    if (EGU32x4_ISSET(Y, 8)) {
        EGU32x4_XOREQ(Z1_9, H1_9);
    }
    bool reduce_8 = EGU32x4_ISSET(H1_9, 127);
    EGU32x4_LSHIFT(H1_9);
    if (reduce_8) {
        H1_9[0] ^= 0x87;
    }

    EGU32x4_t Z1_10 = Z1_9;
    EGU32x4_t H1_10 = H1_9;
    if (EGU32x4_ISSET(Y, 9)) {
        EGU32x4_XOREQ(Z1_10, H1_10);
    }
    bool reduce_9 = EGU32x4_ISSET(H1_10, 127);
    EGU32x4_LSHIFT(H1_10);
    if (reduce_9) {
        H1_10[0] ^= 0x87;
    }

    EGU32x4_t Z1_11 = Z1_10;
    EGU32x4_t H1_11 = H1_10;
    if (EGU32x4_ISSET(Y, 10)) {
        EGU32x4_XOREQ(Z1_11, H1_11);
    }
    bool reduce_10 = EGU32x4_ISSET(H1_11, 127);
    EGU32x4_LSHIFT(H1_11);
    if (reduce_10) {
        H1_11[0] ^= 0x87;
    }

    EGU32x4_t Z1_12 = Z1_11;
    EGU32x4_t H1_12 = H1_11;
    if (EGU32x4_ISSET(Y, 11)) {
        EGU32x4_XOREQ(Z1_12, H1_12);
    }
    bool reduce_11 = EGU32x4_ISSET(H1_12, 127);
    EGU32x4_LSHIFT(H1_12);
    if (reduce_11) {
        H1_12[0] ^= 0x87;
    }

    EGU32x4_t Z1_13 = Z1_12;
    EGU32x4_t H1_13 = H1_12;
    if (EGU32x4_ISSET(Y, 12)) {
        EGU32x4_XOREQ(Z1_13, H1_13);
    }
    bool reduce_12 = EGU32x4_ISSET(H1_13, 127);
    EGU32x4_LSHIFT(H1_13);
    if (reduce_12) {
        H1_13[0] ^= 0x87;
    }

    EGU32x4_t Z1_14 = Z1_13;
    EGU32x4_t H1_14 = H1_13;
    if (EGU32x4_ISSET(Y, 13)) {
        EGU32x4_XOREQ(Z1_14, H1_14);
    }
    bool reduce_13 = EGU32x4_ISSET(H1_14, 127);
    EGU32x4_LSHIFT(H1_14);
    if (reduce_13) {
        H1_14[0] ^= 0x87;
    }

    EGU32x4_t Z1_15 = Z1_14;
    EGU32x4_t H1_15 = H1_14;
    if (EGU32x4_ISSET(Y, 14)) {
        EGU32x4_XOREQ(Z1_15, H1_15);
    }
    bool reduce_14 = EGU32x4_ISSET(H1_15, 127);
    EGU32x4_LSHIFT(H1_15);
    if (reduce_14) {
        H1_15[0] ^= 0x87;
    }

    EGU32x4_t Z1_16 = Z1_15;
    EGU32x4_t H1_16 = H1_15;
    if (EGU32x4_ISSET(Y, 15)) {
        EGU32x4_XOREQ(Z1_16, H1_16);
    }
    bool reduce_15 = EGU32x4_ISSET(H1_16, 127);
    EGU32x4_LSHIFT(H1_16);
    if (reduce_15) {
        H1_16[0] ^= 0x87;
    }

    EGU32x4_t Z1_17 = Z1_16;
    EGU32x4_t H1_17 = H1_16;
    if (EGU32x4_ISSET(Y, 16)) {
        EGU32x4_XOREQ(Z1_17, H1_17);
    }
    bool reduce_16 = EGU32x4_ISSET(H1_17, 127);
    EGU32x4_LSHIFT(H1_17);
    if (reduce_16) {
        H1_17[0] ^= 0x87;
    }

    EGU32x4_t Z1_18 = Z1_17;
    EGU32x4_t H1_18 = H1_17;
    if (EGU32x4_ISSET(Y, 17)) {
        EGU32x4_XOREQ(Z1_18, H1_18);
    }
    bool reduce_17 = EGU32x4_ISSET(H1_18, 127);
    EGU32x4_LSHIFT(H1_18);
    if (reduce_17) {
        H1_18[0] ^= 0x87;
    }

    EGU32x4_t Z1_19 = Z1_18;
    EGU32x4_t H1_19 = H1_18;
    if (EGU32x4_ISSET(Y, 18)) {
        EGU32x4_XOREQ(Z1_19, H1_19);
    }
    bool reduce_18 = EGU32x4_ISSET(H1_19, 127);
    EGU32x4_LSHIFT(H1_19);
    if (reduce_18) {
        H1_19[0] ^= 0x87;
    }

    EGU32x4_t Z1_20 = Z1_19;
    EGU32x4_t H1_20 = H1_19;
    if (EGU32x4_ISSET(Y, 19)) {
        EGU32x4_XOREQ(Z1_20, H1_20);
    }
    bool reduce_19 = EGU32x4_ISSET(H1_20, 127);
    EGU32x4_LSHIFT(H1_20);
    if (reduce_19) {
        H1_20[0] ^= 0x87;
    }

    EGU32x4_t Z1_21 = Z1_20;
    EGU32x4_t H1_21 = H1_20;
    if (EGU32x4_ISSET(Y, 20)) {
        EGU32x4_XOREQ(Z1_21, H1_21);
    }
    bool reduce_20 = EGU32x4_ISSET(H1_21, 127);
    EGU32x4_LSHIFT(H1_21);
    if (reduce_20) {
        H1_21[0] ^= 0x87;
    }

    EGU32x4_t Z1_22 = Z1_21;
    EGU32x4_t H1_22 = H1_21;
    if (EGU32x4_ISSET(Y, 21)) {
        EGU32x4_XOREQ(Z1_22, H1_22);
    }
    bool reduce_21 = EGU32x4_ISSET(H1_22, 127);
    EGU32x4_LSHIFT(H1_22);
    if (reduce_21) {
        H1_22[0] ^= 0x87;
    }

    EGU32x4_t Z1_23 = Z1_22;
    EGU32x4_t H1_23 = H1_22;
    if (EGU32x4_ISSET(Y, 22)) {
        EGU32x4_XOREQ(Z1_23, H1_23);
    }
    bool reduce_22 = EGU32x4_ISSET(H1_23, 127);
    EGU32x4_LSHIFT(H1_23);
    if (reduce_22) {
        H1_23[0] ^= 0x87;
    }

    EGU32x4_t Z1_24 = Z1_23;
    EGU32x4_t H1_24 = H1_23;
    if (EGU32x4_ISSET(Y, 23)) {
        EGU32x4_XOREQ(Z1_24, H1_24);
    }
    bool reduce_23 = EGU32x4_ISSET(H1_24, 127);
    EGU32x4_LSHIFT(H1_24);
    if (reduce_23) {
        H1_24[0] ^= 0x87;
    }

    EGU32x4_t Z1_25 = Z1_24;
    EGU32x4_t H1_25 = H1_24;
    if (EGU32x4_ISSET(Y, 24)) {
        EGU32x4_XOREQ(Z1_25, H1_25);
    }
    bool reduce_24 = EGU32x4_ISSET(H1_25, 127);
    EGU32x4_LSHIFT(H1_25);
    if (reduce_24) {
        H1_25[0] ^= 0x87;
    }

    EGU32x4_t Z1_26 = Z1_25;
    EGU32x4_t H1_26 = H1_25;
    if (EGU32x4_ISSET(Y, 25)) {
        EGU32x4_XOREQ(Z1_26, H1_26);
    }
    bool reduce_25 = EGU32x4_ISSET(H1_26, 127);
    EGU32x4_LSHIFT(H1_26);
    if (reduce_25) {
        H1_26[0] ^= 0x87;
    }

    EGU32x4_t Z1_27 = Z1_26;
    EGU32x4_t H1_27 = H1_26;
    if (EGU32x4_ISSET(Y, 26)) {
        EGU32x4_XOREQ(Z1_27, H1_27);
    }
    bool reduce_26 = EGU32x4_ISSET(H1_27, 127);
    EGU32x4_LSHIFT(H1_27);
    if (reduce_26) {
        H1_27[0] ^= 0x87;
    }

    EGU32x4_t Z1_28 = Z1_27;
    EGU32x4_t H1_28 = H1_27;
    if (EGU32x4_ISSET(Y, 27)) {
        EGU32x4_XOREQ(Z1_28, H1_28);
    }
    bool reduce_27 = EGU32x4_ISSET(H1_28, 127);
    EGU32x4_LSHIFT(H1_28);
    if (reduce_27) {
        H1_28[0] ^= 0x87;
    }

    EGU32x4_t Z1_29 = Z1_28;
    EGU32x4_t H1_29 = H1_28;
    if (EGU32x4_ISSET(Y, 28)) {
        EGU32x4_XOREQ(Z1_29, H1_29);
    }
    bool reduce_28 = EGU32x4_ISSET(H1_29, 127);
    EGU32x4_LSHIFT(H1_29);
    if (reduce_28) {
        H1_29[0] ^= 0x87;
    }

    EGU32x4_t Z1_30 = Z1_29;
    EGU32x4_t H1_30 = H1_29;
    if (EGU32x4_ISSET(Y, 29)) {
        EGU32x4_XOREQ(Z1_30, H1_30);
    }
    bool reduce_29 = EGU32x4_ISSET(H1_30, 127);
    EGU32x4_LSHIFT(H1_30);
    if (reduce_29) {
        H1_30[0] ^= 0x87;
    }

    EGU32x4_t Z1_31 = Z1_30;
    EGU32x4_t H1_31 = H1_30;
    if (EGU32x4_ISSET(Y, 30)) {
        EGU32x4_XOREQ(Z1_31, H1_31);
    }
    bool reduce_30 = EGU32x4_ISSET(H1_31, 127);
    EGU32x4_LSHIFT(H1_31);
    if (reduce_30) {
        H1_31[0] ^= 0x87;
    }

    EGU32x4_t Z1_32 = Z1_31;
    EGU32x4_t H1_32 = H1_31;
    if (EGU32x4_ISSET(Y, 31)) {
        EGU32x4_XOREQ(Z1_32, H1_32);
    }
    bool reduce_31 = EGU32x4_ISSET(H1_32, 127);
    EGU32x4_LSHIFT(H1_32);
    if (reduce_31) {
        H1_32[0] ^= 0x87;
    }

    EGU32x4_t Z1_33 = Z1_32;
    EGU32x4_t H1_33 = H1_32;
    if (EGU32x4_ISSET(Y, 32)) {
        EGU32x4_XOREQ(Z1_33, H1_33);
    }
    bool reduce_32 = EGU32x4_ISSET(H1_33, 127);
    EGU32x4_LSHIFT(H1_33);
    if (reduce_32) {
        H1_33[0] ^= 0x87;
    }

    EGU32x4_t Z1_34 = Z1_33;
    EGU32x4_t H1_34 = H1_33;
    if (EGU32x4_ISSET(Y, 33)) {
        EGU32x4_XOREQ(Z1_34, H1_34);
    }
    bool reduce_33 = EGU32x4_ISSET(H1_34, 127);
    EGU32x4_LSHIFT(H1_34);
    if (reduce_33) {
        H1_34[0] ^= 0x87;
    }

    EGU32x4_t Z1_35 = Z1_34;
    EGU32x4_t H1_35 = H1_34;
    if (EGU32x4_ISSET(Y, 34)) {
        EGU32x4_XOREQ(Z1_35, H1_35);
    }
    bool reduce_34 = EGU32x4_ISSET(H1_35, 127);
    EGU32x4_LSHIFT(H1_35);
    if (reduce_34) {
        H1_35[0] ^= 0x87;
    }

    EGU32x4_t Z1_36 = Z1_35;
    EGU32x4_t H1_36 = H1_35;
    if (EGU32x4_ISSET(Y, 35)) {
        EGU32x4_XOREQ(Z1_36, H1_36);
    }
    bool reduce_35 = EGU32x4_ISSET(H1_36, 127);
    EGU32x4_LSHIFT(H1_36);
    if (reduce_35) {
        H1_36[0] ^= 0x87;
    }

    EGU32x4_t Z1_37 = Z1_36;
    EGU32x4_t H1_37 = H1_36;
    if (EGU32x4_ISSET(Y, 36)) {
        EGU32x4_XOREQ(Z1_37, H1_37);
    }
    bool reduce_36 = EGU32x4_ISSET(H1_37, 127);
    EGU32x4_LSHIFT(H1_37);
    if (reduce_36) {
        H1_37[0] ^= 0x87;
    }

    EGU32x4_t Z1_38 = Z1_37;
    EGU32x4_t H1_38 = H1_37;
    if (EGU32x4_ISSET(Y, 37)) {
        EGU32x4_XOREQ(Z1_38, H1_38);
    }
    bool reduce_37 = EGU32x4_ISSET(H1_38, 127);
    EGU32x4_LSHIFT(H1_38);
    if (reduce_37) {
        H1_38[0] ^= 0x87;
    }

    EGU32x4_t Z1_39 = Z1_38;
    EGU32x4_t H1_39 = H1_38;
    if (EGU32x4_ISSET(Y, 38)) {
        EGU32x4_XOREQ(Z1_39, H1_39);
    }
    bool reduce_38 = EGU32x4_ISSET(H1_39, 127);
    EGU32x4_LSHIFT(H1_39);
    if (reduce_38) {
        H1_39[0] ^= 0x87;
    }

    EGU32x4_t Z1_40 = Z1_39;
    EGU32x4_t H1_40 = H1_39;
    if (EGU32x4_ISSET(Y, 39)) {
        EGU32x4_XOREQ(Z1_40, H1_40);
    }
    bool reduce_39 = EGU32x4_ISSET(H1_40, 127);
    EGU32x4_LSHIFT(H1_40);
    if (reduce_39) {
        H1_40[0] ^= 0x87;
    }

    EGU32x4_t Z1_41 = Z1_40;
    EGU32x4_t H1_41 = H1_40;
    if (EGU32x4_ISSET(Y, 40)) {
        EGU32x4_XOREQ(Z1_41, H1_41);
    }
    bool reduce_40 = EGU32x4_ISSET(H1_41, 127);
    EGU32x4_LSHIFT(H1_41);
    if (reduce_40) {
        H1_41[0] ^= 0x87;
    }

    EGU32x4_t Z1_42 = Z1_41;
    EGU32x4_t H1_42 = H1_41;
    if (EGU32x4_ISSET(Y, 41)) {
        EGU32x4_XOREQ(Z1_42, H1_42);
    }
    bool reduce_41 = EGU32x4_ISSET(H1_42, 127);
    EGU32x4_LSHIFT(H1_42);
    if (reduce_41) {
        H1_42[0] ^= 0x87;
    }

    EGU32x4_t Z1_43 = Z1_42;
    EGU32x4_t H1_43 = H1_42;
    if (EGU32x4_ISSET(Y, 42)) {
        EGU32x4_XOREQ(Z1_43, H1_43);
    }
    bool reduce_42 = EGU32x4_ISSET(H1_43, 127);
    EGU32x4_LSHIFT(H1_43);
    if (reduce_42) {
        H1_43[0] ^= 0x87;
    }

    EGU32x4_t Z1_44 = Z1_43;
    EGU32x4_t H1_44 = H1_43;
    if (EGU32x4_ISSET(Y, 43)) {
        EGU32x4_XOREQ(Z1_44, H1_44);
    }
    bool reduce_43 = EGU32x4_ISSET(H1_44, 127);
    EGU32x4_LSHIFT(H1_44);
    if (reduce_43) {
        H1_44[0] ^= 0x87;
    }

    EGU32x4_t Z1_45 = Z1_44;
    EGU32x4_t H1_45 = H1_44;
    if (EGU32x4_ISSET(Y, 44)) {
        EGU32x4_XOREQ(Z1_45, H1_45);
    }
    bool reduce_44 = EGU32x4_ISSET(H1_45, 127);
    EGU32x4_LSHIFT(H1_45);
    if (reduce_44) {
        H1_45[0] ^= 0x87;
    }

    EGU32x4_t Z1_46 = Z1_45;
    EGU32x4_t H1_46 = H1_45;
    if (EGU32x4_ISSET(Y, 45)) {
        EGU32x4_XOREQ(Z1_46, H1_46);
    }
    bool reduce_45 = EGU32x4_ISSET(H1_46, 127);
    EGU32x4_LSHIFT(H1_46);
    if (reduce_45) {
        H1_46[0] ^= 0x87;
    }

    EGU32x4_t Z1_47 = Z1_46;
    EGU32x4_t H1_47 = H1_46;
    if (EGU32x4_ISSET(Y, 46)) {
        EGU32x4_XOREQ(Z1_47, H1_47);
    }
    bool reduce_46 = EGU32x4_ISSET(H1_47, 127);
    EGU32x4_LSHIFT(H1_47);
    if (reduce_46) {
        H1_47[0] ^= 0x87;
    }

    EGU32x4_t Z1_48 = Z1_47;
    EGU32x4_t H1_48 = H1_47;
    if (EGU32x4_ISSET(Y, 47)) {
        EGU32x4_XOREQ(Z1_48, H1_48);
    }
    bool reduce_47 = EGU32x4_ISSET(H1_48, 127);
    EGU32x4_LSHIFT(H1_48);
    if (reduce_47) {
        H1_48[0] ^= 0x87;
    }

    EGU32x4_t Z1_49 = Z1_48;
    EGU32x4_t H1_49 = H1_48;
    if (EGU32x4_ISSET(Y, 48)) {
        EGU32x4_XOREQ(Z1_49, H1_49);
    }
    bool reduce_48 = EGU32x4_ISSET(H1_49, 127);
    EGU32x4_LSHIFT(H1_49);
    if (reduce_48) {
        H1_49[0] ^= 0x87;
    }

    EGU32x4_t Z1_50 = Z1_49;
    EGU32x4_t H1_50 = H1_49;
    if (EGU32x4_ISSET(Y, 49)) {
        EGU32x4_XOREQ(Z1_50, H1_50);
    }
    bool reduce_49 = EGU32x4_ISSET(H1_50, 127);
    EGU32x4_LSHIFT(H1_50);
    if (reduce_49) {
        H1_50[0] ^= 0x87;
    }

    EGU32x4_t Z1_51 = Z1_50;
    EGU32x4_t H1_51 = H1_50;
    if (EGU32x4_ISSET(Y, 50)) {
        EGU32x4_XOREQ(Z1_51, H1_51);
    }
    bool reduce_50 = EGU32x4_ISSET(H1_51, 127);
    EGU32x4_LSHIFT(H1_51);
    if (reduce_50) {
        H1_51[0] ^= 0x87;
    }

    EGU32x4_t Z1_52 = Z1_51;
    EGU32x4_t H1_52 = H1_51;
    if (EGU32x4_ISSET(Y, 51)) {
        EGU32x4_XOREQ(Z1_52, H1_52);
    }
    bool reduce_51 = EGU32x4_ISSET(H1_52, 127);
    EGU32x4_LSHIFT(H1_52);
    if (reduce_51) {
        H1_52[0] ^= 0x87;
    }

    EGU32x4_t Z1_53 = Z1_52;
    EGU32x4_t H1_53 = H1_52;
    if (EGU32x4_ISSET(Y, 52)) {
        EGU32x4_XOREQ(Z1_53, H1_53);
    }
    bool reduce_52 = EGU32x4_ISSET(H1_53, 127);
    EGU32x4_LSHIFT(H1_53);
    if (reduce_52) {
        H1_53[0] ^= 0x87;
    }

    EGU32x4_t Z1_54 = Z1_53;
    EGU32x4_t H1_54 = H1_53;
    if (EGU32x4_ISSET(Y, 53)) {
        EGU32x4_XOREQ(Z1_54, H1_54);
    }
    bool reduce_53 = EGU32x4_ISSET(H1_54, 127);
    EGU32x4_LSHIFT(H1_54);
    if (reduce_53) {
        H1_54[0] ^= 0x87;
    }

    EGU32x4_t Z1_55 = Z1_54;
    EGU32x4_t H1_55 = H1_54;
    if (EGU32x4_ISSET(Y, 54)) {
        EGU32x4_XOREQ(Z1_55, H1_55);
    }
    bool reduce_54 = EGU32x4_ISSET(H1_55, 127);
    EGU32x4_LSHIFT(H1_55);
    if (reduce_54) {
        H1_55[0] ^= 0x87;
    }

    EGU32x4_t Z1_56 = Z1_55;
    EGU32x4_t H1_56 = H1_55;
    if (EGU32x4_ISSET(Y, 55)) {
        EGU32x4_XOREQ(Z1_56, H1_56);
    }
    bool reduce_55 = EGU32x4_ISSET(H1_56, 127);
    EGU32x4_LSHIFT(H1_56);
    if (reduce_55) {
        H1_56[0] ^= 0x87;
    }

    EGU32x4_t Z1_57 = Z1_56;
    EGU32x4_t H1_57 = H1_56;
    if (EGU32x4_ISSET(Y, 56)) {
        EGU32x4_XOREQ(Z1_57, H1_57);
    }
    bool reduce_56 = EGU32x4_ISSET(H1_57, 127);
    EGU32x4_LSHIFT(H1_57);
    if (reduce_56) {
        H1_57[0] ^= 0x87;
    }

    EGU32x4_t Z1_58 = Z1_57;
    EGU32x4_t H1_58 = H1_57;
    if (EGU32x4_ISSET(Y, 57)) {
        EGU32x4_XOREQ(Z1_58, H1_58);
    }
    bool reduce_57 = EGU32x4_ISSET(H1_58, 127);
    EGU32x4_LSHIFT(H1_58);
    if (reduce_57) {
        H1_58[0] ^= 0x87;
    }

    EGU32x4_t Z1_59 = Z1_58;
    EGU32x4_t H1_59 = H1_58;
    if (EGU32x4_ISSET(Y, 58)) {
        EGU32x4_XOREQ(Z1_59, H1_59);
    }
    bool reduce_58 = EGU32x4_ISSET(H1_59, 127);
    EGU32x4_LSHIFT(H1_59);
    if (reduce_58) {
        H1_59[0] ^= 0x87;
    }

    EGU32x4_t Z1_60 = Z1_59;
    EGU32x4_t H1_60 = H1_59;
    if (EGU32x4_ISSET(Y, 59)) {
        EGU32x4_XOREQ(Z1_60, H1_60);
    }
    bool reduce_59 = EGU32x4_ISSET(H1_60, 127);
    EGU32x4_LSHIFT(H1_60);
    if (reduce_59) {
        H1_60[0] ^= 0x87;
    }

    EGU32x4_t Z1_61 = Z1_60;
    EGU32x4_t H1_61 = H1_60;
    if (EGU32x4_ISSET(Y, 60)) {
        EGU32x4_XOREQ(Z1_61, H1_61);
    }
    bool reduce_60 = EGU32x4_ISSET(H1_61, 127);
    EGU32x4_LSHIFT(H1_61);
    if (reduce_60) {
        H1_61[0] ^= 0x87;
    }

    EGU32x4_t Z1_62 = Z1_61;
    EGU32x4_t H1_62 = H1_61;
    if (EGU32x4_ISSET(Y, 61)) {
        EGU32x4_XOREQ(Z1_62, H1_62);
    }
    bool reduce_61 = EGU32x4_ISSET(H1_62, 127);
    EGU32x4_LSHIFT(H1_62);
    if (reduce_61) {
        H1_62[0] ^= 0x87;
    }

    EGU32x4_t Z1_63 = Z1_62;
    EGU32x4_t H1_63 = H1_62;
    if (EGU32x4_ISSET(Y, 62)) {
        EGU32x4_XOREQ(Z1_63, H1_63);
    }
    bool reduce_62 = EGU32x4_ISSET(H1_63, 127);
    EGU32x4_LSHIFT(H1_63);
    if (reduce_62) {
        H1_63[0] ^= 0x87;
    }

    EGU32x4_t Z1_64 = Z1_63;
    EGU32x4_t H1_64 = H1_63;
    if (EGU32x4_ISSET(Y, 63)) {
        EGU32x4_XOREQ(Z1_64, H1_64);
    }
    bool reduce_63 = EGU32x4_ISSET(H1_64, 127);
    EGU32x4_LSHIFT(H1_64);
    if (reduce_63) {
        H1_64[0] ^= 0x87;
    }

    EGU32x4_t Z1_65 = Z1_64;
    EGU32x4_t H1_65 = H1_64;
    if (EGU32x4_ISSET(Y, 64)) {
        EGU32x4_XOREQ(Z1_65, H1_65);
    }
    bool reduce_64 = EGU32x4_ISSET(H1_65, 127);
    EGU32x4_LSHIFT(H1_65);
    if (reduce_64) {
        H1_65[0] ^= 0x87;
    }

    EGU32x4_t Z1_66 = Z1_65;
    EGU32x4_t H1_66 = H1_65;
    if (EGU32x4_ISSET(Y, 65)) {
        EGU32x4_XOREQ(Z1_66, H1_66);
    }
    bool reduce_65 = EGU32x4_ISSET(H1_66, 127);
    EGU32x4_LSHIFT(H1_66);
    if (reduce_65) {
        H1_66[0] ^= 0x87;
    }

    EGU32x4_t Z1_67 = Z1_66;
    EGU32x4_t H1_67 = H1_66;
    if (EGU32x4_ISSET(Y, 66)) {
        EGU32x4_XOREQ(Z1_67, H1_67);
    }
    bool reduce_66 = EGU32x4_ISSET(H1_67, 127);
    EGU32x4_LSHIFT(H1_67);
    if (reduce_66) {
        H1_67[0] ^= 0x87;
    }

    EGU32x4_t Z1_68 = Z1_67;
    EGU32x4_t H1_68 = H1_67;
    if (EGU32x4_ISSET(Y, 67)) {
        EGU32x4_XOREQ(Z1_68, H1_68);
    }
    bool reduce_67 = EGU32x4_ISSET(H1_68, 127);
    EGU32x4_LSHIFT(H1_68);
    if (reduce_67) {
        H1_68[0] ^= 0x87;
    }

    EGU32x4_t Z1_69 = Z1_68;
    EGU32x4_t H1_69 = H1_68;
    if (EGU32x4_ISSET(Y, 68)) {
        EGU32x4_XOREQ(Z1_69, H1_69);
    }
    bool reduce_68 = EGU32x4_ISSET(H1_69, 127);
    EGU32x4_LSHIFT(H1_69);
    if (reduce_68) {
        H1_69[0] ^= 0x87;
    }

    EGU32x4_t Z1_70 = Z1_69;
    EGU32x4_t H1_70 = H1_69;
    if (EGU32x4_ISSET(Y, 69)) {
        EGU32x4_XOREQ(Z1_70, H1_70);
    }
    bool reduce_69 = EGU32x4_ISSET(H1_70, 127);
    EGU32x4_LSHIFT(H1_70);
    if (reduce_69) {
        H1_70[0] ^= 0x87;
    }

    EGU32x4_t Z1_71 = Z1_70;
    EGU32x4_t H1_71 = H1_70;
    if (EGU32x4_ISSET(Y, 70)) {
        EGU32x4_XOREQ(Z1_71, H1_71);
    }
    bool reduce_70 = EGU32x4_ISSET(H1_71, 127);
    EGU32x4_LSHIFT(H1_71);
    if (reduce_70) {
        H1_71[0] ^= 0x87;
    }

    EGU32x4_t Z1_72 = Z1_71;
    EGU32x4_t H1_72 = H1_71;
    if (EGU32x4_ISSET(Y, 71)) {
        EGU32x4_XOREQ(Z1_72, H1_72);
    }
    bool reduce_71 = EGU32x4_ISSET(H1_72, 127);
    EGU32x4_LSHIFT(H1_72);
    if (reduce_71) {
        H1_72[0] ^= 0x87;
    }

    EGU32x4_t Z1_73 = Z1_72;
    EGU32x4_t H1_73 = H1_72;
    if (EGU32x4_ISSET(Y, 72)) {
        EGU32x4_XOREQ(Z1_73, H1_73);
    }
    bool reduce_72 = EGU32x4_ISSET(H1_73, 127);
    EGU32x4_LSHIFT(H1_73);
    if (reduce_72) {
        H1_73[0] ^= 0x87;
    }

    EGU32x4_t Z1_74 = Z1_73;
    EGU32x4_t H1_74 = H1_73;
    if (EGU32x4_ISSET(Y, 73)) {
        EGU32x4_XOREQ(Z1_74, H1_74);
    }
    bool reduce_73 = EGU32x4_ISSET(H1_74, 127);
    EGU32x4_LSHIFT(H1_74);
    if (reduce_73) {
        H1_74[0] ^= 0x87;
    }

    EGU32x4_t Z1_75 = Z1_74;
    EGU32x4_t H1_75 = H1_74;
    if (EGU32x4_ISSET(Y, 74)) {
        EGU32x4_XOREQ(Z1_75, H1_75);
    }
    bool reduce_74 = EGU32x4_ISSET(H1_75, 127);
    EGU32x4_LSHIFT(H1_75);
    if (reduce_74) {
        H1_75[0] ^= 0x87;
    }

    EGU32x4_t Z1_76 = Z1_75;
    EGU32x4_t H1_76 = H1_75;
    if (EGU32x4_ISSET(Y, 75)) {
        EGU32x4_XOREQ(Z1_76, H1_76);
    }
    bool reduce_75 = EGU32x4_ISSET(H1_76, 127);
    EGU32x4_LSHIFT(H1_76);
    if (reduce_75) {
        H1_76[0] ^= 0x87;
    }

    EGU32x4_t Z1_77 = Z1_76;
    EGU32x4_t H1_77 = H1_76;
    if (EGU32x4_ISSET(Y, 76)) {
        EGU32x4_XOREQ(Z1_77, H1_77);
    }
    bool reduce_76 = EGU32x4_ISSET(H1_77, 127);
    EGU32x4_LSHIFT(H1_77);
    if (reduce_76) {
        H1_77[0] ^= 0x87;
    }

    EGU32x4_t Z1_78 = Z1_77;
    EGU32x4_t H1_78 = H1_77;
    if (EGU32x4_ISSET(Y, 77)) {
        EGU32x4_XOREQ(Z1_78, H1_78);
    }
    bool reduce_77 = EGU32x4_ISSET(H1_78, 127);
    EGU32x4_LSHIFT(H1_78);
    if (reduce_77) {
        H1_78[0] ^= 0x87;
    }

    EGU32x4_t Z1_79 = Z1_78;
    EGU32x4_t H1_79 = H1_78;
    if (EGU32x4_ISSET(Y, 78)) {
        EGU32x4_XOREQ(Z1_79, H1_79);
    }
    bool reduce_78 = EGU32x4_ISSET(H1_79, 127);
    EGU32x4_LSHIFT(H1_79);
    if (reduce_78) {
        H1_79[0] ^= 0x87;
    }

    EGU32x4_t Z1_80 = Z1_79;
    EGU32x4_t H1_80 = H1_79;
    if (EGU32x4_ISSET(Y, 79)) {
        EGU32x4_XOREQ(Z1_80, H1_80);
    }
    bool reduce_79 = EGU32x4_ISSET(H1_80, 127);
    EGU32x4_LSHIFT(H1_80);
    if (reduce_79) {
        H1_80[0] ^= 0x87;
    }

    EGU32x4_t Z1_81 = Z1_80;
    EGU32x4_t H1_81 = H1_80;
    if (EGU32x4_ISSET(Y, 80)) {
        EGU32x4_XOREQ(Z1_81, H1_81);
    }
    bool reduce_80 = EGU32x4_ISSET(H1_81, 127);
    EGU32x4_LSHIFT(H1_81);
    if (reduce_80) {
        H1_81[0] ^= 0x87;
    }

    EGU32x4_t Z1_82 = Z1_81;
    EGU32x4_t H1_82 = H1_81;
    if (EGU32x4_ISSET(Y, 81)) {
        EGU32x4_XOREQ(Z1_82, H1_82);
    }
    bool reduce_81 = EGU32x4_ISSET(H1_82, 127);
    EGU32x4_LSHIFT(H1_82);
    if (reduce_81) {
        H1_82[0] ^= 0x87;
    }

    EGU32x4_t Z1_83 = Z1_82;
    EGU32x4_t H1_83 = H1_82;
    if (EGU32x4_ISSET(Y, 82)) {
        EGU32x4_XOREQ(Z1_83, H1_83);
    }
    bool reduce_82 = EGU32x4_ISSET(H1_83, 127);
    EGU32x4_LSHIFT(H1_83);
    if (reduce_82) {
        H1_83[0] ^= 0x87;
    }

    EGU32x4_t Z1_84 = Z1_83;
    EGU32x4_t H1_84 = H1_83;
    if (EGU32x4_ISSET(Y, 83)) {
        EGU32x4_XOREQ(Z1_84, H1_84);
    }
    bool reduce_83 = EGU32x4_ISSET(H1_84, 127);
    EGU32x4_LSHIFT(H1_84);
    if (reduce_83) {
        H1_84[0] ^= 0x87;
    }

    EGU32x4_t Z1_85 = Z1_84;
    EGU32x4_t H1_85 = H1_84;
    if (EGU32x4_ISSET(Y, 84)) {
        EGU32x4_XOREQ(Z1_85, H1_85);
    }
    bool reduce_84 = EGU32x4_ISSET(H1_85, 127);
    EGU32x4_LSHIFT(H1_85);
    if (reduce_84) {
        H1_85[0] ^= 0x87;
    }

    EGU32x4_t Z1_86 = Z1_85;
    EGU32x4_t H1_86 = H1_85;
    if (EGU32x4_ISSET(Y, 85)) {
        EGU32x4_XOREQ(Z1_86, H1_86);
    }
    bool reduce_85 = EGU32x4_ISSET(H1_86, 127);
    EGU32x4_LSHIFT(H1_86);
    if (reduce_85) {
        H1_86[0] ^= 0x87;
    }

    EGU32x4_t Z1_87 = Z1_86;
    EGU32x4_t H1_87 = H1_86;
    if (EGU32x4_ISSET(Y, 86)) {
        EGU32x4_XOREQ(Z1_87, H1_87);
    }
    bool reduce_86 = EGU32x4_ISSET(H1_87, 127);
    EGU32x4_LSHIFT(H1_87);
    if (reduce_86) {
        H1_87[0] ^= 0x87;
    }

    EGU32x4_t Z1_88 = Z1_87;
    EGU32x4_t H1_88 = H1_87;
    if (EGU32x4_ISSET(Y, 87)) {
        EGU32x4_XOREQ(Z1_88, H1_88);
    }
    bool reduce_87 = EGU32x4_ISSET(H1_88, 127);
    EGU32x4_LSHIFT(H1_88);
    if (reduce_87) {
        H1_88[0] ^= 0x87;
    }

    EGU32x4_t Z1_89 = Z1_88;
    EGU32x4_t H1_89 = H1_88;
    if (EGU32x4_ISSET(Y, 88)) {
        EGU32x4_XOREQ(Z1_89, H1_89);
    }
    bool reduce_88 = EGU32x4_ISSET(H1_89, 127);
    EGU32x4_LSHIFT(H1_89);
    if (reduce_88) {
        H1_89[0] ^= 0x87;
    }

    EGU32x4_t Z1_90 = Z1_89;
    EGU32x4_t H1_90 = H1_89;
    if (EGU32x4_ISSET(Y, 89)) {
        EGU32x4_XOREQ(Z1_90, H1_90);
    }
    bool reduce_89 = EGU32x4_ISSET(H1_90, 127);
    EGU32x4_LSHIFT(H1_90);
    if (reduce_89) {
        H1_90[0] ^= 0x87;
    }

    EGU32x4_t Z1_91 = Z1_90;
    EGU32x4_t H1_91 = H1_90;
    if (EGU32x4_ISSET(Y, 90)) {
        EGU32x4_XOREQ(Z1_91, H1_91);
    }
    bool reduce_90 = EGU32x4_ISSET(H1_91, 127);
    EGU32x4_LSHIFT(H1_91);
    if (reduce_90) {
        H1_91[0] ^= 0x87;
    }

    EGU32x4_t Z1_92 = Z1_91;
    EGU32x4_t H1_92 = H1_91;
    if (EGU32x4_ISSET(Y, 91)) {
        EGU32x4_XOREQ(Z1_92, H1_92);
    }
    bool reduce_91 = EGU32x4_ISSET(H1_92, 127);
    EGU32x4_LSHIFT(H1_92);
    if (reduce_91) {
        H1_92[0] ^= 0x87;
    }

    EGU32x4_t Z1_93 = Z1_92;
    EGU32x4_t H1_93 = H1_92;
    if (EGU32x4_ISSET(Y, 92)) {
        EGU32x4_XOREQ(Z1_93, H1_93);
    }
    bool reduce_92 = EGU32x4_ISSET(H1_93, 127);
    EGU32x4_LSHIFT(H1_93);
    if (reduce_92) {
        H1_93[0] ^= 0x87;
    }

    EGU32x4_t Z1_94 = Z1_93;
    EGU32x4_t H1_94 = H1_93;
    if (EGU32x4_ISSET(Y, 93)) {
        EGU32x4_XOREQ(Z1_94, H1_94);
    }
    bool reduce_93 = EGU32x4_ISSET(H1_94, 127);
    EGU32x4_LSHIFT(H1_94);
    if (reduce_93) {
        H1_94[0] ^= 0x87;
    }

    EGU32x4_t Z1_95 = Z1_94;
    EGU32x4_t H1_95 = H1_94;
    if (EGU32x4_ISSET(Y, 94)) {
        EGU32x4_XOREQ(Z1_95, H1_95);
    }
    bool reduce_94 = EGU32x4_ISSET(H1_95, 127);
    EGU32x4_LSHIFT(H1_95);
    if (reduce_94) {
        H1_95[0] ^= 0x87;
    }

    EGU32x4_t Z1_96 = Z1_95;
    EGU32x4_t H1_96 = H1_95;
    if (EGU32x4_ISSET(Y, 95)) {
        EGU32x4_XOREQ(Z1_96, H1_96);
    }
    bool reduce_95 = EGU32x4_ISSET(H1_96, 127);
    EGU32x4_LSHIFT(H1_96);
    if (reduce_95) {
        H1_96[0] ^= 0x87;
    }

    EGU32x4_t Z1_97 = Z1_96;
    EGU32x4_t H1_97 = H1_96;
    if (EGU32x4_ISSET(Y, 96)) {
        EGU32x4_XOREQ(Z1_97, H1_97);
    }
    bool reduce_96 = EGU32x4_ISSET(H1_97, 127);
    EGU32x4_LSHIFT(H1_97);
    if (reduce_96) {
        H1_97[0] ^= 0x87;
    }

    EGU32x4_t Z1_98 = Z1_97;
    EGU32x4_t H1_98 = H1_97;
    if (EGU32x4_ISSET(Y, 97)) {
        EGU32x4_XOREQ(Z1_98, H1_98);
    }
    bool reduce_97 = EGU32x4_ISSET(H1_98, 127);
    EGU32x4_LSHIFT(H1_98);
    if (reduce_97) {
        H1_98[0] ^= 0x87;
    }

    EGU32x4_t Z1_99 = Z1_98;
    EGU32x4_t H1_99 = H1_98;
    if (EGU32x4_ISSET(Y, 98)) {
        EGU32x4_XOREQ(Z1_99, H1_99);
    }
    bool reduce_98 = EGU32x4_ISSET(H1_99, 127);
    EGU32x4_LSHIFT(H1_99);
    if (reduce_98) {
        H1_99[0] ^= 0x87;
    }

    EGU32x4_t Z1_100 = Z1_99;
    EGU32x4_t H1_100 = H1_99;
    if (EGU32x4_ISSET(Y, 99)) {
        EGU32x4_XOREQ(Z1_100, H1_100);
    }
    bool reduce_99 = EGU32x4_ISSET(H1_100, 127);
    EGU32x4_LSHIFT(H1_100);
    if (reduce_99) {
        H1_100[0] ^= 0x87;
    }

    EGU32x4_t Z1_101 = Z1_100;
    EGU32x4_t H1_101 = H1_100;
    if (EGU32x4_ISSET(Y, 100)) {
        EGU32x4_XOREQ(Z1_101, H1_101);
    }
    bool reduce_100 = EGU32x4_ISSET(H1_101, 127);
    EGU32x4_LSHIFT(H1_101);
    if (reduce_100) {
        H1_101[0] ^= 0x87;
    }

    EGU32x4_t Z1_102 = Z1_101;
    EGU32x4_t H1_102 = H1_101;
    if (EGU32x4_ISSET(Y, 101)) {
        EGU32x4_XOREQ(Z1_102, H1_102);
    }
    bool reduce_101 = EGU32x4_ISSET(H1_102, 127);
    EGU32x4_LSHIFT(H1_102);
    if (reduce_101) {
        H1_102[0] ^= 0x87;
    }

    EGU32x4_t Z1_103 = Z1_102;
    EGU32x4_t H1_103 = H1_102;
    if (EGU32x4_ISSET(Y, 102)) {
        EGU32x4_XOREQ(Z1_103, H1_103);
    }
    bool reduce_102 = EGU32x4_ISSET(H1_103, 127);
    EGU32x4_LSHIFT(H1_103);
    if (reduce_102) {
        H1_103[0] ^= 0x87;
    }

    EGU32x4_t Z1_104 = Z1_103;
    EGU32x4_t H1_104 = H1_103;
    if (EGU32x4_ISSET(Y, 103)) {
        EGU32x4_XOREQ(Z1_104, H1_104);
    }
    bool reduce_103 = EGU32x4_ISSET(H1_104, 127);
    EGU32x4_LSHIFT(H1_104);
    if (reduce_103) {
        H1_104[0] ^= 0x87;
    }

    EGU32x4_t Z1_105 = Z1_104;
    EGU32x4_t H1_105 = H1_104;
    if (EGU32x4_ISSET(Y, 104)) {
        EGU32x4_XOREQ(Z1_105, H1_105);
    }
    bool reduce_104 = EGU32x4_ISSET(H1_105, 127);
    EGU32x4_LSHIFT(H1_105);
    if (reduce_104) {
        H1_105[0] ^= 0x87;
    }

    EGU32x4_t Z1_106 = Z1_105;
    EGU32x4_t H1_106 = H1_105;
    if (EGU32x4_ISSET(Y, 105)) {
        EGU32x4_XOREQ(Z1_106, H1_106);
    }
    bool reduce_105 = EGU32x4_ISSET(H1_106, 127);
    EGU32x4_LSHIFT(H1_106);
    if (reduce_105) {
        H1_106[0] ^= 0x87;
    }

    EGU32x4_t Z1_107 = Z1_106;
    EGU32x4_t H1_107 = H1_106;
    if (EGU32x4_ISSET(Y, 106)) {
        EGU32x4_XOREQ(Z1_107, H1_107);
    }
    bool reduce_106 = EGU32x4_ISSET(H1_107, 127);
    EGU32x4_LSHIFT(H1_107);
    if (reduce_106) {
        H1_107[0] ^= 0x87;
    }

    EGU32x4_t Z1_108 = Z1_107;
    EGU32x4_t H1_108 = H1_107;
    if (EGU32x4_ISSET(Y, 107)) {
        EGU32x4_XOREQ(Z1_108, H1_108);
    }
    bool reduce_107 = EGU32x4_ISSET(H1_108, 127);
    EGU32x4_LSHIFT(H1_108);
    if (reduce_107) {
        H1_108[0] ^= 0x87;
    }

    EGU32x4_t Z1_109 = Z1_108;
    EGU32x4_t H1_109 = H1_108;
    if (EGU32x4_ISSET(Y, 108)) {
        EGU32x4_XOREQ(Z1_109, H1_109);
    }
    bool reduce_108 = EGU32x4_ISSET(H1_109, 127);
    EGU32x4_LSHIFT(H1_109);
    if (reduce_108) {
        H1_109[0] ^= 0x87;
    }

    EGU32x4_t Z1_110 = Z1_109;
    EGU32x4_t H1_110 = H1_109;
    if (EGU32x4_ISSET(Y, 109)) {
        EGU32x4_XOREQ(Z1_110, H1_110);
    }
    bool reduce_109 = EGU32x4_ISSET(H1_110, 127);
    EGU32x4_LSHIFT(H1_110);
    if (reduce_109) {
        H1_110[0] ^= 0x87;
    }

    EGU32x4_t Z1_111 = Z1_110;
    EGU32x4_t H1_111 = H1_110;
    if (EGU32x4_ISSET(Y, 110)) {
        EGU32x4_XOREQ(Z1_111, H1_111);
    }
    bool reduce_110 = EGU32x4_ISSET(H1_111, 127);
    EGU32x4_LSHIFT(H1_111);
    if (reduce_110) {
        H1_111[0] ^= 0x87;
    }

    EGU32x4_t Z1_112 = Z1_111;
    EGU32x4_t H1_112 = H1_111;
    if (EGU32x4_ISSET(Y, 111)) {
        EGU32x4_XOREQ(Z1_112, H1_112);
    }
    bool reduce_111 = EGU32x4_ISSET(H1_112, 127);
    EGU32x4_LSHIFT(H1_112);
    if (reduce_111) {
        H1_112[0] ^= 0x87;
    }

    EGU32x4_t Z1_113 = Z1_112;
    EGU32x4_t H1_113 = H1_112;
    if (EGU32x4_ISSET(Y, 112)) {
        EGU32x4_XOREQ(Z1_113, H1_113);
    }
    bool reduce_112 = EGU32x4_ISSET(H1_113, 127);
    EGU32x4_LSHIFT(H1_113);
    if (reduce_112) {
        H1_113[0] ^= 0x87;
    }

    EGU32x4_t Z1_114 = Z1_113;
    EGU32x4_t H1_114 = H1_113;
    if (EGU32x4_ISSET(Y, 113)) {
        EGU32x4_XOREQ(Z1_114, H1_114);
    }
    bool reduce_113 = EGU32x4_ISSET(H1_114, 127);
    EGU32x4_LSHIFT(H1_114);
    if (reduce_113) {
        H1_114[0] ^= 0x87;
    }

    EGU32x4_t Z1_115 = Z1_114;
    EGU32x4_t H1_115 = H1_114;
    if (EGU32x4_ISSET(Y, 114)) {
        EGU32x4_XOREQ(Z1_115, H1_115);
    }
    bool reduce_114 = EGU32x4_ISSET(H1_115, 127);
    EGU32x4_LSHIFT(H1_115);
    if (reduce_114) {
        H1_115[0] ^= 0x87;
    }

    EGU32x4_t Z1_116 = Z1_115;
    EGU32x4_t H1_116 = H1_115;
    if (EGU32x4_ISSET(Y, 115)) {
        EGU32x4_XOREQ(Z1_116, H1_116);
    }
    bool reduce_115 = EGU32x4_ISSET(H1_116, 127);
    EGU32x4_LSHIFT(H1_116);
    if (reduce_115) {
        H1_116[0] ^= 0x87;
    }

    EGU32x4_t Z1_117 = Z1_116;
    EGU32x4_t H1_117 = H1_116;
    if (EGU32x4_ISSET(Y, 116)) {
        EGU32x4_XOREQ(Z1_117, H1_117);
    }
    bool reduce_116 = EGU32x4_ISSET(H1_117, 127);
    EGU32x4_LSHIFT(H1_117);
    if (reduce_116) {
        H1_117[0] ^= 0x87;
    }

    EGU32x4_t Z1_118 = Z1_117;
    EGU32x4_t H1_118 = H1_117;
    if (EGU32x4_ISSET(Y, 117)) {
        EGU32x4_XOREQ(Z1_118, H1_118);
    }
    bool reduce_117 = EGU32x4_ISSET(H1_118, 127);
    EGU32x4_LSHIFT(H1_118);
    if (reduce_117) {
        H1_118[0] ^= 0x87;
    }

    EGU32x4_t Z1_119 = Z1_118;
    EGU32x4_t H1_119 = H1_118;
    if (EGU32x4_ISSET(Y, 118)) {
        EGU32x4_XOREQ(Z1_119, H1_119);
    }
    bool reduce_118 = EGU32x4_ISSET(H1_119, 127);
    EGU32x4_LSHIFT(H1_119);
    if (reduce_118) {
        H1_119[0] ^= 0x87;
    }

    EGU32x4_t Z1_120 = Z1_119;
    EGU32x4_t H1_120 = H1_119;
    if (EGU32x4_ISSET(Y, 119)) {
        EGU32x4_XOREQ(Z1_120, H1_120);
    }
    bool reduce_119 = EGU32x4_ISSET(H1_120, 127);
    EGU32x4_LSHIFT(H1_120);
    if (reduce_119) {
        H1_120[0] ^= 0x87;
    }

    EGU32x4_t Z1_121 = Z1_120;
    EGU32x4_t H1_121 = H1_120;
    if (EGU32x4_ISSET(Y, 120)) {
        EGU32x4_XOREQ(Z1_121, H1_121);
    }
    bool reduce_120 = EGU32x4_ISSET(H1_121, 127);
    EGU32x4_LSHIFT(H1_121);
    if (reduce_120) {
        H1_121[0] ^= 0x87;
    }

    EGU32x4_t Z1_122 = Z1_121;
    EGU32x4_t H1_122 = H1_121;
    if (EGU32x4_ISSET(Y, 121)) {
        EGU32x4_XOREQ(Z1_122, H1_122);
    }
    bool reduce_121 = EGU32x4_ISSET(H1_122, 127);
    EGU32x4_LSHIFT(H1_122);
    if (reduce_121) {
        H1_122[0] ^= 0x87;
    }

    EGU32x4_t Z1_123 = Z1_122;
    EGU32x4_t H1_123 = H1_122;
    if (EGU32x4_ISSET(Y, 122)) {
        EGU32x4_XOREQ(Z1_123, H1_123);
    }
    bool reduce_122 = EGU32x4_ISSET(H1_123, 127);
    EGU32x4_LSHIFT(H1_123);
    if (reduce_122) {
        H1_123[0] ^= 0x87;
    }

    EGU32x4_t Z1_124 = Z1_123;
    EGU32x4_t H1_124 = H1_123;
    if (EGU32x4_ISSET(Y, 123)) {
        EGU32x4_XOREQ(Z1_124, H1_124);
    }
    bool reduce_123 = EGU32x4_ISSET(H1_124, 127);
    EGU32x4_LSHIFT(H1_124);
    if (reduce_123) {
        H1_124[0] ^= 0x87;
    }

    EGU32x4_t Z1_125 = Z1_124;
    EGU32x4_t H1_125 = H1_124;
    if (EGU32x4_ISSET(Y, 124)) {
        EGU32x4_XOREQ(Z1_125, H1_125);
    }
    bool reduce_124 = EGU32x4_ISSET(H1_125, 127);
    EGU32x4_LSHIFT(H1_125);
    if (reduce_124) {
        H1_125[0] ^= 0x87;
    }

    EGU32x4_t Z1_126 = Z1_125;
    EGU32x4_t H1_126 = H1_125;
    if (EGU32x4_ISSET(Y, 125)) {
        EGU32x4_XOREQ(Z1_126, H1_126);
    }
    bool reduce_125 = EGU32x4_ISSET(H1_126, 127);
    EGU32x4_LSHIFT(H1_126);
    if (reduce_125) {
        H1_126[0] ^= 0x87;
    }

    EGU32x4_t Z1_127 = Z1_126;
    EGU32x4_t H1_127 = H1_126;
    if (EGU32x4_ISSET(Y, 126)) {
        EGU32x4_XOREQ(Z1_127, H1_127);
    }
    bool reduce_126 = EGU32x4_ISSET(H1_127, 127);
    EGU32x4_LSHIFT(H1_127);
    if (reduce_126) {
        H1_127[0] ^= 0x87;
    }

    EGU32x4_t Z1_128 = Z1_127;
    EGU32x4_t H1_128 = H1_127;
    if (EGU32x4_ISSET(Y, 127)) {
        EGU32x4_XOREQ(Z1_128, H1_128);
    }
    bool reduce_127 = EGU32x4_ISSET(H1_128, 127);
    EGU32x4_LSHIFT(H1_128);
    if (reduce_127) {
        H1_128[0] ^= 0x87;
    }

    EGU32x4_t Z_final = Z1_128;
    EGU32x4_BREV8(Z_final);
    *vd_out_3 = Z_final[3];
    *vd_out_2 = Z_final[2];
    *vd_out_1 = Z_final[1];
    *vd_out_0 = Z_final[0];

    JG_OUTPUT_ARRAY(H1_1);
    JG_OUTPUT_ARRAY(H1_2);
    JG_OUTPUT_ARRAY(H1_3);
    JG_OUTPUT_ARRAY(H1_4);
    JG_OUTPUT_ARRAY(H1_5);
    JG_OUTPUT_ARRAY(H1_6);
    JG_OUTPUT_ARRAY(H1_7);
    JG_OUTPUT_ARRAY(H1_8);
    JG_OUTPUT_ARRAY(H1_9);
    JG_OUTPUT_ARRAY(H1_10);
    JG_OUTPUT_ARRAY(H1_11);
    JG_OUTPUT_ARRAY(H1_12);
    JG_OUTPUT_ARRAY(H1_13);
    JG_OUTPUT_ARRAY(H1_14);
    JG_OUTPUT_ARRAY(H1_15);
    JG_OUTPUT_ARRAY(H1_16);
    JG_OUTPUT_ARRAY(H1_17);
    JG_OUTPUT_ARRAY(H1_18);
    JG_OUTPUT_ARRAY(H1_19);
    JG_OUTPUT_ARRAY(H1_20);
    JG_OUTPUT_ARRAY(H1_21);
    JG_OUTPUT_ARRAY(H1_22);
    JG_OUTPUT_ARRAY(H1_23);
    JG_OUTPUT_ARRAY(H1_24);
    JG_OUTPUT_ARRAY(H1_25);
    JG_OUTPUT_ARRAY(H1_26);
    JG_OUTPUT_ARRAY(H1_27);
    JG_OUTPUT_ARRAY(H1_28);
    JG_OUTPUT_ARRAY(H1_29);
    JG_OUTPUT_ARRAY(H1_30);
    JG_OUTPUT_ARRAY(H1_31);
    JG_OUTPUT_ARRAY(H1_32);
    JG_OUTPUT_ARRAY(H1_33);
    JG_OUTPUT_ARRAY(H1_34);
    JG_OUTPUT_ARRAY(H1_35);
    JG_OUTPUT_ARRAY(H1_36);
    JG_OUTPUT_ARRAY(H1_37);
    JG_OUTPUT_ARRAY(H1_38);
    JG_OUTPUT_ARRAY(H1_39);
    JG_OUTPUT_ARRAY(H1_40);
    JG_OUTPUT_ARRAY(H1_41);
    JG_OUTPUT_ARRAY(H1_42);
    JG_OUTPUT_ARRAY(H1_43);
    JG_OUTPUT_ARRAY(H1_44);
    JG_OUTPUT_ARRAY(H1_45);
    JG_OUTPUT_ARRAY(H1_46);
    JG_OUTPUT_ARRAY(H1_47);
    JG_OUTPUT_ARRAY(H1_48);
    JG_OUTPUT_ARRAY(H1_49);
    JG_OUTPUT_ARRAY(H1_50);
    JG_OUTPUT_ARRAY(H1_51);
    JG_OUTPUT_ARRAY(H1_52);
    JG_OUTPUT_ARRAY(H1_53);
    JG_OUTPUT_ARRAY(H1_54);
    JG_OUTPUT_ARRAY(H1_55);
    JG_OUTPUT_ARRAY(H1_56);
    JG_OUTPUT_ARRAY(H1_57);
    JG_OUTPUT_ARRAY(H1_58);
    JG_OUTPUT_ARRAY(H1_59);
    JG_OUTPUT_ARRAY(H1_60);
    JG_OUTPUT_ARRAY(H1_61);
    JG_OUTPUT_ARRAY(H1_62);
    JG_OUTPUT_ARRAY(H1_63);
    JG_OUTPUT_ARRAY(H1_64);
    JG_OUTPUT_ARRAY(H1_65);
    JG_OUTPUT_ARRAY(H1_66);
    JG_OUTPUT_ARRAY(H1_67);
    JG_OUTPUT_ARRAY(H1_68);
    JG_OUTPUT_ARRAY(H1_69);
    JG_OUTPUT_ARRAY(H1_70);
    JG_OUTPUT_ARRAY(H1_71);
    JG_OUTPUT_ARRAY(H1_72);
    JG_OUTPUT_ARRAY(H1_73);
    JG_OUTPUT_ARRAY(H1_74);
    JG_OUTPUT_ARRAY(H1_75);
    JG_OUTPUT_ARRAY(H1_76);
    JG_OUTPUT_ARRAY(H1_77);
    JG_OUTPUT_ARRAY(H1_78);
    JG_OUTPUT_ARRAY(H1_79);
    JG_OUTPUT_ARRAY(H1_80);
    JG_OUTPUT_ARRAY(H1_81);
    JG_OUTPUT_ARRAY(H1_82);
    JG_OUTPUT_ARRAY(H1_83);
    JG_OUTPUT_ARRAY(H1_84);
    JG_OUTPUT_ARRAY(H1_85);
    JG_OUTPUT_ARRAY(H1_86);
    JG_OUTPUT_ARRAY(H1_87);
    JG_OUTPUT_ARRAY(H1_88);
    JG_OUTPUT_ARRAY(H1_89);
    JG_OUTPUT_ARRAY(H1_90);
    JG_OUTPUT_ARRAY(H1_91);
    JG_OUTPUT_ARRAY(H1_92);
    JG_OUTPUT_ARRAY(H1_93);
    JG_OUTPUT_ARRAY(H1_94);
    JG_OUTPUT_ARRAY(H1_95);
    JG_OUTPUT_ARRAY(H1_96);
    JG_OUTPUT_ARRAY(H1_97);
    JG_OUTPUT_ARRAY(H1_98);
    JG_OUTPUT_ARRAY(H1_99);
    JG_OUTPUT_ARRAY(H1_100);
    JG_OUTPUT_ARRAY(H1_101);
    JG_OUTPUT_ARRAY(H1_102);
    JG_OUTPUT_ARRAY(H1_103);
    JG_OUTPUT_ARRAY(H1_104);
    JG_OUTPUT_ARRAY(H1_105);
    JG_OUTPUT_ARRAY(H1_106);
    JG_OUTPUT_ARRAY(H1_107);
    JG_OUTPUT_ARRAY(H1_108);
    JG_OUTPUT_ARRAY(H1_109);
    JG_OUTPUT_ARRAY(H1_110);
    JG_OUTPUT_ARRAY(H1_111);
    JG_OUTPUT_ARRAY(H1_112);
    JG_OUTPUT_ARRAY(H1_113);
    JG_OUTPUT_ARRAY(H1_114);
    JG_OUTPUT_ARRAY(H1_115);
    JG_OUTPUT_ARRAY(H1_116);
    JG_OUTPUT_ARRAY(H1_117);
    JG_OUTPUT_ARRAY(H1_118);
    JG_OUTPUT_ARRAY(H1_119);
    JG_OUTPUT_ARRAY(H1_120);
    JG_OUTPUT_ARRAY(H1_121);
    JG_OUTPUT_ARRAY(H1_122);
    JG_OUTPUT_ARRAY(H1_123);
    JG_OUTPUT_ARRAY(H1_124);
    JG_OUTPUT_ARRAY(H1_125);
    JG_OUTPUT_ARRAY(H1_126);
    JG_OUTPUT_ARRAY(H1_127);
    JG_OUTPUT_ARRAY(H1_128);
    JG_OUTPUT_ARRAY(Z1_1);
    JG_OUTPUT_ARRAY(Z1_2);
    JG_OUTPUT_ARRAY(Z1_3);
    JG_OUTPUT_ARRAY(Z1_4);
    JG_OUTPUT_ARRAY(Z1_5);
    JG_OUTPUT_ARRAY(Z1_6);
    JG_OUTPUT_ARRAY(Z1_7);
    JG_OUTPUT_ARRAY(Z1_8);
    JG_OUTPUT_ARRAY(Z1_9);
    JG_OUTPUT_ARRAY(Z1_10);
    JG_OUTPUT_ARRAY(Z1_11);
    JG_OUTPUT_ARRAY(Z1_12);
    JG_OUTPUT_ARRAY(Z1_13);
    JG_OUTPUT_ARRAY(Z1_14);
    JG_OUTPUT_ARRAY(Z1_15);
    JG_OUTPUT_ARRAY(Z1_16);
    JG_OUTPUT_ARRAY(Z1_17);
    JG_OUTPUT_ARRAY(Z1_18);
    JG_OUTPUT_ARRAY(Z1_19);
    JG_OUTPUT_ARRAY(Z1_20);
    JG_OUTPUT_ARRAY(Z1_21);
    JG_OUTPUT_ARRAY(Z1_22);
    JG_OUTPUT_ARRAY(Z1_23);
    JG_OUTPUT_ARRAY(Z1_24);
    JG_OUTPUT_ARRAY(Z1_25);
    JG_OUTPUT_ARRAY(Z1_26);
    JG_OUTPUT_ARRAY(Z1_27);
    JG_OUTPUT_ARRAY(Z1_28);
    JG_OUTPUT_ARRAY(Z1_29);
    JG_OUTPUT_ARRAY(Z1_30);
    JG_OUTPUT_ARRAY(Z1_31);
    JG_OUTPUT_ARRAY(Z1_32);
    JG_OUTPUT_ARRAY(Z1_33);
    JG_OUTPUT_ARRAY(Z1_34);
    JG_OUTPUT_ARRAY(Z1_35);
    JG_OUTPUT_ARRAY(Z1_36);
    JG_OUTPUT_ARRAY(Z1_37);
    JG_OUTPUT_ARRAY(Z1_38);
    JG_OUTPUT_ARRAY(Z1_39);
    JG_OUTPUT_ARRAY(Z1_40);
    JG_OUTPUT_ARRAY(Z1_41);
    JG_OUTPUT_ARRAY(Z1_42);
    JG_OUTPUT_ARRAY(Z1_43);
    JG_OUTPUT_ARRAY(Z1_44);
    JG_OUTPUT_ARRAY(Z1_45);
    JG_OUTPUT_ARRAY(Z1_46);
    JG_OUTPUT_ARRAY(Z1_47);
    JG_OUTPUT_ARRAY(Z1_48);
    JG_OUTPUT_ARRAY(Z1_49);
    JG_OUTPUT_ARRAY(Z1_50);
    JG_OUTPUT_ARRAY(Z1_51);
    JG_OUTPUT_ARRAY(Z1_52);
    JG_OUTPUT_ARRAY(Z1_53);
    JG_OUTPUT_ARRAY(Z1_54);
    JG_OUTPUT_ARRAY(Z1_55);
    JG_OUTPUT_ARRAY(Z1_56);
    JG_OUTPUT_ARRAY(Z1_57);
    JG_OUTPUT_ARRAY(Z1_58);
    JG_OUTPUT_ARRAY(Z1_59);
    JG_OUTPUT_ARRAY(Z1_60);
    JG_OUTPUT_ARRAY(Z1_61);
    JG_OUTPUT_ARRAY(Z1_62);
    JG_OUTPUT_ARRAY(Z1_63);
    JG_OUTPUT_ARRAY(Z1_64);
    JG_OUTPUT_ARRAY(Z1_65);
    JG_OUTPUT_ARRAY(Z1_66);
    JG_OUTPUT_ARRAY(Z1_67);
    JG_OUTPUT_ARRAY(Z1_68);
    JG_OUTPUT_ARRAY(Z1_69);
    JG_OUTPUT_ARRAY(Z1_70);
    JG_OUTPUT_ARRAY(Z1_71);
    JG_OUTPUT_ARRAY(Z1_72);
    JG_OUTPUT_ARRAY(Z1_73);
    JG_OUTPUT_ARRAY(Z1_74);
    JG_OUTPUT_ARRAY(Z1_75);
    JG_OUTPUT_ARRAY(Z1_76);
    JG_OUTPUT_ARRAY(Z1_77);
    JG_OUTPUT_ARRAY(Z1_78);
    JG_OUTPUT_ARRAY(Z1_79);
    JG_OUTPUT_ARRAY(Z1_80);
    JG_OUTPUT_ARRAY(Z1_81);
    JG_OUTPUT_ARRAY(Z1_82);
    JG_OUTPUT_ARRAY(Z1_83);
    JG_OUTPUT_ARRAY(Z1_84);
    JG_OUTPUT_ARRAY(Z1_85);
    JG_OUTPUT_ARRAY(Z1_86);
    JG_OUTPUT_ARRAY(Z1_87);
    JG_OUTPUT_ARRAY(Z1_88);
    JG_OUTPUT_ARRAY(Z1_89);
    JG_OUTPUT_ARRAY(Z1_90);
    JG_OUTPUT_ARRAY(Z1_91);
    JG_OUTPUT_ARRAY(Z1_92);
    JG_OUTPUT_ARRAY(Z1_93);
    JG_OUTPUT_ARRAY(Z1_94);
    JG_OUTPUT_ARRAY(Z1_95);
    JG_OUTPUT_ARRAY(Z1_96);
    JG_OUTPUT_ARRAY(Z1_97);
    JG_OUTPUT_ARRAY(Z1_98);
    JG_OUTPUT_ARRAY(Z1_99);
    JG_OUTPUT_ARRAY(Z1_100);
    JG_OUTPUT_ARRAY(Z1_101);
    JG_OUTPUT_ARRAY(Z1_102);
    JG_OUTPUT_ARRAY(Z1_103);
    JG_OUTPUT_ARRAY(Z1_104);
    JG_OUTPUT_ARRAY(Z1_105);
    JG_OUTPUT_ARRAY(Z1_106);
    JG_OUTPUT_ARRAY(Z1_107);
    JG_OUTPUT_ARRAY(Z1_108);
    JG_OUTPUT_ARRAY(Z1_109);
    JG_OUTPUT_ARRAY(Z1_110);
    JG_OUTPUT_ARRAY(Z1_111);
    JG_OUTPUT_ARRAY(Z1_112);
    JG_OUTPUT_ARRAY(Z1_113);
    JG_OUTPUT_ARRAY(Z1_114);
    JG_OUTPUT_ARRAY(Z1_115);
    JG_OUTPUT_ARRAY(Z1_116);
    JG_OUTPUT_ARRAY(Z1_117);
    JG_OUTPUT_ARRAY(Z1_118);
    JG_OUTPUT_ARRAY(Z1_119);
    JG_OUTPUT_ARRAY(Z1_120);
    JG_OUTPUT_ARRAY(Z1_121);
    JG_OUTPUT_ARRAY(Z1_122);
    JG_OUTPUT_ARRAY(Z1_123);
    JG_OUTPUT_ARRAY(Z1_124);
    JG_OUTPUT_ARRAY(Z1_125);
    JG_OUTPUT_ARRAY(Z1_126);
    JG_OUTPUT_ARRAY(Z1_127);
    JG_OUTPUT_ARRAY(Z1_128);
    JG_OUTPUT_ARRAY(Y);
    JG_OUTPUT_ARRAY(H_0);

}



void vghsh(uint32_t *vs1_0, uint32_t *vs1_1, uint32_t *vs1_2, uint32_t *vs1_3, uint32_t *vs2_0, uint32_t *vs2_1, uint32_t *vs2_2, uint32_t *vs2_3, uint32_t *vd_0, uint32_t *vd_1, uint32_t *vd_2, uint32_t *vd_3, uint32_t *vd_out_0, uint32_t *vd_out_1, uint32_t *vd_out_2, uint32_t *vd_out_3)
{
    // Loading vectors in little endian (following spikes register conventions)
    // EGU32x4_t Y = {swap_uint32(*vd_0), swap_uint32(*vd_1), swap_uint32(*vd_2), swap_uint32(*vd_3)};
    // EGU32x4_t H_0 = {swap_uint32(*vs2_0), swap_uint32(*vs2_1), swap_uint32(*vs2_2), swap_uint32(*vs2_3)};
    // EGU32x4_t X = {swap_uint32(*vs1_0), swap_uint32(*vs1_1), swap_uint32(*vs1_2), swap_uint32(*vs1_3)};

    EGU32x4_t Y = {*vd_0, *vd_1, *vd_2, *vd_3};
    EGU32x4_t H_0 = {*vs2_0, *vs2_1, *vs2_2, *vs2_3};
    EGU32x4_t X = {*vs1_0, *vs1_1, *vs1_2, *vs1_3};
    EGU32x4_t Z_0 = {0, 0, 0, 0};

    EGU32x4_BREV8(H_0);

    EGU32x4_t S;
    EGU32x4_XOR(S, Y, X);
    EGU32x4_BREV8(S);

    EGU32x4_t Z2_1 = Z_0;
    EGU32x4_t H2_1 = H_0;
    if (EGU32x4_ISSET(S, 0)) {
        EGU32x4_XOREQ(Z2_1, H2_1);
    }
    bool reduce_0 = EGU32x4_ISSET(H2_1, 127);
    EGU32x4_LSHIFT(H2_1);
    if (reduce_0) {
        H2_1[0] ^= 0x87;
    }

    EGU32x4_t Z2_2 = Z2_1;
    EGU32x4_t H2_2 = H2_1;
    if (EGU32x4_ISSET(S, 1)) {
        EGU32x4_XOREQ(Z2_2, H2_2);
    }
    bool reduce_1 = EGU32x4_ISSET(H2_2, 127);
    EGU32x4_LSHIFT(H2_2);
    if (reduce_1) {
        H2_2[0] ^= 0x87;
    }

    EGU32x4_t Z2_3 = Z2_2;
    EGU32x4_t H2_3 = H2_2;
    if (EGU32x4_ISSET(S, 2)) {
        EGU32x4_XOREQ(Z2_3, H2_3);
    }
    bool reduce_2 = EGU32x4_ISSET(H2_3, 127);
    EGU32x4_LSHIFT(H2_3);
    if (reduce_2) {
        H2_3[0] ^= 0x87;
    }

    EGU32x4_t Z2_4 = Z2_3;
    EGU32x4_t H2_4 = H2_3;
    if (EGU32x4_ISSET(S, 3)) {
        EGU32x4_XOREQ(Z2_4, H2_4);
    }
    bool reduce_3 = EGU32x4_ISSET(H2_4, 127);
    EGU32x4_LSHIFT(H2_4);
    if (reduce_3) {
        H2_4[0] ^= 0x87;
    }

    EGU32x4_t Z2_5 = Z2_4;
    EGU32x4_t H2_5 = H2_4;
    if (EGU32x4_ISSET(S, 4)) {
        EGU32x4_XOREQ(Z2_5, H2_5);
    }
    bool reduce_4 = EGU32x4_ISSET(H2_5, 127);
    EGU32x4_LSHIFT(H2_5);
    if (reduce_4) {
        H2_5[0] ^= 0x87;
    }

    EGU32x4_t Z2_6 = Z2_5;
    EGU32x4_t H2_6 = H2_5;
    if (EGU32x4_ISSET(S, 5)) {
        EGU32x4_XOREQ(Z2_6, H2_6);
    }
    bool reduce_5 = EGU32x4_ISSET(H2_6, 127);
    EGU32x4_LSHIFT(H2_6);
    if (reduce_5) {
        H2_6[0] ^= 0x87;
    }

    EGU32x4_t Z2_7 = Z2_6;
    EGU32x4_t H2_7 = H2_6;
    if (EGU32x4_ISSET(S, 6)) {
        EGU32x4_XOREQ(Z2_7, H2_7);
    }
    bool reduce_6 = EGU32x4_ISSET(H2_7, 127);
    EGU32x4_LSHIFT(H2_7);
    if (reduce_6) {
        H2_7[0] ^= 0x87;
    }

    EGU32x4_t Z2_8 = Z2_7;
    EGU32x4_t H2_8 = H2_7;
    if (EGU32x4_ISSET(S, 7)) {
        EGU32x4_XOREQ(Z2_8, H2_8);
    }
    bool reduce_7 = EGU32x4_ISSET(H2_8, 127);
    EGU32x4_LSHIFT(H2_8);
    if (reduce_7) {
        H2_8[0] ^= 0x87;
    }

    EGU32x4_t Z2_9 = Z2_8;
    EGU32x4_t H2_9 = H2_8;
    if (EGU32x4_ISSET(S, 8)) {
        EGU32x4_XOREQ(Z2_9, H2_9);
    }
    bool reduce_8 = EGU32x4_ISSET(H2_9, 127);
    EGU32x4_LSHIFT(H2_9);
    if (reduce_8) {
        H2_9[0] ^= 0x87;
    }

    EGU32x4_t Z2_10 = Z2_9;
    EGU32x4_t H2_10 = H2_9;
    if (EGU32x4_ISSET(S, 9)) {
        EGU32x4_XOREQ(Z2_10, H2_10);
    }
    bool reduce_9 = EGU32x4_ISSET(H2_10, 127);
    EGU32x4_LSHIFT(H2_10);
    if (reduce_9) {
        H2_10[0] ^= 0x87;
    }

    EGU32x4_t Z2_11 = Z2_10;
    EGU32x4_t H2_11 = H2_10;
    if (EGU32x4_ISSET(S, 10)) {
        EGU32x4_XOREQ(Z2_11, H2_11);
    }
    bool reduce_10 = EGU32x4_ISSET(H2_11, 127);
    EGU32x4_LSHIFT(H2_11);
    if (reduce_10) {
        H2_11[0] ^= 0x87;
    }

    EGU32x4_t Z2_12 = Z2_11;
    EGU32x4_t H2_12 = H2_11;
    if (EGU32x4_ISSET(S, 11)) {
        EGU32x4_XOREQ(Z2_12, H2_12);
    }
    bool reduce_11 = EGU32x4_ISSET(H2_12, 127);
    EGU32x4_LSHIFT(H2_12);
    if (reduce_11) {
        H2_12[0] ^= 0x87;
    }

    EGU32x4_t Z2_13 = Z2_12;
    EGU32x4_t H2_13 = H2_12;
    if (EGU32x4_ISSET(S, 12)) {
        EGU32x4_XOREQ(Z2_13, H2_13);
    }
    bool reduce_12 = EGU32x4_ISSET(H2_13, 127);
    EGU32x4_LSHIFT(H2_13);
    if (reduce_12) {
        H2_13[0] ^= 0x87;
    }

    EGU32x4_t Z2_14 = Z2_13;
    EGU32x4_t H2_14 = H2_13;
    if (EGU32x4_ISSET(S, 13)) {
        EGU32x4_XOREQ(Z2_14, H2_14);
    }
    bool reduce_13 = EGU32x4_ISSET(H2_14, 127);
    EGU32x4_LSHIFT(H2_14);
    if (reduce_13) {
        H2_14[0] ^= 0x87;
    }

    EGU32x4_t Z2_15 = Z2_14;
    EGU32x4_t H2_15 = H2_14;
    if (EGU32x4_ISSET(S, 14)) {
        EGU32x4_XOREQ(Z2_15, H2_15);
    }
    bool reduce_14 = EGU32x4_ISSET(H2_15, 127);
    EGU32x4_LSHIFT(H2_15);
    if (reduce_14) {
        H2_15[0] ^= 0x87;
    }

    EGU32x4_t Z2_16 = Z2_15;
    EGU32x4_t H2_16 = H2_15;
    if (EGU32x4_ISSET(S, 15)) {
        EGU32x4_XOREQ(Z2_16, H2_16);
    }
    bool reduce_15 = EGU32x4_ISSET(H2_16, 127);
    EGU32x4_LSHIFT(H2_16);
    if (reduce_15) {
        H2_16[0] ^= 0x87;
    }

    EGU32x4_t Z2_17 = Z2_16;
    EGU32x4_t H2_17 = H2_16;
    if (EGU32x4_ISSET(S, 16)) {
        EGU32x4_XOREQ(Z2_17, H2_17);
    }
    bool reduce_16 = EGU32x4_ISSET(H2_17, 127);
    EGU32x4_LSHIFT(H2_17);
    if (reduce_16) {
        H2_17[0] ^= 0x87;
    }

    EGU32x4_t Z2_18 = Z2_17;
    EGU32x4_t H2_18 = H2_17;
    if (EGU32x4_ISSET(S, 17)) {
        EGU32x4_XOREQ(Z2_18, H2_18);
    }
    bool reduce_17 = EGU32x4_ISSET(H2_18, 127);
    EGU32x4_LSHIFT(H2_18);
    if (reduce_17) {
        H2_18[0] ^= 0x87;
    }

    EGU32x4_t Z2_19 = Z2_18;
    EGU32x4_t H2_19 = H2_18;
    if (EGU32x4_ISSET(S, 18)) {
        EGU32x4_XOREQ(Z2_19, H2_19);
    }
    bool reduce_18 = EGU32x4_ISSET(H2_19, 127);
    EGU32x4_LSHIFT(H2_19);
    if (reduce_18) {
        H2_19[0] ^= 0x87;
    }

    EGU32x4_t Z2_20 = Z2_19;
    EGU32x4_t H2_20 = H2_19;
    if (EGU32x4_ISSET(S, 19)) {
        EGU32x4_XOREQ(Z2_20, H2_20);
    }
    bool reduce_19 = EGU32x4_ISSET(H2_20, 127);
    EGU32x4_LSHIFT(H2_20);
    if (reduce_19) {
        H2_20[0] ^= 0x87;
    }

    EGU32x4_t Z2_21 = Z2_20;
    EGU32x4_t H2_21 = H2_20;
    if (EGU32x4_ISSET(S, 20)) {
        EGU32x4_XOREQ(Z2_21, H2_21);
    }
    bool reduce_20 = EGU32x4_ISSET(H2_21, 127);
    EGU32x4_LSHIFT(H2_21);
    if (reduce_20) {
        H2_21[0] ^= 0x87;
    }

    EGU32x4_t Z2_22 = Z2_21;
    EGU32x4_t H2_22 = H2_21;
    if (EGU32x4_ISSET(S, 21)) {
        EGU32x4_XOREQ(Z2_22, H2_22);
    }
    bool reduce_21 = EGU32x4_ISSET(H2_22, 127);
    EGU32x4_LSHIFT(H2_22);
    if (reduce_21) {
        H2_22[0] ^= 0x87;
    }

    EGU32x4_t Z2_23 = Z2_22;
    EGU32x4_t H2_23 = H2_22;
    if (EGU32x4_ISSET(S, 22)) {
        EGU32x4_XOREQ(Z2_23, H2_23);
    }
    bool reduce_22 = EGU32x4_ISSET(H2_23, 127);
    EGU32x4_LSHIFT(H2_23);
    if (reduce_22) {
        H2_23[0] ^= 0x87;
    }

    EGU32x4_t Z2_24 = Z2_23;
    EGU32x4_t H2_24 = H2_23;
    if (EGU32x4_ISSET(S, 23)) {
        EGU32x4_XOREQ(Z2_24, H2_24);
    }
    bool reduce_23 = EGU32x4_ISSET(H2_24, 127);
    EGU32x4_LSHIFT(H2_24);
    if (reduce_23) {
        H2_24[0] ^= 0x87;
    }

    EGU32x4_t Z2_25 = Z2_24;
    EGU32x4_t H2_25 = H2_24;
    if (EGU32x4_ISSET(S, 24)) {
        EGU32x4_XOREQ(Z2_25, H2_25);
    }
    bool reduce_24 = EGU32x4_ISSET(H2_25, 127);
    EGU32x4_LSHIFT(H2_25);
    if (reduce_24) {
        H2_25[0] ^= 0x87;
    }

    EGU32x4_t Z2_26 = Z2_25;
    EGU32x4_t H2_26 = H2_25;
    if (EGU32x4_ISSET(S, 25)) {
        EGU32x4_XOREQ(Z2_26, H2_26);
    }
    bool reduce_25 = EGU32x4_ISSET(H2_26, 127);
    EGU32x4_LSHIFT(H2_26);
    if (reduce_25) {
        H2_26[0] ^= 0x87;
    }

    EGU32x4_t Z2_27 = Z2_26;
    EGU32x4_t H2_27 = H2_26;
    if (EGU32x4_ISSET(S, 26)) {
        EGU32x4_XOREQ(Z2_27, H2_27);
    }
    bool reduce_26 = EGU32x4_ISSET(H2_27, 127);
    EGU32x4_LSHIFT(H2_27);
    if (reduce_26) {
        H2_27[0] ^= 0x87;
    }

    EGU32x4_t Z2_28 = Z2_27;
    EGU32x4_t H2_28 = H2_27;
    if (EGU32x4_ISSET(S, 27)) {
        EGU32x4_XOREQ(Z2_28, H2_28);
    }
    bool reduce_27 = EGU32x4_ISSET(H2_28, 127);
    EGU32x4_LSHIFT(H2_28);
    if (reduce_27) {
        H2_28[0] ^= 0x87;
    }

    EGU32x4_t Z2_29 = Z2_28;
    EGU32x4_t H2_29 = H2_28;
    if (EGU32x4_ISSET(S, 28)) {
        EGU32x4_XOREQ(Z2_29, H2_29);
    }
    bool reduce_28 = EGU32x4_ISSET(H2_29, 127);
    EGU32x4_LSHIFT(H2_29);
    if (reduce_28) {
        H2_29[0] ^= 0x87;
    }

    EGU32x4_t Z2_30 = Z2_29;
    EGU32x4_t H2_30 = H2_29;
    if (EGU32x4_ISSET(S, 29)) {
        EGU32x4_XOREQ(Z2_30, H2_30);
    }
    bool reduce_29 = EGU32x4_ISSET(H2_30, 127);
    EGU32x4_LSHIFT(H2_30);
    if (reduce_29) {
        H2_30[0] ^= 0x87;
    }

    EGU32x4_t Z2_31 = Z2_30;
    EGU32x4_t H2_31 = H2_30;
    if (EGU32x4_ISSET(S, 30)) {
        EGU32x4_XOREQ(Z2_31, H2_31);
    }
    bool reduce_30 = EGU32x4_ISSET(H2_31, 127);
    EGU32x4_LSHIFT(H2_31);
    if (reduce_30) {
        H2_31[0] ^= 0x87;
    }

    EGU32x4_t Z2_32 = Z2_31;
    EGU32x4_t H2_32 = H2_31;
    if (EGU32x4_ISSET(S, 31)) {
        EGU32x4_XOREQ(Z2_32, H2_32);
    }
    bool reduce_31 = EGU32x4_ISSET(H2_32, 127);
    EGU32x4_LSHIFT(H2_32);
    if (reduce_31) {
        H2_32[0] ^= 0x87;
    }

    EGU32x4_t Z2_33 = Z2_32;
    EGU32x4_t H2_33 = H2_32;
    if (EGU32x4_ISSET(S, 32)) {
        EGU32x4_XOREQ(Z2_33, H2_33);
    }
    bool reduce_32 = EGU32x4_ISSET(H2_33, 127);
    EGU32x4_LSHIFT(H2_33);
    if (reduce_32) {
        H2_33[0] ^= 0x87;
    }

    EGU32x4_t Z2_34 = Z2_33;
    EGU32x4_t H2_34 = H2_33;
    if (EGU32x4_ISSET(S, 33)) {
        EGU32x4_XOREQ(Z2_34, H2_34);
    }
    bool reduce_33 = EGU32x4_ISSET(H2_34, 127);
    EGU32x4_LSHIFT(H2_34);
    if (reduce_33) {
        H2_34[0] ^= 0x87;
    }

    EGU32x4_t Z2_35 = Z2_34;
    EGU32x4_t H2_35 = H2_34;
    if (EGU32x4_ISSET(S, 34)) {
        EGU32x4_XOREQ(Z2_35, H2_35);
    }
    bool reduce_34 = EGU32x4_ISSET(H2_35, 127);
    EGU32x4_LSHIFT(H2_35);
    if (reduce_34) {
        H2_35[0] ^= 0x87;
    }

    EGU32x4_t Z2_36 = Z2_35;
    EGU32x4_t H2_36 = H2_35;
    if (EGU32x4_ISSET(S, 35)) {
        EGU32x4_XOREQ(Z2_36, H2_36);
    }
    bool reduce_35 = EGU32x4_ISSET(H2_36, 127);
    EGU32x4_LSHIFT(H2_36);
    if (reduce_35) {
        H2_36[0] ^= 0x87;
    }

    EGU32x4_t Z2_37 = Z2_36;
    EGU32x4_t H2_37 = H2_36;
    if (EGU32x4_ISSET(S, 36)) {
        EGU32x4_XOREQ(Z2_37, H2_37);
    }
    bool reduce_36 = EGU32x4_ISSET(H2_37, 127);
    EGU32x4_LSHIFT(H2_37);
    if (reduce_36) {
        H2_37[0] ^= 0x87;
    }

    EGU32x4_t Z2_38 = Z2_37;
    EGU32x4_t H2_38 = H2_37;
    if (EGU32x4_ISSET(S, 37)) {
        EGU32x4_XOREQ(Z2_38, H2_38);
    }
    bool reduce_37 = EGU32x4_ISSET(H2_38, 127);
    EGU32x4_LSHIFT(H2_38);
    if (reduce_37) {
        H2_38[0] ^= 0x87;
    }

    EGU32x4_t Z2_39 = Z2_38;
    EGU32x4_t H2_39 = H2_38;
    if (EGU32x4_ISSET(S, 38)) {
        EGU32x4_XOREQ(Z2_39, H2_39);
    }
    bool reduce_38 = EGU32x4_ISSET(H2_39, 127);
    EGU32x4_LSHIFT(H2_39);
    if (reduce_38) {
        H2_39[0] ^= 0x87;
    }

    EGU32x4_t Z2_40 = Z2_39;
    EGU32x4_t H2_40 = H2_39;
    if (EGU32x4_ISSET(S, 39)) {
        EGU32x4_XOREQ(Z2_40, H2_40);
    }
    bool reduce_39 = EGU32x4_ISSET(H2_40, 127);
    EGU32x4_LSHIFT(H2_40);
    if (reduce_39) {
        H2_40[0] ^= 0x87;
    }

    EGU32x4_t Z2_41 = Z2_40;
    EGU32x4_t H2_41 = H2_40;
    if (EGU32x4_ISSET(S, 40)) {
        EGU32x4_XOREQ(Z2_41, H2_41);
    }
    bool reduce_40 = EGU32x4_ISSET(H2_41, 127);
    EGU32x4_LSHIFT(H2_41);
    if (reduce_40) {
        H2_41[0] ^= 0x87;
    }

    EGU32x4_t Z2_42 = Z2_41;
    EGU32x4_t H2_42 = H2_41;
    if (EGU32x4_ISSET(S, 41)) {
        EGU32x4_XOREQ(Z2_42, H2_42);
    }
    bool reduce_41 = EGU32x4_ISSET(H2_42, 127);
    EGU32x4_LSHIFT(H2_42);
    if (reduce_41) {
        H2_42[0] ^= 0x87;
    }

    EGU32x4_t Z2_43 = Z2_42;
    EGU32x4_t H2_43 = H2_42;
    if (EGU32x4_ISSET(S, 42)) {
        EGU32x4_XOREQ(Z2_43, H2_43);
    }
    bool reduce_42 = EGU32x4_ISSET(H2_43, 127);
    EGU32x4_LSHIFT(H2_43);
    if (reduce_42) {
        H2_43[0] ^= 0x87;
    }

    EGU32x4_t Z2_44 = Z2_43;
    EGU32x4_t H2_44 = H2_43;
    if (EGU32x4_ISSET(S, 43)) {
        EGU32x4_XOREQ(Z2_44, H2_44);
    }
    bool reduce_43 = EGU32x4_ISSET(H2_44, 127);
    EGU32x4_LSHIFT(H2_44);
    if (reduce_43) {
        H2_44[0] ^= 0x87;
    }

    EGU32x4_t Z2_45 = Z2_44;
    EGU32x4_t H2_45 = H2_44;
    if (EGU32x4_ISSET(S, 44)) {
        EGU32x4_XOREQ(Z2_45, H2_45);
    }
    bool reduce_44 = EGU32x4_ISSET(H2_45, 127);
    EGU32x4_LSHIFT(H2_45);
    if (reduce_44) {
        H2_45[0] ^= 0x87;
    }

    EGU32x4_t Z2_46 = Z2_45;
    EGU32x4_t H2_46 = H2_45;
    if (EGU32x4_ISSET(S, 45)) {
        EGU32x4_XOREQ(Z2_46, H2_46);
    }
    bool reduce_45 = EGU32x4_ISSET(H2_46, 127);
    EGU32x4_LSHIFT(H2_46);
    if (reduce_45) {
        H2_46[0] ^= 0x87;
    }

    EGU32x4_t Z2_47 = Z2_46;
    EGU32x4_t H2_47 = H2_46;
    if (EGU32x4_ISSET(S, 46)) {
        EGU32x4_XOREQ(Z2_47, H2_47);
    }
    bool reduce_46 = EGU32x4_ISSET(H2_47, 127);
    EGU32x4_LSHIFT(H2_47);
    if (reduce_46) {
        H2_47[0] ^= 0x87;
    }

    EGU32x4_t Z2_48 = Z2_47;
    EGU32x4_t H2_48 = H2_47;
    if (EGU32x4_ISSET(S, 47)) {
        EGU32x4_XOREQ(Z2_48, H2_48);
    }
    bool reduce_47 = EGU32x4_ISSET(H2_48, 127);
    EGU32x4_LSHIFT(H2_48);
    if (reduce_47) {
        H2_48[0] ^= 0x87;
    }

    EGU32x4_t Z2_49 = Z2_48;
    EGU32x4_t H2_49 = H2_48;
    if (EGU32x4_ISSET(S, 48)) {
        EGU32x4_XOREQ(Z2_49, H2_49);
    }
    bool reduce_48 = EGU32x4_ISSET(H2_49, 127);
    EGU32x4_LSHIFT(H2_49);
    if (reduce_48) {
        H2_49[0] ^= 0x87;
    }

    EGU32x4_t Z2_50 = Z2_49;
    EGU32x4_t H2_50 = H2_49;
    if (EGU32x4_ISSET(S, 49)) {
        EGU32x4_XOREQ(Z2_50, H2_50);
    }
    bool reduce_49 = EGU32x4_ISSET(H2_50, 127);
    EGU32x4_LSHIFT(H2_50);
    if (reduce_49) {
        H2_50[0] ^= 0x87;
    }

    EGU32x4_t Z2_51 = Z2_50;
    EGU32x4_t H2_51 = H2_50;
    if (EGU32x4_ISSET(S, 50)) {
        EGU32x4_XOREQ(Z2_51, H2_51);
    }
    bool reduce_50 = EGU32x4_ISSET(H2_51, 127);
    EGU32x4_LSHIFT(H2_51);
    if (reduce_50) {
        H2_51[0] ^= 0x87;
    }

    EGU32x4_t Z2_52 = Z2_51;
    EGU32x4_t H2_52 = H2_51;
    if (EGU32x4_ISSET(S, 51)) {
        EGU32x4_XOREQ(Z2_52, H2_52);
    }
    bool reduce_51 = EGU32x4_ISSET(H2_52, 127);
    EGU32x4_LSHIFT(H2_52);
    if (reduce_51) {
        H2_52[0] ^= 0x87;
    }

    EGU32x4_t Z2_53 = Z2_52;
    EGU32x4_t H2_53 = H2_52;
    if (EGU32x4_ISSET(S, 52)) {
        EGU32x4_XOREQ(Z2_53, H2_53);
    }
    bool reduce_52 = EGU32x4_ISSET(H2_53, 127);
    EGU32x4_LSHIFT(H2_53);
    if (reduce_52) {
        H2_53[0] ^= 0x87;
    }

    EGU32x4_t Z2_54 = Z2_53;
    EGU32x4_t H2_54 = H2_53;
    if (EGU32x4_ISSET(S, 53)) {
        EGU32x4_XOREQ(Z2_54, H2_54);
    }
    bool reduce_53 = EGU32x4_ISSET(H2_54, 127);
    EGU32x4_LSHIFT(H2_54);
    if (reduce_53) {
        H2_54[0] ^= 0x87;
    }

    EGU32x4_t Z2_55 = Z2_54;
    EGU32x4_t H2_55 = H2_54;
    if (EGU32x4_ISSET(S, 54)) {
        EGU32x4_XOREQ(Z2_55, H2_55);
    }
    bool reduce_54 = EGU32x4_ISSET(H2_55, 127);
    EGU32x4_LSHIFT(H2_55);
    if (reduce_54) {
        H2_55[0] ^= 0x87;
    }

    EGU32x4_t Z2_56 = Z2_55;
    EGU32x4_t H2_56 = H2_55;
    if (EGU32x4_ISSET(S, 55)) {
        EGU32x4_XOREQ(Z2_56, H2_56);
    }
    bool reduce_55 = EGU32x4_ISSET(H2_56, 127);
    EGU32x4_LSHIFT(H2_56);
    if (reduce_55) {
        H2_56[0] ^= 0x87;
    }

    EGU32x4_t Z2_57 = Z2_56;
    EGU32x4_t H2_57 = H2_56;
    if (EGU32x4_ISSET(S, 56)) {
        EGU32x4_XOREQ(Z2_57, H2_57);
    }
    bool reduce_56 = EGU32x4_ISSET(H2_57, 127);
    EGU32x4_LSHIFT(H2_57);
    if (reduce_56) {
        H2_57[0] ^= 0x87;
    }

    EGU32x4_t Z2_58 = Z2_57;
    EGU32x4_t H2_58 = H2_57;
    if (EGU32x4_ISSET(S, 57)) {
        EGU32x4_XOREQ(Z2_58, H2_58);
    }
    bool reduce_57 = EGU32x4_ISSET(H2_58, 127);
    EGU32x4_LSHIFT(H2_58);
    if (reduce_57) {
        H2_58[0] ^= 0x87;
    }

    EGU32x4_t Z2_59 = Z2_58;
    EGU32x4_t H2_59 = H2_58;
    if (EGU32x4_ISSET(S, 58)) {
        EGU32x4_XOREQ(Z2_59, H2_59);
    }
    bool reduce_58 = EGU32x4_ISSET(H2_59, 127);
    EGU32x4_LSHIFT(H2_59);
    if (reduce_58) {
        H2_59[0] ^= 0x87;
    }

    EGU32x4_t Z2_60 = Z2_59;
    EGU32x4_t H2_60 = H2_59;
    if (EGU32x4_ISSET(S, 59)) {
        EGU32x4_XOREQ(Z2_60, H2_60);
    }
    bool reduce_59 = EGU32x4_ISSET(H2_60, 127);
    EGU32x4_LSHIFT(H2_60);
    if (reduce_59) {
        H2_60[0] ^= 0x87;
    }

    EGU32x4_t Z2_61 = Z2_60;
    EGU32x4_t H2_61 = H2_60;
    if (EGU32x4_ISSET(S, 60)) {
        EGU32x4_XOREQ(Z2_61, H2_61);
    }
    bool reduce_60 = EGU32x4_ISSET(H2_61, 127);
    EGU32x4_LSHIFT(H2_61);
    if (reduce_60) {
        H2_61[0] ^= 0x87;
    }

    EGU32x4_t Z2_62 = Z2_61;
    EGU32x4_t H2_62 = H2_61;
    if (EGU32x4_ISSET(S, 61)) {
        EGU32x4_XOREQ(Z2_62, H2_62);
    }
    bool reduce_61 = EGU32x4_ISSET(H2_62, 127);
    EGU32x4_LSHIFT(H2_62);
    if (reduce_61) {
        H2_62[0] ^= 0x87;
    }

    EGU32x4_t Z2_63 = Z2_62;
    EGU32x4_t H2_63 = H2_62;
    if (EGU32x4_ISSET(S, 62)) {
        EGU32x4_XOREQ(Z2_63, H2_63);
    }
    bool reduce_62 = EGU32x4_ISSET(H2_63, 127);
    EGU32x4_LSHIFT(H2_63);
    if (reduce_62) {
        H2_63[0] ^= 0x87;
    }

    EGU32x4_t Z2_64 = Z2_63;
    EGU32x4_t H2_64 = H2_63;
    if (EGU32x4_ISSET(S, 63)) {
        EGU32x4_XOREQ(Z2_64, H2_64);
    }
    bool reduce_63 = EGU32x4_ISSET(H2_64, 127);
    EGU32x4_LSHIFT(H2_64);
    if (reduce_63) {
        H2_64[0] ^= 0x87;
    }

    EGU32x4_t Z2_65 = Z2_64;
    EGU32x4_t H2_65 = H2_64;
    if (EGU32x4_ISSET(S, 64)) {
        EGU32x4_XOREQ(Z2_65, H2_65);
    }
    bool reduce_64 = EGU32x4_ISSET(H2_65, 127);
    EGU32x4_LSHIFT(H2_65);
    if (reduce_64) {
        H2_65[0] ^= 0x87;
    }

    EGU32x4_t Z2_66 = Z2_65;
    EGU32x4_t H2_66 = H2_65;
    if (EGU32x4_ISSET(S, 65)) {
        EGU32x4_XOREQ(Z2_66, H2_66);
    }
    bool reduce_65 = EGU32x4_ISSET(H2_66, 127);
    EGU32x4_LSHIFT(H2_66);
    if (reduce_65) {
        H2_66[0] ^= 0x87;
    }

    EGU32x4_t Z2_67 = Z2_66;
    EGU32x4_t H2_67 = H2_66;
    if (EGU32x4_ISSET(S, 66)) {
        EGU32x4_XOREQ(Z2_67, H2_67);
    }
    bool reduce_66 = EGU32x4_ISSET(H2_67, 127);
    EGU32x4_LSHIFT(H2_67);
    if (reduce_66) {
        H2_67[0] ^= 0x87;
    }

    EGU32x4_t Z2_68 = Z2_67;
    EGU32x4_t H2_68 = H2_67;
    if (EGU32x4_ISSET(S, 67)) {
        EGU32x4_XOREQ(Z2_68, H2_68);
    }
    bool reduce_67 = EGU32x4_ISSET(H2_68, 127);
    EGU32x4_LSHIFT(H2_68);
    if (reduce_67) {
        H2_68[0] ^= 0x87;
    }

    EGU32x4_t Z2_69 = Z2_68;
    EGU32x4_t H2_69 = H2_68;
    if (EGU32x4_ISSET(S, 68)) {
        EGU32x4_XOREQ(Z2_69, H2_69);
    }
    bool reduce_68 = EGU32x4_ISSET(H2_69, 127);
    EGU32x4_LSHIFT(H2_69);
    if (reduce_68) {
        H2_69[0] ^= 0x87;
    }

    EGU32x4_t Z2_70 = Z2_69;
    EGU32x4_t H2_70 = H2_69;
    if (EGU32x4_ISSET(S, 69)) {
        EGU32x4_XOREQ(Z2_70, H2_70);
    }
    bool reduce_69 = EGU32x4_ISSET(H2_70, 127);
    EGU32x4_LSHIFT(H2_70);
    if (reduce_69) {
        H2_70[0] ^= 0x87;
    }

    EGU32x4_t Z2_71 = Z2_70;
    EGU32x4_t H2_71 = H2_70;
    if (EGU32x4_ISSET(S, 70)) {
        EGU32x4_XOREQ(Z2_71, H2_71);
    }
    bool reduce_70 = EGU32x4_ISSET(H2_71, 127);
    EGU32x4_LSHIFT(H2_71);
    if (reduce_70) {
        H2_71[0] ^= 0x87;
    }

    EGU32x4_t Z2_72 = Z2_71;
    EGU32x4_t H2_72 = H2_71;
    if (EGU32x4_ISSET(S, 71)) {
        EGU32x4_XOREQ(Z2_72, H2_72);
    }
    bool reduce_71 = EGU32x4_ISSET(H2_72, 127);
    EGU32x4_LSHIFT(H2_72);
    if (reduce_71) {
        H2_72[0] ^= 0x87;
    }

    EGU32x4_t Z2_73 = Z2_72;
    EGU32x4_t H2_73 = H2_72;
    if (EGU32x4_ISSET(S, 72)) {
        EGU32x4_XOREQ(Z2_73, H2_73);
    }
    bool reduce_72 = EGU32x4_ISSET(H2_73, 127);
    EGU32x4_LSHIFT(H2_73);
    if (reduce_72) {
        H2_73[0] ^= 0x87;
    }

    EGU32x4_t Z2_74 = Z2_73;
    EGU32x4_t H2_74 = H2_73;
    if (EGU32x4_ISSET(S, 73)) {
        EGU32x4_XOREQ(Z2_74, H2_74);
    }
    bool reduce_73 = EGU32x4_ISSET(H2_74, 127);
    EGU32x4_LSHIFT(H2_74);
    if (reduce_73) {
        H2_74[0] ^= 0x87;
    }

    EGU32x4_t Z2_75 = Z2_74;
    EGU32x4_t H2_75 = H2_74;
    if (EGU32x4_ISSET(S, 74)) {
        EGU32x4_XOREQ(Z2_75, H2_75);
    }
    bool reduce_74 = EGU32x4_ISSET(H2_75, 127);
    EGU32x4_LSHIFT(H2_75);
    if (reduce_74) {
        H2_75[0] ^= 0x87;
    }

    EGU32x4_t Z2_76 = Z2_75;
    EGU32x4_t H2_76 = H2_75;
    if (EGU32x4_ISSET(S, 75)) {
        EGU32x4_XOREQ(Z2_76, H2_76);
    }
    bool reduce_75 = EGU32x4_ISSET(H2_76, 127);
    EGU32x4_LSHIFT(H2_76);
    if (reduce_75) {
        H2_76[0] ^= 0x87;
    }

    EGU32x4_t Z2_77 = Z2_76;
    EGU32x4_t H2_77 = H2_76;
    if (EGU32x4_ISSET(S, 76)) {
        EGU32x4_XOREQ(Z2_77, H2_77);
    }
    bool reduce_76 = EGU32x4_ISSET(H2_77, 127);
    EGU32x4_LSHIFT(H2_77);
    if (reduce_76) {
        H2_77[0] ^= 0x87;
    }

    EGU32x4_t Z2_78 = Z2_77;
    EGU32x4_t H2_78 = H2_77;
    if (EGU32x4_ISSET(S, 77)) {
        EGU32x4_XOREQ(Z2_78, H2_78);
    }
    bool reduce_77 = EGU32x4_ISSET(H2_78, 127);
    EGU32x4_LSHIFT(H2_78);
    if (reduce_77) {
        H2_78[0] ^= 0x87;
    }

    EGU32x4_t Z2_79 = Z2_78;
    EGU32x4_t H2_79 = H2_78;
    if (EGU32x4_ISSET(S, 78)) {
        EGU32x4_XOREQ(Z2_79, H2_79);
    }
    bool reduce_78 = EGU32x4_ISSET(H2_79, 127);
    EGU32x4_LSHIFT(H2_79);
    if (reduce_78) {
        H2_79[0] ^= 0x87;
    }

    EGU32x4_t Z2_80 = Z2_79;
    EGU32x4_t H2_80 = H2_79;
    if (EGU32x4_ISSET(S, 79)) {
        EGU32x4_XOREQ(Z2_80, H2_80);
    }
    bool reduce_79 = EGU32x4_ISSET(H2_80, 127);
    EGU32x4_LSHIFT(H2_80);
    if (reduce_79) {
        H2_80[0] ^= 0x87;
    }

    EGU32x4_t Z2_81 = Z2_80;
    EGU32x4_t H2_81 = H2_80;
    if (EGU32x4_ISSET(S, 80)) {
        EGU32x4_XOREQ(Z2_81, H2_81);
    }
    bool reduce_80 = EGU32x4_ISSET(H2_81, 127);
    EGU32x4_LSHIFT(H2_81);
    if (reduce_80) {
        H2_81[0] ^= 0x87;
    }

    EGU32x4_t Z2_82 = Z2_81;
    EGU32x4_t H2_82 = H2_81;
    if (EGU32x4_ISSET(S, 81)) {
        EGU32x4_XOREQ(Z2_82, H2_82);
    }
    bool reduce_81 = EGU32x4_ISSET(H2_82, 127);
    EGU32x4_LSHIFT(H2_82);
    if (reduce_81) {
        H2_82[0] ^= 0x87;
    }

    EGU32x4_t Z2_83 = Z2_82;
    EGU32x4_t H2_83 = H2_82;
    if (EGU32x4_ISSET(S, 82)) {
        EGU32x4_XOREQ(Z2_83, H2_83);
    }
    bool reduce_82 = EGU32x4_ISSET(H2_83, 127);
    EGU32x4_LSHIFT(H2_83);
    if (reduce_82) {
        H2_83[0] ^= 0x87;
    }

    EGU32x4_t Z2_84 = Z2_83;
    EGU32x4_t H2_84 = H2_83;
    if (EGU32x4_ISSET(S, 83)) {
        EGU32x4_XOREQ(Z2_84, H2_84);
    }
    bool reduce_83 = EGU32x4_ISSET(H2_84, 127);
    EGU32x4_LSHIFT(H2_84);
    if (reduce_83) {
        H2_84[0] ^= 0x87;
    }

    EGU32x4_t Z2_85 = Z2_84;
    EGU32x4_t H2_85 = H2_84;
    if (EGU32x4_ISSET(S, 84)) {
        EGU32x4_XOREQ(Z2_85, H2_85);
    }
    bool reduce_84 = EGU32x4_ISSET(H2_85, 127);
    EGU32x4_LSHIFT(H2_85);
    if (reduce_84) {
        H2_85[0] ^= 0x87;
    }

    EGU32x4_t Z2_86 = Z2_85;
    EGU32x4_t H2_86 = H2_85;
    if (EGU32x4_ISSET(S, 85)) {
        EGU32x4_XOREQ(Z2_86, H2_86);
    }
    bool reduce_85 = EGU32x4_ISSET(H2_86, 127);
    EGU32x4_LSHIFT(H2_86);
    if (reduce_85) {
        H2_86[0] ^= 0x87;
    }

    EGU32x4_t Z2_87 = Z2_86;
    EGU32x4_t H2_87 = H2_86;
    if (EGU32x4_ISSET(S, 86)) {
        EGU32x4_XOREQ(Z2_87, H2_87);
    }
    bool reduce_86 = EGU32x4_ISSET(H2_87, 127);
    EGU32x4_LSHIFT(H2_87);
    if (reduce_86) {
        H2_87[0] ^= 0x87;
    }

    EGU32x4_t Z2_88 = Z2_87;
    EGU32x4_t H2_88 = H2_87;
    if (EGU32x4_ISSET(S, 87)) {
        EGU32x4_XOREQ(Z2_88, H2_88);
    }
    bool reduce_87 = EGU32x4_ISSET(H2_88, 127);
    EGU32x4_LSHIFT(H2_88);
    if (reduce_87) {
        H2_88[0] ^= 0x87;
    }

    EGU32x4_t Z2_89 = Z2_88;
    EGU32x4_t H2_89 = H2_88;
    if (EGU32x4_ISSET(S, 88)) {
        EGU32x4_XOREQ(Z2_89, H2_89);
    }
    bool reduce_88 = EGU32x4_ISSET(H2_89, 127);
    EGU32x4_LSHIFT(H2_89);
    if (reduce_88) {
        H2_89[0] ^= 0x87;
    }

    EGU32x4_t Z2_90 = Z2_89;
    EGU32x4_t H2_90 = H2_89;
    if (EGU32x4_ISSET(S, 89)) {
        EGU32x4_XOREQ(Z2_90, H2_90);
    }
    bool reduce_89 = EGU32x4_ISSET(H2_90, 127);
    EGU32x4_LSHIFT(H2_90);
    if (reduce_89) {
        H2_90[0] ^= 0x87;
    }

    EGU32x4_t Z2_91 = Z2_90;
    EGU32x4_t H2_91 = H2_90;
    if (EGU32x4_ISSET(S, 90)) {
        EGU32x4_XOREQ(Z2_91, H2_91);
    }
    bool reduce_90 = EGU32x4_ISSET(H2_91, 127);
    EGU32x4_LSHIFT(H2_91);
    if (reduce_90) {
        H2_91[0] ^= 0x87;
    }

    EGU32x4_t Z2_92 = Z2_91;
    EGU32x4_t H2_92 = H2_91;
    if (EGU32x4_ISSET(S, 91)) {
        EGU32x4_XOREQ(Z2_92, H2_92);
    }
    bool reduce_91 = EGU32x4_ISSET(H2_92, 127);
    EGU32x4_LSHIFT(H2_92);
    if (reduce_91) {
        H2_92[0] ^= 0x87;
    }

    EGU32x4_t Z2_93 = Z2_92;
    EGU32x4_t H2_93 = H2_92;
    if (EGU32x4_ISSET(S, 92)) {
        EGU32x4_XOREQ(Z2_93, H2_93);
    }
    bool reduce_92 = EGU32x4_ISSET(H2_93, 127);
    EGU32x4_LSHIFT(H2_93);
    if (reduce_92) {
        H2_93[0] ^= 0x87;
    }

    EGU32x4_t Z2_94 = Z2_93;
    EGU32x4_t H2_94 = H2_93;
    if (EGU32x4_ISSET(S, 93)) {
        EGU32x4_XOREQ(Z2_94, H2_94);
    }
    bool reduce_93 = EGU32x4_ISSET(H2_94, 127);
    EGU32x4_LSHIFT(H2_94);
    if (reduce_93) {
        H2_94[0] ^= 0x87;
    }

    EGU32x4_t Z2_95 = Z2_94;
    EGU32x4_t H2_95 = H2_94;
    if (EGU32x4_ISSET(S, 94)) {
        EGU32x4_XOREQ(Z2_95, H2_95);
    }
    bool reduce_94 = EGU32x4_ISSET(H2_95, 127);
    EGU32x4_LSHIFT(H2_95);
    if (reduce_94) {
        H2_95[0] ^= 0x87;
    }

    EGU32x4_t Z2_96 = Z2_95;
    EGU32x4_t H2_96 = H2_95;
    if (EGU32x4_ISSET(S, 95)) {
        EGU32x4_XOREQ(Z2_96, H2_96);
    }
    bool reduce_95 = EGU32x4_ISSET(H2_96, 127);
    EGU32x4_LSHIFT(H2_96);
    if (reduce_95) {
        H2_96[0] ^= 0x87;
    }

    EGU32x4_t Z2_97 = Z2_96;
    EGU32x4_t H2_97 = H2_96;
    if (EGU32x4_ISSET(S, 96)) {
        EGU32x4_XOREQ(Z2_97, H2_97);
    }
    bool reduce_96 = EGU32x4_ISSET(H2_97, 127);
    EGU32x4_LSHIFT(H2_97);
    if (reduce_96) {
        H2_97[0] ^= 0x87;
    }

    EGU32x4_t Z2_98 = Z2_97;
    EGU32x4_t H2_98 = H2_97;
    if (EGU32x4_ISSET(S, 97)) {
        EGU32x4_XOREQ(Z2_98, H2_98);
    }
    bool reduce_97 = EGU32x4_ISSET(H2_98, 127);
    EGU32x4_LSHIFT(H2_98);
    if (reduce_97) {
        H2_98[0] ^= 0x87;
    }

    EGU32x4_t Z2_99 = Z2_98;
    EGU32x4_t H2_99 = H2_98;
    if (EGU32x4_ISSET(S, 98)) {
        EGU32x4_XOREQ(Z2_99, H2_99);
    }
    bool reduce_98 = EGU32x4_ISSET(H2_99, 127);
    EGU32x4_LSHIFT(H2_99);
    if (reduce_98) {
        H2_99[0] ^= 0x87;
    }

    EGU32x4_t Z2_100 = Z2_99;
    EGU32x4_t H2_100 = H2_99;
    if (EGU32x4_ISSET(S, 99)) {
        EGU32x4_XOREQ(Z2_100, H2_100);
    }
    bool reduce_99 = EGU32x4_ISSET(H2_100, 127);
    EGU32x4_LSHIFT(H2_100);
    if (reduce_99) {
        H2_100[0] ^= 0x87;
    }

    EGU32x4_t Z2_101 = Z2_100;
    EGU32x4_t H2_101 = H2_100;
    if (EGU32x4_ISSET(S, 100)) {
        EGU32x4_XOREQ(Z2_101, H2_101);
    }
    bool reduce_100 = EGU32x4_ISSET(H2_101, 127);
    EGU32x4_LSHIFT(H2_101);
    if (reduce_100) {
        H2_101[0] ^= 0x87;
    }

    EGU32x4_t Z2_102 = Z2_101;
    EGU32x4_t H2_102 = H2_101;
    if (EGU32x4_ISSET(S, 101)) {
        EGU32x4_XOREQ(Z2_102, H2_102);
    }
    bool reduce_101 = EGU32x4_ISSET(H2_102, 127);
    EGU32x4_LSHIFT(H2_102);
    if (reduce_101) {
        H2_102[0] ^= 0x87;
    }

    EGU32x4_t Z2_103 = Z2_102;
    EGU32x4_t H2_103 = H2_102;
    if (EGU32x4_ISSET(S, 102)) {
        EGU32x4_XOREQ(Z2_103, H2_103);
    }
    bool reduce_102 = EGU32x4_ISSET(H2_103, 127);
    EGU32x4_LSHIFT(H2_103);
    if (reduce_102) {
        H2_103[0] ^= 0x87;
    }

    EGU32x4_t Z2_104 = Z2_103;
    EGU32x4_t H2_104 = H2_103;
    if (EGU32x4_ISSET(S, 103)) {
        EGU32x4_XOREQ(Z2_104, H2_104);
    }
    bool reduce_103 = EGU32x4_ISSET(H2_104, 127);
    EGU32x4_LSHIFT(H2_104);
    if (reduce_103) {
        H2_104[0] ^= 0x87;
    }

    EGU32x4_t Z2_105 = Z2_104;
    EGU32x4_t H2_105 = H2_104;
    if (EGU32x4_ISSET(S, 104)) {
        EGU32x4_XOREQ(Z2_105, H2_105);
    }
    bool reduce_104 = EGU32x4_ISSET(H2_105, 127);
    EGU32x4_LSHIFT(H2_105);
    if (reduce_104) {
        H2_105[0] ^= 0x87;
    }

    EGU32x4_t Z2_106 = Z2_105;
    EGU32x4_t H2_106 = H2_105;
    if (EGU32x4_ISSET(S, 105)) {
        EGU32x4_XOREQ(Z2_106, H2_106);
    }
    bool reduce_105 = EGU32x4_ISSET(H2_106, 127);
    EGU32x4_LSHIFT(H2_106);
    if (reduce_105) {
        H2_106[0] ^= 0x87;
    }

    EGU32x4_t Z2_107 = Z2_106;
    EGU32x4_t H2_107 = H2_106;
    if (EGU32x4_ISSET(S, 106)) {
        EGU32x4_XOREQ(Z2_107, H2_107);
    }
    bool reduce_106 = EGU32x4_ISSET(H2_107, 127);
    EGU32x4_LSHIFT(H2_107);
    if (reduce_106) {
        H2_107[0] ^= 0x87;
    }

    EGU32x4_t Z2_108 = Z2_107;
    EGU32x4_t H2_108 = H2_107;
    if (EGU32x4_ISSET(S, 107)) {
        EGU32x4_XOREQ(Z2_108, H2_108);
    }
    bool reduce_107 = EGU32x4_ISSET(H2_108, 127);
    EGU32x4_LSHIFT(H2_108);
    if (reduce_107) {
        H2_108[0] ^= 0x87;
    }

    EGU32x4_t Z2_109 = Z2_108;
    EGU32x4_t H2_109 = H2_108;
    if (EGU32x4_ISSET(S, 108)) {
        EGU32x4_XOREQ(Z2_109, H2_109);
    }
    bool reduce_108 = EGU32x4_ISSET(H2_109, 127);
    EGU32x4_LSHIFT(H2_109);
    if (reduce_108) {
        H2_109[0] ^= 0x87;
    }

    EGU32x4_t Z2_110 = Z2_109;
    EGU32x4_t H2_110 = H2_109;
    if (EGU32x4_ISSET(S, 109)) {
        EGU32x4_XOREQ(Z2_110, H2_110);
    }
    bool reduce_109 = EGU32x4_ISSET(H2_110, 127);
    EGU32x4_LSHIFT(H2_110);
    if (reduce_109) {
        H2_110[0] ^= 0x87;
    }

    EGU32x4_t Z2_111 = Z2_110;
    EGU32x4_t H2_111 = H2_110;
    if (EGU32x4_ISSET(S, 110)) {
        EGU32x4_XOREQ(Z2_111, H2_111);
    }
    bool reduce_110 = EGU32x4_ISSET(H2_111, 127);
    EGU32x4_LSHIFT(H2_111);
    if (reduce_110) {
        H2_111[0] ^= 0x87;
    }

    EGU32x4_t Z2_112 = Z2_111;
    EGU32x4_t H2_112 = H2_111;
    if (EGU32x4_ISSET(S, 111)) {
        EGU32x4_XOREQ(Z2_112, H2_112);
    }
    bool reduce_111 = EGU32x4_ISSET(H2_112, 127);
    EGU32x4_LSHIFT(H2_112);
    if (reduce_111) {
        H2_112[0] ^= 0x87;
    }

    EGU32x4_t Z2_113 = Z2_112;
    EGU32x4_t H2_113 = H2_112;
    if (EGU32x4_ISSET(S, 112)) {
        EGU32x4_XOREQ(Z2_113, H2_113);
    }
    bool reduce_112 = EGU32x4_ISSET(H2_113, 127);
    EGU32x4_LSHIFT(H2_113);
    if (reduce_112) {
        H2_113[0] ^= 0x87;
    }

    EGU32x4_t Z2_114 = Z2_113;
    EGU32x4_t H2_114 = H2_113;
    if (EGU32x4_ISSET(S, 113)) {
        EGU32x4_XOREQ(Z2_114, H2_114);
    }
    bool reduce_113 = EGU32x4_ISSET(H2_114, 127);
    EGU32x4_LSHIFT(H2_114);
    if (reduce_113) {
        H2_114[0] ^= 0x87;
    }

    EGU32x4_t Z2_115 = Z2_114;
    EGU32x4_t H2_115 = H2_114;
    if (EGU32x4_ISSET(S, 114)) {
        EGU32x4_XOREQ(Z2_115, H2_115);
    }
    bool reduce_114 = EGU32x4_ISSET(H2_115, 127);
    EGU32x4_LSHIFT(H2_115);
    if (reduce_114) {
        H2_115[0] ^= 0x87;
    }

    EGU32x4_t Z2_116 = Z2_115;
    EGU32x4_t H2_116 = H2_115;
    if (EGU32x4_ISSET(S, 115)) {
        EGU32x4_XOREQ(Z2_116, H2_116);
    }
    bool reduce_115 = EGU32x4_ISSET(H2_116, 127);
    EGU32x4_LSHIFT(H2_116);
    if (reduce_115) {
        H2_116[0] ^= 0x87;
    }

    EGU32x4_t Z2_117 = Z2_116;
    EGU32x4_t H2_117 = H2_116;
    if (EGU32x4_ISSET(S, 116)) {
        EGU32x4_XOREQ(Z2_117, H2_117);
    }
    bool reduce_116 = EGU32x4_ISSET(H2_117, 127);
    EGU32x4_LSHIFT(H2_117);
    if (reduce_116) {
        H2_117[0] ^= 0x87;
    }

    EGU32x4_t Z2_118 = Z2_117;
    EGU32x4_t H2_118 = H2_117;
    if (EGU32x4_ISSET(S, 117)) {
        EGU32x4_XOREQ(Z2_118, H2_118);
    }
    bool reduce_117 = EGU32x4_ISSET(H2_118, 127);
    EGU32x4_LSHIFT(H2_118);
    if (reduce_117) {
        H2_118[0] ^= 0x87;
    }

    EGU32x4_t Z2_119 = Z2_118;
    EGU32x4_t H2_119 = H2_118;
    if (EGU32x4_ISSET(S, 118)) {
        EGU32x4_XOREQ(Z2_119, H2_119);
    }
    bool reduce_118 = EGU32x4_ISSET(H2_119, 127);
    EGU32x4_LSHIFT(H2_119);
    if (reduce_118) {
        H2_119[0] ^= 0x87;
    }

    EGU32x4_t Z2_120 = Z2_119;
    EGU32x4_t H2_120 = H2_119;
    if (EGU32x4_ISSET(S, 119)) {
        EGU32x4_XOREQ(Z2_120, H2_120);
    }
    bool reduce_119 = EGU32x4_ISSET(H2_120, 127);
    EGU32x4_LSHIFT(H2_120);
    if (reduce_119) {
        H2_120[0] ^= 0x87;
    }

    EGU32x4_t Z2_121 = Z2_120;
    EGU32x4_t H2_121 = H2_120;
    if (EGU32x4_ISSET(S, 120)) {
        EGU32x4_XOREQ(Z2_121, H2_121);
    }
    bool reduce_120 = EGU32x4_ISSET(H2_121, 127);
    EGU32x4_LSHIFT(H2_121);
    if (reduce_120) {
        H2_121[0] ^= 0x87;
    }

    EGU32x4_t Z2_122 = Z2_121;
    EGU32x4_t H2_122 = H2_121;
    if (EGU32x4_ISSET(S, 121)) {
        EGU32x4_XOREQ(Z2_122, H2_122);
    }
    bool reduce_121 = EGU32x4_ISSET(H2_122, 127);
    EGU32x4_LSHIFT(H2_122);
    if (reduce_121) {
        H2_122[0] ^= 0x87;
    }

    EGU32x4_t Z2_123 = Z2_122;
    EGU32x4_t H2_123 = H2_122;
    if (EGU32x4_ISSET(S, 122)) {
        EGU32x4_XOREQ(Z2_123, H2_123);
    }
    bool reduce_122 = EGU32x4_ISSET(H2_123, 127);
    EGU32x4_LSHIFT(H2_123);
    if (reduce_122) {
        H2_123[0] ^= 0x87;
    }

    EGU32x4_t Z2_124 = Z2_123;
    EGU32x4_t H2_124 = H2_123;
    if (EGU32x4_ISSET(S, 123)) {
        EGU32x4_XOREQ(Z2_124, H2_124);
    }
    bool reduce_123 = EGU32x4_ISSET(H2_124, 127);
    EGU32x4_LSHIFT(H2_124);
    if (reduce_123) {
        H2_124[0] ^= 0x87;
    }

    EGU32x4_t Z2_125 = Z2_124;
    EGU32x4_t H2_125 = H2_124;
    if (EGU32x4_ISSET(S, 124)) {
        EGU32x4_XOREQ(Z2_125, H2_125);
    }
    bool reduce_124 = EGU32x4_ISSET(H2_125, 127);
    EGU32x4_LSHIFT(H2_125);
    if (reduce_124) {
        H2_125[0] ^= 0x87;
    }

    EGU32x4_t Z2_126 = Z2_125;
    EGU32x4_t H2_126 = H2_125;
    if (EGU32x4_ISSET(S, 125)) {
        EGU32x4_XOREQ(Z2_126, H2_126);
    }
    bool reduce_125 = EGU32x4_ISSET(H2_126, 127);
    EGU32x4_LSHIFT(H2_126);
    if (reduce_125) {
        H2_126[0] ^= 0x87;
    }

    EGU32x4_t Z2_127 = Z2_126;
    EGU32x4_t H2_127 = H2_126;
    if (EGU32x4_ISSET(S, 126)) {
        EGU32x4_XOREQ(Z2_127, H2_127);
    }
    bool reduce_126 = EGU32x4_ISSET(H2_127, 127);
    EGU32x4_LSHIFT(H2_127);
    if (reduce_126) {
        H2_127[0] ^= 0x87;
    }

    EGU32x4_t Z2_128 = Z2_127;
    EGU32x4_t H2_128 = H2_127;
    if (EGU32x4_ISSET(S, 127)) {
        EGU32x4_XOREQ(Z2_128, H2_128);
    }
    bool reduce_127 = EGU32x4_ISSET(H2_128, 127);
    EGU32x4_LSHIFT(H2_128);
    if (reduce_127) {
        H2_128[0] ^= 0x87;
    }

    EGU32x4_t Z_final = Z2_128;
    EGU32x4_BREV8(Z_final);
    *vd_out_3 = Z_final[3];
    *vd_out_2 = Z_final[2];
    *vd_out_1 = Z_final[1];
    *vd_out_0 = Z_final[0];

    JG_OUTPUT_ARRAY(H2_1);
    JG_OUTPUT_ARRAY(H2_2);
    JG_OUTPUT_ARRAY(H2_3);
    JG_OUTPUT_ARRAY(H2_4);
    JG_OUTPUT_ARRAY(H2_5);
    JG_OUTPUT_ARRAY(H2_6);
    JG_OUTPUT_ARRAY(H2_7);
    JG_OUTPUT_ARRAY(H2_8);
    JG_OUTPUT_ARRAY(H2_9);
    JG_OUTPUT_ARRAY(H2_10);
    JG_OUTPUT_ARRAY(H2_11);
    JG_OUTPUT_ARRAY(H2_12);
    JG_OUTPUT_ARRAY(H2_13);
    JG_OUTPUT_ARRAY(H2_14);
    JG_OUTPUT_ARRAY(H2_15);
    JG_OUTPUT_ARRAY(H2_16);
    JG_OUTPUT_ARRAY(H2_17);
    JG_OUTPUT_ARRAY(H2_18);
    JG_OUTPUT_ARRAY(H2_19);
    JG_OUTPUT_ARRAY(H2_20);
    JG_OUTPUT_ARRAY(H2_21);
    JG_OUTPUT_ARRAY(H2_22);
    JG_OUTPUT_ARRAY(H2_23);
    JG_OUTPUT_ARRAY(H2_24);
    JG_OUTPUT_ARRAY(H2_25);
    JG_OUTPUT_ARRAY(H2_26);
    JG_OUTPUT_ARRAY(H2_27);
    JG_OUTPUT_ARRAY(H2_28);
    JG_OUTPUT_ARRAY(H2_29);
    JG_OUTPUT_ARRAY(H2_30);
    JG_OUTPUT_ARRAY(H2_31);
    JG_OUTPUT_ARRAY(H2_32);
    JG_OUTPUT_ARRAY(H2_33);
    JG_OUTPUT_ARRAY(H2_34);
    JG_OUTPUT_ARRAY(H2_35);
    JG_OUTPUT_ARRAY(H2_36);
    JG_OUTPUT_ARRAY(H2_37);
    JG_OUTPUT_ARRAY(H2_38);
    JG_OUTPUT_ARRAY(H2_39);
    JG_OUTPUT_ARRAY(H2_40);
    JG_OUTPUT_ARRAY(H2_41);
    JG_OUTPUT_ARRAY(H2_42);
    JG_OUTPUT_ARRAY(H2_43);
    JG_OUTPUT_ARRAY(H2_44);
    JG_OUTPUT_ARRAY(H2_45);
    JG_OUTPUT_ARRAY(H2_46);
    JG_OUTPUT_ARRAY(H2_47);
    JG_OUTPUT_ARRAY(H2_48);
    JG_OUTPUT_ARRAY(H2_49);
    JG_OUTPUT_ARRAY(H2_50);
    JG_OUTPUT_ARRAY(H2_51);
    JG_OUTPUT_ARRAY(H2_52);
    JG_OUTPUT_ARRAY(H2_53);
    JG_OUTPUT_ARRAY(H2_54);
    JG_OUTPUT_ARRAY(H2_55);
    JG_OUTPUT_ARRAY(H2_56);
    JG_OUTPUT_ARRAY(H2_57);
    JG_OUTPUT_ARRAY(H2_58);
    JG_OUTPUT_ARRAY(H2_59);
    JG_OUTPUT_ARRAY(H2_60);
    JG_OUTPUT_ARRAY(H2_61);
    JG_OUTPUT_ARRAY(H2_62);
    JG_OUTPUT_ARRAY(H2_63);
    JG_OUTPUT_ARRAY(H2_64);
    JG_OUTPUT_ARRAY(H2_65);
    JG_OUTPUT_ARRAY(H2_66);
    JG_OUTPUT_ARRAY(H2_67);
    JG_OUTPUT_ARRAY(H2_68);
    JG_OUTPUT_ARRAY(H2_69);
    JG_OUTPUT_ARRAY(H2_70);
    JG_OUTPUT_ARRAY(H2_71);
    JG_OUTPUT_ARRAY(H2_72);
    JG_OUTPUT_ARRAY(H2_73);
    JG_OUTPUT_ARRAY(H2_74);
    JG_OUTPUT_ARRAY(H2_75);
    JG_OUTPUT_ARRAY(H2_76);
    JG_OUTPUT_ARRAY(H2_77);
    JG_OUTPUT_ARRAY(H2_78);
    JG_OUTPUT_ARRAY(H2_79);
    JG_OUTPUT_ARRAY(H2_80);
    JG_OUTPUT_ARRAY(H2_81);
    JG_OUTPUT_ARRAY(H2_82);
    JG_OUTPUT_ARRAY(H2_83);
    JG_OUTPUT_ARRAY(H2_84);
    JG_OUTPUT_ARRAY(H2_85);
    JG_OUTPUT_ARRAY(H2_86);
    JG_OUTPUT_ARRAY(H2_87);
    JG_OUTPUT_ARRAY(H2_88);
    JG_OUTPUT_ARRAY(H2_89);
    JG_OUTPUT_ARRAY(H2_90);
    JG_OUTPUT_ARRAY(H2_91);
    JG_OUTPUT_ARRAY(H2_92);
    JG_OUTPUT_ARRAY(H2_93);
    JG_OUTPUT_ARRAY(H2_94);
    JG_OUTPUT_ARRAY(H2_95);
    JG_OUTPUT_ARRAY(H2_96);
    JG_OUTPUT_ARRAY(H2_97);
    JG_OUTPUT_ARRAY(H2_98);
    JG_OUTPUT_ARRAY(H2_99);
    JG_OUTPUT_ARRAY(H2_100);
    JG_OUTPUT_ARRAY(H2_101);
    JG_OUTPUT_ARRAY(H2_102);
    JG_OUTPUT_ARRAY(H2_103);
    JG_OUTPUT_ARRAY(H2_104);
    JG_OUTPUT_ARRAY(H2_105);
    JG_OUTPUT_ARRAY(H2_106);
    JG_OUTPUT_ARRAY(H2_107);
    JG_OUTPUT_ARRAY(H2_108);
    JG_OUTPUT_ARRAY(H2_109);
    JG_OUTPUT_ARRAY(H2_110);
    JG_OUTPUT_ARRAY(H2_111);
    JG_OUTPUT_ARRAY(H2_112);
    JG_OUTPUT_ARRAY(H2_113);
    JG_OUTPUT_ARRAY(H2_114);
    JG_OUTPUT_ARRAY(H2_115);
    JG_OUTPUT_ARRAY(H2_116);
    JG_OUTPUT_ARRAY(H2_117);
    JG_OUTPUT_ARRAY(H2_118);
    JG_OUTPUT_ARRAY(H2_119);
    JG_OUTPUT_ARRAY(H2_120);
    JG_OUTPUT_ARRAY(H2_121);
    JG_OUTPUT_ARRAY(H2_122);
    JG_OUTPUT_ARRAY(H2_123);
    JG_OUTPUT_ARRAY(H2_124);
    JG_OUTPUT_ARRAY(H2_125);
    JG_OUTPUT_ARRAY(H2_126);
    JG_OUTPUT_ARRAY(H2_127);
    JG_OUTPUT_ARRAY(H2_128);
    JG_OUTPUT_ARRAY(Z2_1);
    JG_OUTPUT_ARRAY(Z2_2);
    JG_OUTPUT_ARRAY(Z2_3);
    JG_OUTPUT_ARRAY(Z2_4);
    JG_OUTPUT_ARRAY(Z2_5);
    JG_OUTPUT_ARRAY(Z2_6);
    JG_OUTPUT_ARRAY(Z2_7);
    JG_OUTPUT_ARRAY(Z2_8);
    JG_OUTPUT_ARRAY(Z2_9);
    JG_OUTPUT_ARRAY(Z2_10);
    JG_OUTPUT_ARRAY(Z2_11);
    JG_OUTPUT_ARRAY(Z2_12);
    JG_OUTPUT_ARRAY(Z2_13);
    JG_OUTPUT_ARRAY(Z2_14);
    JG_OUTPUT_ARRAY(Z2_15);
    JG_OUTPUT_ARRAY(Z2_16);
    JG_OUTPUT_ARRAY(Z2_17);
    JG_OUTPUT_ARRAY(Z2_18);
    JG_OUTPUT_ARRAY(Z2_19);
    JG_OUTPUT_ARRAY(Z2_20);
    JG_OUTPUT_ARRAY(Z2_21);
    JG_OUTPUT_ARRAY(Z2_22);
    JG_OUTPUT_ARRAY(Z2_23);
    JG_OUTPUT_ARRAY(Z2_24);
    JG_OUTPUT_ARRAY(Z2_25);
    JG_OUTPUT_ARRAY(Z2_26);
    JG_OUTPUT_ARRAY(Z2_27);
    JG_OUTPUT_ARRAY(Z2_28);
    JG_OUTPUT_ARRAY(Z2_29);
    JG_OUTPUT_ARRAY(Z2_30);
    JG_OUTPUT_ARRAY(Z2_31);
    JG_OUTPUT_ARRAY(Z2_32);
    JG_OUTPUT_ARRAY(Z2_33);
    JG_OUTPUT_ARRAY(Z2_34);
    JG_OUTPUT_ARRAY(Z2_35);
    JG_OUTPUT_ARRAY(Z2_36);
    JG_OUTPUT_ARRAY(Z2_37);
    JG_OUTPUT_ARRAY(Z2_38);
    JG_OUTPUT_ARRAY(Z2_39);
    JG_OUTPUT_ARRAY(Z2_40);
    JG_OUTPUT_ARRAY(Z2_41);
    JG_OUTPUT_ARRAY(Z2_42);
    JG_OUTPUT_ARRAY(Z2_43);
    JG_OUTPUT_ARRAY(Z2_44);
    JG_OUTPUT_ARRAY(Z2_45);
    JG_OUTPUT_ARRAY(Z2_46);
    JG_OUTPUT_ARRAY(Z2_47);
    JG_OUTPUT_ARRAY(Z2_48);
    JG_OUTPUT_ARRAY(Z2_49);
    JG_OUTPUT_ARRAY(Z2_50);
    JG_OUTPUT_ARRAY(Z2_51);
    JG_OUTPUT_ARRAY(Z2_52);
    JG_OUTPUT_ARRAY(Z2_53);
    JG_OUTPUT_ARRAY(Z2_54);
    JG_OUTPUT_ARRAY(Z2_55);
    JG_OUTPUT_ARRAY(Z2_56);
    JG_OUTPUT_ARRAY(Z2_57);
    JG_OUTPUT_ARRAY(Z2_58);
    JG_OUTPUT_ARRAY(Z2_59);
    JG_OUTPUT_ARRAY(Z2_60);
    JG_OUTPUT_ARRAY(Z2_61);
    JG_OUTPUT_ARRAY(Z2_62);
    JG_OUTPUT_ARRAY(Z2_63);
    JG_OUTPUT_ARRAY(Z2_64);
    JG_OUTPUT_ARRAY(Z2_65);
    JG_OUTPUT_ARRAY(Z2_66);
    JG_OUTPUT_ARRAY(Z2_67);
    JG_OUTPUT_ARRAY(Z2_68);
    JG_OUTPUT_ARRAY(Z2_69);
    JG_OUTPUT_ARRAY(Z2_70);
    JG_OUTPUT_ARRAY(Z2_71);
    JG_OUTPUT_ARRAY(Z2_72);
    JG_OUTPUT_ARRAY(Z2_73);
    JG_OUTPUT_ARRAY(Z2_74);
    JG_OUTPUT_ARRAY(Z2_75);
    JG_OUTPUT_ARRAY(Z2_76);
    JG_OUTPUT_ARRAY(Z2_77);
    JG_OUTPUT_ARRAY(Z2_78);
    JG_OUTPUT_ARRAY(Z2_79);
    JG_OUTPUT_ARRAY(Z2_80);
    JG_OUTPUT_ARRAY(Z2_81);
    JG_OUTPUT_ARRAY(Z2_82);
    JG_OUTPUT_ARRAY(Z2_83);
    JG_OUTPUT_ARRAY(Z2_84);
    JG_OUTPUT_ARRAY(Z2_85);
    JG_OUTPUT_ARRAY(Z2_86);
    JG_OUTPUT_ARRAY(Z2_87);
    JG_OUTPUT_ARRAY(Z2_88);
    JG_OUTPUT_ARRAY(Z2_89);
    JG_OUTPUT_ARRAY(Z2_90);
    JG_OUTPUT_ARRAY(Z2_91);
    JG_OUTPUT_ARRAY(Z2_92);
    JG_OUTPUT_ARRAY(Z2_93);
    JG_OUTPUT_ARRAY(Z2_94);
    JG_OUTPUT_ARRAY(Z2_95);
    JG_OUTPUT_ARRAY(Z2_96);
    JG_OUTPUT_ARRAY(Z2_97);
    JG_OUTPUT_ARRAY(Z2_98);
    JG_OUTPUT_ARRAY(Z2_99);
    JG_OUTPUT_ARRAY(Z2_100);
    JG_OUTPUT_ARRAY(Z2_101);
    JG_OUTPUT_ARRAY(Z2_102);
    JG_OUTPUT_ARRAY(Z2_103);
    JG_OUTPUT_ARRAY(Z2_104);
    JG_OUTPUT_ARRAY(Z2_105);
    JG_OUTPUT_ARRAY(Z2_106);
    JG_OUTPUT_ARRAY(Z2_107);
    JG_OUTPUT_ARRAY(Z2_108);
    JG_OUTPUT_ARRAY(Z2_109);
    JG_OUTPUT_ARRAY(Z2_110);
    JG_OUTPUT_ARRAY(Z2_111);
    JG_OUTPUT_ARRAY(Z2_112);
    JG_OUTPUT_ARRAY(Z2_113);
    JG_OUTPUT_ARRAY(Z2_114);
    JG_OUTPUT_ARRAY(Z2_115);
    JG_OUTPUT_ARRAY(Z2_116);
    JG_OUTPUT_ARRAY(Z2_117);
    JG_OUTPUT_ARRAY(Z2_118);
    JG_OUTPUT_ARRAY(Z2_119);
    JG_OUTPUT_ARRAY(Z2_120);
    JG_OUTPUT_ARRAY(Z2_121);
    JG_OUTPUT_ARRAY(Z2_122);
    JG_OUTPUT_ARRAY(Z2_123);
    JG_OUTPUT_ARRAY(Z2_124);
    JG_OUTPUT_ARRAY(Z2_125);
    JG_OUTPUT_ARRAY(Z2_126);
    JG_OUTPUT_ARRAY(Z2_127);
    JG_OUTPUT_ARRAY(Z2_128);


}

int main() {
    uint32_t vs1_0, vs1_1, vs1_2, vs1_3, vs1_4, vs1_5, vs1_6, vs1_7;
    uint32_t vs2_0, vs2_1, vs2_2, vs2_3, vs2_4, vs2_5, vs2_6, vs2_7;
    uint32_t vd_0, vd_1, vd_2, vd_3, vd_4, vd_5, vd_6, vd_7;
    uint32_t vd_out_0, vd_out_1, vd_out_2, vd_out_3, vd_out_4, vd_out_5, vd_out_6, vd_out_7;
    uint8_t imm;

    uint8_t operation;

    JG_INPUT(vs1_0);
    JG_INPUT(vs1_1);
    JG_INPUT(vs1_2);
    JG_INPUT(vs1_3);
    JG_INPUT(vs1_4);
    JG_INPUT(vs1_5);
    JG_INPUT(vs1_6);
    JG_INPUT(vs1_7);

    JG_INPUT(vs2_0);
    JG_INPUT(vs2_1);
    JG_INPUT(vs2_2);
    JG_INPUT(vs2_3);
    JG_INPUT(vs2_4);
    JG_INPUT(vs2_5);
    JG_INPUT(vs2_6);
    JG_INPUT(vs2_7);

    JG_INPUT(vd_0);
    JG_INPUT(vd_1);
    JG_INPUT(vd_2);
    JG_INPUT(vd_3);
    JG_INPUT(vd_4);
    JG_INPUT(vd_5);
    JG_INPUT(vd_6);
    JG_INPUT(vd_7);

    JG_INPUT(imm);

    JG_INPUT(operation);
    

    switch (operation) { 
        case VGMUL:
            vgmul(&vs2_0, &vs2_1, &vs2_2, &vs2_3, &vd_0, &vd_1, &vd_2, &vd_3, &vd_out_0, &vd_out_1, &vd_out_2, &vd_out_3);
            vd_out_4 = 0;
            vd_out_5 = 0;
            vd_out_6 = 0;
            vd_out_7 = 0;
            break;

        case VGHSH:
            vghsh(&vs1_0, &vs1_1, &vs1_2, &vs1_3, &vs2_0, &vs2_1, &vs2_2, &vs2_3, &vd_0, &vd_1, &vd_2, &vd_3, &vd_out_0, &vd_out_1, &vd_out_2, &vd_out_3);
            vd_out_4 = 0;
            vd_out_5 = 0;
            vd_out_6 = 0;
            vd_out_7 = 0;
            break;
        

        default:
            vd_out_0 = 0;
            vd_out_1 = 0;
            vd_out_2 = 0;
            vd_out_3 = 0;
            vd_out_4 = 0;
            vd_out_5 = 0;
            vd_out_6 = 0;
            vd_out_7 = 0;
            
    }

    JG_OUTPUT(vd_out_0);
    JG_OUTPUT(vd_out_1);
    JG_OUTPUT(vd_out_2);
    JG_OUTPUT(vd_out_3);
    JG_OUTPUT(vd_out_4);
    JG_OUTPUT(vd_out_5);
    JG_OUTPUT(vd_out_6);
    JG_OUTPUT(vd_out_7);
    
}
