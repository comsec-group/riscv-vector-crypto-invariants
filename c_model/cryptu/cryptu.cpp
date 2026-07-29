#include <stdio.h>
#include <cstdint>
#include "jasperc.h"

#include "custom_zvknha.h"
#include "custom_zvknhb.h"
#include "custom_zvksh_ext_macros.h"
#include "custom_zvksed_ext_macros.h"
#include "custom_zvkned_ext_macros.h"
#include "custom_zvkg_ext_macros.h"



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

  enum vsew_e {
    EW8,
    EW16,
    EW32,
    EW64,
    EW128,
    EW256,
    EW512,
    EW1024
  };

int main() {
    uint32_t vs1_0, vs1_1, vs1_2, vs1_3, vs1_4, vs1_5, vs1_6, vs1_7;
    uint32_t vs2_0, vs2_1, vs2_2, vs2_3, vs2_4, vs2_5, vs2_6, vs2_7;
    uint32_t vd_0, vd_1, vd_2, vd_3, vd_4, vd_5, vd_6, vd_7;
    uint32_t vd_out_0, vd_out_1, vd_out_2, vd_out_3, vd_out_4, vd_out_5, vd_out_6, vd_out_7;
    uint32_t t_out_h, t_out_g, t_out_f, t_out_e, t_out_d, t_out_c, t_out_b, t_out_a;
    uint8_t imm, vsew;
    uint8_t a, b, c;

    uint8_t operation;

    //The following comments declare which variables should be exported as inputs (and at the end of the file, outputs)
    // for the formal verification equivalence checking.

    //INPUT(vs1_0);
    //INPUT(vs1_1);
    //INPUT(vs1_2);
    //INPUT(vs1_3);
    //INPUT(vs1_4);
    //INPUT(vs1_5);
    //INPUT(vs1_6);
    //INPUT(vs1_7);

    //INPUT(vs2_0);
    //INPUT(vs2_1);
    //INPUT(vs2_2);
    //INPUT(vs2_3);
    //INPUT(vs2_4);
    //INPUT(vs2_5);
    //INPUT(vs2_6);
    //INPUT(vs2_7);

    //INPUT(vd_0);
    //INPUT(vd_1);
    //INPUT(vd_2);
    //INPUT(vd_3);
    //INPUT(vd_4);
    //INPUT(vd_5);
    //INPUT(vd_6);
    //INPUT(vd_7);

    //INPUT(imm);
    //INPUT(vsew);

    //INPUT(operation);
    
    
    //large values for vsha512
    uint64_t vs1_0_64 = ((uint64_t) vs1_1 << 32) | vs1_0;
    uint64_t vs1_1_64 = ((uint64_t) vs1_3 << 32) | vs1_2;
    uint64_t vs1_2_64 = ((uint64_t) vs1_5 << 32) | vs1_4;
    uint64_t vs1_3_64 = ((uint64_t) vs1_7 << 32) | vs1_6;
    uint64_t vs2_0_64 = ((uint64_t) vs2_1 << 32) | vs2_0;
    uint64_t vs2_1_64 = ((uint64_t) vs2_3 << 32) | vs2_2;
    uint64_t vs2_2_64 = ((uint64_t) vs2_5 << 32) | vs2_4;
    uint64_t vs2_3_64 = ((uint64_t) vs2_7 << 32) | vs2_6;
    uint64_t vd_0_64 = ((uint64_t) vd_1 << 32) | vd_0;
    uint64_t vd_1_64 = ((uint64_t) vd_3 << 32) | vd_2;
    uint64_t vd_2_64 = ((uint64_t) vd_5 << 32) | vd_4;
    uint64_t vd_3_64 = ((uint64_t) vd_7 << 32) | vd_6;
    uint64_t vd_out_0_64, vd_out_1_64, vd_out_2_64, vd_out_3_64;
    vsew = (0b111 & vsew); // ensures vsew is 3 bits, as it is in the Hardware.
    a = 0;
    b = 0;
    c = 0;

    switch (operation) { 
        case VSHA2MS:
            switch (vsew) {
                case EW32:
                    vd_out_0 = ZVK_SHA256_SCHEDULE(vs1_2, vs2_1, vd_1, vd_0);
                    vd_out_1 = ZVK_SHA256_SCHEDULE(vs1_3, vs2_2, vd_2, vd_1);
                    vd_out_2 = ZVK_SHA256_SCHEDULE(vd_out_0, vs2_3, vd_3, vd_2);
                    vd_out_3 = ZVK_SHA256_SCHEDULE(vd_out_1, vs1_0, vs2_0, vd_3);
                    vd_out_4 = 0;
                    vd_out_5 = 0;
                    vd_out_6 = 0;
                    vd_out_7 = 0;
                    break;
                case EW64:
                    vd_out_0_64 = ZVK_SHA512_SCHEDULE(vs1_2_64, vs2_1_64, vd_1_64, vd_0_64);
                    vd_out_1_64 = ZVK_SHA512_SCHEDULE(vs1_3_64, vs2_2_64, vd_2_64, vd_1_64);
                    vd_out_2_64 = ZVK_SHA512_SCHEDULE(vd_out_0_64, vs2_3_64, vd_3_64, vd_2_64);
                    vd_out_3_64 = ZVK_SHA512_SCHEDULE(vd_out_1_64, vs1_0_64, vs2_0_64, vd_3_64);

                    vd_out_0 = (uint32_t) (vd_out_0_64);
                    vd_out_1 = (uint32_t) (vd_out_0_64 >> 32);
                    vd_out_2 = (uint32_t) (vd_out_1_64);
                    vd_out_3 = (uint32_t) (vd_out_1_64 >> 32);
                    vd_out_4 = (uint32_t) (vd_out_2_64);
                    vd_out_5 = (uint32_t) (vd_out_2_64 >> 32);
                    vd_out_6 = (uint32_t) (vd_out_3_64);
                    vd_out_7 = (uint32_t) (vd_out_3_64 >> 32);
                    break;
            }
            break;

        case VSHA2CH:

            if (vsew == EW32){
                ZVK_SHA256_COMPRESS(vs2_3, vs2_2, vd_3, vd_2, vs2_1, vs2_0, vd_1, vd_0, vs1_2);
                
                t_out_a = vs2_3;
                t_out_b = vs2_2;
                t_out_c = vd_3;
                t_out_d = vd_2;
                t_out_e = vs2_1;
                t_out_f = vs2_0;
                t_out_g = vd_1;
                t_out_h = vd_0;
                
                ZVK_SHA256_COMPRESS(vs2_3, vs2_2, vd_3, vd_2, vs2_1, vs2_0, vd_1, vd_0, vs1_3);

                vd_out_0 = vs2_0;
                vd_out_1 = vs2_1;
                vd_out_2 = vs2_2;
                vd_out_3 = vs2_3;
                vd_out_4 = 0;
                vd_out_5 = 0;
                vd_out_6 = 0;
                vd_out_7 = 0;
                break;
            }
            
            if(vsew == EW64){
                ZVK_SHA512_COMPRESS(vs2_3_64, vs2_2_64, vd_3_64, vd_2_64, vs2_1_64, vs2_0_64, vd_1_64, vd_0_64, vs1_2_64);
                ZVK_SHA512_COMPRESS(vs2_3_64, vs2_2_64, vd_3_64, vd_2_64, vs2_1_64, vs2_0_64, vd_1_64, vd_0_64, vs1_3_64);

                vd_out_0_64 = vs2_0_64;
                vd_out_1_64 = vs2_1_64;
                vd_out_2_64 = vs2_2_64;
                vd_out_3_64 = vs2_3_64;

                vd_out_0 = (uint32_t) (vd_out_0_64);
                vd_out_1 = (uint32_t) (vd_out_0_64 >> 32);
                vd_out_2 = (uint32_t) (vd_out_1_64);
                vd_out_3 = (uint32_t) (vd_out_1_64 >> 32);
                vd_out_4 = (uint32_t) (vd_out_2_64);
                vd_out_5 = (uint32_t) (vd_out_2_64 >> 32);
                vd_out_6 = (uint32_t) (vd_out_3_64);
                vd_out_7 = (uint32_t) (vd_out_3_64 >> 32);
                break;
            }
            break;

        case VSHA2CL:

            if (vsew == EW32){
                ZVK_SHA256_COMPRESS(vs2_3, vs2_2, vd_3, vd_2, vs2_1, vs2_0, vd_1, vd_0, vs1_0);
                
                t_out_a = vs2_3;
                t_out_b = vs2_2;
                t_out_c = vd_3;
                t_out_d = vd_2;
                t_out_e = vs2_1;
                t_out_f = vs2_0;
                t_out_g = vd_1;
                t_out_h = vd_0;
                
                ZVK_SHA256_COMPRESS(vs2_3, vs2_2, vd_3, vd_2, vs2_1, vs2_0, vd_1, vd_0, vs1_1);

                vd_out_0 = vs2_0;
                vd_out_1 = vs2_1;
                vd_out_2 = vs2_2;
                vd_out_3 = vs2_3;
                vd_out_4 = 0;
                vd_out_5 = 0;
                vd_out_6 = 0;
                vd_out_7 = 0;
                break;
            }
            
            if(vsew == EW64){
                ZVK_SHA512_COMPRESS(vs2_3_64, vs2_2_64, vd_3_64, vd_2_64, vs2_1_64, vs2_0_64, vd_1_64, vd_0_64, vs1_0_64);
                ZVK_SHA512_COMPRESS(vs2_3_64, vs2_2_64, vd_3_64, vd_2_64, vs2_1_64, vs2_0_64, vd_1_64, vd_0_64, vs1_1_64);

                vd_out_0_64 = vs2_0_64;
                vd_out_1_64 = vs2_1_64;
                vd_out_2_64 = vs2_2_64;
                vd_out_3_64 = vs2_3_64;

                vd_out_0 = (uint32_t) (vd_out_0_64);
                vd_out_1 = (uint32_t) (vd_out_0_64 >> 32);
                vd_out_2 = (uint32_t) (vd_out_1_64);
                vd_out_3 = (uint32_t) (vd_out_1_64 >> 32);
                vd_out_4 = (uint32_t) (vd_out_2_64);
                vd_out_5 = (uint32_t) (vd_out_2_64 >> 32);
                vd_out_6 = (uint32_t) (vd_out_3_64);
                vd_out_7 = (uint32_t) (vd_out_3_64 >> 32);
                break;
            }
            break;

        case VSM3ME:
            VSM3_MESSAGE_EXPANSION(vs1_0, vs1_1, vs1_2, vs1_3, vs1_4, vs1_5, vs1_6, vs1_7, vs2_0, vs2_1, vs2_2, vs2_3, vs2_4, vs2_5, vs2_6, vs2_7, vd_out_0, vd_out_1, vd_out_2, vd_out_3, vd_out_4, vd_out_5, vd_out_6, vd_out_7);
            break;
        
        case VSM3C:
            VSM3_COMPRESSION(vd_0, vd_1, vd_2, vd_3, vd_4, vd_5, vd_6, vd_7, vs2_0, vs2_1, vs2_4, vs2_5, imm, vd_out_7, vd_out_6, vd_out_5, vd_out_4, vd_out_3, vd_out_2, vd_out_1, vd_out_0);
            break;

        case VSM4K:
            VSM4_KEYGEN(vs2_3, vs2_2, vs2_1, vs2_0, imm, vd_out_3, vd_out_2, vd_out_1, vd_out_0);
            vd_out_4 = 0;
            vd_out_5 = 0;
            vd_out_6 = 0;
            vd_out_7 = 0;
            break;

        case VSM4R_VS:
        case VSM4R_VV:
            VSM4_ROUND(vd_3, vd_2, vd_1, vd_0, vs2_3, vs2_2, vs2_1, vs2_0, vd_out_3, vd_out_2, vd_out_1, vd_out_0);
            vd_out_4 = 0;
            vd_out_5 = 0;
            vd_out_6 = 0;
            vd_out_7 = 0;
            break;
        
        case VAESK2:
            vaeskf2(&vs2_3, &vd_0, &vd_1, &vd_2, &vd_3, &imm, &vd_out_0, &vd_out_1, &vd_out_2, &vd_out_3);
            vd_out_4 = 0;
            vd_out_5 = 0;
            vd_out_6 = 0;
            vd_out_7 = 0;
            break;

        case VAESK1:
            vaeskf1(&vs2_0, &vs2_1, &vs2_2, &vs2_3, &imm, &vd_out_0, &vd_out_1, &vd_out_2, &vd_out_3);
            vd_out_4 = 0;
            vd_out_5 = 0;
            vd_out_6 = 0;
            vd_out_7 = 0;
            break;

        case VAESZ_VS:
            vaesz(&vs2_0, &vs2_1, &vs2_2, &vs2_3, &vd_0, &vd_1, &vd_2, &vd_3, &vd_out_0, &vd_out_1, &vd_out_2, &vd_out_3);
            vd_out_4 = 0;
            vd_out_5 = 0;
            vd_out_6 = 0;
            vd_out_7 = 0;
            break;
        
        case VAESEF_VS:
        case VAESEF_VV:
            vaesef(&vs2_0, &vs2_1, &vs2_2, &vs2_3, &vd_0, &vd_1, &vd_2, &vd_3, &vd_out_0, &vd_out_1, &vd_out_2, &vd_out_3);
            vd_out_4 = 0;
            vd_out_5 = 0;
            vd_out_6 = 0;
            vd_out_7 = 0;
            break;
        
        case VAESEM_VS:
        case VAESEM_VV:
            vaesem(&vs2_0, &vs2_1, &vs2_2, &vs2_3, &vd_0, &vd_1, &vd_2, &vd_3, &vd_out_0, &vd_out_1, &vd_out_2, &vd_out_3);
            vd_out_4 = 0;
            vd_out_5 = 0;
            vd_out_6 = 0;
            vd_out_7 = 0;
            break;

        case VAESDF_VS:
        case VAESDF_VV:
            vaesdf(&vs2_0, &vs2_1, &vs2_2, &vs2_3, &vd_0, &vd_1, &vd_2, &vd_3, &vd_out_0, &vd_out_1, &vd_out_2, &vd_out_3);
            vd_out_4 = 0;
            vd_out_5 = 0;
            vd_out_6 = 0;
            vd_out_7 = 0;
            break;

        case VAESDM_VS:
        case VAESDM_VV:
            vaesdm(&vs2_0, &vs2_1, &vs2_2, &vs2_3, &vd_0, &vd_1, &vd_2, &vd_3, &vd_out_0, &vd_out_1, &vd_out_2, &vd_out_3);
            vd_out_4 = 0;
            vd_out_5 = 0;
            vd_out_6 = 0;
            vd_out_7 = 0;
            break;

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

    //OUTPUT(vd_out_0);
    //OUTPUT(vd_out_1);
    //OUTPUT(vd_out_2);
    //OUTPUT(vd_out_3);
    //OUTPUT(vd_out_4);
    //OUTPUT(vd_out_5);
    //OUTPUT(vd_out_6);
    //OUTPUT(vd_out_7);

    //OUTPUT(vd_out_0_64);
    //OUTPUT(vd_out_1_64);
    //OUTPUT(vd_out_2_64);
    //OUTPUT(vd_out_3_64);

    
    //OUTPUT(t_out_h);
    //OUTPUT(t_out_g);
    //OUTPUT(t_out_f);
    //OUTPUT(t_out_e);
    //OUTPUT(t_out_d);
    //OUTPUT(t_out_c);
    //OUTPUT(t_out_b);
    //OUTPUT(t_out_a);

    //OUTPUT(a);
    //OUTPUT(b);
    //OUTPUT(c);
}

