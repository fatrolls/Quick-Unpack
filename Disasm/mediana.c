/******************************************************************************
* Copyright (c) 2010, Mikae
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
* 3. All advertising materials mentioning features or use of this software
*    must display the following acknowledgement:
*    This product includes software developed by Mikae.
* 4. Neither the name of Mikae nor the
*    names of its contributors may be used to endorse or promote products
*    derived from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY Mikae ''AS IS'' AND ANY
* EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Mikae BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************
*
* Core file of the disassembler. If you found a bug, or want to suggest a 
* feature, feel free to contact me:
*
* mika0x65@gmail.com
* mika0x65.livejournal.com
*
*******************************************************************************
*/

#include <string.h>
#include "mediana.h"
#include "utils.h"
#include "tables.h"
#include "tables.inc"

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER
#endif

#define PREF_SEG_INDEX      0x0
#define PREF_OPSIZE_INDEX   0x1
#define PREF_ADDRSIZE_INDEX 0x2
#define PREF_REP_INDEX      0x3
#define PREF_LOCK_INDEX     0x4
#define PREF_REX_INDEX      0x5

#define PREFIX_COUNT        0x6

//PREF_SEG_*
#define PREF_CS_ID       0x0
#define PREF_DS_ID       0x1
#define PREF_ES_ID       0x2
#define PREF_SS_ID       0x3
#define PREF_FS_ID       0x4
#define PREF_GS_ID       0x5

//PREF_OPSIZE_*
#define PREF_OPSIZE_ID   0x6

//PREF_ADDRSIZE_*
#define PREF_ADDRSIZE_ID 0x7

//PREF_REP_*
#define PREF_REPZ_ID     0x8
#define PREF_REPNZ_ID    0x9

//PREF_LOCK_*
#define PREF_LOCK_ID     0xA

//PREF_REX_*
#define PREF_REX_ID      0xB

//Used to convert rax, ... rdi to r8, ... r15
#define REG_CODE_64 0x8

//Holds operand's real and intended sizes, value of sign.
struct OPERAND_SIZE
{
    uint16_t size_in_stream;
    uint16_t size;
    uint8_t sign;
};

struct DISASM_INTERNAL_DATA
{
    uint8_t prefixes[PREFIX_COUNT]; //Valuable prefixes.
    uint8_t severe_err;             //Severe disassembling error.
    uint32_t err;                   //Disassembling error.
    uint8_t is_opsize_used;         //Prefixes were used during disassembling.
    uint8_t is_addrsize_used;       //
    uint8_t is_seg_used;            //
    uint8_t is_rex_used;            //
    struct RWBUFF rbuff;            //Contains current offset and buffer size.
};

/******************************************************
* Operand's type qualifers (TQ_*) handlers' prototypes.
*******************************************************
*/
static uint32_t tq_1(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_3(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_A(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_C(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_D(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_E(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_G(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_H(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_I(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_J(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_M(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_N(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_O(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_P(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_Q(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_R(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_S(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_T(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_U(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_V(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_W(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_X(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_Y(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_Z(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_rAX(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_rCX(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_rDX(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_rBX(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_rSP(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_rBP(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_rSI(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_rDI(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_fST0(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_fES(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_fEST(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_CS(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_DS(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_SS(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_ES(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_FS(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t tq_GS(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t pref_CS_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t pref_DS_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t pref_SS_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t pref_ES_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t pref_FS_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t pref_GS_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t pref_OPSIZE_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t pref_ADDRSIZE_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t pref_REPZ_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t pref_REPNZ_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t pref_LOCK_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);

//Array of type qualifiers' handlers.
static uint32_t (*tq_handlers[])(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode) = 
{
    tq_1,
    tq_3,
    tq_A,
    tq_C,
    tq_D,
    tq_E,
    tq_G,
    tq_H,
    tq_I,
    tq_J,
    tq_M,
    tq_N,
    tq_O,
    tq_P,
    tq_Q,
    tq_R,
    tq_S,
    tq_T,
    tq_U,
    tq_V,
    tq_W,
    tq_X,
    tq_Y,
    tq_Z,
    tq_rAX,
    tq_rCX,
    tq_rDX,
    tq_rBX,
    tq_rSP,
    tq_rBP,
    tq_rSI,
    tq_rDI,
    tq_fES,
    tq_fEST,
    tq_fST0,
    tq_CS,
    tq_DS,
    tq_ES,
    tq_SS,
    tq_FS,
    tq_GS,    
    pref_CS_set,
    pref_DS_set,
    pref_ES_set,
    pref_SS_set,
    pref_FS_set,
    pref_GS_set,
    pref_OPSIZE_set,
    pref_ADDRSIZE_set,
    pref_REPZ_set,
    pref_REPNZ_set,
    pref_LOCK_set
};

/*******************************************************
* Operand's size qualifiers (SQ_*) handlers' prototypes.
********************************************************
*/
static void sq_a(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_b(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_bcd(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_bdqp(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_bs(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_bsj(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_bss(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_d(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_ddq(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_di(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_dq(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_dq64(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_dqp(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_dr(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_ds(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_e(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_er(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_p(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_pd(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_pi(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_ps(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_psd(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_psq(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_ptp(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_q(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_qdq(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_qi(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_s(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_sd(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_sr(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_ss(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_st(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_stx(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_v(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_v67d64(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_vd64(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_vds(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_vq64(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_vqp(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_vs(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_w(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_wdq(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_wdqp(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_wi(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_wv(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void sq_wvqp(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);

//Array of size qualifiers' handlers.
static void (*sq_handlers[])(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode) = 
{
    sq_a,
    sq_b,
    sq_bcd,
    sq_bdqp,
    sq_bs,
    sq_bsj,
    sq_bss,
    sq_d,
    sq_ddq,
    sq_di,
    sq_dq,
    sq_dq64,
    sq_dqp,
    sq_dr,
    sq_ds,
    sq_e,
    sq_er,
    sq_p,
    sq_pd,
    sq_pi,
    sq_ps,
    sq_psd,
    sq_psq,
    sq_ptp,
    sq_q,
    sq_qdq,
    sq_qi,
    sq_s,
    sq_sd,
    sq_sr,
    sq_ss,
    sq_st,
    sq_stx,
    sq_v,
    sq_v67d64,
    sq_vd64,
    sq_vds,
    sq_vq64,
    sq_vqp,
    sq_vs,
    sq_w,
    sq_wdq,
    sq_wdqp,
    sq_wi,
    sq_wv,
    sq_wvqp
};

/***************************************
* Postprocessing functions's prototypes.
****************************************
*/
static uint32_t post_proc_arpl_movsxd(struct INSTRUCTION *instr,
                                      struct DISASM_INTERNAL_DATA *idata,
                                      uint32_t *len,
                                      struct DISASM_PARAMS *params);

static uint32_t post_proc_nop_pause(struct INSTRUCTION *instr,
                                    struct DISASM_INTERNAL_DATA *idata,
                                    uint32_t *len,
                                    struct DISASM_PARAMS *params);

static uint32_t post_proc_multinop(struct INSTRUCTION *instr,
                                   struct DISASM_INTERNAL_DATA *idata,
                                   uint32_t *len,
                                   struct DISASM_PARAMS *params);

static uint32_t post_proc_cmpxchg8b(struct INSTRUCTION *instr,
                                    struct DISASM_INTERNAL_DATA *idata,
                                    uint32_t *len,
                                    struct DISASM_PARAMS *params);

static uint32_t post_proc_pextrd(struct INSTRUCTION *instr,
                                 struct DISASM_INTERNAL_DATA *idata,
                                 uint32_t *len,
                                 struct DISASM_PARAMS *params);

static uint32_t post_proc_pinsrd(struct INSTRUCTION *instr,
                                 struct DISASM_INTERNAL_DATA *idata,
                                 uint32_t *len,
                                 struct DISASM_PARAMS *params);

static uint32_t post_proc_lea(struct INSTRUCTION *instr,
                              struct DISASM_INTERNAL_DATA *idata,
                              uint32_t *len,
                              struct DISASM_PARAMS *params);

//Array of potsprocessing handlers.
static uint32_t (*postprocs[])(struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint32_t *len, struct DISASM_PARAMS *params) = 
{
    post_proc_arpl_movsxd,
    post_proc_nop_pause,
    post_proc_multinop,
    post_proc_cmpxchg8b,
    post_proc_pextrd,
    post_proc_pinsrd,
    post_proc_lea
};

//Table for building 16bit addresses in my representation.
static struct ADDR addrs_16bit[] =
{
      //seg         mod                                           base         index        scale
    { SREG_CODE_DS, ADDR_MOD_BASE | ADDR_MOD_IDX,                 REG_CODE_BX, REG_CODE_SI, 0x1 },
    { SREG_CODE_DS, ADDR_MOD_BASE | ADDR_MOD_IDX,                 REG_CODE_BX, REG_CODE_DI, 0x1 },
    { SREG_CODE_SS, ADDR_MOD_BASE | ADDR_MOD_IDX,                 REG_CODE_BP, REG_CODE_SI, 0x1 },
    { SREG_CODE_SS, ADDR_MOD_BASE | ADDR_MOD_IDX,                 REG_CODE_BP, REG_CODE_DI, 0x1 },
    { SREG_CODE_DS, ADDR_MOD_BASE,                                REG_CODE_SI, 0x0,         0x1 },
    { SREG_CODE_DS, ADDR_MOD_BASE,                                REG_CODE_DI, 0x0,         0x1 },
    { SREG_CODE_DS, ADDR_MOD_DISP,                                0x0,         0x0,         0x1 },
    { SREG_CODE_DS, ADDR_MOD_BASE,                                REG_CODE_BX, 0x0,         0x1 },
    { SREG_CODE_DS, ADDR_MOD_BASE | ADDR_MOD_IDX | ADDR_MOD_DISP, REG_CODE_BX, REG_CODE_SI, 0x1 },
    { SREG_CODE_DS, ADDR_MOD_BASE | ADDR_MOD_IDX | ADDR_MOD_DISP, REG_CODE_BX, REG_CODE_DI, 0x1 },
    { SREG_CODE_SS, ADDR_MOD_BASE | ADDR_MOD_IDX | ADDR_MOD_DISP, REG_CODE_BP, REG_CODE_SI, 0x1 },
    { SREG_CODE_SS, ADDR_MOD_BASE | ADDR_MOD_IDX | ADDR_MOD_DISP, REG_CODE_BP, REG_CODE_DI, 0x1 },
    { SREG_CODE_DS, ADDR_MOD_BASE | ADDR_MOD_DISP,                REG_CODE_SI, 0x0,         0x1 },
    { SREG_CODE_DS, ADDR_MOD_BASE | ADDR_MOD_DISP,                REG_CODE_DI, 0x0,         0x1 },
    { SREG_CODE_SS, ADDR_MOD_BASE | ADDR_MOD_DISP,                REG_CODE_BP, 0x0,         0x1 },
    { SREG_CODE_DS, ADDR_MOD_BASE | ADDR_MOD_DISP,                REG_CODE_BX, 0x0,         0x1 },
    { SREG_CODE_DS, ADDR_MOD_BASE | ADDR_MOD_IDX | ADDR_MOD_DISP, REG_CODE_BX, REG_CODE_SI, 0x1 },
    { SREG_CODE_DS, ADDR_MOD_BASE | ADDR_MOD_IDX | ADDR_MOD_DISP, REG_CODE_BX, REG_CODE_DI, 0x1 },
    { SREG_CODE_SS, ADDR_MOD_BASE | ADDR_MOD_IDX | ADDR_MOD_DISP, REG_CODE_BP, REG_CODE_SI, 0x1 },
    { SREG_CODE_SS, ADDR_MOD_BASE | ADDR_MOD_IDX | ADDR_MOD_DISP, REG_CODE_BP, REG_CODE_DI, 0x1 },
    { SREG_CODE_DS, ADDR_MOD_BASE | ADDR_MOD_DISP,                REG_CODE_SI, 0x0,         0x1 },
    { SREG_CODE_DS, ADDR_MOD_BASE | ADDR_MOD_DISP,                REG_CODE_DI, 0x0,         0x1 },
    { SREG_CODE_SS, ADDR_MOD_BASE | ADDR_MOD_DISP,                REG_CODE_BP, 0x0,         0x1 },
    { SREG_CODE_DS, ADDR_MOD_BASE | ADDR_MOD_DISP,                REG_CODE_BX, 0x0,         0x1 }
};

static uint8_t sregs_codes[] =
{
    SREG_CODE_CS,
    SREG_CODE_DS,
    SREG_CODE_ES,
    SREG_CODE_SS,
    SREG_CODE_FS,
    SREG_CODE_GS
};

static uint16_t pref_bits[] = 
{
    INSTR_PREFIX_CS,
    INSTR_PREFIX_DS,
    INSTR_PREFIX_ES,
    INSTR_PREFIX_SS,
    INSTR_PREFIX_FS,
    INSTR_PREFIX_GS,
    INSTR_PREFIX_OPSIZE,
    INSTR_PREFIX_ADDRSIZE,
    INSTR_PREFIX_REPNZ,
    INSTR_PREFIX_REPZ,
    INSTR_PREFIX_LOCK,
    INSTR_PREFIX_REX
};

/**********************************
* Some unsorted internal prototypes.
***********************************
*/
static void create_reg_operand(struct INSTRUCTION *instr, int op_index, uint8_t type, uint8_t code, uint16_t size);
static void create_xmmreg_operand(struct INSTRUCTION *instr, int op_index, uint8_t code, uint16_t size, uint8_t rex, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void create_genreg_operand(struct INSTRUCTION *instr, int op_index, uint8_t code, uint16_t size, uint8_t rex, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void get_seg(struct INSTRUCTION *instr, int op_index, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint8_t get_operand_size(struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint8_t get_operand_size_16_32(struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t parse_mem_operand(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static uint32_t parse_rm_operand(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode);
static void movsx(void *value, unsigned int size1, unsigned int size2);
static void add_sf_prefix(uint8_t prefixes[], uint32_t index, struct INSTRUCTION *instr, struct DISASM_PARAMS *params);

static void readbuff_init(struct RWBUFF *rbuff, uint8_t *origin_offset, uint8_t *offset, size_t bufflen)
{
    rbuff ->offset = offset;
    rbuff ->origin_offset = origin_offset;
    if (bufflen < MAX_INSTRUCTION_LEN)
    {
        rbuff ->length = bufflen;
        rbuff ->err = DASM_ERR_NO_BUFF;
    }
    else
    {
        rbuff ->length = MAX_INSTRUCTION_LEN;
        rbuff ->err = DASM_ERR_TOO_LONG;
    }
}

static int readbuff_get_bytes(struct RWBUFF *rbuff, struct DISASM_INTERNAL_DATA *idata, void *result, size_t count)
{
    int res;

    if (rbuff ->offset - rbuff ->origin_offset + count > rbuff ->length)
    {
        idata ->severe_err = rbuff ->err;
        res = 0;
    }
    else
    {
        memcpy(result, rbuff ->offset, count);
        res = 1;
    }

    return res;
}

static int readbuff_get_bytes_inc(struct RWBUFF *rbuff, struct DISASM_INTERNAL_DATA *idata, void *result, unsigned int count)
{
    int res;
    
    res = readbuff_get_bytes(rbuff, idata, result, count);
    rbuff ->offset += count;

    return res;
}

static void readbuff_inc(struct RWBUFF *rbuff, unsigned int count)
{
    rbuff ->offset += count;
}

/********************************************
* Operand's type qualifiers' (TQ_*) handlers.
*********************************************
*/
static uint32_t tq_1(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(opsize);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    instr ->ops[op_index].flags |= OPERAND_TYPE_IMM;
    instr ->ops[op_index].size = 1;
    instr ->ops[op_index].value.imm.imm8 = 0x1;

    return 0x0;
}

static uint32_t tq_3(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(opsize);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    instr ->ops[op_index].flags |= OPERAND_TYPE_IMM;
    instr ->ops[op_index].size = 1;
    instr ->ops[op_index].value.imm.imm8 = 0x3;

    return 0;
}

static uint32_t tq_A(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(mode);

    instr ->ops[op_index].flags |= OPERAND_TYPE_DIR;
    instr ->ops[op_index].size = opsize ->size;
    instr ->ops[op_index].value.far_addr.offset = (uint8_t)(idata ->rbuff.offset - idata ->rbuff.origin_offset);
    //memcpy(&(instr ->ops[op_index].value.far_addr), offset, instr ->ops[op_index].size);
    readbuff_get_bytes_inc(&idata ->rbuff, idata, &(instr ->ops[op_index].value.far_addr), instr ->ops[op_index].size);

    return instr ->ops[op_index].size;
}

static uint32_t tq_C(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(opsize);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    create_reg_operand(instr, op_index, REG_TYPE_CR, (instr ->modrm >> 0x3) & 0x7, instr ->ops[op_index].size);

    return 0x0;
}

static uint32_t tq_D(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(opsize);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    create_reg_operand(instr, op_index, REG_TYPE_DBG, (instr ->modrm >> 0x3) & 0x7, instr ->ops[op_index].size);

    return 0x0;
}

static uint32_t tq_E(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    return parse_rm_operand(instr, op_index, opsize, idata, mode);
}


static uint32_t tq_G(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    create_genreg_operand(instr, op_index, (instr ->modrm >> 3) & 0x7, opsize ->size, PREFIX_REX_R, idata, mode);

    return 0x0;
}

static uint32_t tq_H(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    create_genreg_operand(instr, op_index, instr ->modrm & 0x7, opsize ->size, PREFIX_REX_B, idata, mode);

    return 0x0;
}

static uint32_t tq_I(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(mode);

    instr ->ops[op_index].flags |= OPERAND_TYPE_IMM;
    instr ->ops[op_index].size = opsize ->size;
    instr ->ops[op_index].value.imm.size = (uint8_t)opsize ->size_in_stream;
    instr ->ops[op_index].value.imm.offset = (uint8_t)(idata ->rbuff.offset - idata ->rbuff.origin_offset);
    //memcpy(&(instr ->ops[op_index].value.imm.imm8), offset, opsize ->size_in_stream);
    readbuff_get_bytes_inc(&idata ->rbuff, idata, &(instr ->ops[op_index].value.imm.imm8), opsize ->size_in_stream);
    movsx(&(instr ->ops[op_index].value.imm.imm8), opsize ->size_in_stream, 0x8);

    return (uint8_t)opsize ->size_in_stream;
}

static uint32_t tq_J(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    instr ->ops[op_index].flags |= OPERAND_FLAG_REL;
    return tq_I(instr, op_index, opsize, idata, mode);
}

static uint32_t tq_M(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    uint32_t res = parse_rm_operand(instr, op_index, opsize, idata, mode);
    if ((instr ->modrm & 0xC0) == 0xC0)
    {
        if (!idata ->err)
            idata ->err = DASM_ERR_RM_REG;//error: rm encodes memory.
    }
    return res;
}

static uint32_t tq_N(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    create_reg_operand(instr, op_index, REG_TYPE_MMX, instr ->modrm & 0x7, opsize ->size);

    return 0x0;
}

static uint32_t tq_O(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    uint32_t res;

    res = instr ->addrsize;
    instr ->ops[op_index].flags |= OPERAND_TYPE_MEM;
    instr ->ops[op_index].size = opsize ->size;
    instr ->ops[op_index].value.addr.mod = ADDR_MOD_DISP;
    //memcpy(&(instr ->disp.value), offset, instr ->addrsize);
    readbuff_get_bytes_inc(&idata ->rbuff, idata, &(instr ->disp.value), instr ->addrsize);
    instr ->disp.offset = 1;
    instr ->disp.size = instr ->addrsize;
    get_seg(instr, op_index, idata, mode);

    return res;
}

static uint32_t tq_P(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    create_reg_operand(instr, op_index, REG_TYPE_MMX, (instr ->modrm >> 0x3) & 0x7, opsize ->size);

    return 0x0;
}

static uint32_t tq_Q(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    uint32_t res;

    res = 0x0;
    if ((instr ->modrm & 0xC0) == 0xC0)
    {
        create_reg_operand(instr, op_index, REG_TYPE_MMX, instr ->modrm & 0x7, opsize ->size);
    }
    else
    {
        res = parse_mem_operand(instr, op_index, opsize, idata, mode);
    }

    return res;
}

static uint32_t tq_R(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    uint32_t res = parse_rm_operand(instr, op_index, opsize, idata, mode);
    if ((instr ->modrm & 0xC0) != 0xC0)
    {
        if (!idata ->err)
            idata ->err = DASM_ERR_RM_MEM;//error: rm encodes memory.
    }
    return res;
}

static uint32_t tq_S(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(opsize);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    create_reg_operand(instr, op_index, REG_TYPE_SEG, (instr ->modrm >> 3) & 0x7, 2);

    return 0x0;
}

static uint32_t tq_T(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    create_reg_operand(instr, op_index, REG_TYPE_TR, (instr ->modrm >> 0x3) & 0x7, opsize ->size);

    return 0x0;
}

static uint32_t tq_U(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if ((instr ->modrm & 0xC0) != 0xC0)
    {
        if (!idata ->err)
        {
            idata ->err = DASM_ERR_RM_MEM;
        }
    }
    else
    {
        create_xmmreg_operand(instr, op_index, instr ->modrm & 0x7, opsize ->size, PREFIX_REX_B, idata, mode);
    }

    return 0x0;
}

static uint32_t tq_V(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    create_xmmreg_operand(instr, op_index, (instr ->modrm >> 0x3) & 0x7, opsize ->size, PREFIX_REX_R, idata, mode);

    return 0;
}

static uint32_t tq_W(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    uint32_t res;

    if ((instr ->modrm & 0xC0) == 0xC0)
    {
        create_xmmreg_operand(instr, op_index, instr ->modrm & 0x7, opsize ->size, PREFIX_REX_B, idata, mode);
        res = 0;
    }
    else
    {
        res = parse_mem_operand(instr, op_index, opsize, idata, mode);
    }

    return res;
}

static uint32_t tq_X(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    uint32_t res;

    res = 0;
    instr ->ops[op_index].flags |= OPERAND_TYPE_MEM;
    instr ->ops[op_index].size = opsize ->size;
    instr ->ops[op_index].value.addr.mod = ADDR_MOD_BASE;
    instr ->ops[op_index].value.addr.base = REG_CODE_SI;
    get_seg(instr, op_index, idata, mode);

    return 0x0;
}

static uint32_t tq_Y(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(idata);

    instr ->ops[op_index].flags |= OPERAND_TYPE_MEM;
    instr ->ops[op_index].size = opsize ->size;
    if (mode == DISASSEMBLE_MODE_64)
        instr ->ops[op_index].value.addr.seg = SREG_CODE_CS;
    else
        instr ->ops[op_index].value.addr.seg = SREG_CODE_ES;
    instr ->ops[op_index].value.addr.mod = ADDR_MOD_BASE;
    instr ->ops[op_index].value.addr.base = REG_CODE_DI;

    return 0x0;
}

static uint32_t tq_Z(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    //We already consumed opcode, hence we need to look backward.
    create_genreg_operand(instr, op_index, idata ->rbuff.offset[-1] & 0x7, opsize ->size, PREFIX_REX_B, idata, mode);

    return 0x0;
}

static uint32_t tq_rAX(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    create_genreg_operand(instr, op_index, REG_CODE_AX, opsize ->size, PREFIX_REX_B, idata, mode);

    return 0x0;
}

static uint32_t tq_rCX(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    create_genreg_operand(instr, op_index, REG_CODE_CX, opsize ->size, PREFIX_REX_B, idata, mode);

    return 0x0;
}

static uint32_t tq_rDX(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    create_genreg_operand(instr, op_index, REG_CODE_DX, opsize ->size, PREFIX_REX_B, idata, mode);

    return 0x0;
}

static uint32_t tq_rBX(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    create_genreg_operand(instr, op_index, REG_CODE_BX, opsize ->size, PREFIX_REX_B, idata, mode);

    return 0x0;
}

static uint32_t tq_rSP(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    create_genreg_operand(instr, op_index, REG_CODE_SP, opsize ->size, PREFIX_REX_B, idata, mode);

    return 0x0;
}

static uint32_t tq_rBP(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    create_genreg_operand(instr, op_index, REG_CODE_BP, opsize ->size, PREFIX_REX_B, idata, mode);

    return 0x0;
}

static uint32_t tq_rSI(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    create_genreg_operand(instr, op_index, REG_CODE_SI, opsize ->size, PREFIX_REX_B, idata, mode);

    return 0x0;
}

static uint32_t tq_rDI(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    create_genreg_operand(instr, op_index, REG_CODE_DI, opsize ->size, PREFIX_REX_B, idata, mode);

    return 0x0;
}

static uint32_t tq_fES(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    uint32_t res;

    if ((instr ->modrm & 0xC0) == 0xC0)
        res = tq_fEST(instr, op_index, opsize, idata, mode);
    else
        res = tq_M(instr, op_index, opsize, idata, mode);

    return res;
}

static uint32_t tq_fEST(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    create_reg_operand(instr, op_index, REG_TYPE_FPU, instr ->modrm & 0x7, opsize ->size);

    return 0;
}

static uint32_t tq_fST0(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    create_reg_operand(instr, op_index, REG_TYPE_FPU, FREG_CODE_ST0, opsize ->size);

    return 0;
}

static uint32_t tq_CS(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    create_reg_operand(instr, op_index, REG_TYPE_SEG, SREG_CODE_CS, opsize ->size);

    return 0;
}

static uint32_t tq_DS(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    create_reg_operand(instr, op_index, REG_TYPE_SEG, SREG_CODE_DS, opsize ->size);

    return 0;
}

static uint32_t tq_ES(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    create_reg_operand(instr, op_index, REG_TYPE_SEG, SREG_CODE_ES, opsize ->size);

    return 0;
}

static uint32_t tq_SS(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    create_reg_operand(instr, op_index, REG_TYPE_SEG, SREG_CODE_SS, opsize ->size);

    return 0;
}

static uint32_t tq_FS(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    create_reg_operand(instr, op_index, REG_TYPE_SEG, SREG_CODE_FS, opsize ->size);

    return 0;
}

static uint32_t tq_GS(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    create_reg_operand(instr, op_index, REG_TYPE_SEG, SREG_CODE_GS, opsize ->size);

    return 0;
}

static uint32_t pref_CS_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(op_index);
    UNREFERENCED_PARAMETER(opsize);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    return PREF_SEG_INDEX << 8 | PREF_CS_ID;
}

static uint32_t pref_DS_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(op_index);
    UNREFERENCED_PARAMETER(opsize);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    return PREF_SEG_INDEX  << 8 | PREF_DS_ID;
}

static uint32_t pref_ES_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(op_index);
    UNREFERENCED_PARAMETER(opsize);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    return PREF_SEG_INDEX  << 8 | PREF_ES_ID;
}

static uint32_t pref_SS_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(op_index);
    UNREFERENCED_PARAMETER(opsize);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    return PREF_SEG_INDEX  << 8 | PREF_SS_ID;
}

static uint32_t pref_FS_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(op_index);
    UNREFERENCED_PARAMETER(opsize);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    return PREF_SEG_INDEX  << 8 | PREF_FS_ID;
}
    
static uint32_t pref_GS_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(op_index);
    UNREFERENCED_PARAMETER(opsize);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    return PREF_SEG_INDEX  << 8 | PREF_GS_ID;
}

static uint32_t pref_OPSIZE_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(op_index);
    UNREFERENCED_PARAMETER(opsize);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    return PREF_OPSIZE_INDEX << 8 | PREF_OPSIZE_ID;
}

static uint32_t pref_ADDRSIZE_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(op_index);
    UNREFERENCED_PARAMETER(opsize);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    return PREF_ADDRSIZE_INDEX << 8 | PREF_ADDRSIZE_ID;
}

static uint32_t pref_REPZ_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(op_index);
    UNREFERENCED_PARAMETER(opsize);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    return PREF_REP_INDEX << 8 | PREF_REPZ_ID;
}

static uint32_t pref_REPNZ_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(op_index);
    UNREFERENCED_PARAMETER(opsize);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    return PREF_REP_INDEX << 8 | PREF_REPNZ_ID;
}

static uint32_t pref_LOCK_set(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(op_index);
    UNREFERENCED_PARAMETER(opsize);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    return PREF_LOCK_INDEX << 8 | PREF_LOCK_ID;
}

/********************************************
* Operand's size qualifiers' (SQ_*) handlers.
*********************************************
*/
static void sq_a(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(opsize);
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);
}

static void sq_b(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    opsize ->size_in_stream = 1;
    opsize ->size = 1;
    opsize ->sign = 0;
}

static void sq_bcd(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    sq_er(opsize, instr, idata, mode);
}

static void sq_bdqp(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if ((instr ->modrm & 0xC0) == 0xC0)
    {
        sq_dqp(opsize, instr, idata, mode);
    }
    else
    {
        sq_b(opsize, instr, idata, mode);
    }
}

static void sq_bs(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);

    opsize ->size_in_stream = 1;

    if (mode != DISASSEMBLE_MODE_64)
    {
        opsize ->size = get_operand_size_16_32(idata, mode);
    }
    else
    {
        if (idata ->prefixes[PREF_OPSIZE_INDEX] != 0xFF)
        {
            opsize ->size = get_operand_size_16_32(idata, mode);
        }
        else
        {
            opsize ->size = 8;
        }
    }

    opsize ->sign = 1;
}

static void sq_bsj(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);

    opsize ->size_in_stream = 1;
    if (mode == DISASSEMBLE_MODE_64)
    {
        opsize ->size = 8;
    }
    else
    {
        opsize ->size = get_operand_size_16_32(idata, mode);
    }
    opsize ->sign = 1;
}

static void sq_bss(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(idata);

    opsize ->size_in_stream = 1;
    switch(mode)
    {
    case DISASSEMBLE_MODE_16:
        opsize ->size = 2;
        break;
    case DISASSEMBLE_MODE_32:
        opsize ->size = 4;
        break;
    case DISASSEMBLE_MODE_64:
        opsize ->size = 8;
        break;
    }
    opsize ->sign = 1;
}

static void sq_d(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    opsize ->size_in_stream = 4;
    opsize ->size = 4;
    opsize ->sign = 0;
}

static void sq_ddq(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if ((instr ->modrm & 0xC0) == 0xC0)
    {
        sq_dq(opsize, instr, idata, mode);
    }
    else
    {
        sq_d(opsize, instr, idata, mode);
    }
}

static void sq_di(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    opsize ->size_in_stream = 4;
    opsize ->size = opsize ->size_in_stream;
    opsize ->sign = 0;
}

static void sq_dq(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    opsize ->size_in_stream = 16;
    opsize ->size = opsize ->size_in_stream;
    opsize ->sign = 0;
}

static void sq_dq64(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if (mode != DISASSEMBLE_MODE_64)
    {
        sq_d(opsize, instr, idata, mode);
    }
    else
    {
        sq_q(opsize, instr, idata, mode);
    }
}

static void sq_dqp(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if (mode == DISASSEMBLE_MODE_64)
    {
        opsize ->size_in_stream = get_operand_size(instr, idata, mode);
        opsize ->size = opsize ->size_in_stream;
        opsize ->sign = 0;
    }
    else
    {
        sq_d(opsize, instr, idata, mode);
    }
}

static void sq_dr(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    opsize ->size_in_stream = 8;
    opsize ->size = opsize ->size_in_stream;
    opsize ->sign = 0;
}

static void sq_ds(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    sq_d(opsize, instr, idata, mode);
    opsize ->sign = 1;
}

static void sq_e(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);

    if (get_operand_size_16_32(idata, mode) == 2)
    {
        opsize ->size_in_stream = 14;
    }
    else
    {
        opsize ->size_in_stream = 28;
    }

    opsize ->size = opsize ->size_in_stream;
    opsize ->sign = 0;
}

static void sq_er(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    opsize ->size_in_stream = 10;
    opsize ->size = opsize ->size_in_stream;
    opsize ->sign = 0;
}

static void sq_p(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);

    opsize ->size_in_stream = get_operand_size_16_32(idata, mode) + 2;
    opsize ->size = opsize ->size_in_stream;
    opsize ->sign = 0;
}

static void sq_pd(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    sq_dq(opsize, instr, idata, mode);
}

static void sq_pi(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    sq_q(opsize, instr, idata, mode);
}

static void sq_ps(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    opsize ->size_in_stream = 16;
    opsize ->size = opsize ->size_in_stream;
    opsize ->sign = 0;
}

static void sq_psd(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if ((instr ->modrm & 0xC0) == 0xC0)
    {
        sq_d(opsize, instr, idata, mode);
    }
    else
    {
        sq_ps(opsize, instr, idata, mode);
    }
}

static void sq_psq(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    sq_q(opsize, instr, idata, mode);
}

static void sq_ptp(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if (mode == DISASSEMBLE_MODE_64)
    {
        opsize ->size_in_stream = get_operand_size(instr, idata, mode) + 2;
        opsize ->size = opsize ->size_in_stream;
        opsize ->sign = 0;
    }
    else
    {
        sq_p(opsize, instr, idata, mode);
    }
}

static void sq_q(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    opsize ->size_in_stream = 8;
    opsize ->size = opsize ->size_in_stream;
    opsize ->sign = 0;
}

static void sq_qdq(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if ((instr ->modrm & 0xC0) == 0xC0)
    {
        sq_dq(opsize, instr, idata, mode);
    }
    else
    {
        sq_q(opsize, instr, idata, mode);
    }
}

static void sq_qi(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    opsize ->size_in_stream = 8;
    opsize ->size = opsize ->size_in_stream;
    opsize ->sign = 0;
}

static void sq_s(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    opsize ->size_in_stream = 6;
    opsize ->size = opsize ->size_in_stream;
    opsize ->sign = 0;
}

static void sq_sd(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    sq_dq(opsize, instr, idata, mode);
}

static void sq_sr(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    opsize ->size_in_stream = 4;
    opsize ->size = opsize ->size_in_stream;
    opsize ->sign = 0;
}

static void sq_ss(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    sq_dq(opsize, instr, idata, mode);
}

static void sq_st(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);

    if (get_operand_size_16_32(idata, mode) == 2)
    {
        opsize ->size_in_stream = 94;
    }
    else
    {
        opsize ->size_in_stream = 108;
    }

    opsize ->size = opsize ->size_in_stream;
    opsize ->sign = 0;
}

static void sq_stx(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    opsize ->size_in_stream = 512;
    opsize ->size = opsize ->size_in_stream;
    opsize ->sign = 0;
}

static void sq_v(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);

    opsize ->size_in_stream = get_operand_size_16_32(idata, mode);
    opsize ->size = opsize ->size_in_stream;
    opsize ->sign = 0;
}

static void sq_v67d64(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if (mode == DISASSEMBLE_MODE_64)
    {
        if (idata ->prefixes[PREF_ADDRSIZE_INDEX] != 0xFF)
        {
            sq_d(opsize, instr, idata, mode);
            idata ->is_addrsize_used = 1;
        }
        else
        {
            sq_q(opsize, instr, idata, mode);
        }
    }
    else
    {
        if (idata ->prefixes[PREF_ADDRSIZE_INDEX] != 0xFF)
        {
            mode ^= (DISASSEMBLE_MODE_16 | DISASSEMBLE_MODE_32);
            idata ->is_addrsize_used = 1;
        }

        if (mode == DISASSEMBLE_MODE_16)
        {
            sq_w(opsize, instr, idata, mode);
        }
        else
        {
            sq_d(opsize, instr, idata, mode);
        }
    }
}

static void sq_vd64(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if (mode != DISASSEMBLE_MODE_64)
    {
        sq_v(opsize, instr, idata, mode);
    }
    else
    {
        if (idata ->prefixes[PREF_OPSIZE_INDEX] != 0xFF)
        {
            idata ->is_opsize_used = 1;
            sq_w(opsize, instr, idata, mode);
        }
        else
        {
            sq_q(opsize, instr, idata, mode);
        }
    }
}

static void sq_vds(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if (mode == DISASSEMBLE_MODE_64)
    {
        /*
        sq_v(opsize, instr, idata, mode);

        if (opsize ->size_in_stream == 4)
        {
            opsize ->size = 8;
            opsize ->sign = 1;
        }
        */
        
        opsize ->size_in_stream = 4;
        opsize ->size = 8;
        opsize ->sign = 1;
    }
    else
    {
        sq_v(opsize, instr, idata, mode);
    }
}

static void sq_vq64(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if (mode == DISASSEMBLE_MODE_64)
    {
        sq_q(opsize, instr, idata, mode);
    }
    else
    {
        sq_v(opsize, instr, idata, mode);
    }
}

static void sq_vqp(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if (mode == DISASSEMBLE_MODE_64)
    {
        opsize ->size_in_stream = get_operand_size(instr, idata, mode);
        opsize ->size = opsize ->size_in_stream;
        opsize ->sign = 0;
    }
    else
    {
        sq_v(opsize, instr, idata, mode);
    }
}

static void sq_vs(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if (mode != DISASSEMBLE_MODE_64)
    {
        sq_v(opsize, instr, idata, mode);
    }
    else
    {
        opsize ->size_in_stream = get_operand_size_16_32(idata, mode);
        if (idata ->prefixes[PREF_OPSIZE_INDEX] != 0xFF)
        {
            opsize ->size = 2;
        }
        else
        {
            opsize ->size = 8;
        }
    }
}

static void sq_w(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    opsize ->size_in_stream = 2;
    opsize ->size = 2;
    opsize ->sign = 0;
}

static void sq_wdq(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if ((instr ->modrm & 0xC0) == 0xC0)
    {
        sq_dq(opsize, instr, idata, mode);
    }
    else
    {
        sq_w(opsize, instr, idata, mode);
    }
}

static void sq_wdqp(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if ((instr ->modrm & 0xC0) == 0xC0)
    {
        sq_dqp(opsize, instr, idata, mode);
    }
    else
    {
        sq_w(opsize, instr, idata, mode);
    }
}

static void sq_wi(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(idata);
    UNREFERENCED_PARAMETER(mode);

    opsize ->size_in_stream = 2;
    opsize ->size = opsize ->size_in_stream;
    opsize ->sign = 0;
}

static void sq_wv(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if ((instr ->modrm & 0xC0) == 0xC0)
    {
        sq_v(opsize, instr, idata, mode);
    }
    else
    {
        sq_w(opsize, instr, idata, mode);
    }
}

static void sq_wvqp(struct OPERAND_SIZE *opsize, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if ((instr ->modrm & 0xC0) == 0xC0)
    {
        sq_vqp(opsize, instr, idata, mode);
    }
    else
    {
        sq_w(opsize, instr, idata, mode);
    }
}

/*************************
* Postprocessing routines.
**************************
*/
static uint32_t post_proc_arpl_movsxd(struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint32_t *len, struct DISASM_PARAMS *params)
{
    uint32_t res;

    res = 0;
    if (params ->mode == DISASSEMBLE_MODE_64)
    {
        struct OPERAND_SIZE opsize;
        struct RWBUFF *rbuff;

        instr ->id = ID_MOVSXD;
        instr ->groups = GRP_GEN | GRP_CONVER;
        instr ->tested_flags = 0;
        instr ->modified_flags = 0;
        instr ->set_flags = 0;
        instr ->cleared_flags = 0;
        instr ->flags &= (INSTR_FLAG_MODRM | INSTR_FLAG_SIB);

        unistrcpy(instr ->mnemonic, _UT("movsxd"));
        rbuff = &idata ->rbuff;
        readbuff_init(rbuff,
                      rbuff ->origin_offset,
                      rbuff ->origin_offset + instr ->opcode_offset + 1,
                      rbuff ->length - instr ->opcode_offset);

        res = instr ->opcode_offset;
        res++; //opcode byte.
        if (instr ->flags & INSTR_FLAG_MODRM)
        {
            res++;
            idata ->rbuff.offset++;
        }
        if (instr ->flags & INSTR_FLAG_SIB)
        {
            res++;
            idata ->rbuff.offset++;
        }
        memset(instr ->ops, 0x0, sizeof(instr ->ops));
        instr ->ops[0].flags = OPERAND_FLAG_PRESENT;
        instr ->ops[0].flags |= OPERAND_FLAG_WRITE;
        instr ->ops[1].flags = OPERAND_FLAG_PRESENT;
        instr ->ops[1].flags |= OPERAND_FLAG_READ;

        sq_q(&opsize, instr, idata, params ->mode);
        res += tq_G(instr, 0, &opsize, idata, params ->mode);
        sq_d(&opsize, instr, idata, params ->mode);
        res += tq_E(instr, 1, &opsize, idata, params ->mode);
        if (instr ->ops[1].flags & OPERAND_TYPE_MEM)
        {
            get_seg(instr, 1, idata, params ->mode);
        }

        *len = res;
    }

    return res;
}

static uint32_t post_proc_nop_pause(struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint32_t *len, struct DISASM_PARAMS *params)
{
    UNREFERENCED_PARAMETER(len);
    UNREFERENCED_PARAMETER(params);

    if (idata ->prefixes[PREF_REP_INDEX] == PREF_REPNZ_ID)
    {
        instr ->id = ID_PAUSE;
        instr ->groups = GRP_CACHECT | GRP_SSE2;
        idata ->prefixes[PREF_REP_INDEX] = 0xFF;
        unistrcpy(instr ->mnemonic, _UT("pause"));
    }

    return 0;
}

static uint32_t post_proc_multinop(struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint32_t *len, struct DISASM_PARAMS *params)
{
    UNREFERENCED_PARAMETER(len);

    if (params ->arch & ARCH_AMD)
    {
        if ((instr ->modrm & 0xC0) == 0xC0)
        {
            idata ->err = DASM_ERR_RM_REG;
        }
        else
        {
            switch((instr ->modrm >> 0x3) & 0x7)
            {
            case 0:
                unistrcpy(instr ->mnemonic, _UT("prefetch"));
                break;
            case 1:
                unistrcpy(instr ->mnemonic, _UT("prefetchw"));
                break;
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
                unistrcpy(instr ->mnemonic, _UT("prefetch"));
                break;
            }
        }
    }

    return 0;
}

static uint32_t post_proc_cmpxchg8b(struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint32_t *len, struct DISASM_PARAMS *params)
{
    UNREFERENCED_PARAMETER(len);

    instr ->opsize = 8;
    if (params ->mode == DISASSEMBLE_MODE_64)
    {
        if (idata ->prefixes[PREF_REX_INDEX] != 0xFF && instr ->rex & PREFIX_REX_W)
        {
            idata ->is_rex_used = 1;
            unistrcpy(instr ->mnemonic, _UT("cmpxchg16b"));
            instr ->ops[0].size = 16;
            instr ->opsize = 16;
        }
    }

    return 0;
}

static uint32_t post_proc_pextrd(struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint32_t *len, struct DISASM_PARAMS *params)
{
    UNREFERENCED_PARAMETER(len);

    if (params ->mode == DISASSEMBLE_MODE_64)
    {
        if (idata ->prefixes[PREF_REX_INDEX] != 0xFF && instr ->rex & PREFIX_REX_W)
        {
            idata ->is_rex_used = 1;
            instr ->id = ID_PEXTRQ;
            unistrcpy(instr ->mnemonic, _UT("pextrq"));
            instr ->ops[0].size = 8;
        }
    }

    return 0;
}

static uint32_t post_proc_pinsrd(struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint32_t *len, struct DISASM_PARAMS *params)
{
    UNREFERENCED_PARAMETER(len);

    if (params ->mode == DISASSEMBLE_MODE_64)
    {
        if (idata ->prefixes[PREF_REX_INDEX] != 0xFF && instr ->rex & PREFIX_REX_W)
        {
            idata ->is_rex_used = 1;
            instr ->id = ID_PINSRQ;
            unistrcpy(instr ->mnemonic, _UT("pinsrq"));
            instr ->ops[0].size = 8;
        }
    }

    return 0;
}

static uint32_t post_proc_lea(struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint32_t *len, struct DISASM_PARAMS *params)
{
    UNREFERENCED_PARAMETER(len);

    if (idata ->prefixes[PREF_SEG_INDEX] != 0xFF)
    {
        add_sf_prefix(idata ->prefixes, PREF_SEG_INDEX, instr, params);
    }

    return 0;
}

/*******************************
* Some internal common routines.
********************************
*/
static void movsx(void *value, unsigned int size1, unsigned int size2)
{
    uint8_t msb;

    if (size1 < size2)
    {
        msb = *((uint8_t *)((uint8_t *)value + size1 - 1));
        if (msb & 0x80)
            memset((uint8_t *)value + size1, 0xFF, size2 - size1);
        else
            memset((uint8_t *)value + size1, 0x0, size2 - size1);
    }
}

//Creates OPERAND_TYPE_REG operand of given type.
static void create_reg_operand(struct INSTRUCTION *instr, int op_index, uint8_t type, uint8_t code, uint16_t size)
{
    instr ->ops[op_index].flags |= OPERAND_TYPE_REG;
    instr ->ops[op_index].value.reg.type = type;
    instr ->ops[op_index].value.reg.code = code;
    instr ->ops[op_index].size = (uint8_t)size;
}

static void create_genreg_operand(struct INSTRUCTION *instr, int op_index, uint8_t code, uint16_t size, uint8_t rex_rxb, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if (mode != DISASSEMBLE_MODE_64)
    {
        if (code > REG_CODE_BX && size == 1)
        {
            code += 0xC;
        }
    }
    else
    {
        if (idata ->prefixes[PREF_REX_INDEX] == 0xFF)
        {
            if (code > REG_CODE_BX && size == 1)
            {
                code += 0xC;
            }
        }
        else
        {
            rex_rxb &= (PREFIX_REX_R | PREFIX_REX_X | PREFIX_REX_B);

            if (instr ->rex & rex_rxb)
            {
                code |= REG_CODE_64;
                idata ->is_rex_used = 1;
            }
        }
    }
    create_reg_operand(instr, op_index, REG_TYPE_GEN, code, size);
}

static void create_xmmreg_operand(struct INSTRUCTION *instr, int op_index, uint8_t code, uint16_t size, uint8_t rex, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if (mode == DISASSEMBLE_MODE_64 && idata ->prefixes[PREF_REX_INDEX] != 0xFF)
    {
        if (instr ->rex & rex)
        {
            code |= REG_CODE_64;
            idata ->is_rex_used = 1;
        }
    }
    create_reg_operand(instr, op_index, REG_TYPE_XMM, code, size);
}

//Returns size accordingly to disassemble mode and opsize prefix.
static uint8_t get_operand_size_16_32(struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    uint8_t res;

    if (mode == DISASSEMBLE_MODE_64)
        mode = DISASSEMBLE_MODE_32;

    if (idata ->prefixes[PREF_OPSIZE_INDEX] != 0xFF)
    {
        mode ^= (DISASSEMBLE_MODE_16 | DISASSEMBLE_MODE_32);
        idata ->is_opsize_used = 1;
    }

    if (mode == DISASSEMBLE_MODE_16)
        res = 2;
    else
        res = 4;

    return res;
}

//Returns size accordingly to disassemble mode, size override and REX.W prefixes.
static uint8_t get_operand_size(struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    uint8_t res;

    if (mode == DISASSEMBLE_MODE_64)
    {
        if (idata ->prefixes[PREF_REX_INDEX] != 0xFF && instr ->rex & PREFIX_REX_W)
        {
            res = 8;
            idata ->is_rex_used = 1;
        }
        else
        {
            res = get_operand_size_16_32(idata, mode);
        }
    }
    else
    {
        res = get_operand_size_16_32(idata, mode);
    }

    return res;
}

//Returns address size. Address size is common for all operands.
static void get_address_size(struct INSTRUCTION *instr, uint8_t prefixes[], uint8_t mode)
{
    if (mode == DISASSEMBLE_MODE_64)
    {
        if (prefixes[PREF_ADDRSIZE_INDEX] != 0xFF)
            instr ->addrsize = 4;
        else
            instr ->addrsize = 8;
    }
    else
    {
        if (prefixes[PREF_ADDRSIZE_INDEX] != 0xFF)
            mode ^= (DISASSEMBLE_MODE_16 | DISASSEMBLE_MODE_32);

        if (mode == DISASSEMBLE_MODE_16)
            instr ->addrsize = 2;
        else
            instr ->addrsize = 4;
    }
}

//Calculates segment for memory addressing operands accordingly to
//mode, segment override prefixes and address base register.
static void get_seg(struct INSTRUCTION *instr, int op_index, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if (idata ->prefixes[PREF_SEG_INDEX] == 0xFF)
    {
        if (mode == DISASSEMBLE_MODE_64)
        {
            instr ->ops[op_index].value.addr.seg = SREG_CODE_CS;
        }
        else
        {
            if ( !(instr ->ops[op_index].value.addr.mod & ADDR_MOD_BASE) )
            {
                instr ->ops[op_index].value.addr.seg = SREG_CODE_DS;
            }
            else
            {
                if ((instr ->ops[op_index].value.addr.base != REG_CODE_BP) && (instr ->ops[op_index].value.addr.base != REG_CODE_SP))
                {
                    instr ->ops[op_index].value.addr.seg = SREG_CODE_DS;
                }
                else
                {
                    instr ->ops[op_index].value.addr.seg = SREG_CODE_SS;
                }
            }
        }
    }
    else
    {
        if (mode == DISASSEMBLE_MODE_64)
        {
            if (idata ->prefixes[PREF_SEG_INDEX] == PREF_FS_ID || idata ->prefixes[PREF_SEG_INDEX] == PREF_GS_ID)
            {
                instr ->ops[op_index].value.addr.seg = sregs_codes[idata ->prefixes[PREF_SEG_INDEX]];
                idata ->is_seg_used = 1;
                instr ->ops[op_index].flags |= OPERAND_FLAG_SEG_OVERRIDE;
            }
            else
            {
                instr ->ops[op_index].value.addr.seg = SREG_CODE_CS;
            }
        }
        else
        {
            instr ->ops[op_index].value.addr.seg = sregs_codes[idata ->prefixes[PREF_SEG_INDEX]];

            //Set flag if prefix was really used.
            if ( !(instr ->ops[op_index].value.addr.mod & ADDR_MOD_BASE) )
            {
                if (idata ->prefixes[PREF_SEG_INDEX] != PREF_DS_ID)
                {
                    idata ->is_seg_used = 1;
                    instr ->ops[op_index].flags |= OPERAND_FLAG_SEG_OVERRIDE;
                }
            }
            else
            {
                if ((instr ->ops[op_index].value.addr.base == REG_CODE_BP) || (instr ->ops[op_index].value.addr.base == REG_CODE_SP))
                {
                    if (instr ->ops[op_index].value.addr.seg != SREG_CODE_SS)
                    {
                        idata ->is_seg_used = 1;
                        instr ->ops[op_index].flags |= OPERAND_FLAG_SEG_OVERRIDE;
                    }
                }
                else
                {
                    if (instr ->ops[op_index].value.addr.seg != SREG_CODE_DS)
                    {
                        idata ->is_seg_used = 1;
                        instr ->ops[op_index].flags |= OPERAND_FLAG_SEG_OVERRIDE;
                    }
                }
            }
        }
    }
}

//Builds ADDR.mod field from instruction's MODRM byte.
static void get_mod_type_modrm(struct INSTRUCTION *instr, int op_index)
{
    if (instr ->ops[op_index].value.addr.mod != 0x0)
    {
        instr ->ops[op_index].value.addr.mod = ADDR_MOD_BASE | ADDR_MOD_DISP;
    }
    else
    {
        switch(instr ->ops[op_index].value.addr.base)
        {
        case REG_CODE_IP:
            instr ->ops[op_index].value.addr.mod = ADDR_MOD_BASE | ADDR_MOD_DISP;
            break;
        case REG_CODE_BP:
        case REG_CODE_R13:
            instr ->ops[op_index].value.addr.mod = ADDR_MOD_DISP;
            break;
        default:
            instr ->ops[op_index].value.addr.mod = ADDR_MOD_BASE;
            break;
        }
    }
}

//Builds ADDR.mod field from instruction's SIB byte.
static void get_mod_type_sib(struct INSTRUCTION *instr, int op_index)
{
    if (instr ->ops[op_index].value.addr.index == REG_CODE_SP)
    {
        get_mod_type_modrm(instr, op_index);
    }
    else
    {
        if (instr ->ops[op_index].value.addr.mod == 0)
        {
            if ( (instr ->ops[op_index].value.addr.base == REG_CODE_BP) || (instr ->ops[op_index].value.addr.base == REG_CODE_R13) )
            {
                instr ->ops[op_index].value.addr.mod = ADDR_MOD_IDX | ADDR_MOD_DISP;
            }
            else
            {
                instr ->ops[op_index].value.addr.mod = ADDR_MOD_BASE | ADDR_MOD_IDX;
            }
        }
        else
        {
            instr ->ops[op_index].value.addr.mod = ADDR_MOD_BASE | ADDR_MOD_IDX | ADDR_MOD_DISP;
        }
    }
}

//Calculates displacement's size and copies it to struct DISPLACEMENT.
static uint8_t get_disp(struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, int op_index)
{
    uint8_t len;

    switch(instr ->ops[op_index].value.addr.mod)
    {
    case 0x0:
        if (instr ->ops[op_index].value.addr.base == REG_CODE_BP || instr ->ops[op_index].value.addr.base == REG_CODE_IP)
            len = instr ->addrsize;
        else
            len = 0x0;
        break;
    case 0x1:
        len = 0x1;
        break;
    case 0x2:
        len = instr ->addrsize;
        break;
    default:
        len = 0;
        idata ->severe_err = DASM_ERR_INTERNAL;
        break;
    }

    if (len == 8)
        len = 4;

    instr ->disp.size = len;
    if (len)
    {
        //memcpy(&(instr ->disp.value), offset, len);
        readbuff_get_bytes_inc(&idata ->rbuff, idata, &(instr ->disp.value), len);
        movsx(&(instr ->disp.value), len, 0x8);
        instr ->disp.offset = (uint8_t)(idata ->rbuff.offset - idata ->rbuff.origin_offset);
    }

    return len;
}

//Parses 16bit memory address operand.
static uint32_t parse_mem_operand_16(struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, int op_index)
{
    uint8_t len;
    unsigned int index;

    instr ->ops[op_index].value.addr.mod = instr ->modrm >> 0x6;
    len = get_disp(instr, idata, op_index);
    index = (instr ->modrm >> 0x3 & 0x18) | (instr ->modrm & 0x7);
    instr ->ops[op_index].value.addr.seg = addrs_16bit[index].seg;
    instr ->ops[op_index].value.addr.mod = addrs_16bit[index].mod;
    instr ->ops[op_index].value.addr.base = addrs_16bit[index].base;
    instr ->ops[op_index].value.addr.index = addrs_16bit[index].index;
    instr ->ops[op_index].value.addr.scale = addrs_16bit[index].scale;

    return len;
}

//Parses 32/64bit memory address operand.
static uint32_t parse_mem_operand_32_64(struct INSTRUCTION *instr, int op_index, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    uint32_t len = 0;

    if (instr ->flags & INSTR_FLAG_SIB)
    {
        instr ->ops[op_index].value.addr.mod = instr ->modrm >> 0x6;
        instr ->ops[op_index].value.addr.base = instr ->sib & 0x7;
        instr ->ops[op_index].value.addr.index = (instr ->sib >> 3) & 0x7;
        instr ->ops[op_index].value.addr.scale = 1 << (instr ->sib >> 0x6);

        if (mode == DISASSEMBLE_MODE_64 && idata ->prefixes[PREF_REX_INDEX] != 0xFF)
        {
            if (instr ->rex & PREFIX_REX_B)
            {
                instr ->ops[op_index].value.addr.base |= REG_CODE_64;
                idata ->is_rex_used = 1;
            }
            if (instr ->rex & PREFIX_REX_X)
            {
                instr ->ops[op_index].value.addr.index |= REG_CODE_64;
                idata ->is_rex_used = 1;
            }
        }
        len = get_disp(instr, idata, op_index);
        get_mod_type_sib(instr, op_index);
    }
    else
    {
        instr ->ops[op_index].value.addr.mod = instr ->modrm >> 0x6;
        instr ->ops[op_index].value.addr.base = instr ->modrm & 0x7;

        if (mode == DISASSEMBLE_MODE_64)
        {
            if (idata ->prefixes[PREF_REX_INDEX] != 0xFF && instr ->rex & PREFIX_REX_B)
            {
                instr ->ops[op_index].value.addr.base |= REG_CODE_64;
                idata ->is_rex_used = 1;
            }

            if ( (instr ->ops[op_index].value.addr.mod == 0x0) &&
                 ((instr ->ops[op_index].value.addr.base == REG_CODE_BP) ||
                  (instr ->ops[op_index].value.addr.base == REG_CODE_R13)) )
            {
                instr ->ops[op_index].value.addr.base = REG_CODE_IP;
            }
        }
        len = get_disp(instr, idata, op_index);
        get_mod_type_modrm(instr, op_index);
    }
    get_seg(instr, op_index, idata, mode);

    return len;
}

//Parses memory address operand.
static uint32_t parse_mem_operand(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    uint32_t len;

    instr ->ops[op_index].flags |= OPERAND_TYPE_MEM;
    instr ->ops[op_index].size = opsize ->size;
    if (instr ->addrsize == 2)
    {
        len = parse_mem_operand_16(instr, idata, op_index);
    }
    else
    {
        len = parse_mem_operand_32_64(instr, op_index, idata, mode);
    }
    idata ->is_addrsize_used = 1;

    return len;
}

//Parses operand accordingly to MODRM value.
static uint32_t parse_rm_operand(struct INSTRUCTION *instr, int op_index, struct OPERAND_SIZE *opsize, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    uint32_t len = 0;

    if ((instr ->modrm & 0xC0) == 0xC0)
    {
        create_genreg_operand(instr, op_index, instr ->modrm & 0x7, opsize ->size, PREFIX_REX_B, idata, mode);
    }
    else
    {
        len = parse_mem_operand(instr, op_index, opsize, idata, mode);
    }

    return len;
}

static uint32_t parse_operand(struct INTERNAL_OPERAND *iop, struct INSTRUCTION *instr, int op_index, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    uint32_t res = 0;
    struct OPERAND_SIZE opsize;

    if (iop ->flags & FLG_W)
        instr ->ops[op_index].flags |= OPERAND_FLAG_WRITE;
    if (iop ->flags & FLG_R)
        instr ->ops[op_index].flags |= OPERAND_FLAG_READ;
    if (iop ->flags & FLG_X)
        instr ->ops[op_index].flags |= OPERAND_FLAG_EXEC;

    if (iop ->type != TQ_NULL)
    {
        instr ->ops[op_index].flags |= OPERAND_FLAG_PRESENT;
        if (iop ->size >= sizeof(sq_handlers) / sizeof(sq_handlers[0]))
        {
            idata ->severe_err = DASM_ERR_INTERNAL;
        }
        else
        {
            sq_handlers[iop ->size](&opsize, instr, idata, mode);
        }

        if (iop ->size >= sizeof(tq_handlers) / sizeof(tq_handlers[0]))
        {
            idata ->severe_err = DASM_ERR_INTERNAL;
        }
        else
        {
            res = tq_handlers[iop ->type](instr, op_index, &opsize, idata, mode);
        }
    }

    return res;
}

//Checks if LOCK is superfluous.
static uint8_t check_lock_superfluous(struct INSTRUCTION *instr, struct OPCODE_DESCRIPTOR *opcode)
{
    uint8_t         res;
    int             i;
    struct OPERAND *op;

    if (!(opcode ->props & PROP_LOCK))
    {
        res = DASM_ERR_NON_LOCKABLE;
    }
    else
    {
        op = NULL;
        for (i = 0; i < MAX_OPERANDS_COUNT; i++)
        {
            if (instr ->ops[i].flags & OPERAND_TYPE_MEM)
            {
                op = instr ->ops + i;
                break;
            }
        }

        if (!op)
        {
            res = DASM_ERR_NON_LOCKABLE;
        }
        else if (!(op ->flags & OPERAND_FLAG_WRITE))
        {
            res = DASM_ERR_NON_LOCKABLE;
        }
        else
        {
            res = DASM_ERR_OK;
        }
    }

    return res;
}

//Applies disassembling options.
static void apply_disasm_options(struct INSTRUCTION *instr, uint32_t len, struct DISASM_PARAMS *params)
{
    int i;

    for (i = 0; i < MAX_OPERANDS_COUNT; i++)
    {
        if (params ->options & DISASM_OPTION_APPLY_REL)
        {
            if (instr ->ops[i].flags & OPERAND_FLAG_REL)
            {
                instr ->ops[i].value.imm.imm64 += len + params ->base;
            }
        }

        if (params ->options & DISASM_OPTION_OPTIMIZE_DISP)
        {
            if ((instr ->ops[i].flags & OPERAND_TYPE_MEM) && (instr ->ops[i].value.addr.mod != ADDR_MOD_DISP))
            {
                if (instr ->disp.value.d64 == 0x0)
                    instr ->ops[i].value.addr.mod &= ~ADDR_MOD_DISP;
            }
        }

        if (params ->options & DISASM_OPTION_COMPUTE_RIP)
        {
            if ((instr ->ops[i].flags & OPERAND_TYPE_MEM) &&
                (instr ->ops[i].value.addr.mod == (ADDR_MOD_BASE | ADDR_MOD_DISP)) &&
                (instr ->ops[i].value.addr.base == REG_CODE_IP))
            {
                instr ->ops[i].value.addr.mod = ADDR_MOD_DISP;
                instr ->disp.value.d64 += len + params ->base;
            }
        }
    }
}

//Copies instruction's flags from struct OPCODE_DESCRIPTOR to struct INSTRUCTION.
static void copy_instr_flags(struct INSTRUCTION *instr, struct OPCODE_DESCRIPTOR *opcode)
{
    if (opcode ->props & PROP_IOPL)
        instr ->flags |= INSTR_FLAG_IOPL;
    if (opcode ->props & PROP_RING0)
        instr ->flags |= INSTR_FLAG_RING0;
    if (opcode ->props & PROP_SERIAL)
        instr ->flags |= INSTR_FLAG_SERIAL;
    if (opcode ->props & PROP_UNDOC)
        instr ->flags |= INSTR_FLAG_UNDOC;
}

//Copies instruction's tested, modified, set, cleared and underfined
//eflags values from struct OPCODE_DESCRIPTOR to struct INSTRUCTION.
static void copy_eflags(struct INSTRUCTION *instr, struct OPCODE_DESCRIPTOR *opcode)
{
    instr ->tested_flags = opcode ->tested_flags;
    instr ->modified_flags = opcode ->modified_flags;
    instr ->set_flags = opcode ->set_flags;
    instr ->cleared_flags = opcode ->cleared_flags;
    instr ->undefined_flags = opcode ->undefined_flags;
}

//Copies MODRM and SIB bytes to struct INSTRUCTION.
static uint8_t parse_modrm_sib(struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, struct OPCODE_DESCRIPTOR *opcode)
{
    uint8_t len = 0;

    if (opcode ->props & PROP_MODRM)
    {
        len++;
        instr ->flags |= INSTR_FLAG_MODRM;
        readbuff_get_bytes_inc(&idata ->rbuff, idata, &instr ->modrm, 1);
        if (instr ->addrsize != 2)
        {
            if ((instr ->modrm & 0x7) == 0x4 && (instr ->modrm & 0xC0) != 0xC0)
            {
                len++;
                instr ->flags |= INSTR_FLAG_SIB;
                readbuff_get_bytes_inc(&idata ->rbuff, idata, &instr ->sib, 1);
            }
        }
    }

    return len;
}

//Converts prefixes from internal to external representation.
static void convert_prefixes(struct INSTRUCTION *instr, uint8_t prefixes[])
{
    int i;

    for (i = 0; i < PREFIX_COUNT; i++)
    {
        if (prefixes[i] != 0xFF)
            instr ->prefixes |= pref_bits[prefixes[i]];
    }
}

//If DISASM_PARAMS.sf_prefixes != NULL, copies superfluous prefix's value to the array.
static void add_sf_prefix_value(uint8_t prefixes[], int index, uint8_t value, struct INSTRUCTION *instr, struct DISASM_PARAMS *params)
{
    instr ->flags |= INSTR_FLAG_SF_PREFIXES;

    if (params ->sf_prefixes)
        params ->sf_prefixes[params ->sf_prefixes_len++] = value;
    prefixes[index] = 0xFF;
}

//Gets superfluous prefix's value by its index and call to function above :).
static void add_sf_prefix(uint8_t prefixes[], uint32_t index, struct INSTRUCTION *instr, struct DISASM_PARAMS *params)
{
    add_sf_prefix_value(prefixes, index, pref_opcodes[prefixes[index]], instr, params);
}

//Checks if opcode-extension prefixes (repz, repnz, opsize) are superfluous.
/*
static void check_ext_sf_prefixes(uint8_t prefixes[], struct INSTRUCTION *instr, struct DISASM_PARAMS *params)
{
    if (prefixes[PREF_OPSIZE_INDEX] != 0xFF)
        add_sf_prefix(prefixes, PREF_OPSIZE_INDEX, instr, params);
    if (prefixes[PREF_REP_INDEX] != 0xFF)
        add_sf_prefix(prefixes, PREF_OPSIZE_INDEX, instr, params);
}
*/

//Get instruction's size. Well, really this is size of implicit operand
// that influences on instruction's mnemonic.
static void get_instruction_opsize(struct MULTI_MNEMONIC *multi_mnemonic, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    struct OPERAND_SIZE opsize;

    if (multi_mnemonic ->size >= sizeof(sq_handlers) / sizeof(sq_handlers[0]))
    {
        opsize.sign = 0;
        opsize.size = 0;
        opsize.size_in_stream = 0;

        idata ->severe_err = DASM_ERR_INTERNAL;
    }
    else
    {
        sq_handlers[multi_mnemonic ->size](&opsize, instr, idata, mode);
    }

    instr ->opsize = (uint8_t)opsize.size; //Possible sizes are 2/4/8.
}

//Parses instruction's mnemonic. If mnemonic is simple, it is just copied to
// struct INSTRUCTION. If mnemonic contains has multi mnemonic indicator (MM_INDICATOR)
// at first character then it depends on implicit operand's size. In this case the function
// calls get_instruction_opsize and builds choses mnemonic basing on result.
static void parse_mnemonic(struct OPCODE_DESCRIPTOR *opcode, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t mode)
{
    if (opcode ->mnemonic.value[0] != MM_INDICATOR)
    {
        unistrcpy(instr ->mnemonic, opcode ->mnemonic.value);
    }
    else
    {
        get_instruction_opsize(opcode ->mnemonic.multi_mnemonic, instr, idata, mode);
        if (!instr ->opsize)
        {
            idata ->severe_err = DASM_ERR_INTERNAL;
        }
        else
        {
            if (instr ->opsize == 1)
            {
                unistrcpy(instr ->mnemonic,opcode ->mnemonic.multi_mnemonic ->values[0]);
            }
            else
            {
                unistrcpy(instr ->mnemonic,opcode ->mnemonic.multi_mnemonic ->values[bsf(instr ->opsize) - 1]);
            }
        }
    }
}

//Main function for parsing prefixes. Reads input stream until meets non-prefix byte
// or maximum instruction length is exceeded. The function checks if a prefix of the same group
// was already met and if so, replaces old prefix with a new one.
// Old prefix is added to superfluous prefixes array.
// The function also checks if a prefix is opcode-extension.
static uint32_t parse_prefixes(struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, uint8_t *ext_table_index, uint8_t *ext_pref_index, struct DISASM_PARAMS *params)
{
    uint8_t pref_code;
    uint8_t rex_found;
    uint8_t pref_id;
    uint8_t pref_index;
    uint32_t res;
    uint32_t tmp;
    struct OPCODE_DESCRIPTOR *ptr;

    res = 0;
    rex_found = 0;

    for(;;)
    {
        readbuff_get_bytes(&idata ->rbuff, idata, &pref_code, 1);
        /*pref_code = *offset;
        if (res > MAX_INSTRUCTION_LEN)
        {
            idata ->severe_err = DASM_ERR_TOO_LONG;//error: instruction too long.
            break;
        }
        */
        if (idata ->severe_err)
            break;

        ptr = &(tables[IDX_1BYTE].opcodes[pref_code]);
        if ( !( (ptr ->groups & GRP_PREFIX) ||
                (params ->mode == DISASSEMBLE_MODE_64 && pref_code >= 0x40 && pref_code <= 0x4F && !rex_found) ) )
        {
            break;
        }
        else
        {
            if (rex_found)
            {
                idata ->severe_err = DASM_ERR_REX_NOOPCD;//error: an opcode should follow after rex.
                break;
            }

            if (!rex_found && params ->mode == DISASSEMBLE_MODE_64)
            {
                if ( (pref_code >= 0x40) && (pref_code <= 0x4F) )
                {
                    idata ->prefixes[PREF_REX_INDEX] = PREF_REX_ID;
                    instr ->rex = pref_code;
                    rex_found = 1;

                    readbuff_inc(&idata ->rbuff, 1);
                    res++;
                    continue;
                }
            }

            tmp = tq_handlers[ptr ->ops[0].type](instr, 0, NULL, NULL, params ->mode);
            pref_index = (uint8_t)(tmp >> 8);
            pref_id = tmp & 0xFF;
            if (idata ->prefixes[pref_index] != 0xFF)
            {
                add_sf_prefix(idata ->prefixes, pref_index, instr, params);
            }
            idata ->prefixes[pref_index] = pref_id;

            //Used later for prefix table switch.
            if (ptr ->id == ID_66 || ptr ->id == ID_REPZ || ptr ->id == ID_REPNZ)
            {
                *ext_table_index = ptr ->props & 0xFF;
                *ext_pref_index = pref_index;
            }

            readbuff_inc(&idata ->rbuff, 1);
            res++;
        }
    }

    return res;
}

//Reads input stream and iterates through tables looking up appropriate struct OPCODE_DESCRIPTOR.
// Byte value at [offset] is used as index, the function checks tables limits and max instruction's length.
static uint32_t lookup_opcode(uint8_t table,
                              struct OPCODE_DESCRIPTOR **opcode_descr,
                              struct INSTRUCTION *instr,
                              struct DISASM_INTERNAL_DATA *idata)
{
    uint8_t max;
    uint8_t opcode, orig_opcode;
    uint32_t res;

    res = 0;
    *opcode_descr = NULL;
    for(;;)
    {
        readbuff_get_bytes(&idata ->rbuff, idata, &opcode, 1);
        orig_opcode = opcode;
        if (idata ->severe_err)
            break;
        opcode >>= tables[table].shift;
        opcode &= tables[table].mask;
        opcode -= tables[table].min;
        //It looks strange, but I want that table descriptors contain
        // "real" values.
        max = tables[table].max - tables[table].min;
        if (opcode > max)
        {
            idata ->severe_err = DASM_ERR_BADCODE;
            break;
        }

        if ( !(tables[table].props & TBL_PROP_MODRM) )
        {
            readbuff_inc(&idata ->rbuff, 1);
            res++;
            instr ->opcodes[instr ->opcodes_len++] = orig_opcode;
        }

        if (tables[table].opcodes[opcode].groups & GRP_SWITCH)
        {
            table = tables[table].opcodes[opcode].props & 0xFF;
            continue;
        }
        break;
    }

    if ( !(idata ->severe_err) )
        *opcode_descr = &(tables[table].opcodes[opcode]);

    return res;
}

//Main function for parsing opcode and prefixes. First of all it parses all prefixes and then
// looks up for struct OPCODE_DESCRIPTOR. The following algorithm is used to handle instructions that
// use prefixes as opcode extension:
//
// * Have we prefix that may be opcode extension?
//   No: Lookup starts from 1byte table.
//       * Is instruction found?
//         No: Error.
//         Yes: Success.
//   Yes: Lookup starts from 'ext_table_index' table.
//        * Is instruction found?
//          No: Lookup starts from 1byte table.
//              * Is instruction found?
//                No: Error.
//                Yes: Success.
//          Yes: Success.
static uint32_t parse_opcode(struct OPCODE_DESCRIPTOR **opcode_descr, struct INSTRUCTION *instr, struct DISASM_INTERNAL_DATA *idata, struct DISASM_PARAMS *params)
{
    uint8_t ext_table_index;
    uint8_t ext_prefix_index;
    uint32_t res;
    uint32_t tmp;

    ext_table_index = 0xFF;
    res = parse_prefixes(instr, idata, &ext_table_index, &ext_prefix_index, params);
    if (!idata ->severe_err)
    {
        instr ->opcode_offset = (uint8_t)res;

        if (ext_table_index != 0xFF && *(idata ->rbuff.offset) == 0xF)
        {
            tmp = lookup_opcode(ext_table_index, opcode_descr, instr, idata);
            if (!idata ->severe_err && (*opcode_descr) ->id != ID_NULL)
            {
                instr ->opcode_pref = pref_opcodes[idata ->prefixes[ext_prefix_index]];
                idata ->prefixes[ext_prefix_index] = 0xFF;
                //check_ext_sf_prefixes(idata ->prefixes, instr, params);
                if (idata ->prefixes[PREF_REP_INDEX] != 0xFF)
                {
                    add_sf_prefix(&idata ->prefixes[PREF_REP_INDEX], PREF_REP_INDEX, instr, params);
                }
                res += tmp;
            }
            else
            {
                idata ->severe_err = 0;
                instr ->opcodes_len = 0;

                readbuff_init(&idata ->rbuff,
                              idata ->rbuff.origin_offset,
                              idata ->rbuff.origin_offset + instr ->opcode_offset,
                              idata ->rbuff.length - instr ->opcode_offset);
                res += lookup_opcode(IDX_1BYTE, opcode_descr, instr, idata);
            }
        }
        else
        {
            res += lookup_opcode(IDX_1BYTE, opcode_descr, instr, idata);
        }

        if (!idata ->severe_err && (*opcode_descr) ->id == ID_NULL)
        {
            idata ->severe_err = DASM_ERR_BADCODE;//error: invalid opcode.
        }
    }

    return res;
}

//Disassembler's entry point. So long because does everything :).
uint32_t medi_disassemble(uint8_t *buff, size_t bufflen, struct INSTRUCTION *instr, struct DISASM_PARAMS *params)
{
    uint32_t len;
    uint32_t res;
    struct OPCODE_DESCRIPTOR *opcode;
    struct DISASM_INTERNAL_DATA idata;

    //Setup everything.
    memset(instr, 0x0, sizeof(*instr));
    memset(&idata, 0x0, sizeof(idata));
    memset(idata.prefixes, 0xFF, sizeof(idata.prefixes));
    readbuff_init(&idata.rbuff, buff, buff, bufflen);
    params ->sf_prefixes_len = 0;
    len = res = 0;

    //Lookup opcode.
    res = parse_opcode(&opcode, instr, &idata, params);
    if (idata.severe_err)
    {
        return idata.severe_err;
    }
    len += res;

    get_address_size(instr, idata.prefixes, params ->mode);

    //Parse MODRM and SIB bytes.
    res = parse_modrm_sib(instr, &idata, opcode);
    if (idata.severe_err)
    {
        return idata.severe_err;
    }
    len += res;

    //Copy flags, eflags, id, groups.
    copy_eflags(instr, opcode);
    copy_instr_flags(instr, opcode);
    instr ->id = opcode ->id;
    instr ->groups = opcode ->groups;

    //Parse mnemonic.
    parse_mnemonic(opcode, instr, &idata, params ->mode);
    if (idata.severe_err)
    {
        return idata.severe_err;
    }

    //Deal with operands.
    res = parse_operand(opcode ->ops, instr, 0, &idata, params ->mode);
    if (idata.severe_err)
    {
        return idata.severe_err;
    }
    len += res;

    res = parse_operand(opcode ->ops + 1, instr, 1, &idata, params ->mode);
    if (idata.severe_err)
    {
        return idata.severe_err;
    }
    len += res;

    res = parse_operand(opcode ->ops + 2, instr, 2, &idata, params ->mode);
    if (idata.severe_err)
    {
        return idata.severe_err;
    }
    len += res;

    //Do postprocessing if necessary.
    if (opcode ->props & PROP_POST_PROC)
    {
        res = postprocs[opcode ->props >> POST_PROC_SHIFT](instr, &idata, &len, params);
        if (idata.severe_err)
        {
            return idata.severe_err;
        }
    }

    //Check if REX is superfluous.
    if (params ->mode == DISASSEMBLE_MODE_64 && instr ->rex && !idata.is_rex_used)
        add_sf_prefix_value(idata.prefixes, PREF_REX_INDEX, instr ->rex, instr, params);
    //Check if opsize is superfluous. 
    if (!idata.is_opsize_used && idata.prefixes[PREF_OPSIZE_INDEX] != 0xFF)
        add_sf_prefix(idata.prefixes, PREF_OPSIZE_INDEX, instr, params);
    //Check if addrsize is superfluous. 
    if (!idata.is_addrsize_used && idata.prefixes[PREF_ADDRSIZE_INDEX] != 0xFF)
        add_sf_prefix(idata.prefixes, PREF_ADDRSIZE_INDEX, instr, params);
    //Check if segment prefix is superfluous. 
    if (!idata.is_seg_used && idata.prefixes[PREF_SEG_INDEX] != 0xFF)
        add_sf_prefix(idata.prefixes, PREF_SEG_INDEX, instr, params);
    //Check if repz/repnz prefix is superfluous.
    if (!(opcode ->props & PROP_ALLOW_REP) && idata.prefixes[PREF_REP_INDEX] != 0xFF)
        add_sf_prefix(idata.prefixes, PREF_REP_INDEX, instr, params);

    //Convert prefixes to output representation.
    convert_prefixes(instr, idata.prefixes);

    //And post checks.
    if (!(params ->arch & opcode ->arch))
        idata.err = DASM_ERR_ANOT_ARCH;//error: another architecture.
    else if (instr ->prefixes & INSTR_PREFIX_LOCK)
        idata.err = check_lock_superfluous(instr, opcode);//error: check if prefix lock on non-lockable instruction.
    else if ((opcode ->props & PROP_I64) && (params ->mode == DISASSEMBLE_MODE_64))
        idata.err = DASM_ERR_16_32_ONLY;//error: instruction is 16/32bit mode only.
    else if (opcode ->props & PROP_O64 && params ->mode != DISASSEMBLE_MODE_64)
        idata.err = DASM_ERR_64_ONLY;//error: instruction is 64bit mode only.

    apply_disasm_options(instr, len, params);

    //Copy length
    instr ->length = (uint8_t)len;

    return idata.err;
}