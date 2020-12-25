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
*/

#include <stdlib.h>
#include <string.h>
#include "mediana.h"

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER
#endif

struct STREAM
{
    unichar_t *origin;
    unichar_t *offset;
    size_t     bufflen;
    size_t     reallen;
};

static int internal_dump_reg(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr, int op_index);
static int internal_dump_addr(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr, int op_index);

#if defined(MEDIANA_CTRL_DUMP)

unichar_t *regs8[] = 
{
    _UT("al"), _UT("cl"), _UT("dl"), _UT("bl"), _UT("spl"), _UT("bpl"), _UT("sil"), _UT("dil"),
    _UT("r8b"), _UT("r9b"), _UT("r10b"), _UT("r11b"), _UT("r12b"), _UT("r13b"), _UT("r14b"), _UT("r15b"),
    _UT("ah"), _UT("ch"), _UT("dh"), _UT("bh"), _UT("badreg8")
};

unichar_t *regs16[] = 
{
    _UT("ax"), _UT("cx"), _UT("dx"), _UT("bx"), _UT("sp"), _UT("bp"), _UT("si"), _UT("di"),
    _UT("r8w"), _UT("r9w"), _UT("r10w"), _UT("r11w"), _UT("r12w"), _UT("r13w"), _UT("r14w"), _UT("r15w"),
    _UT("badreg16_1"), _UT("badreg16_2"), _UT("badreg16_3"), _UT("badreg16_4"), _UT("badreg16_5"),
};

unichar_t *regs32[] = 
{
    _UT("eax"), _UT("ecx"), _UT("edx"), _UT("ebx"), _UT("esp"), _UT("ebp"), _UT("esi"), _UT("edi"),
    _UT("r8d"), _UT("r9d"), _UT("r10d"), _UT("r11d"), _UT("r12d"), _UT("r13d"), _UT("r14d"), _UT("r15d"),
    _UT("badreg32_1"), _UT("badreg32_2"), _UT("badreg32_3"), _UT("badreg32_4"), _UT("eip"),
};

unichar_t *regs64[] = 
{
    _UT("rax"), _UT("rcx"), _UT("rdx"), _UT("rbx"), _UT("rsp"), _UT("rbp"), _UT("rsi"), _UT("rdi"),
    _UT("r8"), _UT("r9"), _UT("r10"), _UT("r11"), _UT("r12"), _UT("r13"), _UT("r14"), _UT("r15"),
    _UT("badreg64_1"), _UT("badreg64_2"), _UT("badreg64_3"), _UT("badreg64_4"), _UT("rip"),
};

unichar_t *sregs[] = 
{
    _UT("es"), _UT("cs"), _UT("ss"), _UT("ds"), _UT("fs"), _UT("gs"), _UT("badsreg7"), _UT("badsreg8")
};

unichar_t *fregs[] = 
{
    _UT("st0"), _UT("st1"), _UT("st2"), _UT("st3"), _UT("st4"), _UT("st5"), _UT("st6"), _UT("st7"), _UT("badfreg8")
};

unichar_t *cregs[] = 
{
    _UT("cr0"), _UT("cr1"), _UT("cr2"), _UT("cr3"), _UT("cr4"), _UT("cr5"), _UT("cr6"), _UT("cr7"), _UT("cr8"), _UT("badcreg9")
};

unichar_t *dregs[] = 
{
    _UT("dr0"), _UT("dr1"), _UT("dr2"), _UT("dr3"), _UT("dr4"), _UT("dr5"), _UT("dr6"), _UT("dr7"), _UT("baddreg")
};

unichar_t *tregs[] = 
{
    _UT("tr0"), _UT("tr1"), _UT("tr2"), _UT("tr3"), _UT("tr4"), _UT("tr5"), _UT("tr6"), _UT("tr7"), _UT("badtreg")
};

unichar_t *mregs[] = 
{
    _UT("mm0"), _UT("mm1"), _UT("mm2"), _UT("mm3"), _UT("mm4"), _UT("mm5"), _UT("mm6"), _UT("mm7"), _UT("badmreg8")
};

unichar_t *xregs[] = 
{
    _UT("xmm0"), _UT("xmm1"), _UT("xmm2"), _UT("xmm3"), _UT("xmm4"), _UT("xmm5"), _UT("xmm6"), _UT("xmm7"),
    _UT("xmm8"), _UT("xmm9"), _UT("xmm10"), _UT("xmm11"), _UT("xmm12"), _UT("xmm13"), _UT("xmm14"), _UT("xmm15"),
    _UT("badxreg16")
};

//Common dump functions.
void safe_init(struct STREAM *stream, unichar_t *offset, size_t bufflen)
{
    stream ->origin = offset;
    stream ->offset = offset;
    stream ->bufflen = bufflen;
    stream ->reallen = 0;
}

void safe_tell(const struct STREAM *stream, size_t *reallen, size_t *bufflen)
{
    *reallen = stream ->reallen;
    *bufflen = stream ->bufflen;
}

void safe_seek(struct STREAM *stream, size_t reallen, size_t bufflen)
{
    stream ->reallen = reallen;
    stream ->bufflen -= bufflen;
}

void safe_insert_unichar(struct STREAM *stream, unichar_t ch)
{
    if (stream ->bufflen)
    {
        *stream ->offset = ch;
        stream ->bufflen--;
        stream ->offset++;
    }
    stream ->reallen++;
}

void safe_remove_unichar(struct STREAM *stream)
{
    if (stream ->offset > stream ->origin)
    {
        stream ->bufflen++;
        stream ->offset--;
    }
    if (stream ->reallen)
    {
        stream ->reallen--;
    }
}

void safe_unistrncpy(struct STREAM *stream, const unichar_t *src)
{
    while (*src)
    {
        safe_insert_unichar(stream, *src);
        src++;
    }
}

void safe_itoa(struct STREAM *stream, uint64_t num, uint16_t size, int is_signed, int need_sign, int radix)
{
    char dig;
    uint64_t div;
    uint64_t tmp;

    div = 1;
    if (is_signed)
    {
        uint8_t *ptr = (uint8_t *)&num;
        ptr += size - 1;
        if (*ptr & 0x80)
        {
            if (need_sign)
            {
                safe_insert_unichar(stream, '-');
            }
            num = ~num; //Just to shut up the warning.
            num++;
        }
    }

    tmp = 0xFFFFFFFFFFFFFFFFL;
    for(size = 8 - size + 1; size; size--)
    {
        num &= tmp;
        tmp >>= 0x8;
    }

    while(num / div >= radix)
        div *= radix;
    while(div)
    {
        dig = (uint8_t)((num / div) % radix);
        if (dig >= 10)
            dig += 'A' - 10;
        else
            dig += '0';
        safe_insert_unichar(stream, dig);
        div /= radix;
    }
}
#endif //defined(MEDIANA_CTRL_DUMP) || defined(MEDIANA_CTRL_DUMP_DBG)

#ifdef MEDIANA_CTRL_DUMP

/***********************
* Default dump_handlers.
************************
*/
static struct DUMP_HANDLERS_REG dump_handlers_reg_default =
{
    dump_reg_sreg,
    dump_reg_gen,
    dump_reg_freg,
    dump_reg_creg,
    dump_reg_dreg,
    dump_reg_treg,
    dump_reg_mreg,
    dump_reg_xreg
};

static int (MEDIANA_API *dump_handlers_addr_default[])(struct DUMP_HANDLERS *, struct STREAM *, const struct INSTRUCTION *, int) =
{
    dump_addr_ptr_size,
    dump_addr_seg_reg,
    dump_addr_open_brace,
    dump_addr_base_reg,
    dump_addr_base_idx_delimiter,
    dump_addr_idx,
    dump_addr_idx_mltplr_delimiter,
    dump_addr_idx_mltplr,
    dump_addr_mltplr_disp_delimiter,
    dump_addr_disp,
    dump_addr_close_brace
};

static int (MEDIANA_API *dump_handlers_instr_default[])(struct DUMP_HANDLERS *, struct STREAM *, const struct INSTRUCTION *) =
{
    dump_prefixes,
    dump_prefixes_mnem_delimiter,
    dump_mnemonic,
    dump_mnem_ops_delimiter,
    dump_operand0,
    dump_op0_op1_delimiter,
    dump_operand1,
    dump_op1_op2_delimiter,
    dump_operand2
};

/*************************
* Base internal functions.
**************************
*/
static int internal_dump_addr(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr, int op_index)
{
    int i, res;

    res = 1;
    for (i = 0; i < dump_handlers ->addr_handlers_len; i++)
    {
        res = dump_handlers ->dump_handlers_addr[i](dump_handlers, stream, instr, op_index);
        if (!res)
            break;
    }

    return res;
}

static int internal_dump_reg(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr, int op_index)
{
    uint8_t code, type;
    int     res;
    struct DUMP_HANDLERS_REG *handlers;
    
    type = instr ->ops[op_index].value.reg.type;
    code = instr ->ops[op_index].value.reg.code;
    handlers = dump_handlers ->dump_handlers_reg;

    switch(type)
    {
    case REG_TYPE_GEN:
        res = handlers ->dump_reg_gen(dump_handlers, stream, code, instr ->ops[op_index].size);
        break;
    case REG_TYPE_SEG:
        res = handlers ->dump_reg_sreg(dump_handlers, stream, code);
        break;
    case REG_TYPE_FPU:
        res = handlers ->dump_reg_freg(dump_handlers, stream, code);
        break;
    case REG_TYPE_CR:
        res = handlers ->dump_reg_creg(dump_handlers, stream, code);
        break;
    case REG_TYPE_DBG:
        res = handlers ->dump_reg_dreg(dump_handlers, stream, code);
        break;
    case REG_TYPE_TR:
        res = handlers ->dump_reg_treg(dump_handlers, stream, code);
        break;
    case REG_TYPE_MMX:
        res = handlers ->dump_reg_mreg(dump_handlers, stream, code);
        break;
    case REG_TYPE_XMM:
        res = handlers ->dump_reg_xreg(dump_handlers, stream, code);
        break;
    default:
        safe_unistrncpy(stream, _UT("internal error"));
        res = 0;
        break;
    }

    return res;
}

static int internal_dump_operand(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION *instr, int op_index)
{
    int res;
    const struct OPERAND *op;

    res = 0;
    if (op_index > 3 || op_index < 0)
    {
        safe_unistrncpy(stream, _UT("bad operand index"));
        return res;
    }
    else
    {
        op = instr ->ops + op_index;
        if (op ->flags & OPERAND_FLAG_PRESENT)
        {
            switch (op ->flags & OPERAND_TYPE_MASK)
            {
            case OPERAND_TYPE_REG:
                res = internal_dump_reg(dump_handlers, stream, instr, op_index);
                break;
            case OPERAND_TYPE_MEM:
                res = internal_dump_addr(dump_handlers, stream, instr, op_index);
                break;
            case OPERAND_TYPE_IMM:
                res = dump_handlers ->dump_handler_imm(dump_handlers, stream, instr, op_index);
                break;
            case OPERAND_TYPE_DIR:
                res = dump_handlers ->dump_handler_dir(dump_handlers, stream, instr, op_index);
                break;
            default:
                res = 0;
                safe_unistrncpy(stream, _UT("bad operand type"));
                break;
            }
        }
    }

    return res;
}

static void prepare_dump_handlers_reg(struct DUMP_HANDLERS_REG *local_dump_handlers_reg)
{
    if (local_dump_handlers_reg ->dump_reg_sreg == NULL)
        local_dump_handlers_reg ->dump_reg_sreg = dump_reg_sreg;

    if (local_dump_handlers_reg ->dump_reg_gen == NULL)
        local_dump_handlers_reg ->dump_reg_gen = dump_reg_gen;

    if (local_dump_handlers_reg ->dump_reg_freg == NULL)
        local_dump_handlers_reg ->dump_reg_freg = dump_reg_freg;

    if (local_dump_handlers_reg ->dump_reg_creg == NULL)
        local_dump_handlers_reg ->dump_reg_creg = dump_reg_creg;

    if (local_dump_handlers_reg ->dump_reg_dreg == NULL)
        local_dump_handlers_reg ->dump_reg_dreg = dump_reg_dreg;

    if (local_dump_handlers_reg ->dump_reg_treg == NULL)
        local_dump_handlers_reg ->dump_reg_treg = dump_reg_treg;

    if (local_dump_handlers_reg ->dump_reg_mreg == NULL)
        local_dump_handlers_reg ->dump_reg_mreg = dump_reg_mreg;

    if (local_dump_handlers_reg ->dump_reg_xreg == NULL)
        local_dump_handlers_reg ->dump_reg_xreg = dump_reg_xreg;
}

static void prepare_dump_handlers(struct DUMP_HANDLERS *local_dump_handlers,
                                  struct DUMP_HANDLERS_REG *local_dump_handlers_reg,
                                  struct DUMP_HANDLERS *dump_handlers)
{
    if (!dump_handlers)
    {
        local_dump_handlers ->dump_handlers_instr = dump_handlers_instr_default;
        local_dump_handlers ->instr_handlers_len = 
            sizeof(dump_handlers_instr_default) / sizeof(dump_handlers_instr_default[0]);

        local_dump_handlers ->dump_handlers_addr = dump_handlers_addr_default;
        local_dump_handlers ->addr_handlers_len = 
            sizeof(dump_handlers_addr_default) / sizeof(dump_handlers_addr_default[0]);

        local_dump_handlers ->dump_handlers_reg = &dump_handlers_reg_default;
        local_dump_handlers ->dump_handler_imm = dump_operand_imm;
        local_dump_handlers ->dump_handler_dir = dump_operand_dir;
    }
    else
    {
        memcpy(local_dump_handlers, dump_handlers, sizeof(struct DUMP_HANDLERS));
        if (local_dump_handlers ->dump_handlers_reg)
        {
            memcpy(local_dump_handlers_reg, dump_handlers ->dump_handlers_reg, sizeof(struct DUMP_HANDLERS_REG));
            local_dump_handlers ->dump_handlers_reg = local_dump_handlers_reg;
            prepare_dump_handlers_reg(local_dump_handlers ->dump_handlers_reg);
        }
        else
        {
            local_dump_handlers ->dump_handlers_reg = &dump_handlers_reg_default;
        }

        if (local_dump_handlers ->dump_handlers_instr == NULL)
        {
            local_dump_handlers ->dump_handlers_instr = dump_handlers_instr_default;
            local_dump_handlers ->instr_handlers_len = 
                sizeof(dump_handlers_instr_default) / sizeof(dump_handlers_instr_default[0]);
        }
        if (local_dump_handlers ->dump_handlers_addr == NULL)
        {
            local_dump_handlers ->dump_handlers_addr = dump_handlers_addr_default;
            local_dump_handlers ->addr_handlers_len = 
                sizeof(dump_handlers_addr_default) / sizeof(dump_handlers_addr_default[0]);
        }
        if (local_dump_handlers ->dump_handler_imm == NULL)
        {
            local_dump_handlers ->dump_handler_imm = dump_operand_imm;
        }
        if (local_dump_handlers ->dump_handler_dir == NULL)
        {
            local_dump_handlers ->dump_handler_dir = dump_operand_dir;
        }
    }
}
/**************************
* Public dump dir function.
***************************
*/
int MEDIANA_API dump_operand_dir(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr, int op_index)
{
    const struct OPERAND *op;

    UNREFERENCED_PARAMETER(dump_handlers);

    op = instr ->ops + op_index;
    switch (op ->size)
    {
    case 4:
        safe_itoa(stream, op ->value.far_addr.far_addr32.seg, 0x2, 0x0, 0x0, 0x10);
        safe_insert_unichar(stream, ':');
        safe_itoa(stream, op ->value.far_addr.far_addr32.offset, 0x2, 0x0, 0x0, 0x10);
        break;
    case 6:
        safe_itoa(stream, op ->value.far_addr.far_addr48.seg, 0x2, 0x0, 0x0, 0x10);
        safe_insert_unichar(stream, ':');
        safe_itoa(stream, op ->value.far_addr.far_addr48.offset, 0x4, 0x0, 0x0, 0x10);
        break;
    default:
        safe_unistrncpy(stream, _UT("internal error"));
        break;
    }

    return 1;
}

/**************************
* Public dump imm function.
***************************
*/
int MEDIANA_API dump_operand_imm(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr, int op_index)
{
    const struct OPERAND *op;

    UNREFERENCED_PARAMETER(dump_handlers);

    op = instr ->ops + op_index;
    if (op ->value.imm.imm64 > 9)
    {
        safe_insert_unichar(stream, _UT('0'));
    }
    safe_itoa(stream, op ->value.imm.imm64, op ->size, 0x0, 0x0, 0x10);
    if (op ->value.imm.imm64 > 9)
    {
        safe_insert_unichar(stream, _UT('h'));
    }

    return 1;
}


/***************************
* Public dump reg functions.
****************************
*/
int MEDIANA_API dump_reg_sreg(struct DUMP_HANDLERS * dump_handlers, struct STREAM *stream, uint8_t code)
{
    UNREFERENCED_PARAMETER(dump_handlers);

    safe_unistrncpy(stream, sregs[code]);

    return 1;
}

int MEDIANA_API dump_reg_gen(struct DUMP_HANDLERS * dump_handlers, struct STREAM *stream, uint8_t code, uint16_t size)
{
    UNREFERENCED_PARAMETER(dump_handlers);

    switch(size)
    {
    case 1:
        safe_unistrncpy(stream, regs8[code]);
        break;
    case 2:
        safe_unistrncpy(stream, regs16[code]);
        break;
    case 4:
        safe_unistrncpy(stream, regs32[code]);
        break;
    case 8:
        safe_unistrncpy(stream, regs64[code]);
        break;
    }

    return 1;
}

int MEDIANA_API dump_reg_freg(struct DUMP_HANDLERS * dump_handlers, struct STREAM *stream, uint8_t code)
{
    UNREFERENCED_PARAMETER(dump_handlers);

    safe_unistrncpy(stream, fregs[code]);

    return 1;
}

int MEDIANA_API dump_reg_creg(struct DUMP_HANDLERS * dump_handlers, struct STREAM *stream, uint8_t code)
{
    UNREFERENCED_PARAMETER(dump_handlers);

    safe_unistrncpy(stream, cregs[code]);

    return 1;
}

int MEDIANA_API dump_reg_dreg(struct DUMP_HANDLERS * dump_handlers, struct STREAM *stream, uint8_t code)
{
    UNREFERENCED_PARAMETER(dump_handlers);

    safe_unistrncpy(stream, dregs[code]);

    return 1;
}

int MEDIANA_API dump_reg_treg(struct DUMP_HANDLERS * dump_handlers, struct STREAM *stream, uint8_t code)
{
    UNREFERENCED_PARAMETER(dump_handlers);

    safe_unistrncpy(stream, tregs[code]);

    return 1;
}

int MEDIANA_API dump_reg_mreg(struct DUMP_HANDLERS * dump_handlers, struct STREAM *stream, uint8_t code)
{
    UNREFERENCED_PARAMETER(dump_handlers);

    safe_unistrncpy(stream, mregs[code]);

    return 1;
}

int MEDIANA_API dump_reg_xreg(struct DUMP_HANDLERS * dump_handlers, struct STREAM *stream, uint8_t code)
{
    UNREFERENCED_PARAMETER(dump_handlers);

    safe_unistrncpy(stream, xregs[code]);

    return 1;
}

/****************************
* Public dump addr functions.
*****************************
*/
void dump_ptr_size(struct STREAM *stream, const struct OPERAND *op)
{
    switch(op ->size)
    {
    case 1:
        safe_unistrncpy(stream, _UT("byte ptr"));
        break;
    case 2:
        safe_unistrncpy(stream, _UT("word ptr"));
        break;
    case 4:
        safe_unistrncpy(stream, _UT("dword ptr"));
        break;
    case 6:
        safe_unistrncpy(stream, _UT("fword ptr"));
        break;
    case 8:
        safe_unistrncpy(stream, _UT("qword ptr"));
        break;
    case 10:
        safe_unistrncpy(stream, _UT("tbyte ptr"));
        break;
    case 16:
        safe_unistrncpy(stream, _UT("dqword ptr"));
        break;
    case 14:
        safe_unistrncpy(stream, _UT("14bytes ptr"));
        break;
    case 28:
        safe_unistrncpy(stream, _UT("28bytes ptr"));
        break;
    case 94:
        safe_unistrncpy(stream, _UT("94bytes ptr"));
        break;
    case 108:
        safe_unistrncpy(stream, _UT("108bytes ptr"));
        break;
    case 512:
        safe_unistrncpy(stream, _UT("512bytes ptr"));
        break;
    default:
        safe_unistrncpy(stream, _UT("strange ptr"));
        break;
    }
}

int need_ptr_size(const struct INSTRUCTION * instr)
{
    int res;
    int i, ops_count;

    res = ops_count = 0;
    for (i = 0; i < 3; i++)
    {
        if (instr ->ops[i].flags & OPERAND_FLAG_PRESENT)
        {
            ops_count++;
        }
    }

    if (ops_count == 1)
    {
        if ((instr ->ops[0].flags & OPERAND_TYPE_MASK) == OPERAND_TYPE_MEM)
        {
            res = 1;
        }
    }
    else //if (ops_count == 2)
    {
        if ( ((instr ->ops[0].flags & OPERAND_TYPE_MASK) == OPERAND_TYPE_MEM) && ((instr ->ops[1].flags & OPERAND_TYPE_MASK) == OPERAND_TYPE_IMM) )
        {
            res = 1;
        }
        else if ( ((instr ->ops[0].flags & OPERAND_TYPE_MASK) != OPERAND_TYPE_MEM) && ((instr ->ops[1].flags & OPERAND_TYPE_MASK) == OPERAND_TYPE_MEM) )
        {
            if (instr ->ops[0].size != instr ->ops[1].size)
            {
                res = 1;
            }
        }
    }

    return res;
}

int MEDIANA_API dump_addr_ptr_size(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr, int op_index)
{
    UNREFERENCED_PARAMETER(dump_handlers);

    if (need_ptr_size(instr))
    {
        dump_ptr_size(stream, instr ->ops + op_index);
        safe_insert_unichar(stream, _UT(' '));
    }

    return 1;
}

int MEDIANA_API dump_addr_seg_reg(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr, int op_index)
{
    UNREFERENCED_PARAMETER(dump_handlers);

    if (instr ->ops[op_index].flags & OPERAND_FLAG_SEG_OVERRIDE)
    {
        safe_unistrncpy(stream, sregs[instr ->ops[op_index].value.addr.seg]);
        safe_insert_unichar(stream, _UT(':'));
    }

    return 1;
}

int MEDIANA_API dump_addr_open_brace(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr, int op_index)
{
    UNREFERENCED_PARAMETER(dump_handlers);
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(op_index);

    safe_insert_unichar(stream, _UT('['));

    return 1;
}

int MEDIANA_API dump_addr_base_reg(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr, int op_index)
{
    const struct OPERAND *op;

    op = instr ->ops + op_index;
    if (op ->value.addr.mod & ADDR_MOD_BASE)
    {
        dump_reg_gen(dump_handlers, stream, op ->value.addr.base, instr ->addrsize);
    }

    return 1;
}

int MEDIANA_API dump_addr_base_idx_delimiter(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr, int op_index)
{
    const struct OPERAND *op;

    UNREFERENCED_PARAMETER(dump_handlers);

    op = instr ->ops + op_index;
    if (op ->value.addr.mod & ADDR_MOD_BASE && (op ->value.addr.mod & ADDR_MOD_IDX || op ->value.addr.mod & ADDR_MOD_DISP))
    {
        safe_insert_unichar(stream, _UT('+'));
    }

    return 1;
}

int MEDIANA_API dump_addr_idx(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr, int op_index)
{
    const struct OPERAND *op;

    op = instr ->ops + op_index;
    if (op ->value.addr.mod & ADDR_MOD_IDX)
    {
        dump_reg_gen(dump_handlers, stream, op ->value.addr.index, instr ->addrsize);
    }

    return 1;
}

int MEDIANA_API dump_addr_idx_mltplr_delimiter(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr, int op_index)
{
    const struct OPERAND *op;

    UNREFERENCED_PARAMETER(dump_handlers);

    op = instr ->ops + op_index;
    if (op ->value.addr.mod & ADDR_MOD_IDX)
    {
        safe_insert_unichar(stream, _UT('*'));
    }

    return 1;
}

int MEDIANA_API dump_addr_idx_mltplr(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr, int op_index)
{
    const struct OPERAND *op;

    UNREFERENCED_PARAMETER(dump_handlers);

    op = instr ->ops + op_index;
    if (op ->value.addr.mod & ADDR_MOD_IDX)
    {
        safe_itoa(stream, op ->value.addr.scale, 0x1, 0x0, 0x0, 0xA);
    }

    return 1;
}

int MEDIANA_API dump_addr_mltplr_disp_delimiter(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr, int op_index)
{
    const struct OPERAND *op;

    UNREFERENCED_PARAMETER(dump_handlers);

    op = instr ->ops + op_index;
    if (op ->value.addr.mod & ADDR_MOD_IDX && op ->value.addr.mod & ADDR_MOD_DISP)
    {
        safe_insert_unichar(stream, _UT('+'));
    }

    return 1;
}

int MEDIANA_API dump_addr_disp(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr, int op_index)
{
    const struct OPERAND *op;

    UNREFERENCED_PARAMETER(dump_handlers);

    op = instr ->ops + op_index;
    if (op ->value.addr.mod & ADDR_MOD_DISP)
    {
        if (instr ->disp.value.d64 > 9)
        {
            safe_insert_unichar(stream, _UT('0'));
        }
        safe_itoa(stream, instr ->disp.value.d64, instr ->addrsize, 0x0, 0x0, 0x10);
        if (instr ->disp.value.d64 > 9)
        {
            safe_insert_unichar(stream, _UT('h'));
        }        
    }

    return 1;
}

int MEDIANA_API dump_addr_close_brace(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr, int op_index)
{
    UNREFERENCED_PARAMETER(dump_handlers);
    UNREFERENCED_PARAMETER(instr);
    UNREFERENCED_PARAMETER(op_index);

    safe_insert_unichar(stream, _UT(']'));

    return 1;
}

/*****************************
* Public dump instr functions.
******************************
*/
int MEDIANA_API dump_operand2(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr)
{
    return internal_dump_operand(dump_handlers, stream, instr, 2);
}

int MEDIANA_API dump_op1_op2_delimiter(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr)
{
    int res;

    UNREFERENCED_PARAMETER(dump_handlers);

    res = 0;
    if (instr ->ops[2].flags & OPERAND_FLAG_PRESENT)
    {
        safe_unistrncpy(stream, _UT(", "));
        res = 1;
    }

    return res;
}

int MEDIANA_API dump_operand1(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr)
{
    return internal_dump_operand(dump_handlers, stream, instr, 1);
}

int MEDIANA_API dump_op0_op1_delimiter(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr)
{
    int res;

    UNREFERENCED_PARAMETER(dump_handlers);

    res = 0;
    if (instr ->ops[1].flags & OPERAND_FLAG_PRESENT)
    {
        safe_unistrncpy(stream, _UT(", "));
        res = 1;
    }

    return res;
}

int MEDIANA_API dump_operand0(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr)
{
    return internal_dump_operand(dump_handlers, stream, instr, 0);
}

int MEDIANA_API dump_mnem_ops_delimiter(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr)
{
    UNREFERENCED_PARAMETER(dump_handlers);
    UNREFERENCED_PARAMETER(instr);

    if (instr ->ops[0].flags & OPERAND_FLAG_PRESENT)
    {
        safe_insert_unichar(stream, _UT(' '));
    }

    return 1;
}

int MEDIANA_API dump_mnemonic(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr)
{
    UNREFERENCED_PARAMETER(dump_handlers);

    safe_unistrncpy(stream, instr ->mnemonic);

    return 1;
}

int MEDIANA_API dump_prefixes_mnem_delimiter(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr)
{
    UNREFERENCED_PARAMETER(dump_handlers);

    if (instr ->prefixes & INSTR_PREFIX_LOCK || instr ->prefixes & INSTR_PREFIX_REP_MASK)
        safe_insert_unichar(stream, _UT(' '));

    return 1;
}

int MEDIANA_API dump_prefixes(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION * instr)
{
    int found;

    UNREFERENCED_PARAMETER(dump_handlers);

    found = 0;
    if (instr ->prefixes & INSTR_PREFIX_LOCK)
    {
        safe_unistrncpy(stream, _UT("lock "));
        found = 1;
    }
    if (instr ->prefixes & INSTR_PREFIX_REPZ)
    {
        safe_unistrncpy(stream, _UT("repz "));
        found = 1;
    }
    if (instr ->prefixes & INSTR_PREFIX_REPNZ)
    {
        safe_unistrncpy(stream, _UT("repnz "));
        found = 1;
    }

    if (found)
        safe_remove_unichar(stream);

    return 1;
}

size_t medi_dump(const struct INSTRUCTION * instr,
                 unichar_t *buff,
                 size_t bufflen,
                 struct DUMP_HANDLERS *dump_handlers)
{
    int                      i, count;
    struct STREAM            stream;
    struct DUMP_HANDLERS     local_dump_handlers;
    struct DUMP_HANDLERS_REG local_dump_handlers_reg;

    safe_init(&stream, buff, bufflen);
    prepare_dump_handlers(&local_dump_handlers, &local_dump_handlers_reg, dump_handlers);

    count = local_dump_handlers.instr_handlers_len;
    for (i = 0; i < count; i++)
    {
        if (!local_dump_handlers.dump_handlers_instr[i](&local_dump_handlers, &stream, instr))
            break;
    }

    return stream.reallen;
}
#endif //MEDIANA_CTRL_DUMP