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

//Warning: may contain a lot of tables!

/*60*/ static struct MULTI_MNEMONIC pusha    = { MM_INDICATOR, SQ_v,      { _UT("pusha"),   _UT("pushad"),  _UT("bad_mnem") } };
/*61*/ static struct MULTI_MNEMONIC popa     = { MM_INDICATOR, SQ_v,      { _UT("popa"),    _UT("popad"),   _UT("bad_mnem") } };
/*6D*/ static struct MULTI_MNEMONIC ins      = { MM_INDICATOR, SQ_v,      { _UT("insw"),    _UT("insd"),    _UT("bad_mnem") } };
/*6F*/ static struct MULTI_MNEMONIC outs     = { MM_INDICATOR, SQ_v,      { _UT("outsw"),   _UT("outsd"),   _UT("bad_mnem") } };
/*98*/ static struct MULTI_MNEMONIC cbw      = { MM_INDICATOR, SQ_vqp,    { _UT("cbw"),     _UT("cwde"),    _UT("cdqe")     } };
/*99*/ static struct MULTI_MNEMONIC cwd      = { MM_INDICATOR, SQ_vqp,    { _UT("cwd"),     _UT("cdq"),     _UT("cqo")      } };
/*9C*/ static struct MULTI_MNEMONIC pushf    = { MM_INDICATOR, SQ_vd64,   { _UT("pushfw"),  _UT("pushfd"),  _UT("pushfq")   } };
/*9D*/ static struct MULTI_MNEMONIC popf     = { MM_INDICATOR, SQ_vd64,   { _UT("popfw"),   _UT("popfd"),   _UT("popfq")    } };
/*A5*/ static struct MULTI_MNEMONIC movsb    = { MM_INDICATOR, SQ_b,      { _UT("movsb"),   _UT("movsb"),   _UT("movsb")    } };
/*A5*/ static struct MULTI_MNEMONIC movs     = { MM_INDICATOR, SQ_vqp,    { _UT("movsw"),   _UT("movsd"),   _UT("movsq")    } };
/*A7*/ static struct MULTI_MNEMONIC cmpsb    = { MM_INDICATOR, SQ_b,      { _UT("cmpsb"),   _UT("cmpsb"),   _UT("cmpsb")    } };
/*A7*/ static struct MULTI_MNEMONIC cmps     = { MM_INDICATOR, SQ_vqp,    { _UT("cmpsw"),   _UT("cmpsd"),   _UT("cmpsq")    } };
/*AB*/ static struct MULTI_MNEMONIC stosb    = { MM_INDICATOR, SQ_b,      { _UT("stosb"),   _UT("stosb"),   _UT("stosb")    } };
/*AB*/ static struct MULTI_MNEMONIC stos     = { MM_INDICATOR, SQ_vqp,    { _UT("stosw"),   _UT("stosd"),   _UT("stosq")    } };
/*AD*/ static struct MULTI_MNEMONIC lodsb    = { MM_INDICATOR, SQ_b,      { _UT("lodsb"),   _UT("lodsb"),   _UT("lodsb")    } };
/*AD*/ static struct MULTI_MNEMONIC lods     = { MM_INDICATOR, SQ_vqp,    { _UT("lodsw"),   _UT("lodsd"),   _UT("lodsq")    } };
/*AF*/ static struct MULTI_MNEMONIC scasb    = { MM_INDICATOR, SQ_b,      { _UT("scasb"),   _UT("scasb"),   _UT("scasb")    } };
/*AF*/ static struct MULTI_MNEMONIC scas     = { MM_INDICATOR, SQ_vqp,    { _UT("scasw"),   _UT("scasd"),   _UT("scasq")    } };
/*C2*/ static struct MULTI_MNEMONIC retn_arg = { MM_INDICATOR, SQ_vq64,   { _UT("retn"),    _UT("retn"),    _UT("retn")     } };
/*C3*/ static struct MULTI_MNEMONIC retn     = { MM_INDICATOR, SQ_vq64,   { _UT("retn"),    _UT("retn"),    _UT("retn")     } };
/*C8*/ static struct MULTI_MNEMONIC enter    = { MM_INDICATOR, SQ_vd64,   { _UT("enterw"),  _UT("enterd"),  _UT("enterq")   } };
/*C9*/ static struct MULTI_MNEMONIC leave    = { MM_INDICATOR, SQ_vd64,   { _UT("leavew"),  _UT("leaved"),  _UT("leaveq")   } };
/*CA*/ static struct MULTI_MNEMONIC retf_arg = { MM_INDICATOR, SQ_vqp,    { _UT("retf"),    _UT("retf"),    _UT("retf")     } };
/*CB*/ static struct MULTI_MNEMONIC retf     = { MM_INDICATOR, SQ_vqp,    { _UT("retf"),    _UT("retf"),    _UT("retf")     } };
/*CF*/ static struct MULTI_MNEMONIC iret     = { MM_INDICATOR, SQ_vqp,    { _UT("iretw"),   _UT("iretd"),   _UT("iretq")    } };
/*E0*/ static struct MULTI_MNEMONIC loopnz   = { MM_INDICATOR, SQ_v67d64, { _UT("loopwnz"), _UT("loopdnz"), _UT("loopqnz")  } };
/*E1*/ static struct MULTI_MNEMONIC loopz    = { MM_INDICATOR, SQ_v67d64, { _UT("loopwz"),  _UT("loopdz"),  _UT("loopqz")   } };
/*E2*/ static struct MULTI_MNEMONIC loop     = { MM_INDICATOR, SQ_v67d64, { _UT("loopw"),   _UT("loopd"),   _UT("loopq")    } };
/*E3*/ static struct MULTI_MNEMONIC jcxz     = { MM_INDICATOR, SQ_v67d64, { _UT("jcxz"),    _UT("jecxz"),   _UT("jrcxz")    } };

static struct OPCODE_DESCRIPTOR opcodes_1byte[] = 
{
/*00*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("add") }, ID_ADD, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_G, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*01*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("add") }, ID_ADD, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_G, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*02*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("add") }, ID_ADD, { { TQ_G, SQ_b, FLG_R | FLG_W }, { TQ_E, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*03*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("add") }, ID_ADD, { { TQ_G, SQ_vqp, FLG_R | FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*04*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("add") }, ID_ADD, { { TQ_rAX, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*05*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("add") }, ID_ADD, { { TQ_rAX, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*06*/ { GRP_GEN | GRP_STACK | GRP_SEGREG, { _UT("push") }, ID_PUSH, { { TQ_ES, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*07*/ { GRP_GEN | GRP_STACK | GRP_SEGREG, { _UT("pop") }, ID_POP, { { TQ_ES, SQ_w, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*08*/ { GRP_GEN | GRP_LOGICAL, { _UT("or") }, ID_OR, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_G, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*09*/ { GRP_GEN | GRP_LOGICAL, { _UT("or") }, ID_OR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_G, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*0A*/ { GRP_GEN | GRP_LOGICAL, { _UT("or") }, ID_OR, { { TQ_G, SQ_b, FLG_R | FLG_W }, { TQ_E, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*0B*/ { GRP_GEN | GRP_LOGICAL, { _UT("or") }, ID_OR, { { TQ_G, SQ_vqp, FLG_R | FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*0C*/ { GRP_GEN | GRP_LOGICAL, { _UT("or") }, ID_OR, { { TQ_rAX, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*0D*/ { GRP_GEN | GRP_LOGICAL, { _UT("or") }, ID_OR, { { TQ_rAX, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*0E*/ { GRP_GEN | GRP_STACK | GRP_SEGREG, { _UT("push") }, ID_PUSH, { { TQ_CS, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0F*/ { GRP_SWITCH, NULL, ID_0F, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*10*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("adc") }, ID_ADC, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_G, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*11*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("adc") }, ID_ADC, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_G, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*12*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("adc") }, ID_ADC, { { TQ_G, SQ_b, FLG_R | FLG_W }, { TQ_E, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*13*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("adc") }, ID_ADC, { { TQ_G, SQ_vqp, FLG_R | FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*14*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("adc") }, ID_ADC, { { TQ_rAX, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*15*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("adc") }, ID_ADC, { { TQ_rAX, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*16*/ { GRP_GEN | GRP_STACK | GRP_SEGREG, { _UT("push") }, ID_PUSH, { { TQ_SS, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*17*/ { GRP_GEN | GRP_STACK | GRP_SEGREG, { _UT("pop") }, ID_POP, { { TQ_SS, SQ_w, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*18*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sbb") }, ID_SBB, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_G, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*19*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sbb") }, ID_SBB, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_G, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1A*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sbb") }, ID_SBB, { { TQ_G, SQ_b, FLG_R | FLG_W }, { TQ_E, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1B*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sbb") }, ID_SBB, { { TQ_G, SQ_vqp, FLG_R | FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1C*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sbb") }, ID_SBB, { { TQ_rAX, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1D*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sbb") }, ID_SBB, { { TQ_rAX, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1E*/ { GRP_GEN | GRP_STACK | GRP_SEGREG, { _UT("push") }, ID_PUSH, { { TQ_DS, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1F*/ { GRP_GEN | GRP_STACK | GRP_SEGREG, { _UT("pop") }, ID_POP, { { TQ_DS, SQ_w, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*20*/ { GRP_GEN | GRP_LOGICAL, { _UT("and") }, ID_AND, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_G, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*21*/ { GRP_GEN | GRP_LOGICAL, { _UT("and") }, ID_AND, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_G, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*22*/ { GRP_GEN | GRP_LOGICAL, { _UT("and") }, ID_AND, { { TQ_G, SQ_b, FLG_R | FLG_W }, { TQ_E, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*23*/ { GRP_GEN | GRP_LOGICAL, { _UT("and") }, ID_AND, { { TQ_G, SQ_vqp, FLG_R | FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*24*/ { GRP_GEN | GRP_LOGICAL, { _UT("and") }, ID_AND, { { TQ_rAX, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*25*/ { GRP_GEN | GRP_LOGICAL, { _UT("and") }, ID_AND, { { TQ_rAX, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*26*/ { GRP_PREFIX, NULL, ID_ES, { { TQ_PREF_ES, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*27*/ { GRP_GEN | GRP_ARITH | GRP_DECIMAL, { _UT("daa") }, ID_DAA, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x5, 0x9F, 0x0, 0x0, 0x80, ARCH_COMMON },
/*28*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sub") }, ID_SUB, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_G, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*29*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sub") }, ID_SUB, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_G, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2A*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sub") }, ID_SUB, { { TQ_G, SQ_b, FLG_R | FLG_W }, { TQ_E, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2B*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sub") }, ID_SUB, { { TQ_G, SQ_vqp, FLG_R | FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2C*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sub") }, ID_SUB, { { TQ_rAX, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2D*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sub") }, ID_SUB, { { TQ_rAX, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2E*/ { GRP_PREFIX, NULL, ID_CS, { { TQ_PREF_CS, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2F*/ { GRP_GEN | GRP_ARITH | GRP_DECIMAL, { _UT("das") }, ID_DAS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x5, 0x9F, 0x0, 0x0, 0x80, ARCH_COMMON },
/*30*/ { GRP_GEN | GRP_LOGICAL, { _UT("xor") }, ID_XOR, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_G, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*31*/ { GRP_GEN | GRP_LOGICAL, { _UT("xor") }, ID_XOR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_G, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*32*/ { GRP_GEN | GRP_LOGICAL, { _UT("xor") }, ID_XOR, { { TQ_G, SQ_b, FLG_R | FLG_W }, { TQ_E, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*33*/ { GRP_GEN | GRP_LOGICAL, { _UT("xor") }, ID_XOR, { { TQ_G, SQ_vqp, FLG_R | FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*34*/ { GRP_GEN | GRP_LOGICAL, { _UT("xor") }, ID_XOR, { { TQ_rAX, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*35*/ { GRP_GEN | GRP_LOGICAL, { _UT("xor") }, ID_XOR, { { TQ_rAX, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*36*/ { GRP_PREFIX, NULL, ID_SS, { { TQ_PREF_SS, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*37*/ { GRP_GEN | GRP_ARITH | GRP_DECIMAL, { _UT("aaa") }, ID_AAA, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x4, 0x9F, 0x0, 0x0, 0x9A, ARCH_COMMON },
/*38*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("cmp") }, ID_CMP, { { TQ_E, SQ_b, FLG_R }, { TQ_G, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*39*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("cmp") }, ID_CMP, { { TQ_E, SQ_vqp, FLG_R }, { TQ_G, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3A*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("cmp") }, ID_CMP, { { TQ_G, SQ_b, FLG_R }, { TQ_E, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3B*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("cmp") }, ID_CMP, { { TQ_G, SQ_vqp, FLG_R }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3C*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("cmp") }, ID_CMP, { { TQ_rAX, SQ_b, FLG_R }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3D*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("cmp") }, ID_CMP, { { TQ_rAX, SQ_vqp, FLG_R }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3E*/ { GRP_PREFIX, NULL, ID_DS, { { TQ_PREF_DS, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3F*/ { GRP_GEN | GRP_ARITH | GRP_DECIMAL, { _UT("aas") }, ID_AAS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x4, 0x9F, 0x0, 0x0, 0x9A, ARCH_COMMON },
/*40*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("inc") }, ID_INC, { { TQ_Z, SQ_v, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*41*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("inc") }, ID_INC, { { TQ_Z, SQ_v, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*42*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("inc") }, ID_INC, { { TQ_Z, SQ_v, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*43*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("inc") }, ID_INC, { { TQ_Z, SQ_v, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*44*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("inc") }, ID_INC, { { TQ_Z, SQ_v, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*45*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("inc") }, ID_INC, { { TQ_Z, SQ_v, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*46*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("inc") }, ID_INC, { { TQ_Z, SQ_v, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*47*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("inc") }, ID_INC, { { TQ_Z, SQ_v, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*48*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("dec") }, ID_DEC, { { TQ_Z, SQ_v, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*49*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("dec") }, ID_DEC, { { TQ_Z, SQ_v, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4A*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("dec") }, ID_DEC, { { TQ_Z, SQ_v, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4B*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("dec") }, ID_DEC, { { TQ_Z, SQ_v, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4C*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("dec") }, ID_DEC, { { TQ_Z, SQ_v, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4D*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("dec") }, ID_DEC, { { TQ_Z, SQ_v, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4E*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("dec") }, ID_DEC, { { TQ_Z, SQ_v, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4F*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("dec") }, ID_DEC, { { TQ_Z, SQ_v, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*50*/ { GRP_GEN | GRP_STACK, { _UT("push") }, ID_PUSH, { { TQ_Z, SQ_vd64, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*51*/ { GRP_GEN | GRP_STACK, { _UT("push") }, ID_PUSH, { { TQ_Z, SQ_vd64, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*52*/ { GRP_GEN | GRP_STACK, { _UT("push") }, ID_PUSH, { { TQ_Z, SQ_vd64, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*53*/ { GRP_GEN | GRP_STACK, { _UT("push") }, ID_PUSH, { { TQ_Z, SQ_vd64, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*54*/ { GRP_GEN | GRP_STACK, { _UT("push") }, ID_PUSH, { { TQ_Z, SQ_vd64, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*55*/ { GRP_GEN | GRP_STACK, { _UT("push") }, ID_PUSH, { { TQ_Z, SQ_vd64, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*56*/ { GRP_GEN | GRP_STACK, { _UT("push") }, ID_PUSH, { { TQ_Z, SQ_vd64, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*57*/ { GRP_GEN | GRP_STACK, { _UT("push") }, ID_PUSH, { { TQ_Z, SQ_vd64, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*58*/ { GRP_GEN | GRP_STACK, { _UT("pop") }, ID_POP, { { TQ_Z, SQ_vd64, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*59*/ { GRP_GEN | GRP_STACK, { _UT("pop") }, ID_POP, { { TQ_Z, SQ_vd64, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5A*/ { GRP_GEN | GRP_STACK, { _UT("pop") }, ID_POP, { { TQ_Z, SQ_vd64, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5B*/ { GRP_GEN | GRP_STACK, { _UT("pop") }, ID_POP, { { TQ_Z, SQ_vd64, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5C*/ { GRP_GEN | GRP_STACK, { _UT("pop") }, ID_POP, { { TQ_Z, SQ_vd64, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5D*/ { GRP_GEN | GRP_STACK, { _UT("pop") }, ID_POP, { { TQ_Z, SQ_vd64, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5E*/ { GRP_GEN | GRP_STACK, { _UT("pop") }, ID_POP, { { TQ_Z, SQ_vd64, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5F*/ { GRP_GEN | GRP_STACK, { _UT("pop") }, ID_POP, { { TQ_Z, SQ_vd64, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*60*/ { GRP_GEN | GRP_STACK, { (unichar_t *)&pusha }, ID_PUSHA, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*61*/ { GRP_GEN | GRP_STACK, { (unichar_t *)&popa }, ID_POPA, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*62*/ { GRP_GEN | GRP_BREAK | GRP_STACK, { _UT("bound") }, ID_BOUND, { { TQ_G, SQ_v, FLG_R }, { TQ_M, SQ_a, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_I64, 0x0, 0x20, 0x0, 0x20, 0x0, ARCH_COMMON },
/*63*/ { GRP_GEN | GRP_SYSTEM, { _UT("arpl") }, ID_ARPL, { { TQ_E, SQ_w, FLG_R }, { TQ_G, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_POST_PROC | POST_PROC_ARPL_MOVSXD, 0x0, 0x8, 0x0, 0x0, 0x0, ARCH_COMMON },
/*64*/ { GRP_PREFIX, NULL, ID_FS, { { TQ_PREF_FS, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*65*/ { GRP_PREFIX, NULL, ID_GS, { { TQ_PREF_GS, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*66*/ { GRP_PREFIX, NULL, ID_66, { { TQ_PREF_66, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_66_0F_JMP, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*67*/ { GRP_PREFIX, NULL, ID_67, { { TQ_PREF_67, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*68*/ { GRP_GEN | GRP_STACK, { _UT("push") }, ID_PUSH, { { TQ_I, SQ_vs, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*69*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("imul") }, ID_IMUL, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_I, SQ_vds, FLG_R } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x1E, ARCH_COMMON },
/*6A*/ { GRP_GEN | GRP_STACK, { _UT("push") }, ID_PUSH, { { TQ_I, SQ_bss, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6B*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("imul") }, ID_IMUL, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_I, SQ_bs, FLG_R } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x1E, ARCH_COMMON },
/*6C*/ { GRP_GEN | GRP_INOUT | GRP_STRING, { _UT("insb") }, ID_INS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_IOPL | PROP_ALLOW_REP, 0x40, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6D*/ { GRP_GEN | GRP_INOUT | GRP_STRING, { (unichar_t *)&ins }, ID_INS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_IOPL | PROP_ALLOW_REP, 0x40, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6E*/ { GRP_GEN | GRP_INOUT | GRP_STRING, { _UT("outsb") }, ID_OUTS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_IOPL | PROP_ALLOW_REP, 0x40, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6F*/ { GRP_GEN | GRP_INOUT | GRP_STRING, { (unichar_t *)&outs }, ID_OUTS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_IOPL | PROP_ALLOW_REP, 0x40, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*70*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jo") }, ID_JO, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x80, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*71*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jno") }, ID_JNO, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x80, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*72*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jb") }, ID_JB, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x1, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*73*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jae") }, ID_JAE, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x1, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*74*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jz") }, ID_JZ, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x8, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*75*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jnz") }, ID_JNZ, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x8, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*76*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jbe") }, ID_JBE, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x9, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*77*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("ja") }, ID_JA, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x9, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*78*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("js") }, ID_JS, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x10, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*79*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jns") }, ID_JNS, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x10, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7A*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jp") }, ID_JP, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x2, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7B*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jnp") }, ID_JNP, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x2, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7C*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jl") }, ID_JL, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x90, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7D*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jge") }, ID_JGE, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x90, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7E*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jle") }, ID_JLE, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x98, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7F*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jg") }, ID_JG, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x98, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*80*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_80, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*81*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_81, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*82*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_82, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*83*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_83, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*84*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("test") }, ID_TEST, { { TQ_E, SQ_b, FLG_R }, { TQ_G, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*85*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("test") }, ID_TEST, { { TQ_E, SQ_vqp, FLG_R }, { TQ_G, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*86*/ { GRP_GEN | GRP_DATAMOV, { _UT("xchg") }, ID_XCHG, { { TQ_G, SQ_b, FLG_R | FLG_W }, { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*87*/ { GRP_GEN | GRP_DATAMOV, { _UT("xchg") }, ID_XCHG, { { TQ_G, SQ_vqp, FLG_R | FLG_W }, { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*88*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_E, SQ_b, FLG_W }, { TQ_G, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*89*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_E, SQ_vqp, FLG_W }, { TQ_G, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8A*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_G, SQ_b, FLG_W }, { TQ_E, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8B*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8C*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_E, SQ_wv, FLG_W }, { TQ_S, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8D*/ { GRP_GEN | GRP_DATAMOV, { _UT("lea") }, ID_LEA, { { TQ_G, SQ_vqp, FLG_W }, { TQ_M, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_POST_PROC | POST_PROC_LEA, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8E*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_S, SQ_w, FLG_W }, { TQ_E, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8F*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_8F, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*90*/ { GRP_GEN | GRP_CONTROL, { _UT("nop") }, ID_NOP, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_POST_PROC | POST_PROC_NOP_PAUSE, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*91*/ { GRP_GEN | GRP_DATAMOV, { _UT("xchg") }, ID_XCHG, { { TQ_rAX, SQ_vqp, FLG_R | FLG_W }, { TQ_Z, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*92*/ { GRP_GEN | GRP_DATAMOV, { _UT("xchg") }, ID_XCHG, { { TQ_rAX, SQ_vqp, FLG_R | FLG_W }, { TQ_Z, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*93*/ { GRP_GEN | GRP_DATAMOV, { _UT("xchg") }, ID_XCHG, { { TQ_rAX, SQ_vqp, FLG_R | FLG_W }, { TQ_Z, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*94*/ { GRP_GEN | GRP_DATAMOV, { _UT("xchg") }, ID_XCHG, { { TQ_rAX, SQ_vqp, FLG_R | FLG_W }, { TQ_Z, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*95*/ { GRP_GEN | GRP_DATAMOV, { _UT("xchg") }, ID_XCHG, { { TQ_rAX, SQ_vqp, FLG_R | FLG_W }, { TQ_Z, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*96*/ { GRP_GEN | GRP_DATAMOV, { _UT("xchg") }, ID_XCHG, { { TQ_rAX, SQ_vqp, FLG_R | FLG_W }, { TQ_Z, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*97*/ { GRP_GEN | GRP_DATAMOV, { _UT("xchg") }, ID_XCHG, { { TQ_rAX, SQ_vqp, FLG_R | FLG_W }, { TQ_Z, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*98*/ { GRP_GEN | GRP_CONVER, { (unichar_t *)&cbw }, ID_CBW, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*99*/ { GRP_GEN | GRP_CONVER, { (unichar_t *)&cwd }, ID_CWD, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9A*/ { GRP_GEN | GRP_BREAK | GRP_STACK, { _UT("callf") }, ID_CALLF, { { TQ_A, SQ_p, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9B*/ { GRP_X87FPU | GRP_CONTROL, { _UT("fwait") }, ID_FWAIT, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9C*/ { GRP_GEN | GRP_STACK | GRP_FLGCTRL, { (unichar_t *)&pushf }, ID_PUSHF, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0xFF, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9D*/ { GRP_GEN | GRP_STACK | GRP_FLGCTRL, { (unichar_t *)&popf }, ID_POPF, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0xFF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9E*/ { GRP_GEN | GRP_DATAMOV | GRP_FLGCTRL, { _UT("sahf") }, ID_SAHF, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x1F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9F*/ { GRP_GEN | GRP_DATAMOV | GRP_FLGCTRL, { _UT("lahf") }, ID_LAHF, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x1F, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A0*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_rAX, SQ_b, FLG_W }, { TQ_O, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A1*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_rAX, SQ_vqp, FLG_W }, { TQ_O, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A2*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_O, SQ_b, FLG_W }, { TQ_rAX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A3*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_O, SQ_vqp, FLG_W }, { TQ_rAX, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A4*/ { GRP_GEN | GRP_DATAMOV | GRP_STRING, { (unichar_t *)&movsb }, ID_MOVS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_ALLOW_REP, 0x40, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A5*/ { GRP_GEN | GRP_DATAMOV | GRP_STRING, { (unichar_t *)&movs }, ID_MOVS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_ALLOW_REP, 0x40, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A6*/ { GRP_GEN | GRP_ARITH | GRP_STRING | GRP_BINARY, { (unichar_t *)&cmpsb }, ID_CMPS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_ALLOW_REP, 0x40, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A7*/ { GRP_GEN | GRP_ARITH | GRP_STRING | GRP_BINARY, { (unichar_t *)&cmps }, ID_CMPS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_ALLOW_REP, 0x40, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A8*/ { GRP_GEN | GRP_LOGICAL, { _UT("test") }, ID_TEST, { { TQ_rAX, SQ_b, FLG_R }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*A9*/ { GRP_GEN | GRP_LOGICAL, { _UT("test") }, ID_TEST, { { TQ_rAX, SQ_vqp, FLG_R }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*AA*/ { GRP_GEN | GRP_DATAMOV | GRP_STRING, { (unichar_t *)&stosb }, ID_STOS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_ALLOW_REP, 0x40, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AB*/ { GRP_GEN | GRP_DATAMOV | GRP_STRING, { (unichar_t *)&stos }, ID_STOS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_ALLOW_REP, 0x40, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AC*/ { GRP_GEN | GRP_DATAMOV | GRP_STRING, { (unichar_t *)&lodsb }, ID_LODS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_ALLOW_REP, 0x40, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AD*/ { GRP_GEN | GRP_DATAMOV | GRP_STRING, { (unichar_t *)&lods }, ID_LODS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_ALLOW_REP, 0x40, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AE*/ { GRP_GEN | GRP_ARITH | GRP_STRING | GRP_BINARY, { (unichar_t *)&scasb }, ID_SCAS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_ALLOW_REP, 0x40, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AF*/ { GRP_GEN | GRP_ARITH | GRP_STRING | GRP_BINARY, { (unichar_t *)&scas }, ID_SCAS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_ALLOW_REP, 0x40, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B0*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_Z, SQ_b, FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B1*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_Z, SQ_b, FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B2*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_Z, SQ_b, FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B3*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_Z, SQ_b, FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B4*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_Z, SQ_b, FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B5*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_Z, SQ_b, FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B6*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_Z, SQ_b, FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B7*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_Z, SQ_b, FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B8*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_Z, SQ_vqp, FLG_W }, { TQ_I, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B9*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_Z, SQ_vqp, FLG_W }, { TQ_I, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BA*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_Z, SQ_vqp, FLG_W }, { TQ_I, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BB*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_Z, SQ_vqp, FLG_W }, { TQ_I, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BC*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_Z, SQ_vqp, FLG_W }, { TQ_I, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BD*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_Z, SQ_vqp, FLG_W }, { TQ_I, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BE*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_Z, SQ_vqp, FLG_W }, { TQ_I, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BF*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_Z, SQ_vqp, FLG_W }, { TQ_I, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C0*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_C0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C1*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_C1, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C2*/ { GRP_GEN | GRP_BRANCH | GRP_STACK, { (unichar_t *)&retn_arg }, ID_RETN, { { TQ_I, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C3*/ { GRP_GEN | GRP_BRANCH | GRP_STACK, { (unichar_t *)&retn }, ID_RETN, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C4*/ { GRP_GEN | GRP_DATAMOV | GRP_SEGREG, { _UT("les") }, ID_LES, { { TQ_G, SQ_v, FLG_W }, { TQ_M, SQ_p, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_I64, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C5*/ { GRP_GEN | GRP_DATAMOV | GRP_SEGREG, { _UT("lds") }, ID_LDS, { { TQ_G, SQ_v, FLG_W }, { TQ_M, SQ_p, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_I64, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C6*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_C6, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C7*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_C7, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C8*/ { GRP_GEN | GRP_STACK, { (unichar_t *)&enter }, ID_ENTER, { { TQ_I, SQ_w, FLG_R }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C9*/ { GRP_GEN | GRP_STACK, { (unichar_t *)&leave }, ID_LEAVE, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CA*/ { GRP_GEN | GRP_BREAK | GRP_STACK, { (unichar_t *)&retf_arg }, ID_RETF, { { TQ_I, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CB*/ { GRP_GEN | GRP_BREAK | GRP_STACK, { (unichar_t *)&retf }, ID_RETF, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CC*/ { GRP_GEN | GRP_BREAK | GRP_STACK, { _UT("int") }, ID_INT, { { TQ_3, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x20, 0x0, 0x20, 0x0, ARCH_COMMON },
/*CD*/ { GRP_GEN | GRP_BREAK | GRP_STACK, { _UT("int") }, ID_INT, { { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x20, 0x0, 0x20, 0x0, ARCH_COMMON },
/*CE*/ { GRP_GEN | GRP_BREAK | GRP_STACK, { _UT("into") }, ID_INTO, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x80, 0x20, 0x0, 0x20, 0x0, ARCH_COMMON },
/*CF*/ { GRP_GEN | GRP_BREAK | GRP_STACK, { (unichar_t *)&iret }, ID_IRET, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D0*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_D0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D1*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_D1, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D2*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_D2, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D3*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_D3, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D4*/ { GRP_GEN | GRP_ARITH | GRP_DECIMAL, { _UT("aam") }, ID_AAM, { { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x9F, 0x0, 0x0, 0x85, ARCH_COMMON },
/*D5*/ { GRP_GEN | GRP_ARITH | GRP_DECIMAL, { _UT("aad") }, ID_AAD, { { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x9F, 0x0, 0x0, 0x85, ARCH_COMMON },
/*D6*/ { GRP_GEN | GRP_DATAMOV, { _UT("salc") }, ID_SALC, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64 | PROP_UNDOC, 0x1, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D7*/ { GRP_GEN | GRP_DATAMOV, { _UT("xlat") }, ID_XLAT, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D8*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_D8_SWTCH, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D9*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_D9_SWTCH, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DA*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DA_SWTCH, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DB*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DB_SWTCH, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DC*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DC_SWTCH, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DD*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DD_SWTCH, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DE*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DE_SWTCH, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DF*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DF_SWTCH, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E0*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { (unichar_t *)&loopnz }, ID_LOOPNZ, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x8, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E1*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { (unichar_t *)&loopz }, ID_LOOPZ, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x8, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E2*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { (unichar_t *)&loop }, ID_LOOP, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E3*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { (unichar_t *)&jcxz }, ID_JCXZ, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E4*/ { GRP_GEN | GRP_INOUT, { _UT("in") }, ID_IN, { { TQ_rAX, SQ_b, FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_IOPL, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E5*/ { GRP_GEN | GRP_INOUT, { _UT("in") }, ID_IN, { { TQ_rAX, SQ_v, FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_IOPL, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E6*/ { GRP_GEN | GRP_INOUT, { _UT("out") }, ID_OUT, { { TQ_I, SQ_b, FLG_R }, { TQ_rAX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_IOPL, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E7*/ { GRP_GEN | GRP_INOUT, { _UT("out") }, ID_OUT, { { TQ_I, SQ_b, FLG_R }, { TQ_rAX, SQ_v, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_IOPL, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E8*/ { GRP_GEN | GRP_BRANCH | GRP_STACK, { _UT("call") }, ID_CALL, { { TQ_J, SQ_vds, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E9*/ { GRP_GEN | GRP_BRANCH, { _UT("jmp") }, ID_JMP, { { TQ_J, SQ_vds, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EA*/ { GRP_GEN | GRP_BREAK, { _UT("jmpf") }, ID_JMPF, { { TQ_A, SQ_p, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EB*/ { GRP_GEN | GRP_BRANCH, { _UT("jmp") }, ID_JMP, { { TQ_J, SQ_bsj, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EC*/ { GRP_GEN | GRP_INOUT, { _UT("in") }, ID_IN, { { TQ_rAX, SQ_b, FLG_W }, { TQ_rDX, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_IOPL, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*ED*/ { GRP_GEN | GRP_INOUT, { _UT("in") }, ID_IN, { { TQ_rAX, SQ_v, FLG_W }, { TQ_rDX, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_IOPL, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EE*/ { GRP_GEN | GRP_INOUT, { _UT("out") }, ID_OUT, { { TQ_rDX, SQ_w, FLG_R }, { TQ_rAX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_IOPL, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EF*/ { GRP_GEN | GRP_INOUT, { _UT("out") }, ID_OUT, { { TQ_rDX, SQ_w, FLG_R }, { TQ_rAX, SQ_v, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_IOPL, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F0*/ { GRP_PREFIX, { _UT("lock") }, ID_LOCK, { { TQ_PREF_F0, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F1*/ { GRP_GEN | GRP_BREAK | GRP_STACK, { _UT("icebp") }, ID_ICEBP, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_UNDOC, 0x0, 0x20, 0x0, 0x20, 0x0, ARCH_COMMON },
/*F2*/ { GRP_PREFIX, { _UT("repnz") }, ID_REPNZ, { { TQ_PREF_F2, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_F2_0F_JMP, 0x8, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F3*/ { GRP_PREFIX, { _UT("repz") }, ID_REPZ, { { TQ_PREF_F3, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_F3_0F_JMP, 0x8, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F4*/ { GRP_GEN | GRP_SYSTEM, { _UT("hlt") }, ID_HLT, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_RING0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F5*/ { GRP_GEN | GRP_FLGCTRL, { _UT("cmc") }, ID_CMC, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x1, 0x1, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F6*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_F6, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F7*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_F7, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F8*/ { GRP_GEN | GRP_FLGCTRL, { _UT("clc") }, ID_CLC, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x1, 0x0, 0x1, 0x0, ARCH_COMMON },
/*F9*/ { GRP_GEN | GRP_FLGCTRL, { _UT("stc") }, ID_STC, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x1, 0x1, 0x0, 0x0, ARCH_COMMON },
/*FA*/ { GRP_GEN | GRP_FLGCTRL, { _UT("cli") }, ID_CLI, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_IOPL, 0x0, 0x20, 0x0, 0x20, 0x0, ARCH_COMMON },
/*FB*/ { GRP_GEN | GRP_FLGCTRL, { _UT("sti") }, ID_STI, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_IOPL, 0x0, 0x20, 0x20, 0x0, 0x0, ARCH_COMMON },
/*FC*/ { GRP_GEN | GRP_FLGCTRL, { _UT("cld") }, ID_CLD, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x40, 0x0, 0x40, 0x0, ARCH_COMMON },
/*FD*/ { GRP_GEN | GRP_FLGCTRL, { _UT("std") }, ID_STD, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x40, 0x40, 0x0, 0x0, ARCH_COMMON },
/*FE*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_FE, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*FF*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_FF, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
}; 

static struct OPCODE_DESCRIPTOR opcodes_80[] = 
{
/*0*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("add") }, ID_ADD, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_LOGICAL, { _UT("or") }, ID_OR, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*2*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("adc") }, ID_ADC, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sbb") }, ID_SBB, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_GEN | GRP_LOGICAL, { _UT("and") }, ID_AND, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*5*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sub") }, ID_SUB, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6*/ { GRP_GEN | GRP_LOGICAL, { _UT("xor") }, ID_XOR, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*7*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("cmp") }, ID_CMP, { { TQ_E, SQ_b, FLG_R }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_81[] = 
{
/*0*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("add") }, ID_ADD, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_LOGICAL, { _UT("or") }, ID_OR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*2*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("adc") }, ID_ADC, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sbb") }, ID_SBB, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_GEN | GRP_LOGICAL, { _UT("and") }, ID_AND, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*5*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sub") }, ID_SUB, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6*/ { GRP_GEN | GRP_LOGICAL, { _UT("xor") }, ID_XOR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*7*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("cmp") }, ID_CMP, { { TQ_E, SQ_vqp, FLG_R }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_82[] = 
{
/*0*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("add") }, ID_ADD, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_I64 | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_LOGICAL, { _UT("or") }, ID_OR, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_I64 | PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*2*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("adc") }, ID_ADC, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_I64 | PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sbb") }, ID_SBB, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_I64 | PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_GEN | GRP_LOGICAL, { _UT("and") }, ID_AND, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_I64 | PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*5*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sub") }, ID_SUB, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_I64 | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6*/ { GRP_GEN | GRP_LOGICAL, { _UT("xor") }, ID_XOR, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_I64 | PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*7*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("cmp") }, ID_CMP, { { TQ_E, SQ_b, FLG_R }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_I64 | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_83[] = 
{
/*0*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("add") }, ID_ADD, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_bs, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_LOGICAL, { _UT("or") }, ID_OR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_bs, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*2*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("adc") }, ID_ADC, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_bs, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sbb") }, ID_SBB, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_bs, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_GEN | GRP_LOGICAL, { _UT("and") }, ID_AND, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_bs, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*5*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("sub") }, ID_SUB, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_bs, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6*/ { GRP_GEN | GRP_LOGICAL, { _UT("xor") }, ID_XOR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_bs, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*7*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("cmp") }, ID_CMP, { { TQ_E, SQ_vqp, FLG_R }, { TQ_I, SQ_bs, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_8F[] = 
{
/*0*/ { GRP_GEN | GRP_STACK, { _UT("pop") }, ID_POP, { { TQ_E, SQ_vd64, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_C0[] = 
{
/*0*/ { GRP_GEN | GRP_SHFTROT, { _UT("rol") }, ID_ROL, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x80, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_SHFTROT, { _UT("ror") }, ID_ROR, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x80, ARCH_COMMON },
/*2*/ { GRP_GEN | GRP_SHFTROT, { _UT("rcl") }, ID_RCL, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x80, ARCH_COMMON },
/*3*/ { GRP_GEN | GRP_SHFTROT, { _UT("rcr") }, ID_RCR, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x80, ARCH_COMMON },
/*4*/ { GRP_GEN | GRP_SHFTROT, { _UT("shl") }, ID_SHL, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x85, ARCH_COMMON },
/*5*/ { GRP_GEN | GRP_SHFTROT, { _UT("shr") }, ID_SHR, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x85, ARCH_COMMON },
/*6*/ { GRP_GEN | GRP_SHFTROT, { _UT("sal") }, ID_SAL, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x85, ARCH_COMMON },
/*7*/ { GRP_GEN | GRP_SHFTROT, { _UT("sar") }, ID_SAR, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x84, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_C1[] = 
{
/*0*/ { GRP_GEN | GRP_SHFTROT, { _UT("rol") }, ID_ROL, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x80, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_SHFTROT, { _UT("ror") }, ID_ROR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x80, ARCH_COMMON },
/*2*/ { GRP_GEN | GRP_SHFTROT, { _UT("rcl") }, ID_RCL, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x80, ARCH_COMMON },
/*3*/ { GRP_GEN | GRP_SHFTROT, { _UT("rcr") }, ID_RCR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x80, ARCH_COMMON },
/*4*/ { GRP_GEN | GRP_SHFTROT, { _UT("shl") }, ID_SHL, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x85, ARCH_COMMON },
/*5*/ { GRP_GEN | GRP_SHFTROT, { _UT("shr") }, ID_SHR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x85, ARCH_COMMON },
/*6*/ { GRP_GEN | GRP_SHFTROT, { _UT("sal") }, ID_SAL, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x85, ARCH_COMMON },
/*7*/ { GRP_GEN | GRP_SHFTROT, { _UT("sar") }, ID_SAR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x84, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_C6[] = 
{
/*0*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_E, SQ_b, FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_C7[] = 
{
/*0*/ { GRP_GEN | GRP_DATAMOV, { _UT("mov") }, ID_MOV, { { TQ_E, SQ_vqp, FLG_W }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_D0[] = 
{
/*0*/ { GRP_GEN | GRP_SHFTROT, { _UT("rol") }, ID_ROL, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_1, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_SHFTROT, { _UT("ror") }, ID_ROR, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_1, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_GEN | GRP_SHFTROT, { _UT("rcl") }, ID_RCL, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_1, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_GEN | GRP_SHFTROT, { _UT("rcr") }, ID_RCR, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_1, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_GEN | GRP_SHFTROT, { _UT("shl") }, ID_SHL, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_1, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x4, ARCH_COMMON },
/*5*/ { GRP_GEN | GRP_SHFTROT, { _UT("shr") }, ID_SHR, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_1, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x4, ARCH_COMMON },
/*6*/ { GRP_GEN | GRP_SHFTROT, { _UT("sal") }, ID_SAL, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_1, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x4, ARCH_COMMON },
/*7*/ { GRP_GEN | GRP_SHFTROT, { _UT("sar") }, ID_SAR, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_1, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x4, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_D1[] = 
{
/*0*/ { GRP_GEN | GRP_SHFTROT, { _UT("rol") }, ID_ROL, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_1, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_SHFTROT, { _UT("ror") }, ID_ROR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_1, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_GEN | GRP_SHFTROT, { _UT("rcl") }, ID_RCL, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_1, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_GEN | GRP_SHFTROT, { _UT("rcr") }, ID_RCR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_1, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_GEN | GRP_SHFTROT, { _UT("shl") }, ID_SHL, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_1, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x4, ARCH_COMMON },
/*5*/ { GRP_GEN | GRP_SHFTROT, { _UT("shr") }, ID_SHR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_1, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x4, ARCH_COMMON },
/*6*/ { GRP_GEN | GRP_SHFTROT, { _UT("sal") }, ID_SAL, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_1, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x4, ARCH_COMMON },
/*7*/ { GRP_GEN | GRP_SHFTROT, { _UT("sar") }, ID_SAR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_1, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x4, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_D2[] = 
{
/*0*/ { GRP_GEN | GRP_SHFTROT, { _UT("rol") }, ID_ROL, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_rCX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x80, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_SHFTROT, { _UT("ror") }, ID_ROR, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_rCX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x80, ARCH_COMMON },
/*2*/ { GRP_GEN | GRP_SHFTROT, { _UT("rcl") }, ID_RCL, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_rCX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x80, ARCH_COMMON },
/*3*/ { GRP_GEN | GRP_SHFTROT, { _UT("rcr") }, ID_RCR, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_rCX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x80, ARCH_COMMON },
/*4*/ { GRP_GEN | GRP_SHFTROT, { _UT("shl") }, ID_SHL, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_rCX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x85, ARCH_COMMON },
/*5*/ { GRP_GEN | GRP_SHFTROT, { _UT("shr") }, ID_SHR, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_rCX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x85, ARCH_COMMON },
/*6*/ { GRP_GEN | GRP_SHFTROT, { _UT("sal") }, ID_SAL, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_rCX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x85, ARCH_COMMON },
/*7*/ { GRP_GEN | GRP_SHFTROT, { _UT("sar") }, ID_SAR, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_rCX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x84, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_D3[] = 
{
/*0*/ { GRP_GEN | GRP_SHFTROT, { _UT("rol") }, ID_ROL, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_rCX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x80, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_SHFTROT, { _UT("ror") }, ID_ROR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_rCX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x80, ARCH_COMMON },
/*2*/ { GRP_GEN | GRP_SHFTROT, { _UT("rcl") }, ID_RCL, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_rCX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x80, ARCH_COMMON },
/*3*/ { GRP_GEN | GRP_SHFTROT, { _UT("rcr") }, ID_RCR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_rCX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x9F, 0x0, 0x0, 0x80, ARCH_COMMON },
/*4*/ { GRP_GEN | GRP_SHFTROT, { _UT("shl") }, ID_SHL, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_rCX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x85, ARCH_COMMON },
/*5*/ { GRP_GEN | GRP_SHFTROT, { _UT("shr") }, ID_SHR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_rCX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x85, ARCH_COMMON },
/*6*/ { GRP_GEN | GRP_SHFTROT, { _UT("sal") }, ID_SAL, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_rCX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x85, ARCH_COMMON },
/*7*/ { GRP_GEN | GRP_SHFTROT, { _UT("sar") }, ID_SAR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_rCX, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x4, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_F6[] = 
{
/*0*/ { GRP_GEN | GRP_LOGICAL, { _UT("test") }, ID_TEST, { { TQ_E, SQ_b, FLG_R }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_LOGICAL, { _UT("test") }, ID_TEST, { { TQ_E, SQ_b, FLG_R }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*2*/ { GRP_GEN | GRP_LOGICAL, { _UT("not") }, ID_NOT, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("neg") }, ID_NEG, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("mul") }, ID_MUL, { { TQ_E, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x1E, ARCH_COMMON },
/*5*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("imul") }, ID_IMUL, { { TQ_E, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x1E, ARCH_COMMON },
/*6*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("div") }, ID_DIV, { { TQ_E, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x9F, ARCH_COMMON },
/*7*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("idiv") }, ID_IDIV, { { TQ_E, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x9F, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_F7[] = 
{
/*0*/ { GRP_GEN | GRP_LOGICAL, { _UT("test") }, ID_TEST, { { TQ_E, SQ_vqp, FLG_R }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_LOGICAL, { _UT("test") }, ID_TEST, { { TQ_E, SQ_vqp, FLG_R }, { TQ_I, SQ_vds, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0x9F, 0x0, 0x81, 0x4, ARCH_COMMON },
/*2*/ { GRP_GEN | GRP_LOGICAL, { _UT("not") }, ID_NOT, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("neg") }, ID_NEG, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("mul") }, ID_MUL, { { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x1E, ARCH_COMMON },
/*5*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("imul") }, ID_IMUL, { { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x1E, ARCH_COMMON },
/*6*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("div") }, ID_DIV, { { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x9F, ARCH_COMMON },
/*7*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("idiv") }, ID_IDIV, { { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x9F, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_FE[] = 
{
/*0*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("inc") }, ID_INC, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("dec") }, ID_DEC, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_FF[] = 
{
/*0*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("inc") }, ID_INC, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("dec") }, ID_DEC, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9E, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_GEN | GRP_BRANCH | GRP_STACK, { _UT("call") }, ID_CALL, { { TQ_E, SQ_vq64, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_GEN | GRP_BREAK | GRP_STACK, { _UT("callf") }, ID_CALLF, { { TQ_M, SQ_ptp, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_GEN | GRP_BRANCH, { _UT("jmp") }, ID_JMP, { { TQ_E, SQ_vq64, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5*/ { GRP_GEN | GRP_BREAK, { _UT("jmpf") }, ID_JMPF, { { TQ_M, SQ_ptp, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6*/ { GRP_GEN | GRP_STACK, { _UT("push") }, ID_PUSH, { { TQ_E, SQ_vd64, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_D8_swtch[] =
{
/*0*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_D8_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_D8_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_D8_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_D8_NOMEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_D8_mem[] =
{
/*0*/ { GRP_X87FPU | GRP_ARITH, { _UT("fadd") }, ID_FADD, { { TQ_fST0, SQ_sr, FLG_R | FLG_W }, { TQ_M, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1*/ { GRP_X87FPU | GRP_ARITH, { _UT("fmul") }, ID_FMUL, { { TQ_fST0, SQ_sr, FLG_R | FLG_W }, { TQ_M, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcom") }, ID_FCOM,  { { TQ_M, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomp") }, ID_FCOMP, { { TQ_M, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsub") }, ID_FSUB, { { TQ_fST0, SQ_sr, FLG_R | FLG_W }, { TQ_M, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*5*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubr") }, ID_FSUBR, { { TQ_fST0, SQ_sr, FLG_R | FLG_W }, { TQ_M, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*6*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdiv") }, ID_FDIV, { { TQ_fST0, SQ_sr, FLG_R | FLG_W }, { TQ_M, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*7*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivr") }, ID_FDIVR, { { TQ_fST0, SQ_sr, FLG_R | FLG_W }, { TQ_M, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_D8_nomem[] = 
{
/*0*/ { GRP_X87FPU | GRP_ARITH, { _UT("fadd") }, ID_FADD, { { TQ_fST0, SQ_sr, FLG_R | FLG_W }, { TQ_fEST, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1*/ { GRP_X87FPU | GRP_ARITH, { _UT("fmul") }, ID_FMUL, { { TQ_fST0, SQ_sr, FLG_R | FLG_W }, { TQ_fEST, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcom") }, ID_FCOM, { { TQ_fEST, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomp") }, ID_FCOMP, { { TQ_fEST, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsub") }, ID_FSUB, { { TQ_fST0, SQ_sr, FLG_R | FLG_W }, { TQ_fEST, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*5*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubr") }, ID_FSUBR, { { TQ_fST0, SQ_sr, FLG_R | FLG_W }, { TQ_fEST, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*6*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdiv") }, ID_FDIV, { { TQ_fST0, SQ_sr, FLG_R | FLG_W }, { TQ_fEST, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*7*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivr") }, ID_FDIVR, { { TQ_fST0, SQ_sr, FLG_R | FLG_W }, { TQ_fEST, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_D9_swtch[] =
{
/*0*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_D9_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_D9_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_D9_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_D9_NOMEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_D9_mem[] =
{
/*0*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fld") }, ID_FLD, { { TQ_fES, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, TQ_NULL, 0 }, { TQ_NULL, TQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fst") }, ID_FST, { { TQ_M, SQ_sr, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*3*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp") }, ID_FSTP, { { TQ_M, SQ_sr, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*4*/ { GRP_X87FPU | GRP_CONTROL, { _UT("fldenv") }, ID_FLDENV, { { TQ_M, SQ_e, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5*/ { GRP_X87FPU | GRP_CONTROL, { _UT("fldcw") }, ID_FLDCW, { { TQ_M, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xF, ARCH_COMMON },
/*6*/ { GRP_X87FPU | GRP_CONTROL, { _UT("fnstenv") }, ID_FNSTENV, { { TQ_M, SQ_e, FLG_W }, { TQ_NULL, TQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xF, ARCH_COMMON },
/*7*/ { GRP_X87FPU | GRP_CONTROL, { _UT("fnstcw") }, ID_FNSTCW, { { TQ_M, SQ_w, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xF, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_D9_nomem[] =
{
/*00*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fld") }, ID_FLD, { { TQ_fEST, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*01*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fld") }, ID_FLD, { { TQ_fEST, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*02*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fld") }, ID_FLD, { { TQ_fEST, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*03*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fld") }, ID_FLD, { { TQ_fEST, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*04*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fld") }, ID_FLD, { { TQ_fEST, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*05*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fld") }, ID_FLD, { { TQ_fEST, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*06*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fld") }, ID_FLD, { { TQ_fEST, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*07*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fld") }, ID_FLD, { { TQ_fEST, SQ_sr, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*08*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fxch") }, ID_FXCH, { { TQ_fEST, SQ_sr, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*09*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fxch") }, ID_FXCH, { { TQ_fEST, SQ_sr, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0A*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fxch") }, ID_FXCH, { { TQ_fEST, SQ_sr, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0B*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fxch") }, ID_FXCH, { { TQ_fEST, SQ_sr, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0C*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fxch") }, ID_FXCH, { { TQ_fEST, SQ_sr, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0D*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fxch") }, ID_FXCH, { { TQ_fEST, SQ_sr, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0E*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fxch") }, ID_FXCH, { { TQ_fEST, SQ_sr, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0F*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fxch") }, ID_FXCH, { { TQ_fEST, SQ_sr, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*10*/ { GRP_X87FPU | GRP_CONTROL, { _UT("fnop") }, ID_FNOP, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xF, ARCH_COMMON },
/*11*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*12*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*13*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*14*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*15*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*16*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*17*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*18*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp1") }, ID_FSTP1, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xD, ARCH_COMMON },
/*19*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp1") }, ID_FSTP1, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xD, ARCH_COMMON },
/*1A*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp1") }, ID_FSTP1, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xD, ARCH_COMMON },
/*1B*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp1") }, ID_FSTP1, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xD, ARCH_COMMON },
/*1C*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp1") }, ID_FSTP1, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xD, ARCH_COMMON },
/*1D*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp1") }, ID_FSTP1, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xD, ARCH_COMMON },
/*1E*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp1") }, ID_FSTP1, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xD, ARCH_COMMON },
/*1F*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp1") }, ID_FSTP1, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xD, ARCH_COMMON },
/*20*/ { GRP_X87FPU | GRP_ARITH, { _UT("fchs") }, ID_FCHS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*21*/ { GRP_X87FPU | GRP_ARITH, { _UT("fabs") }, ID_FABS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*22*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*23*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*24*/ { GRP_X87FPU | GRP_COMPAR, { _UT("ftst") }, ID_FTST, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*25*/ { GRP_X87FPU, { _UT("fxam") }, ID_FXAM, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*26*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*27*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*28*/ { GRP_X87FPU | GRP_LDCONST, { _UT("fld1") }, ID_FLD1, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*29*/ { GRP_X87FPU | GRP_LDCONST, { _UT("fldl2t") }, ID_FLDL2T, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2A*/ { GRP_X87FPU | GRP_LDCONST, { _UT("fldl2e") }, ID_FLDL2E, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2B*/ { GRP_X87FPU | GRP_LDCONST, { _UT("fldpi") }, ID_FLDPI, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2C*/ { GRP_X87FPU | GRP_LDCONST, { _UT("fldlg2") }, ID_FLDLG2, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2D*/ { GRP_X87FPU | GRP_LDCONST, { _UT("fldln2") }, ID_FLDLN2, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2E*/ { GRP_X87FPU | GRP_LDCONST, { _UT("fldz") }, ID_FLDZ, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*30*/ { GRP_X87FPU | GRP_TRANS, { _UT("f2xm1") }, ID_F2XM1, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*31*/ { GRP_X87FPU | GRP_TRANS, { _UT("fyl2x") }, ID_FYL2X, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*32*/ { GRP_X87FPU | GRP_TRANS, { _UT("fptan") }, ID_FPTAN, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x8, ARCH_COMMON },
/*33*/ { GRP_X87FPU | GRP_TRANS, { _UT("fpatan") }, ID_FPATAN, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*34*/ { GRP_X87FPU | GRP_ARITH, { _UT("fxtract") }, ID_FXTRACT, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*35*/ { GRP_X87FPU | GRP_ARITH, { _UT("fprem1") }, ID_FPREM1, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*36*/ { GRP_X87FPU | GRP_CONTROL, { _UT("fdecstp") }, ID_FDECSTP, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*37*/ { GRP_X87FPU | GRP_CONTROL, { _UT("fincstp") }, ID_FINCSTP, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*38*/ { GRP_X87FPU | GRP_ARITH, { _UT("fprem") }, ID_FPREM, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*39*/ { GRP_X87FPU | GRP_TRANS, { _UT("fyl2xp1") }, ID_FYL2XP1, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*3A*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsqrt") }, ID_FSQRT, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*3B*/ { GRP_X87FPU | GRP_TRANS, { _UT("fsincos") }, ID_FSINCOS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x8, ARCH_COMMON },
/*3C*/ { GRP_X87FPU | GRP_ARITH, { _UT("frndint") }, ID_FRNDINT, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*3D*/ { GRP_X87FPU | GRP_ARITH, { _UT("fscale") }, ID_FSCALE, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*3E*/ { GRP_X87FPU | GRP_TRANS, { _UT("fsin") }, ID_FSIN, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x8, ARCH_COMMON },
/*3F*/ { GRP_X87FPU | GRP_TRANS, { _UT("fcos") }, ID_FCOS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x8, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_DA_swtch[] =
{
/*0*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DA_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DA_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON},
/*2*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DA_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON},
/*3*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DA_NOMEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_DA_mem[] =
{
/*0*/ { GRP_X87FPU | GRP_ARITH, { _UT("fiadd") }, ID_FIADD, { { TQ_M, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1*/ { GRP_X87FPU | GRP_ARITH, { _UT("fimul") }, ID_FIMUL, { { TQ_M, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2*/ { GRP_X87FPU | GRP_COMPAR, { _UT("ficom") }, ID_FICOM, { { TQ_M, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM,0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_X87FPU | GRP_COMPAR, { _UT("ficomp") }, ID_FICOMP, { { TQ_M, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_X87FPU | GRP_ARITH, { _UT("fisub") }, ID_FISUB, { { TQ_M, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*5*/ { GRP_X87FPU | GRP_ARITH, { _UT("fisubr") }, ID_FISUBR, { { TQ_M, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*6*/ { GRP_X87FPU | GRP_ARITH, { _UT("fidiv") }, ID_FIDIV, { { TQ_M, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*7*/ { GRP_X87FPU | GRP_ARITH, { _UT("fidivr") }, ID_FIDIVR, { { TQ_M, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_DA_nomem[] =
{
/*00*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovb") }, ID_FCMOVB, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*01*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovb") }, ID_FCMOVB, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*02*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovb") }, ID_FCMOVB, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*03*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovb") }, ID_FCMOVB, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*04*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovb") }, ID_FCMOVB, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*05*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovb") }, ID_FCMOVB, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*06*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovb") }, ID_FCMOVB, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*07*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovb") }, ID_FCMOVB, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*08*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovz") }, ID_FCMOVZ, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*09*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovz") }, ID_FCMOVZ, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0A*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovz") }, ID_FCMOVZ, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0B*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovz") }, ID_FCMOVZ, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0C*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovz") }, ID_FCMOVZ, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0D*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovz") }, ID_FCMOVZ, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0E*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovz") }, ID_FCMOVZ, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0F*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovz") }, ID_FCMOVZ, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*10*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovbe") }, ID_FCMOVBE, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*11*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovbe") }, ID_FCMOVBE, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*12*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovbe") }, ID_FCMOVBE, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*13*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovbe") }, ID_FCMOVBE, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*14*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovbe") }, ID_FCMOVBE, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*15*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovbe") }, ID_FCMOVBE, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*16*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovbe") }, ID_FCMOVBE, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*17*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovbe") }, ID_FCMOVBE, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*18*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovu") }, ID_FCMOVU, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*19*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovu") }, ID_FCMOVU, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1A*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovu") }, ID_FCMOVU, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1B*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovu") }, ID_FCMOVU, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1C*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovu") }, ID_FCMOVU, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1D*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovu") }, ID_FCMOVU, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1E*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovu") }, ID_FCMOVU, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1F*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovu") }, ID_FCMOVU, { { TQ_fEST, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*20*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*21*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*22*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*23*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*24*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*25*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*26*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*27*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*28*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*29*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucompp") }, ID_FUCOMPP, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_DB_swtch[] =
{
/*0*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DB_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DB_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DB_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON  },
/*3*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DB_NOMEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_DB_mem[] =
{
/*0*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fild") }, ID_FILD, { { TQ_M, SQ_di, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1*/ { GRP_SSE3 | GRP_CONVER, { _UT("fisttp") }, ID_FISTTP, { { TQ_M, SQ_di, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fist") }, ID_FIST, { { TQ_M, SQ_di, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*3*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fistp") }, ID_FISTP, { { TQ_M, SQ_di, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fld") }, ID_FLD, { { TQ_M, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp") }, ID_FSTP, { { TQ_M, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_DB_nomem[] =
{
/*00*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnb") }, ID_FCMOVNB, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*01*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnb") }, ID_FCMOVNB, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*02*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnb") }, ID_FCMOVNB, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*03*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnb") }, ID_FCMOVNB, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*04*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnb") }, ID_FCMOVNB, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*05*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnb") }, ID_FCMOVNB, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*06*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnb") }, ID_FCMOVNB, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*07*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnb") }, ID_FCMOVNB, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*08*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnz") }, ID_FCMOVNZ, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*09*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnz") }, ID_FCMOVNZ, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0A*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnz") }, ID_FCMOVNZ, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0B*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnz") }, ID_FCMOVNZ, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0C*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnz") }, ID_FCMOVNZ, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0D*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnz") }, ID_FCMOVNZ, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0E*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnz") }, ID_FCMOVNZ, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0F*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnz") }, ID_FCMOVNZ, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*10*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmova") }, ID_FCMOVA, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*11*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmova") }, ID_FCMOVA, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*12*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmova") }, ID_FCMOVA, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*13*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmova") }, ID_FCMOVA, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*14*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmova") }, ID_FCMOVA, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*15*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmova") }, ID_FCMOVA, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*16*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmova") }, ID_FCMOVA, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*17*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmova") }, ID_FCMOVA, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*18*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnu") }, ID_FCMOVNU, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*19*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnu") }, ID_FCMOVNU, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1A*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnu") }, ID_FCMOVNU, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1B*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnu") }, ID_FCMOVNU, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1C*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnu") }, ID_FCMOVNU, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1D*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnu") }, ID_FCMOVNU, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1E*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnu") }, ID_FCMOVNU, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1F*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fcmovnu") }, ID_FCMOVNU, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*20*/ { GRP_X87FPU | GRP_CONTROL, { _UT("fneni") }, ID_FNENI, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*21*/ { GRP_X87FPU | GRP_CONTROL, { _UT("fndisi") }, ID_FNDISI, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*22*/ { GRP_X87FPU | GRP_CONTROL, { _UT("fnclex") }, ID_FNCLEX, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xF, ARCH_COMMON },
/*23*/ { GRP_X87FPU | GRP_CONTROL, { _UT("fninit") }, ID_FNINIT, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0xF, 0x0, ARCH_COMMON },
/*24*/ { GRP_X87FPU | GRP_CONTROL, { _UT("fnsetpm") }, ID_FNSETPM, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*25*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*26*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*27*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*28*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucomi") }, ID_FUCOMI, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*29*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucomi") }, ID_FUCOMI, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2A*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucomi") }, ID_FUCOMI, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2B*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucomi") }, ID_FUCOMI, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2C*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucomi") }, ID_FUCOMI, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2D*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucomi") }, ID_FUCOMI, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2E*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucomi") }, ID_FUCOMI, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2F*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucomi") }, ID_FUCOMI, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*30*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomi") }, ID_FCOMI, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*31*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomi") }, ID_FCOMI, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*32*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomi") }, ID_FCOMI, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*33*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomi") }, ID_FCOMI, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*34*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomi") }, ID_FCOMI, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*35*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomi") }, ID_FCOMI, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*36*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomi") }, ID_FCOMI, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*37*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomi") }, ID_FCOMI, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_DC_swtch[] =
{
/*0*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DC_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DC_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DC_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DC_NOMEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_DC_mem[] =
{
/*0*/ { GRP_X87FPU | GRP_ARITH, { _UT("fadd") }, ID_FADD, { { TQ_fST0, SQ_dr, FLG_R | FLG_W }, { TQ_M, SQ_dr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1*/ { GRP_X87FPU | GRP_ARITH, { _UT("fmul") }, ID_FMUL, { { TQ_fST0, SQ_dr, FLG_R | FLG_W }, { TQ_M, SQ_dr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcom") }, ID_FCOM, { { TQ_M, SQ_dr, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomp") }, ID_FCOMP, { { TQ_M, SQ_dr, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsub") }, ID_FSUB, { { TQ_fST0, SQ_dr, FLG_R | FLG_W }, { TQ_M, SQ_dr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*5*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubr") }, ID_FSUBR, { { TQ_fST0, SQ_dr, FLG_R | FLG_W }, { TQ_M, SQ_dr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*6*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdiv") }, ID_FDIV, { { TQ_fST0, SQ_dr, FLG_R | FLG_W }, { TQ_M, SQ_dr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*7*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivr") }, ID_FDIVR, { { TQ_fST0, SQ_dr, FLG_R | FLG_W }, { TQ_M, SQ_dr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_DC_nomem[] =
{
/*0*/ { GRP_X87FPU | GRP_ARITH, { _UT("fadd") }, ID_FADD, { { TQ_fEST, SQ_dr, FLG_R | FLG_W }, { TQ_fST0, SQ_dr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1*/ { GRP_X87FPU | GRP_ARITH, { _UT("fmul") }, ID_FMUL, { { TQ_fEST, SQ_dr, FLG_R | FLG_W }, { TQ_fST0, SQ_dr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcom2") }, ID_FCOM2, { { TQ_fEST, SQ_dr, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomp3") }, ID_FCOMP3, { { TQ_fEST, SQ_dr, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubr") }, ID_FSUBR, { { TQ_fEST, SQ_dr, FLG_R | FLG_W }, { TQ_fST0, SQ_dr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*5*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsub") }, ID_FSUB, { { TQ_fEST, SQ_dr, FLG_R | FLG_W }, { TQ_fST0, SQ_dr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*6*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivr") }, ID_FDIVR, { { TQ_fEST, SQ_dr, FLG_R | FLG_W }, { TQ_fST0, SQ_dr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*7*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdiv") }, ID_FDIV, { { TQ_fEST, SQ_dr, FLG_R | FLG_W }, { TQ_fST0, SQ_dr, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_DD_swtch[] =
{
/*0*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DD_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DD_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DD_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DD_NOMEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_DD_mem[] =
{
/*0*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fld") }, ID_FLD, { { TQ_M, SQ_dr, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1*/ { GRP_SSE3 | GRP_CONVER, { _UT("fisttp") }, ID_FISTTP, { { TQ_M, SQ_qi, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x2, 0xC, ARCH_COMMON },
/*2*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fst") }, ID_FST, { { TQ_M, SQ_dr, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*3*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp") }, ID_FSTP, { { TQ_M, SQ_dr, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*4*/ { GRP_X87FPU | GRP_CONTROL, { _UT("frstor") }, ID_FRSTOR, { { TQ_M, SQ_st, FLG_R }, { TQ_NULL, TQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6*/ { GRP_X87FPU | GRP_CONTROL, { _UT("fnsave") }, ID_FNSAVE, { { TQ_M, SQ_st, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0xF, 0x0, ARCH_COMMON },
/*7*/ { GRP_X87FPU | GRP_CONTROL, { _UT("fnstsw") }, ID_FNSTSW, { { TQ_M, SQ_w, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xF, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_DD_nomem[] =
{
/*0*/ { GRP_X87FPU | GRP_CONTROL, { _UT("ffree") }, ID_FFREE, { { TQ_fEST, SQ_er, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xF, ARCH_COMMON },
/*1*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fxch4") }, ID_FXCH4, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fst") }, ID_FST, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*3*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp") }, ID_FSTP, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*4*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucom") }, ID_FUCOM, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucomp") }, ID_FUCOMP, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_DE_swtch[] =
{
/*0*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DE_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DE_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DE_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DE_NOMEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_DE_mem[] =
{
/*0*/ { GRP_X87FPU | GRP_ARITH, { _UT("fiadd") }, ID_FIADD, { { TQ_M, SQ_wi, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1*/ { GRP_X87FPU | GRP_ARITH, { _UT("fimul") }, ID_FIMUL, { { TQ_M, SQ_wi, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2*/ { GRP_X87FPU | GRP_COMPAR, { _UT("ficom") }, ID_FICOM, { { TQ_M, SQ_wi, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_X87FPU | GRP_COMPAR, { _UT("ficomp") }, ID_FICOMP, { { TQ_M, SQ_wi, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_X87FPU | GRP_ARITH, { _UT("fisub") }, ID_FISUB, { { TQ_M, SQ_wi, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*5*/ { GRP_X87FPU | GRP_ARITH, { _UT("fisubr") }, ID_FISUBR, { { TQ_M, SQ_wi, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*6*/ { GRP_X87FPU | GRP_ARITH, { _UT("fidiv") }, ID_FIDIV, { { TQ_M, SQ_wi, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*7*/ { GRP_X87FPU | GRP_ARITH, { _UT("fidivr") }, ID_FIDIVR, { { TQ_M, SQ_wi, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_DE_nomem[] =
{
/*00*/ { GRP_X87FPU | GRP_ARITH, { _UT("faddp") }, ID_FADDP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*01*/ { GRP_X87FPU | GRP_ARITH, { _UT("faddp") }, ID_FADDP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*02*/ { GRP_X87FPU | GRP_ARITH, { _UT("faddp") }, ID_FADDP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*03*/ { GRP_X87FPU | GRP_ARITH, { _UT("faddp") }, ID_FADDP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*04*/ { GRP_X87FPU | GRP_ARITH, { _UT("faddp") }, ID_FADDP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*05*/ { GRP_X87FPU | GRP_ARITH, { _UT("faddp") }, ID_FADDP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*06*/ { GRP_X87FPU | GRP_ARITH, { _UT("faddp") }, ID_FADDP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*07*/ { GRP_X87FPU | GRP_ARITH, { _UT("faddp") }, ID_FADDP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*08*/ { GRP_X87FPU | GRP_ARITH, { _UT("fmulp") }, ID_FMULP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*09*/ { GRP_X87FPU | GRP_ARITH, { _UT("fmulp") }, ID_FMULP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0A*/ { GRP_X87FPU | GRP_ARITH, { _UT("fmulp") }, ID_FMULP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0B*/ { GRP_X87FPU | GRP_ARITH, { _UT("fmulp") }, ID_FMULP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0C*/ { GRP_X87FPU | GRP_ARITH, { _UT("fmulp") }, ID_FMULP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0D*/ { GRP_X87FPU | GRP_ARITH, { _UT("fmulp") }, ID_FMULP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0E*/ { GRP_X87FPU | GRP_ARITH, { _UT("fmulp") }, ID_FMULP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0F*/ { GRP_X87FPU | GRP_ARITH, { _UT("fmulp") }, ID_FMULP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*10*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomp5") }, ID_FCOMP5, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*11*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomp5") }, ID_FCOMP5, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*12*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomp5") }, ID_FCOMP5, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*13*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomp5") }, ID_FCOMP5, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*14*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomp5") }, ID_FCOMP5, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*15*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomp5") }, ID_FCOMP5, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*16*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomp5") }, ID_FCOMP5, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*17*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomp5") }, ID_FCOMP5, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*18*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*19*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcompp") }, ID_FCOMPP, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*20*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubrp") }, ID_FSUBRP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*21*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubrp") }, ID_FSUBRP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*22*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubrp") }, ID_FSUBRP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*23*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubrp") }, ID_FSUBRP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*24*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubrp") }, ID_FSUBRP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*25*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubrp") }, ID_FSUBRP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*26*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubrp") }, ID_FSUBRP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*27*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubrp") }, ID_FSUBRP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*28*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubp") }, ID_FSUBP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*29*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubp") }, ID_FSUBP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2A*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubp") }, ID_FSUBP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2B*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubp") }, ID_FSUBP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2C*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubp") }, ID_FSUBP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2D*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubp") }, ID_FSUBP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2E*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubp") }, ID_FSUBP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2F*/ { GRP_X87FPU | GRP_ARITH, { _UT("fsubp") }, ID_FSUBP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0}, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*30*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivrp") }, ID_FDIVRP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*31*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivrp") }, ID_FDIVRP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*32*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivrp") }, ID_FDIVRP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*33*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivrp") }, ID_FDIVRP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*34*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivrp") }, ID_FDIVRP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*35*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivrp") }, ID_FDIVRP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*36*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivrp") }, ID_FDIVRP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*37*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivrp") }, ID_FDIVRP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*38*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivp") }, ID_FDIVP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*39*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivp") }, ID_FDIVP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*3A*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivp") }, ID_FDIVP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*3B*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivp") }, ID_FDIVP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*3C*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivp") }, ID_FDIVP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*3D*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivp") }, ID_FDIVP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*3E*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivp") }, ID_FDIVP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*3F*/ { GRP_X87FPU | GRP_ARITH, { _UT("fdivp") }, ID_FDIVP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_DF_swtch[] =
{
/*0*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DF_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DF_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DF_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_DF_NOMEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_DF_mem[] =
{
/*0*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fild") }, ID_FILD, { { TQ_M, SQ_wi, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1*/ { GRP_SSE3 | GRP_CONVER, { _UT("fisttp") }, ID_FISTTP, { { TQ_M, SQ_wi, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*2*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fist") }, ID_FIST, { { TQ_M, SQ_wi, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*3*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fistp") }, ID_FISTP, { { TQ_M, SQ_wi, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*4*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fbld") }, ID_FBLD, { { TQ_M, SQ_bcd, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*5*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fild") }, ID_FILD, { { TQ_M, SQ_qi, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*6*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fbstp") }, ID_FBSTP, { { TQ_M, SQ_bcd, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*7*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fistp") }, ID_FISTP, { { TQ_M, SQ_qi, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_DF_nomem[] =
{
/*00*/ { GRP_X87FPU | GRP_CONTROL, { _UT("ffreep") }, ID_FFREEP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xF, ARCH_COMMON },
/*01*/ { GRP_X87FPU | GRP_CONTROL, { _UT("ffreep") }, ID_FFREEP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xF, ARCH_COMMON },
/*02*/ { GRP_X87FPU | GRP_CONTROL, { _UT("ffreep") }, ID_FFREEP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xF, ARCH_COMMON },
/*03*/ { GRP_X87FPU | GRP_CONTROL, { _UT("ffreep") }, ID_FFREEP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xF, ARCH_COMMON },
/*04*/ { GRP_X87FPU | GRP_CONTROL, { _UT("ffreep") }, ID_FFREEP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xF, ARCH_COMMON },
/*05*/ { GRP_X87FPU | GRP_CONTROL, { _UT("ffreep") }, ID_FFREEP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xF, ARCH_COMMON },
/*06*/ { GRP_X87FPU | GRP_CONTROL, { _UT("ffreep") }, ID_FFREEP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xF, ARCH_COMMON },
/*07*/ { GRP_X87FPU | GRP_CONTROL, { _UT("ffreep") }, ID_FFREEP, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xF, ARCH_COMMON },
/*08*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fxch7") }, ID_FXCH7, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*09*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fxch7") }, ID_FXCH7, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0A*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fxch7") }, ID_FXCH7, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0B*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fxch7") }, ID_FXCH7, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0C*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fxch7") }, ID_FXCH7, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0D*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fxch7") }, ID_FXCH7, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0E*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fxch7") }, ID_FXCH7, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*0F*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fxch7") }, ID_FXCH7, { { TQ_fEST, SQ_er, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*10*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp8") }, ID_FSTP8, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*11*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp8") }, ID_FSTP8, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*12*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp8") }, ID_FSTP8, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*13*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp8") }, ID_FSTP8, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*14*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp8") }, ID_FSTP8, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*15*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp8") }, ID_FSTP8, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*16*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp8") }, ID_FSTP8, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*17*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp8") }, ID_FSTP8, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*18*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp9") }, ID_FSTP9, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*19*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp9") }, ID_FSTP9, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1A*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp9") }, ID_FSTP9, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1B*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp9") }, ID_FSTP9, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1C*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp9") }, ID_FSTP9, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1D*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp9") }, ID_FSTP9, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1E*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp9") }, ID_FSTP9, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*1F*/ { GRP_X87FPU | GRP_DATAMOV, { _UT("fstp9") }, ID_FSTP9, { { TQ_fEST, SQ_er, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xC, ARCH_COMMON },
/*20*/ { GRP_X87FPU | GRP_CONTROL, { _UT("fnstsw") }, ID_FNSTSW, { { TQ_rAX, SQ_w, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xF, 0x0, 0x0, 0xF, ARCH_COMMON },
/*21*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*22*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*23*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*24*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*25*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*26*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*27*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*28*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucomip") }, ID_FUCOMIP, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*29*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucomip") }, ID_FUCOMIP, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2A*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucomip") }, ID_FUCOMIP, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2B*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucomip") }, ID_FUCOMIP, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2C*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucomip") }, ID_FUCOMIP, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2D*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucomip") }, ID_FUCOMIP, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2E*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucomip") }, ID_FUCOMIP, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2F*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fucomip") }, ID_FUCOMIP, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*30*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomip") }, ID_FCOMIP, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*31*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomip") }, ID_FCOMIP, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*32*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomip") }, ID_FCOMIP, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*33*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomip") }, ID_FCOMIP, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*34*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomip") }, ID_FCOMIP, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*35*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomip") }, ID_FCOMIP, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*36*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomip") }, ID_FCOMIP, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON },
/*37*/ { GRP_X87FPU | GRP_COMPAR, { _UT("fcomip") }, ID_FCOMIP, { { TQ_fEST, SQ_er, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x2, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_0F[] = 
{
/*00*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_00, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*01*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_01_SWTCH, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*02*/ { GRP_GEN | GRP_SYSTEM, { _UT("lar") }, ID_LAR, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_wv, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x8, 0x0, 0x0, 0x0, ARCH_COMMON },
/*03*/ { GRP_GEN | GRP_SYSTEM, { _UT("lsl") }, ID_LSL, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_wv, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x8, 0x0, 0x0, 0x0, ARCH_COMMON },
/*04*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*05*/ { GRP_GEN | GRP_SYSTEM | GRP_BREAK, { _UT("syscall") }, ID_SYSCALL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_O64, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*06*/ { GRP_GEN | GRP_SYSTEM, { _UT("clts") }, ID_CLTS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_RING0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*07*/ { GRP_GEN | GRP_SYSTEM | GRP_BREAK | GRP_TRANS, { _UT("sysret") }, ID_SYSRET, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_O64, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*08*/ { GRP_GEN | GRP_SYSTEM, { _UT("invd") }, ID_INVD, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_RING0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*09*/ { GRP_GEN | GRP_SYSTEM, { _UT("wbinvd") }, ID_WBINVD, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_RING0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0B*/ { GRP_GEN | GRP_CONTROL | GRP_BREAK, { _UT("ud2") }, ID_UD2, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0D*/ { GRP_GEN | GRP_CONTROL, { _UT("nop") }, ID_NOP, { { TQ_E, SQ_v, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_POST_PROC | POST_PROC_MULTINOP, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*10*/ { GRP_SSE1 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movups") }, ID_MOVUPS, { { TQ_V, SQ_ps, FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*11*/ { GRP_SSE1 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movups") }, ID_MOVUPS, { { TQ_W, SQ_ps, FLG_W }, { TQ_V, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*12*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_12, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*13*/ { GRP_SSE1 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movlps") }, ID_MOVLPS, { { TQ_M, SQ_q, FLG_R | FLG_W }, { TQ_V, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*14*/ { GRP_SSE1 | GRP_SIMDFP | GRP_SHUNPCK, { _UT("unpcklps") }, ID_UNPCKLPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*15*/ { GRP_SSE1 | GRP_SIMDFP | GRP_SHUNPCK, { _UT("unpckhps") }, ID_UNPCKHPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*16*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_16, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*17*/ { GRP_SSE1 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movhps") }, ID_MOVHPS, { { TQ_M, SQ_q, FLG_R | FLG_W }, { TQ_V, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*18*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_18, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*19*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_19, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1A*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_19, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1B*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_19, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1C*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_19, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1D*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_19, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1E*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_19, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1F*/ { GRP_GEN | GRP_CONTROL, { _UT("nop") }, ID_NOP, { { TQ_E, SQ_v, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*20*/ { GRP_GEN | GRP_SYSTEM, { _UT("mov") }, ID_MOV, { { TQ_H, SQ_dq64, FLG_W }, { TQ_C, SQ_dq64, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x9F, 0x0, 0x0, 0x9F, ARCH_COMMON },
/*21*/ { GRP_GEN | GRP_SYSTEM, { _UT("mov") }, ID_MOV, { { TQ_H, SQ_dq64, FLG_W }, { TQ_D, SQ_dq64, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x9F, 0x0, 0x0, 0x9F, ARCH_COMMON },
/*22*/ { GRP_GEN | GRP_SYSTEM, { _UT("mov") }, ID_MOV, { { TQ_C, SQ_dq64, FLG_W }, { TQ_H, SQ_dq64, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0 | PROP_SERIAL, 0x0, 0x9F, 0x0, 0x0, 0x9F, ARCH_COMMON },
/*23*/ { GRP_GEN | GRP_SYSTEM, { _UT("mov") }, ID_MOV, { { TQ_D, SQ_dq64, FLG_W }, { TQ_H, SQ_dq64, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0 | PROP_SERIAL, 0x0, 0x9F, 0x0, 0x0, 0x9F, ARCH_COMMON },
/*24*/ { GRP_GEN | GRP_SYSTEM, { _UT("mov") }, ID_MOV, { { TQ_H, SQ_d, FLG_W }, { TQ_T, SQ_d, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x9F, 0x0, 0x0, 0x9F, ARCH_COMMON },
/*25*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*26*/ { GRP_GEN | GRP_SYSTEM, { _UT("mov") }, ID_MOV, { { TQ_T, SQ_d, FLG_W }, { TQ_H, SQ_d, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x9F, 0x0, 0x0, 0x9F, ARCH_COMMON },
/*27*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*28*/ { GRP_SSE1 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movaps") }, ID_MOVAPS, { { TQ_V, SQ_ps, FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*29*/ { GRP_SSE1 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movaps") }, ID_MOVAPS, { { TQ_W, SQ_ps, FLG_W }, { TQ_V, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2A*/ { GRP_SSE2 | GRP_CONVER, { _UT("cvtpi2ps") }, ID_CVTPI2PS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_Q, SQ_pi, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2B*/ { GRP_SSE1 | GRP_CACHECT, { _UT("movntps") }, ID_MOVNTPS, { { TQ_M, SQ_ps, FLG_W }, { TQ_V, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2C*/ { GRP_SSE2 | GRP_CONVER, { _UT("cvttps2pi") }, ID_CVTTPS2PI, { { TQ_P, SQ_pi, FLG_W }, { TQ_W, SQ_psq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2D*/ { GRP_SSE2 | GRP_CONVER, { _UT("cvtps2pi") }, ID_CVTPS2PI, { { TQ_P, SQ_pi, FLG_W }, { TQ_W, SQ_psq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2E*/ { GRP_SSE1 | GRP_SIMDFP | GRP_COMPAR, { _UT("ucomiss") }, ID_UCOMISS, { { TQ_V, SQ_ss, FLG_R }, { TQ_W, SQ_ss, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xB, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2F*/ { GRP_SSE1 | GRP_SIMDFP | GRP_COMPAR, { _UT("comiss") }, ID_COMISS, { { TQ_V, SQ_ss, FLG_R }, { TQ_W, SQ_ss, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xB, 0x0, 0x0, 0x0, ARCH_COMMON },
/*30*/ { GRP_GEN | GRP_SYSTEM, { _UT("wrmsr") }, ID_WRMSR, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_RING0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*31*/ { GRP_GEN | GRP_SYSTEM, { _UT("rdtsc") }, ID_RDTSC, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*32*/ { GRP_GEN | GRP_SYSTEM, { _UT("rdmsr") }, ID_RDMSR, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_RING0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*33*/ { GRP_GEN | GRP_SYSTEM, { _UT("rdpmc") }, ID_RDPMC, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*34*/ { GRP_GEN | GRP_SYSTEM | GRP_BREAK | GRP_TRANS, { _UT("sysenter") }, ID_SYSENTER, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x20, 0x0, 0x20, 0x0, ARCH_COMMON },
/*35*/ { GRP_GEN | GRP_SYSTEM | GRP_BREAK | GRP_TRANS, { _UT("sysexit") }, ID_SYSEXIT, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x00, 0x0, 0x00, 0x0, ARCH_COMMON },
/*36*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*37*/ { GRP_SMX | GRP_BREAK, { _UT("getsec") }, ID_GETSEC, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_INTEL },
/*38*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_38, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*39*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3A*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_3A, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*40*/ { GRP_GEN | GRP_DATAMOV, { _UT("cmovo") }, ID_CMOVO, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x80, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*41*/ { GRP_GEN | GRP_DATAMOV, { _UT("cmovno") }, ID_CMOVNO, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x80, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*42*/ { GRP_GEN | GRP_DATAMOV, { _UT("cmovb") }, ID_CMOVB, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*43*/ { GRP_GEN | GRP_DATAMOV, { _UT("cmovae") }, ID_CMOVAE, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*44*/ { GRP_GEN | GRP_DATAMOV, { _UT("cmovz") }, ID_CMOVZ, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x8, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*45*/ { GRP_GEN | GRP_DATAMOV, { _UT("cmovnz") }, ID_CMOVNZ, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x8, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*46*/ { GRP_GEN | GRP_DATAMOV, { _UT("cmovbe") }, ID_CMOVBE, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x9, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*47*/ { GRP_GEN | GRP_DATAMOV, { _UT("cmova") }, ID_CMOVA, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x9, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*48*/ { GRP_GEN | GRP_DATAMOV, { _UT("cmovs") }, ID_CMOVS, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x10, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*49*/ { GRP_GEN | GRP_DATAMOV, { _UT("cmovns") }, ID_CMOVNS, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x10, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4A*/ { GRP_GEN | GRP_DATAMOV, { _UT("cmovp") }, ID_CMOVP, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x2, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4B*/ { GRP_GEN | GRP_DATAMOV, { _UT("cmovnp") }, ID_CMOVNP, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x2, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4C*/ { GRP_GEN | GRP_DATAMOV, { _UT("cmovl") }, ID_CMOVL, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x90, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4D*/ { GRP_GEN | GRP_DATAMOV, { _UT("cmovge") }, ID_CMOVGE, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x90, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4E*/ { GRP_GEN | GRP_DATAMOV, { _UT("cmovle") }, ID_CMOVLE, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x98, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4F*/ { GRP_GEN | GRP_DATAMOV, { _UT("cmovg") }, ID_CMOVG, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x98, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*50*/ { GRP_SSE1 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movmskps") }, ID_MOVMSKPS, { { TQ_G, SQ_dqp, FLG_W }, { TQ_U, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*51*/ { GRP_SSE1 | GRP_SIMDFP | GRP_ARITH, { _UT("sqrtps") }, ID_SQRTPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*52*/ { GRP_SSE1 | GRP_SIMDFP | GRP_ARITH, { _UT("rsqrtps") }, ID_RSQRTPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*53*/ { GRP_SSE2 | GRP_SIMDFP | GRP_ARITH, { _UT("rcpps") }, ID_RCPPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*54*/ { GRP_SSE1 | GRP_SIMDFP | GRP_LOGICAL, { _UT("andps") }, ID_ANDPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*55*/ { GRP_SSE1 | GRP_SIMDFP | GRP_LOGICAL, { _UT("andnps") }, ID_ANDNPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*56*/ { GRP_SSE1 | GRP_SIMDFP | GRP_LOGICAL, { _UT("orps") }, ID_ORPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*57*/ { GRP_SSE2 | GRP_SIMDFP | GRP_LOGICAL, { _UT("xorps") }, ID_XORPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*58*/ { GRP_SSE2 | GRP_SIMDFP | GRP_ARITH, { _UT("addps") }, ID_ADDPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*59*/ { GRP_SSE2 | GRP_SIMDFP | GRP_ARITH, { _UT("mulps") }, ID_MULPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5A*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_CONVER, { _UT("cvtps2pd") }, ID_CVTPS2PD, { { TQ_V, SQ_pd, FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5B*/ { GRP_SSE2 | GRP_PCKSP, { _UT("cvtdq2ps") }, ID_CVTDQ2PS, { { TQ_V, SQ_ps, FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5C*/ { GRP_SSE1 | GRP_SIMDFP | GRP_ARITH, { _UT("subps") }, ID_SUBPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5D*/ { GRP_SSE1 | GRP_SIMDFP | GRP_ARITH, { _UT("minps") }, ID_MINPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5E*/ { GRP_SSE1 | GRP_SIMDFP | GRP_ARITH, { _UT("divps") }, ID_DIVPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5F*/ { GRP_SSE1 | GRP_SIMDFP | GRP_ARITH, { _UT("maxps") }, ID_MAXPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*60*/ { GRP_MMX | GRP_UNPACK, { _UT("punpcklbw") }, ID_PUNPCKLBW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_d, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*61*/ { GRP_MMX | GRP_UNPACK, { _UT("punpcklwd") }, ID_PUNPCKLWD, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_d, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*62*/ { GRP_MMX | GRP_UNPACK, { _UT("punpckldq") }, ID_PUNPCKLDQ, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_d, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*63*/ { GRP_MMX | GRP_CONVER, { _UT("packsswb") }, ID_PACKSSWB, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_d, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*64*/ { GRP_MMX | GRP_COMPAR, { _UT("pcmpgtb") }, ID_PCMPGTB, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_d, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*65*/ { GRP_MMX | GRP_COMPAR, { _UT("pcmpgtw") }, ID_PCMPGTW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_d, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*66*/ { GRP_MMX | GRP_COMPAR, { _UT("pcmpgtd") }, ID_PCMPGTD, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_d, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*67*/ { GRP_MMX | GRP_CONVER, { _UT("packuswb") }, ID_PACKUSWB, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*68*/ { GRP_MMX | GRP_UNPACK, { _UT("punpckhbw") }, ID_PUNPCKHBW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*69*/ { GRP_MMX | GRP_UNPACK, { _UT("punpckhwd") }, ID_PUNPCKHWD, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6A*/ { GRP_MMX | GRP_UNPACK, { _UT("punpckhdq") }, ID_PUNPCKHDQ, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6B*/ { GRP_MMX | GRP_CONVER, { _UT("packssdw") }, ID_PACKSSDW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6E*/ { GRP_MMX | GRP_DATAMOV, { _UT("movd") }, ID_MOVD, { { TQ_P, SQ_q, FLG_W }, { TQ_E, SQ_dqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6F*/ { GRP_MMX | GRP_DATAMOV, { _UT("movq") }, ID_MOVQ, { { TQ_P, SQ_q, FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*70*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("pshufw") }, ID_PSHUFW, { { TQ_P, SQ_q, FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*71*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_71, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*72*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_72, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*73*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_73, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*74*/ { GRP_MMX | GRP_COMPAR, { _UT("pcmpeqb") }, ID_PCMPEQB, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*75*/ { GRP_MMX | GRP_COMPAR, { _UT("pcmpeqw") }, ID_PCMPEQW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*76*/ { GRP_MMX | GRP_COMPAR, { _UT("pcmpeqd") }, ID_PCMPEQD, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*77*/ { GRP_MMX | GRP_CONTROL, { _UT("emms") }, ID_EMMS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*78*/ { GRP_VMX, { _UT("vmread") }, ID_VMREAD, { { TQ_E, SQ_dq64, FLG_W }, { TQ_G, SQ_dq64, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x9F, 0x0, 0x9E, 0x0, ARCH_INTEL },
/*79*/ { GRP_VMX, { _UT("vmwrite") }, ID_VMWRITE, { { TQ_G, SQ_dq64, FLG_R }, { TQ_E, SQ_dq64, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x9F, 0x0, 0x9E, 0x0, ARCH_INTEL },
/*7A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7E*/ { GRP_MMX | GRP_DATAMOV, { _UT("movd") }, ID_MOVD, { { TQ_E, SQ_dqp, FLG_W }, { TQ_P, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7F*/ { GRP_MMX | GRP_DATAMOV, { _UT("movq") }, ID_MOVQ, { { TQ_Q, SQ_q, FLG_W }, { TQ_P, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*80*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jo") }, ID_JO, { { TQ_J, SQ_vds, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x80, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*81*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jno") }, ID_JNO, { { TQ_J, SQ_vds, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x80, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*82*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jb") }, ID_JB, { { TQ_J, SQ_vds, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x1, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*83*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jae") }, ID_JAE, { { TQ_J, SQ_vds, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x1, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*84*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jz") }, ID_JZ, { { TQ_J, SQ_vds, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x8, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*85*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jnz") }, ID_JNZ, { { TQ_J, SQ_vds, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x8, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*86*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jbe") }, ID_JBE, { { TQ_J, SQ_vds, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x9, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*87*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("ja") }, ID_JA, { { TQ_J, SQ_vds, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x9, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*88*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("js") }, ID_JS, { { TQ_J, SQ_vds, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x10, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*89*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jns") }, ID_JNS, { { TQ_J, SQ_vds, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x10, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8A*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jp") }, ID_JP, { { TQ_J, SQ_vds, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x2, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8B*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jnp") }, ID_JNP, { { TQ_J, SQ_vds, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x2, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8C*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jl") }, ID_JL, { { TQ_J, SQ_vds, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x90, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8D*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jge") }, ID_JGE, { { TQ_J, SQ_vds, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x90, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8E*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jle") }, ID_JLE, { { TQ_J, SQ_vds, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x98, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8F*/ { GRP_GEN | GRP_BRANCH | GRP_COND, { _UT("jg") }, ID_JG, { { TQ_J, SQ_vds, FLG_R | FLG_X }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x98, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*90*/ { GRP_GEN | GRP_DATAMOV, { _UT("seto") }, ID_SETO, { { TQ_E, SQ_b, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x80, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*91*/ { GRP_GEN | GRP_DATAMOV, { _UT("setno") }, ID_SETNO, { { TQ_E, SQ_b, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x80, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*92*/ { GRP_GEN | GRP_DATAMOV, { _UT("setb") }, ID_SETB, { { TQ_E, SQ_b, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*93*/ { GRP_GEN | GRP_DATAMOV, { _UT("setae") }, ID_SETAE, { { TQ_E, SQ_b, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x1, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*94*/ { GRP_GEN | GRP_DATAMOV, { _UT("setz") }, ID_SETZ, { { TQ_E, SQ_b, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x8, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*95*/ { GRP_GEN | GRP_DATAMOV, { _UT("setnz") }, ID_SETNZ, { { TQ_E, SQ_b, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x8, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*96*/ { GRP_GEN | GRP_DATAMOV, { _UT("setbe") }, ID_SETBE, { { TQ_E, SQ_b, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x9, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*97*/ { GRP_GEN | GRP_DATAMOV, { _UT("seta") }, ID_SETA, { { TQ_E, SQ_b, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x9, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*98*/ { GRP_GEN | GRP_DATAMOV, { _UT("sets") }, ID_SETS, { { TQ_E, SQ_b, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x10, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*99*/ { GRP_GEN | GRP_DATAMOV, { _UT("setns") }, ID_SETNS, { { TQ_E, SQ_b, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x10, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9A*/ { GRP_GEN | GRP_DATAMOV, { _UT("setp") }, ID_SETP, { { TQ_E, SQ_b, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x2, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9B*/ { GRP_GEN | GRP_DATAMOV, { _UT("setnp") }, ID_SETNP, { { TQ_E, SQ_b, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x2, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9C*/ { GRP_GEN | GRP_DATAMOV, { _UT("setl") }, ID_SETL, { { TQ_E, SQ_b, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x90, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9D*/ { GRP_GEN | GRP_DATAMOV, { _UT("setge") }, ID_SETGE, { { TQ_E, SQ_b, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x90, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9E*/ { GRP_GEN | GRP_DATAMOV, { _UT("setle") }, ID_SETLE, { { TQ_E, SQ_b, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x98, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9F*/ { GRP_GEN | GRP_DATAMOV, { _UT("setg") }, ID_SETG, { { TQ_E, SQ_b, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x98, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A0*/ { GRP_GEN | GRP_STACK | GRP_SEGREG, { _UT("push") }, ID_PUSH, { { TQ_FS, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A1*/ { GRP_GEN | GRP_STACK | GRP_SEGREG, { _UT("pop") }, ID_POP, { { TQ_FS, SQ_w, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A2*/ { GRP_GEN | GRP_CONTROL, { _UT("cpuid") }, ID_CPUID, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A3*/ { GRP_GEN | GRP_BIT, { _UT("bt") }, ID_BT, { { TQ_E, SQ_vqp, FLG_R }, { TQ_G, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x9E, ARCH_COMMON },
/*A4*/ { GRP_GEN | GRP_SHFTROT, { _UT("shld") }, ID_SHLD, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_G, SQ_vqp, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x85, ARCH_COMMON },
/*A5*/ { GRP_GEN | GRP_SHFTROT, { _UT("shld") }, ID_SHLD, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_G, SQ_vqp, FLG_R }, { TQ_rCX, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x85, ARCH_COMMON },
/*A6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A7*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A8*/ { GRP_GEN | GRP_STACK | GRP_SEGREG, { _UT("push") }, ID_PUSH, { { TQ_GS, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A9*/ { GRP_GEN | GRP_STACK | GRP_SEGREG, { _UT("pop") }, ID_POP, { { TQ_GS, SQ_w, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AA*/ { GRP_GEN | GRP_SYSTEM | GRP_BREAK, { _UT("rsm") }, ID_RSM, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AB*/ { GRP_GEN | GRP_BIT, { _UT("bts") }, ID_BTS, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_G, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_LOCK, 0x0, 0x9F, 0x0, 0x0, 0x9E, ARCH_COMMON },
/*AC*/ { GRP_GEN | GRP_SHFTROT, { _UT("shrd") }, ID_SHRD, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_G, SQ_vqp, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x85, ARCH_COMMON },
/*AD*/ { GRP_GEN | GRP_SHFTROT, { _UT("shrd") }, ID_SHRD, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_G, SQ_vqp, FLG_R }, { TQ_rCX, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x85, ARCH_COMMON },
/*AE*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_AE_SWTCH, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AF*/ { GRP_GEN | GRP_ARITH | GRP_BINARY, { _UT("imul") }, ID_IMUL, { { TQ_G, SQ_vqp, FLG_R | FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x1E, ARCH_COMMON },
/*B0*/ { GRP_GEN | GRP_DATAMOV | GRP_ARITH | GRP_BINARY, { _UT("cmpxchg") }, ID_CMPXCHG, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_G, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B1*/ { GRP_GEN | GRP_DATAMOV | GRP_ARITH | GRP_BINARY, { _UT("cmpxchg") }, ID_CMPXCHG, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_G, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B2*/ { GRP_GEN | GRP_DATAMOV | GRP_SEGREG, { _UT("lss") }, ID_LSS, { { TQ_G, SQ_vqp, FLG_W }, { TQ_M, SQ_ptp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B3*/ { GRP_GEN | GRP_BIT, { _UT("btr") }, ID_BTR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_G, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_LOCK, 0x0, 0x9F, 0x0, 0x0, 0x9E, ARCH_COMMON },
/*B4*/ { GRP_GEN | GRP_DATAMOV | GRP_SEGREG, { _UT("lfs") }, ID_LFS, { { TQ_G, SQ_vqp, FLG_W }, { TQ_M, SQ_ptp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B5*/ { GRP_GEN | GRP_DATAMOV | GRP_SEGREG, { _UT("lgs") }, ID_LGS, { { TQ_G, SQ_vqp, FLG_W }, { TQ_M, SQ_ptp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B6*/ { GRP_GEN | GRP_CONVER, { _UT("movzx") }, ID_MOVZX, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B7*/ { GRP_GEN | GRP_CONVER, { _UT("movzx") }, ID_MOVZX, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B8*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B9*/ { GRP_GEN | GRP_CONTROL | GRP_BREAK, { _UT("ud") }, ID_UD, { { TQ_G, SQ_NULL, 0 }, { TQ_E, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BA*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_BA, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BB*/ { GRP_GEN | GRP_BIT, { _UT("btc") }, ID_BTC, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_G, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_LOCK, 0x0, 0x9F, 0x0, 0x0, 0x9E, ARCH_COMMON },
/*BC*/ { GRP_GEN | GRP_BIT, { _UT("bsf") }, ID_BSF, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x97, ARCH_COMMON },
/*BD*/ { GRP_GEN | GRP_BIT, { _UT("bsr") }, ID_BSR, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x97, ARCH_COMMON },
/*BE*/ { GRP_GEN | GRP_CONVER, { _UT("movsx") }, ID_MOVSX, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BF*/ { GRP_GEN | GRP_CONVER, { _UT("movsx") }, ID_MOVSX, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C0*/ { GRP_GEN | GRP_DATAMOV | GRP_ARITH | GRP_BINARY, { _UT("xadd") }, ID_XADD, { { TQ_E, SQ_b, FLG_R | FLG_W }, { TQ_G, SQ_b, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C1*/ { GRP_GEN | GRP_DATAMOV | GRP_ARITH | GRP_BINARY, { _UT("xadd") }, ID_XADD, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_G, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C2*/ { GRP_SSE1 | GRP_SIMDFP | GRP_COMPAR, { _UT("cmpps") }, ID_CMPPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C3*/ { GRP_SSE2 | GRP_CACHECT, { _UT("movnti") }, ID_MOVNTI, { { TQ_M, SQ_dqp, FLG_W }, { TQ_G, SQ_dqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C4*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("pinsrw") }, ID_PINSRW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_E, SQ_wdqp, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C5*/ { GRP_MMX | GRP_SIMDINT, { _UT("pextrw") }, ID_PEXTRW, { { TQ_G, SQ_dqp, FLG_W }, { TQ_N, SQ_q, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C6*/ { GRP_SSE1 | GRP_SIMDFP | GRP_SHUNPCK, { _UT("shufps") }, ID_SHUFPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C7*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_C7, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C8*/ { GRP_GEN | GRP_DATAMOV, { _UT("bswap") }, ID_BSWAP, { { TQ_Z, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C9*/ { GRP_GEN | GRP_DATAMOV, { _UT("bswap") }, ID_BSWAP, { { TQ_Z, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CA*/ { GRP_GEN | GRP_DATAMOV, { _UT("bswap") }, ID_BSWAP, { { TQ_Z, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CB*/ { GRP_GEN | GRP_DATAMOV, { _UT("bswap") }, ID_BSWAP, { { TQ_Z, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CC*/ { GRP_GEN | GRP_DATAMOV, { _UT("bswap") }, ID_BSWAP, { { TQ_Z, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CD*/ { GRP_GEN | GRP_DATAMOV, { _UT("bswap") }, ID_BSWAP, { { TQ_Z, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CE*/ { GRP_GEN | GRP_DATAMOV, { _UT("bswap") }, ID_BSWAP, { { TQ_Z, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CF*/ { GRP_GEN | GRP_DATAMOV, { _UT("bswap") }, ID_BSWAP, { { TQ_Z, SQ_vqp, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D1*/ { GRP_MMX | GRP_SHIFT, { _UT("psrlw") }, ID_PSRLW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D2*/ { GRP_MMX | GRP_SHIFT, { _UT("psrld") }, ID_PSRLD, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D3*/ { GRP_MMX | GRP_SHIFT, { _UT("psrlq") }, ID_PSRLQ, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D4*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("paddq") }, ID_PADDQ, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D5*/ { GRP_MMX | GRP_ARITH, { _UT("pmullw") }, ID_PMULLW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D7*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("pmovmskb") }, ID_PMOVMSKB, { { TQ_G, SQ_dqp, FLG_W }, { TQ_N, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D8*/ { GRP_MMX | GRP_ARITH, { _UT("psubusb") }, ID_PSUBUSB, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D9*/ { GRP_MMX | GRP_ARITH, { _UT("psubusw") }, ID_PSUBUSW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DA*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("pminub") }, ID_PMINUB, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DB*/ { GRP_MMX | GRP_LOGICAL, { _UT("pand") }, ID_PAND, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_d, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DC*/ { GRP_MMX | GRP_ARITH, { _UT("paddusb") }, ID_PADDUSB, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DD*/ { GRP_MMX | GRP_ARITH, { _UT("paddusw") }, ID_PADDUSW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DE*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("pmaxub") }, ID_PMAXUB, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DF*/ { GRP_MMX | GRP_LOGICAL, { _UT("pandn") }, ID_PANDN, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E0*/ { GRP_MMX | GRP_SIMDINT, { _UT("pavgb") }, ID_PAVGB, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E1*/ { GRP_MMX | GRP_SHIFT, { _UT("psraw") }, ID_PSRAW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E2*/ { GRP_MMX | GRP_SHIFT, { _UT("psrad") }, ID_PSRAD, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E3*/ { GRP_MMX | GRP_SIMDINT, { _UT("pavgw") }, ID_PAVGW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E4*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("pmulhuw") }, ID_PMULHUW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E5*/ { GRP_MMX | GRP_ARITH, { _UT("pmulhw") }, ID_PMULHW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E7*/ { GRP_MMX | GRP_CACHECT, { _UT("movntq") }, ID_MOVNTQ, { { TQ_M, SQ_q, FLG_W }, { TQ_P, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E8*/ { GRP_MMX | GRP_ARITH, { _UT("psubsb") }, ID_PSUBSB, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E9*/ { GRP_MMX | GRP_ARITH, { _UT("psubsw") }, ID_PSUBSW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EA*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("pminsw") }, ID_PMINSW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EB*/ { GRP_MMX | GRP_LOGICAL, { _UT("por") }, ID_POR, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EC*/ { GRP_MMX | GRP_ARITH, { _UT("paddsb") }, ID_PADDSB, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*ED*/ { GRP_MMX | GRP_ARITH, { _UT("paddsw") }, ID_PADDSW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EE*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("pmaxsw") }, ID_PMAXSW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EF*/ { GRP_MMX | GRP_LOGICAL, { _UT("pxor") }, ID_PXOR, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F1*/ { GRP_MMX | GRP_SHIFT, { _UT("psllw") }, ID_PSLLW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F2*/ { GRP_MMX | GRP_SHIFT, { _UT("pslld") }, ID_PSLLD, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F3*/ { GRP_MMX | GRP_SHIFT, { _UT("psllq") }, ID_PSLLQ, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F4*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("pmuludq") }, ID_PMULUDQ, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F5*/ { GRP_MMX | GRP_ARITH, { _UT("pmaddwd") }, ID_PMADDWD, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_d, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F6*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("psadbw") }, ID_PSADBW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F7*/ { GRP_SSE1 | GRP_CACHECT, { _UT("maskmovq") }, ID_MASKMOVQ, { { TQ_P, SQ_q, FLG_R }, { TQ_N, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F8*/ { GRP_MMX | GRP_ARITH, { _UT("psubb") }, ID_PSUBB, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F9*/ { GRP_MMX | GRP_ARITH, { _UT("psubw") }, ID_PSUBW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*FA*/ { GRP_MMX | GRP_ARITH, { _UT("psubd") }, ID_PSUBD, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*FB*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("psubq") }, ID_PSUBQ, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*FC*/ { GRP_MMX | GRP_ARITH, { _UT("paddb") }, ID_PADDB, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*FD*/ { GRP_MMX | GRP_ARITH, { _UT("paddw") }, ID_PADDW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*FE*/ { GRP_MMX | GRP_ARITH, { _UT("paddd") }, ID_PADDD, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_0F_00[] = 
{
/*0*/ { GRP_GEN | GRP_SYSTEM, { _UT("sldt") }, ID_SLDT, { { TQ_E, SQ_wvqp, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_SYSTEM, { _UT("str") }, ID_STR, { { TQ_E, SQ_wvqp, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_GEN | GRP_SYSTEM, { _UT("lldt") }, ID_LLDT, { { TQ_E, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0 | PROP_SERIAL, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_GEN | GRP_SYSTEM, { _UT("ltr") }, ID_LTR, { { TQ_E, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0 | PROP_SERIAL, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_GEN | GRP_SYSTEM, { _UT("verr") }, ID_VERR, { { TQ_E, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x8, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5*/ { GRP_GEN | GRP_SYSTEM, { _UT("verw") }, ID_VERW, { { TQ_E, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x8, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_0F_01_swtch[] = 
{
/*0*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_01_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_01_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_01_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_01_NOMEM_SWTCH, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_0F_01_mem[] = 
{
/*0*/ { GRP_GEN | GRP_SYSTEM, { _UT("sgdt") }, ID_SGDT, { { TQ_M, SQ_s, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_SYSTEM, { _UT("sidt") }, ID_SIDT, { { TQ_M, SQ_s, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_GEN | GRP_SYSTEM, { _UT("lgdt") }, ID_LGDT, { { TQ_M, SQ_s, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0 | PROP_SERIAL, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_GEN | GRP_SYSTEM, { _UT("lidt") }, ID_LIDT, { { TQ_M, SQ_s, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0 | PROP_SERIAL, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_GEN | GRP_SYSTEM, { _UT("smsw") }, ID_SMSW, { { TQ_M, SQ_w, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6*/ { GRP_GEN | GRP_SYSTEM, { _UT("lmsw") }, ID_LMSW, { { TQ_E, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0 | PROP_SERIAL, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7*/ { GRP_GEN | GRP_SYSTEM, { _UT("invlpg") }, ID_INVLPG, { { TQ_M, SQ_b, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0 | PROP_SERIAL, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_0F_01_nomem_swtch[] = 
{
/*0*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_01_NOMEM_00, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_01_NOMEM_01, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_01_NOMEM_02, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_01_NOMEM_03, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_GEN | GRP_SYSTEM, { _UT("smsw") }, ID_SMSW, { { TQ_R, SQ_v, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6*/ { GRP_GEN | GRP_SYSTEM, { _UT("lmsw") }, ID_LMSW, { { TQ_E, SQ_w, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0 | PROP_SERIAL, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_01_NOMEM_07, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_0F_01_nomem_00[] = 
{
/*0*/ { GRP_SYSTEM | GRP_VMX | GRP_BREAK, { _UT("vmcall") }, ID_VMCALL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_INTEL },
/*1*/ { GRP_SYSTEM | GRP_VMX | GRP_BREAK, { _UT("vmlaunch") }, ID_VMLAUNCH, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_INTEL },
/*2*/ { GRP_SYSTEM | GRP_VMX | GRP_BREAK, { _UT("vmresume") }, ID_VMRESUME, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_INTEL },
/*3*/ { GRP_SYSTEM | GRP_VMX, { _UT("vmxoff") }, ID_VMXOFF, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_INTEL },
};

static struct OPCODE_DESCRIPTOR opcodes_0F_01_nomem_01[] = 
{
/*0*/ { GRP_SSE3 | GRP_SYNC, { _UT("monitor") }, ID_MONITOR, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_SSE3 | GRP_SYNC, { _UT("mwait") }, ID_MWAIT, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_0F_01_nomem_02[] = 
{
/*0*/ { GRP_GEN | GRP_SYSTEM, { _UT("xgetbv") }, ID_XGETBV, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_SYSTEM, { _UT("xsetbv") }, ID_XSETBV, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_0F_01_nomem_03[] = 
{
/*0*/ { GRP_SYSTEM | GRP_VMX | GRP_BREAK, { _UT("vmrun") }, ID_VMRUN, { { TQ_rAX, SQ_v67d64, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_AMD },
/*1*/ { GRP_SYSTEM | GRP_VMX | GRP_BREAK, { _UT("vmmcall") }, ID_VMMCALL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_AMD },
/*2*/ { GRP_SYSTEM | GRP_VMX, { _UT("vmload") }, ID_VMLOAD, { { TQ_rAX, SQ_v67d64, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_AMD },
/*3*/ { GRP_SYSTEM | GRP_VMX, { _UT("vmsave") }, ID_VMSAVE, { { TQ_rAX, SQ_v67d64, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_AMD },
/*4*/ { GRP_SYSTEM | GRP_VMX, { _UT("stgi") }, ID_STGI, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_AMD },
/*5*/ { GRP_SYSTEM | GRP_VMX, { _UT("clgi") }, ID_CLGI, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_AMD },
/*6*/ { GRP_SYSTEM | GRP_VMX | GRP_BREAK, { _UT("skinit") }, ID_SKINIT, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x0, 0x0, 0xFF, 0x0, ARCH_AMD },
/*7*/ { GRP_SYSTEM | GRP_VMX, { _UT("invlpga") }, ID_INVLPGA, { { TQ_rAX, SQ_v67d64, FLG_R }, { TQ_rCX, SQ_d, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_AMD },
};

static struct OPCODE_DESCRIPTOR opcodes_0F_01_nomem_07[] = 
{
/*0*/ { GRP_GEN | GRP_SYSTEM, { _UT("swapgs") }, ID_SWAPGS, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0 | PROP_O64, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_SYSTEM, { _UT("rdtscp") }, ID_RDTSCP, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_SERIAL, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_0F_12[] = 
{
/*0*/ { GRP_SSE1 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movlps") }, ID_MOVLPS, { { TQ_V, SQ_q, FLG_R | FLG_W }, { TQ_M, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_SSE1 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movlps") }, ID_MOVLPS, { { TQ_V, SQ_q, FLG_R | FLG_W }, { TQ_M, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_SSE1 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movlps") }, ID_MOVLPS, { { TQ_V, SQ_q, FLG_R | FLG_W }, { TQ_M, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_SSE1 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movhlps") }, ID_MOVHLPS, { { TQ_V, SQ_q, FLG_R | FLG_W }, { TQ_U, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_0F_16[] = 
{
/*0*/ { GRP_SSE1 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movhps") }, ID_MOVHPS, { { TQ_V, SQ_q, FLG_R | FLG_W }, { TQ_M, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_SSE1 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movhps") }, ID_MOVHPS, { { TQ_V, SQ_q, FLG_R | FLG_W }, { TQ_M, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_SSE1 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movhps") }, ID_MOVHPS, { { TQ_V, SQ_q, FLG_R | FLG_W }, { TQ_M, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_SSE1 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movlhps") }, ID_MOVLHPS, { { TQ_V, SQ_q, FLG_R | FLG_W }, { TQ_U, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_0F_18[] = 
{
/*0*/ { GRP_SSE1 | GRP_FETCH, { _UT("prefetchnta") }, ID_PREFETCHNTA, { { TQ_M, SQ_b, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_SSE1 | GRP_FETCH, { _UT("prefetcht0") }, ID_PREFETCHT0, { { TQ_M, SQ_b, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_SSE1 | GRP_FETCH, { _UT("prefetcht1") }, ID_PREFETCHT1, { { TQ_M, SQ_b, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_SSE1 | GRP_FETCH, { _UT("prefetcht2") }, ID_PREFETCHT2, { { TQ_M, SQ_b, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_GEN | GRP_CONTROL, { _UT("hint_nop") }, ID_HINTNOP, { { TQ_E, SQ_v, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5*/ { GRP_GEN | GRP_CONTROL, { _UT("hint_nop") }, ID_HINTNOP, { { TQ_E, SQ_v, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6*/ { GRP_GEN | GRP_CONTROL, { _UT("hint_nop") }, ID_HINTNOP, { { TQ_E, SQ_v, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7*/ { GRP_GEN | GRP_CONTROL, { _UT("hint_nop") }, ID_HINTNOP, { { TQ_E, SQ_v, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_0F_19[] = 
{
/*0*/ { GRP_GEN | GRP_CONTROL, { _UT("hint_nop") }, ID_HINTNOP, { { TQ_E, SQ_v, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_GEN | GRP_CONTROL, { _UT("hint_nop") }, ID_HINTNOP, { { TQ_E, SQ_v, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_GEN | GRP_CONTROL, { _UT("hint_nop") }, ID_HINTNOP, { { TQ_E, SQ_v, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_GEN | GRP_CONTROL, { _UT("hint_nop") }, ID_HINTNOP, { { TQ_E, SQ_v, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_GEN | GRP_CONTROL, { _UT("hint_nop") }, ID_HINTNOP, { { TQ_E, SQ_v, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5*/ { GRP_GEN | GRP_CONTROL, { _UT("hint_nop") }, ID_HINTNOP, { { TQ_E, SQ_v, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6*/ { GRP_GEN | GRP_CONTROL, { _UT("hint_nop") }, ID_HINTNOP, { { TQ_E, SQ_v, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7*/ { GRP_GEN | GRP_CONTROL, { _UT("hint_nop") }, ID_HINTNOP, { { TQ_E, SQ_v, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_UNDOC, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_0F_71[] = 
{
/*2*/ { GRP_MMX | GRP_SHIFT, { _UT("psrlw") }, ID_PSRLW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0 },
/*4*/ { GRP_MMX | GRP_SHIFT, { _UT("psraw") }, ID_PSRAW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0 },
/*6*/ { GRP_MMX | GRP_SHIFT, { _UT("psllw") }, ID_PSLLW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_0F_72[] = 
{
/*2*/ { GRP_MMX | GRP_SHIFT, { _UT("psrld") }, ID_PSRLD, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0 },
/*4*/ { GRP_MMX | GRP_SHIFT, { _UT("psrad") }, ID_PSRAD, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0 },
/*6*/ { GRP_MMX | GRP_SHIFT, { _UT("pslld") }, ID_PSLLD, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_0F_73[] = 
{
/*2*/ { GRP_MMX | GRP_SHIFT, { _UT("psrlq") }, ID_PSRLQ, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0 },
/*4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0 },
/*5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0 },
/*6*/ { GRP_MMX | GRP_SHIFT, { _UT("psllq") }, ID_PSLLQ, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_0F_AE_swtch[] = 
{
/*0*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_AE_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_AE_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_AE_MEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_0F_AE_NOMEM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_0F_AE_mem[] = 
{
/*0*/ { GRP_SSE1, { _UT("fxsave") }, ID_FXSAVE, { { TQ_M, SQ_stx, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1*/ { GRP_SSE1, { _UT("fxrstor") }, ID_FXRSTOR, { { TQ_M, SQ_stx, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_SSE1 | GRP_MXCSRSM, { _UT("ldmxcsr") }, ID_LDMXCSR, { { TQ_M, SQ_d, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_SSE1 | GRP_MXCSRSM, { _UT("stmxcsr") }, ID_STMXCSR, { { TQ_M, SQ_d, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_SSE1 | GRP_SYSTEM, { _UT("xsave") }, ID_XSAVE, { { TQ_M, SQ_vqp, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5*/ { GRP_SSE1 | GRP_SYSTEM, { _UT("xrstor") }, ID_XRSTOR, { { TQ_M, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0 },
/*7*/ { GRP_SSE2 | GRP_CACHECT, { _UT("clflush") }, ID_CLFLUSH, { { TQ_M, SQ_b, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_0F_AE_nomem[] = 
{
/*5*/ { GRP_SSE2 | GRP_ORDER, { _UT("lfence") }, ID_LFENCE, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6*/ { GRP_SSE2 | GRP_ORDER, { _UT("mfence") }, ID_MFENCE, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7*/ { GRP_SSE1 | GRP_ORDER, { _UT("sfence") }, ID_SFENCE, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON }
};

static struct OPCODE_DESCRIPTOR opcodes_0F_BA[] = 
{
/*4*/ { GRP_GEN | GRP_BIT, { _UT("bt") }, ID_BT, { { TQ_E, SQ_vqp, FLG_R }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x9E, ARCH_COMMON },
/*5*/ { GRP_GEN | GRP_BIT, { _UT("bts") }, ID_BTS, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x9E, ARCH_COMMON },
/*6*/ { GRP_GEN | GRP_BIT, { _UT("btr") }, ID_BTR, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x9E, ARCH_COMMON },
/*7*/ { GRP_GEN | GRP_BIT, { _UT("btc") }, ID_BTC, { { TQ_E, SQ_vqp, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x9E, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_0F_C7[] = 
{
/*1*/ { GRP_GEN | GRP_DATAMOV | GRP_ARITH | GRP_BINARY, { _UT("cmpxchg8b") }, ID_CMPXCHG8B, { { TQ_M, SQ_q, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_LOCK | PROP_MODRM | PROP_POST_PROC | POST_PROC_CMPXCHG8B, 0x0, 0x8, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0 },
/*3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0 },
/*4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0 },
/*5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0 },
/*6*/ { GRP_VMX, { _UT("vmptrld") }, ID_VMPTRLD, { { TQ_M, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_RING0 | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_INTEL },
/*7*/ { GRP_VMX, { _UT("vmptrst") }, ID_VMPTRST, { { TQ_M, SQ_q, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_RING0 | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_INTEL },
};

static struct OPCODE_DESCRIPTOR opcodes_66_0F_jmp[] = 
{
/*0F*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_66_0F, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_66_0F[] =
{
/*10*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_DATAMOV, { _UT("movupd") }, ID_MOVUPD, { { TQ_V, SQ_pd, FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*11*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_DATAMOV, { _UT("movupd") }, ID_MOVUPD, { { TQ_W, SQ_pd, FLG_W }, { TQ_V, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*12*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_DATAMOV, { _UT("movlpd") }, ID_MOVLPD, { { TQ_V, SQ_q, FLG_R | FLG_W }, { TQ_M, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*13*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_DATAMOV, { _UT("movlpd") }, ID_MOVLPD, { { TQ_M, SQ_q, FLG_R | FLG_W }, { TQ_V, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*14*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_SHUNPCK, { _UT("unpcklpd") }, ID_UNPCKLPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*15*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_SHUNPCK, { _UT("unpckhpd") }, ID_UNPCKHPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*16*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_DATAMOV, { _UT("movhpd") }, ID_MOVHPD, { { TQ_V, SQ_q, FLG_R | FLG_W }, { TQ_M, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*17*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_DATAMOV, { _UT("movhpd") }, ID_MOVHPD, { { TQ_M, SQ_q, FLG_R | FLG_W }, { TQ_V, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*18*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*19*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*20*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*21*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*22*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*23*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*24*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*25*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*26*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*27*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*28*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_DATAMOV, { _UT("movapd") }, ID_MOVAPD, { { TQ_V, SQ_pd, FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*29*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_DATAMOV, { _UT("movapd") }, ID_MOVAPD, { { TQ_W, SQ_pd, FLG_W }, { TQ_V, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2A*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_CONVER, { _UT("cvtpi2pd") }, ID_CVTPI2PD, { { TQ_V, SQ_pd, FLG_W }, { TQ_Q, SQ_pi, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2B*/ { GRP_SSE2 | GRP_CACHECT, { _UT("movntpd") }, ID_MOVNTPD, { { TQ_M, SQ_pd, FLG_W }, { TQ_V, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2C*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_CONVER, { _UT("cvttpd2pi") }, ID_CVTTPD2PI, { { TQ_P, SQ_pi, FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2D*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_CONVER, { _UT("cvtpd2pi") }, ID_CVTPD2PI, { { TQ_P, SQ_pi, FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2E*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_COMPAR, { _UT("ucomisd") }, ID_UCOMISD, { { TQ_V, SQ_sd, FLG_R }, { TQ_W, SQ_sd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xB, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2F*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_COMPAR, { _UT("comisd") }, ID_COMISD, { { TQ_V, SQ_sd, FLG_R }, { TQ_W, SQ_sd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0xB, 0x0, 0x0, 0x0, ARCH_COMMON },
/*30*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*31*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*32*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*33*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*34*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*35*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*36*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*37*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*38*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_66_0F38, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*39*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3A*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_66_0F3A, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*40*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*41*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*42*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*43*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*44*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*45*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*46*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*47*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*48*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*49*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*50*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_DATAMOV, { _UT("movmskpd") }, ID_MOVMSKPD, { { TQ_G, SQ_dqp, FLG_W }, { TQ_U, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*51*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_ARITH, { _UT("sqrtpd") }, ID_SQRTPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*52*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*53*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*54*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_LOGICAL, { _UT("andpd") }, ID_ANDPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*55*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_LOGICAL, { _UT("andnpd") }, ID_ANDNPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*56*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_LOGICAL, { _UT("orpd") }, ID_ORPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*57*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_LOGICAL, { _UT("xorpd") }, ID_XORPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*58*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_ARITH, { _UT("addpd") }, ID_ADDPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*59*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_ARITH, { _UT("mulpd") }, ID_MULPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5A*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_CONVER, { _UT("cvtpd2ps") }, ID_CVTPD2PS, { { TQ_V, SQ_ps, FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5B*/ { GRP_SSE2 | GRP_PCKSP, { _UT("cvtps2dq") }, ID_CVTPS2DQ, { { TQ_V, SQ_dq, FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5C*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_ARITH, { _UT("subpd") }, ID_SUBPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5D*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_ARITH, { _UT("minpd") }, ID_MINPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5E*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_ARITH, { _UT("divpd") }, ID_DIVPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5F*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_ARITH, { _UT("maxpd") }, ID_MAXPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*60*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHUNPCK, { _UT("punpcklbw") }, ID_PUNPCKLBW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*61*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHUNPCK, { _UT("punpcklwd") }, ID_PUNPCKLWD, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*62*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHUNPCK, { _UT("punpckldq") }, ID_PUNPCKLDQ, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*63*/ { GRP_SSE2 | GRP_SIMDINT | GRP_CONVER, { _UT("packsswb") }, ID_PACKSSWB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*64*/ { GRP_SSE2 | GRP_SIMDINT | GRP_COMPAR, { _UT("pcmpgtb") }, ID_PCMPGTB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*65*/ { GRP_SSE2 | GRP_SIMDINT | GRP_COMPAR, { _UT("pcmpgtw") }, ID_PCMPGTW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*66*/ { GRP_SSE2 | GRP_SIMDINT | GRP_COMPAR, { _UT("pcmpgtd") }, ID_PCMPGTD, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*67*/ { GRP_SSE2 | GRP_SIMDINT | GRP_CONVER, { _UT("packuswb") }, ID_PACKUSWB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*68*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHUNPCK, { _UT("punpckhbw") }, ID_PUNPCKHBW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*69*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHUNPCK, { _UT("punpckhwd") }, ID_PUNPCKHWD, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6A*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHUNPCK, { _UT("punpckhdq") }, ID_PUNPCKHDQ, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6B*/ { GRP_SSE2 | GRP_SIMDINT | GRP_CONVER, { _UT("packssdw") }, ID_PACKSSDW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6C*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHUNPCK, { _UT("punpcklqdq") }, ID_PUNPCKLQDQ, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6D*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHUNPCK, { _UT("punpckhqdq") }, ID_PUNPCKHQDQ, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6E*/ { GRP_SSE2 | GRP_SIMDINT | GRP_DATAMOV, { _UT("movd") }, ID_MOVD, { { TQ_V, SQ_dq, FLG_W }, { TQ_E, SQ_dqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6F*/ { GRP_SSE2 | GRP_SIMDINT | GRP_DATAMOV, { _UT("movdqa") }, ID_MOVDQA, { { TQ_V, SQ_dq, FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*70*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHUNPCK, { _UT("pshufd") }, ID_PSHUFD, { { TQ_V, SQ_dq, FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*71*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_66_0F71, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*72*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_66_0F72, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*73*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_66_0F73, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*74*/ { GRP_SSE2 | GRP_SIMDINT | GRP_COMPAR, { _UT("pcmpeqb") }, ID_PCMPEQB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*75*/ { GRP_SSE2 | GRP_SIMDINT | GRP_COMPAR, { _UT("pcmpeqw") }, ID_PCMPEQW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*76*/ { GRP_SSE2 | GRP_SIMDINT | GRP_COMPAR, { _UT("pcmpeqd") }, ID_PCMPEQD, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*77*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*78*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_66_0F78, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*79*/ { GRP_SSE4A, _UT("extrq"), ID_EXTRQ, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_U, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_AMD },
/*7A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7C*/ { GRP_SSE3 | GRP_SIMDFP | GRP_ARITH, { _UT("haddpd") }, ID_HADDPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7D*/ { GRP_SSE3 | GRP_SIMDFP | GRP_ARITH, { _UT("hsubpd") }, ID_HSUBPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7E*/ { GRP_SSE2 | GRP_SIMDINT | GRP_DATAMOV, { _UT("movd") }, ID_MOVD, { { TQ_E, SQ_dqp, FLG_W }, { TQ_V, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7F*/ { GRP_SSE2 | GRP_SIMDINT | GRP_DATAMOV, { _UT("movdqa") }, ID_MOVDQA, { { TQ_W, SQ_dq, FLG_W }, { TQ_V, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*80*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*81*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*82*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*83*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*84*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*85*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*86*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*87*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*88*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*89*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*90*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*91*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*92*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*93*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*94*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*95*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*96*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*97*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*98*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*99*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A2*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A7*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A8*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A9*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AA*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AB*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AC*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AD*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AE*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AF*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B2*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B7*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B8*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B9*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BA*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BB*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BC*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BD*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BE*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BF*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C2*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_COMPAR, { _UT("cmppd") }, ID_CMPPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C4*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("pinsrw") }, ID_PINSRW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_E, SQ_wdqp, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C5*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("pextrw") }, ID_PEXTRW, { { TQ_G, SQ_dqp, FLG_W }, { TQ_U, SQ_dq, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C6*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_SHUNPCK, { _UT("shufpd") }, ID_SHUFPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C7*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_66_0FC7, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C8*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C9*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CA*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CB*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CC*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CD*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CE*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CF*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D0*/ { GRP_SSE2 | GRP_SIMDFP | GRP_ARITH, { _UT("addsubpd") }, ID_ADDSUBPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D1*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHIFT, { _UT("psrlw") }, ID_PSRLW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D2*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHIFT, { _UT("psrld") }, ID_PSRLD, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D3*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHIFT, { _UT("psrlq") }, ID_PSRLQ, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D4*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("paddq") }, ID_PADDQ, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D5*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("pmullw") }, ID_PMULLW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D6*/ { GRP_SSE2 | GRP_SIMDINT | GRP_DATAMOV, { _UT("movq") }, ID_MOVQ, { { TQ_W, SQ_q, FLG_W }, { TQ_V, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D7*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("pmovmskb") }, ID_PMOVMSKB, { { TQ_G, SQ_dqp, FLG_W }, { TQ_U, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D8*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("psubusb") }, ID_PSUBUSB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D9*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("psubusw") }, ID_PSUBUSW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DA*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("pminub") }, ID_PMINUB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DB*/ { GRP_SSE2 | GRP_SIMDINT | GRP_LOGICAL, { _UT("pand") }, ID_PAND, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DC*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("paddusb") }, ID_PADDUSB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DD*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("paddusw") }, ID_PADDUSW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DE*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("pmaxub") }, ID_PMAXUB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DF*/ { GRP_SSE2 | GRP_SIMDINT | GRP_LOGICAL, { _UT("pandn") }, ID_PANDN, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E0*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("pavgb") }, ID_PAVGB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E1*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHIFT, { _UT("psraw") }, ID_PSRAW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E2*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHIFT, { _UT("psrad") }, ID_PSRAD, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E3*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("pavgw") }, ID_PAVGW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E4*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("pmulhuw") }, ID_PMULHUW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E5*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("pmulhw") }, ID_PMULHW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E6*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_CONVER, { _UT("cvttpd2dq") }, ID_CVTTPD2DQ, { { TQ_V, SQ_dq, FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E7*/ { GRP_SSE2 | GRP_CACHECT, { _UT("movntdq") }, ID_MOVNTDQ, { { TQ_M, SQ_dq, FLG_W }, { TQ_V, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E8*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("psubsb") }, ID_PSUBSB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E9*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("psubsw") }, ID_PSUBSW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EA*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("pminsw") }, ID_PMINSW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EB*/ { GRP_SSE2 | GRP_SIMDINT | GRP_LOGICAL, { _UT("por") }, ID_POR, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EC*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("paddsb") }, ID_PADDSB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*ED*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("paddsw") }, ID_PADDSW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EE*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("pmaxsw") }, ID_PMAXSW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EF*/ { GRP_SSE2 | GRP_SIMDINT | GRP_LOGICAL, { _UT("pxor") }, ID_XOR, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F1*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHIFT, { _UT("psllw") }, ID_PSLLW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F2*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHIFT, { _UT("pslld") }, ID_PSLLD, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F3*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHIFT, { _UT("psllq") }, ID_PSLLQ, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F4*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("pmuludq") }, ID_PMULUDQ, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F5*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("pmaddwd") }, ID_PMADDWD, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F6*/ { GRP_SSE1 | GRP_SIMDINT, { _UT("psadbw") }, ID_PSADBW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F7*/ { GRP_SSE2 | GRP_CACHECT, { _UT("maskmovdqu") }, ID_MASKMOVDQU, { { TQ_V, SQ_dq, FLG_R }, { TQ_U, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F8*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("psubb") }, ID_PSUBB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F9*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("psubw") }, ID_PSUBW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*FA*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("psubd") }, ID_PSUBD, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*FB*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("psubq") }, ID_PSUBQ, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*FC*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("paddb") }, ID_PADDB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*FD*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("paddw") }, ID_PADDW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*FE*/ { GRP_SSE2 | GRP_SIMDINT | GRP_ARITH, { _UT("paddd") }, ID_PADDD, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_66_0F71[] = 
{
/*2*/ { GRP_SSE2 | GRP_SHIFT, { _UT("psrlw") }, ID_PSRLW, { { TQ_U, SQ_dq, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_SSE2 | GRP_SHIFT, { _UT("psraw") }, ID_PSRAW, { { TQ_U, SQ_dq, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6*/ { GRP_SSE2 | GRP_SHIFT, { _UT("psllw") }, ID_PSLLW, { { TQ_U, SQ_dq, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_66_0F72[] = 
{
/*2*/ { GRP_SSE2 | GRP_SHIFT, { _UT("psrld") }, ID_PSRLD, { { TQ_U, SQ_dq, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_SSE2 | GRP_SHIFT, { _UT("psrad") }, ID_PSRAD, { { TQ_U, SQ_dq, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6*/ { GRP_SSE2 | GRP_SHIFT, { _UT("pslld") }, ID_PSLLD, { { TQ_U, SQ_dq, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_66_0F73[] = 
{
/*2*/ { GRP_SSE2 | GRP_SHIFT, { _UT("psrlq") }, ID_PSRLQ, { { TQ_U, SQ_dq, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHIFT, { _UT("psrldq") }, ID_PSRLDQ, { { TQ_U, SQ_dq, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6*/ { GRP_SSE2 | GRP_SHIFT, { _UT("psllq") }, ID_PSLLQ, { { TQ_U, SQ_dq, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHIFT, { _UT("pslldq") }, ID_PSLLDQ, { { TQ_U, SQ_dq, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_66_0F78[] = 
{
/*0*/ { GRP_SSE4A, { _UT("extrq") }, ID_EXTRQ, { { TQ_U, SQ_dq, FLG_R | FLG_W }, { TQ_I, SQ_b, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_AMD },
};

static struct OPCODE_DESCRIPTOR opcodes_66_0FC7[] = 
{
/*6*/ { GRP_VMX, { _UT("vmclear") }, ID_VMCLEAR, { { TQ_M, SQ_q, FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_RING0 | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_INTEL },
};

static struct OPCODE_DESCRIPTOR opcodes_F2_0F_jmp[] = 
{
/*0F*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_F2_0F, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },	
};

static struct OPCODE_DESCRIPTOR opcodes_F2_0F[] = 
{
/*10*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_DATAMOV, { _UT("movsd") }, ID_MOVSD, { { TQ_V, SQ_sd, FLG_R | FLG_W }, { TQ_W, SQ_sd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*11*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_DATAMOV, { _UT("movsd") }, ID_MOVSD, { { TQ_W, SQ_sd, FLG_R | FLG_W }, { TQ_V, SQ_sd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*12*/ { GRP_SSE3 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movddup") }, ID_MOVDDUP, { { TQ_V, SQ_q, FLG_W }, { TQ_W, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*13*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*14*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*15*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*16*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*17*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*18*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*19*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*20*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*21*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*22*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*23*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*24*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*25*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*26*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*27*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*28*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*29*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2A*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_CONVER, { _UT("cvtsi2sd") }, ID_CVTSI2SD, { { TQ_V, SQ_sd, FLG_R | FLG_W }, { TQ_E, SQ_dqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2B*/ { GRP_SSE4A, _UT("movntsd"), ID_MOVNTSD, { { TQ_M, SQ_q, FLG_W }, { TQ_V, SQ_sd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_AMD },
/*2C*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_CONVER, { _UT("cvttsd2si") }, ID_CVTTSD2SI, { { TQ_G, SQ_dqp, FLG_W }, { TQ_W, SQ_sd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2D*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_CONVER, { _UT("cvtsd2si") }, ID_CVTSD2SI, { { TQ_G, SQ_dqp, FLG_W }, { TQ_W, SQ_sd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*30*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*31*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*32*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*33*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*34*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*35*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*36*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*37*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*38*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_F2_0F38, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*39*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*40*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*41*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*42*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*43*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*44*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*45*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*46*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*47*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*48*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*49*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*50*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*51*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_ARITH, { _UT("sqrtsd") }, ID_SQRTSD, { { TQ_V, SQ_sd, FLG_R | FLG_W }, { TQ_W, SQ_sd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*52*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*53*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*54*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*55*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*56*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*57*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*58*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_ARITH, { _UT("addsd") }, ID_ADDSD, { { TQ_V, SQ_sd, FLG_R | FLG_W }, { TQ_W, SQ_sd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*59*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_ARITH, { _UT("mulsd") }, ID_MULSD, { { TQ_V, SQ_sd, FLG_R | FLG_W }, { TQ_W, SQ_sd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5A*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_CONVER, { _UT("cvtsd2ss") }, ID_CVTSD2SS, { { TQ_V, SQ_ss, FLG_R | FLG_W }, { TQ_W, SQ_sd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5C*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_ARITH, { _UT("subsd") }, ID_SUBSD, { { TQ_V, SQ_sd, FLG_R | FLG_W }, { TQ_W, SQ_sd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5D*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_ARITH, { _UT("minsd") }, ID_MINSD, { { TQ_V, SQ_sd, FLG_R | FLG_W }, { TQ_W, SQ_sd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5E*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_ARITH, { _UT("divsd") }, ID_DIVSD, { { TQ_V, SQ_sd, FLG_R | FLG_W }, { TQ_W, SQ_sd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5F*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_ARITH, { _UT("maxsd") }, ID_MAXSD, { { TQ_V, SQ_sd, FLG_R | FLG_W }, { TQ_W, SQ_sd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*60*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*61*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*62*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*63*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*64*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*65*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*66*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*67*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*68*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*69*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*70*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHUNPCK, { _UT("pshuflw") }, ID_PSHUFLW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*71*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*72*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*73*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*74*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*75*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*76*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*77*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*78*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*79*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7C*/ { GRP_SSE3 | GRP_SIMDFP | GRP_ARITH, { _UT("haddps") }, ID_HADDPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7D*/ { GRP_SSE3 | GRP_SIMDFP | GRP_ARITH, { _UT("hsubps") }, ID_HSUBPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*80*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*81*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*82*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*83*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*84*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*85*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*86*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*87*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*88*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*89*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*90*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*91*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*92*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*93*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*94*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*95*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*96*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*97*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*98*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*99*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A2*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A7*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A8*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A9*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AA*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AB*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AC*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AD*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AE*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AF*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B2*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B7*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B8*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B9*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BA*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BB*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BC*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BD*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BE*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BF*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C2*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_COMPAR, { _UT("cmpsd") }, ID_CMPSD, { { TQ_V, SQ_sd, FLG_R | FLG_W }, { TQ_W, SQ_sd, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C7*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C8*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C9*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CA*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CB*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CC*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CD*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CE*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CF*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D0*/ { GRP_SSE1 | GRP_SIMDFP | GRP_ARITH, { _UT("addsubps") }, ID_ADDSUBPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D2*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D6*/ { GRP_SSE2 | GRP_SIMDINT | GRP_DATAMOV, { _UT("movdq2q") }, ID_MOVDQ2Q, { { TQ_P, SQ_q, FLG_W }, { TQ_U, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D7*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D8*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D9*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DA*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DB*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DC*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DD*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DE*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DF*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E2*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E6*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_CONVER, { _UT("cvtpd2dq") }, ID_CVTPD2DQ, { { TQ_V, SQ_dq, FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E7*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E8*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E9*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EA*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EB*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EC*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*ED*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EE*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EF*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F0*/ { GRP_SSE3 | GRP_CACHECT, { _UT("lddqu") }, ID_LDDQU, { { TQ_V, SQ_dq, FLG_W }, { TQ_M, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_F3_0F_jmp[] = 
{
/*0F*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_F3_0F, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },	
};

static struct OPCODE_DESCRIPTOR opcodes_F3_0F[] = 
{
/*10*/ { GRP_SSE1 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movss") }, ID_MOVSS, { { TQ_V, SQ_ss, FLG_R | FLG_W }, { TQ_W, SQ_ss, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*11*/ { GRP_SSE1 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movss") }, ID_MOVSS, { { TQ_W, SQ_ss, FLG_R | FLG_W }, { TQ_V, SQ_ss, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*12*/ { GRP_SSE3 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movsldup") }, ID_MOVSLDUP, { { TQ_V, SQ_q, FLG_W }, { TQ_W, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*13*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*14*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*15*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*16*/ { GRP_SSE3 | GRP_SIMDFP | GRP_DATAMOV, { _UT("movshdup") }, ID_MOVSHDUP, { { TQ_V, SQ_q, FLG_W }, { TQ_W, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*17*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*18*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*19*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*20*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*21*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*22*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*23*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*24*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*25*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*26*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*27*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*28*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*29*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2A*/ { GRP_SSE1 | GRP_CONVER, { _UT("cvtsi2ss") }, ID_CVTSI2SS, { { TQ_V, SQ_ss, FLG_R | FLG_W }, { TQ_E, SQ_dqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2B*/ { GRP_SSE4A, { _UT("movntss") }, ID_MOVNTSS, { { TQ_M, SQ_d, FLG_W }, { TQ_V, SQ_ss, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_AMD },
/*2C*/ { GRP_SSE1 | GRP_CONVER, { _UT("cvttss2si") }, ID_CVTTSS2SI, { { TQ_G, SQ_dqp, FLG_W }, { TQ_W, SQ_ss, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2D*/ { GRP_SSE1 | GRP_CONVER, { _UT("cvtss2si") }, ID_CVTSS2SI, { { TQ_G, SQ_dqp, FLG_W }, { TQ_W, SQ_ss, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*30*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*31*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*32*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*33*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*34*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*35*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*36*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*37*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*38*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*39*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*40*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*41*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*42*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*43*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*44*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*45*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*46*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*47*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*48*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*49*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*50*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*51*/ { GRP_SSE1 | GRP_SIMDFP | GRP_ARITH, { _UT("sqrtss") }, ID_SQRTSS, { { TQ_V, SQ_ss, FLG_R | FLG_W }, { TQ_W, SQ_ss, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*52*/ { GRP_SSE1 | GRP_SIMDFP | GRP_ARITH, { _UT("rsqrtss") }, ID_RSQRTSS, { { TQ_V, SQ_ss, FLG_R | FLG_W }, { TQ_W, SQ_ss, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*53*/ { GRP_SSE2 | GRP_SIMDFP | GRP_ARITH, { _UT("rcpss") }, ID_RCPSS, { { TQ_V, SQ_ss, FLG_R | FLG_W }, { TQ_W, SQ_ss, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*54*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*55*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*56*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*57*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*58*/ { GRP_SSE1 | GRP_SIMDFP | GRP_ARITH, { _UT("addss") }, ID_ADDSS, { { TQ_V, SQ_ss, FLG_R | FLG_W }, { TQ_W, SQ_ss, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*59*/ { GRP_SSE1 | GRP_SIMDFP | GRP_ARITH, { _UT("mulss") }, ID_MULSS, { { TQ_V, SQ_ss, FLG_R | FLG_W }, { TQ_W, SQ_ss, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5A*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_CONVER, { _UT("cvtss2sd") }, ID_CVTSS2SD, { { TQ_V, SQ_sd, FLG_R | FLG_W }, { TQ_W, SQ_ss, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5B*/ { GRP_SSE2 | GRP_PCKSP, { _UT("cvttps2dq") }, ID_CVTTPS2DQ, { { TQ_V, SQ_dq, FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5C*/ { GRP_SSE2 | GRP_SIMDFP | GRP_ARITH, { _UT("subss") }, ID_SUBSS, { { TQ_V, SQ_ss, FLG_R | FLG_W }, { TQ_W, SQ_ss, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5D*/ { GRP_SSE1 | GRP_SIMDFP | GRP_ARITH, { _UT("minss") }, ID_MINSS, { { TQ_V, SQ_ss, FLG_R | FLG_W }, { TQ_W, SQ_ss, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5E*/ { GRP_SSE1 | GRP_SIMDFP | GRP_ARITH, { _UT("divss") }, ID_DIVSS, { { TQ_V, SQ_ss, FLG_R | FLG_W }, { TQ_W, SQ_ss, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5F*/ { GRP_SSE1 | GRP_SIMDFP | GRP_ARITH, { _UT("maxss") }, ID_MAXSS, { { TQ_V, SQ_ss, FLG_R | FLG_W }, { TQ_W, SQ_ss, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*60*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*61*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*62*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*63*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*64*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*65*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*66*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*67*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*68*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*69*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6F*/ { GRP_SSE2 | GRP_SIMDINT | GRP_DATAMOV, { _UT("movdqu") }, ID_MOVDQU, { { TQ_V, SQ_dq, FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*70*/ { GRP_SSE2 | GRP_SIMDINT | GRP_SHUNPCK, { _UT("pshufhw") }, ID_PSHUFHW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*71*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*72*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*73*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*74*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*75*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*76*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*77*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*78*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*79*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7E*/ { GRP_SSE2 | GRP_SIMDINT | GRP_DATAMOV, { _UT("movq") }, ID_MOVQ, { { TQ_V, SQ_q, FLG_W }, { TQ_W, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7F*/ { GRP_SSE2 | GRP_SIMDINT | GRP_DATAMOV, { _UT("movdqu") }, ID_MOVDQU, { { TQ_W, SQ_dq, FLG_W }, { TQ_V, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*80*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*81*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*82*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*83*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*84*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*85*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*86*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*87*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*88*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*89*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*90*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*91*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*92*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*93*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*94*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*95*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*96*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*97*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*98*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*99*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A2*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A7*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A8*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A9*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AA*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AB*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AC*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AD*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AE*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AF*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B2*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B7*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B8*/ { GRP_SSE42 | GRP_BIT, { _UT("popcnt") }, ID_POPCNT, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x97, 0x0, ARCH_COMMON },
/*B9*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BA*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BB*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BC*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BD*/ { GRP_SSE42 | GRP_BIT, { _UT("lzcnt") }, ID_LZCNT, { { TQ_G, SQ_vqp, FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x96, ARCH_AMD },
/*BE*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BF*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C2*/ { GRP_SSE1 | GRP_SIMDFP | GRP_COMPAR, { _UT("cmpss") }, ID_CMPSS, { { TQ_V, SQ_ss, FLG_R | FLG_W }, { TQ_W, SQ_ss, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C7*/ { GRP_SWITCH, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, IDX_F3_0FC7, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C8*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C9*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CA*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CB*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CC*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CD*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CE*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CF*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D2*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D6*/ { GRP_SSE2 | GRP_SIMDINT | GRP_DATAMOV, { _UT("movq2dq") }, ID_MOVQ2DQ, { { TQ_V, SQ_dq, FLG_W }, { TQ_N, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D7*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D8*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D9*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DA*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DB*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DC*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DD*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DE*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DF*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E2*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E6*/ { GRP_SSE2 | GRP_PCKSCLR | GRP_CONVER, { _UT("cvtdq2pd") }, ID_CVTDQ2PD, { { TQ_V, SQ_pd, FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_F3_0FC7[] = 
{
/*6*/ { GRP_VMX, { _UT("vmxon") }, ID_VMXON, { { TQ_M, SQ_q, FLG_R | FLG_W }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, PROP_RING0 | PROP_MODRM, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_INTEL },
};

static struct OPCODE_DESCRIPTOR opcodes_0F_38[] = 
{
/*00*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("pshufb") }, ID_PSHUFB, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*01*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("phaddw") }, ID_PHADDW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*02*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("phaddd") }, ID_PHADDD, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*03*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("phaddsw") }, ID_PHADDSW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*04*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("pmaddubsw") }, ID_PMADDUBSW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*05*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("phsubw") }, ID_PHSUBW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*06*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("phsubd") }, ID_PHSUBD, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*07*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("phsubsw") }, ID_PHSUBSW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*08*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("psignb") }, ID_PSIGNB, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*09*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("psignw") }, ID_PSIGNW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0A*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("psignd") }, ID_PSIGND, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0B*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("pmulhrsw") }, ID_PMULHRSW, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*10*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*11*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*12*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*13*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*14*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*15*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*16*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*17*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*18*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*19*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1C*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("pabsb") }, ID_PABSB, { { TQ_P, SQ_q, FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1D*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("pabsw") }, ID_PABSW, { { TQ_P, SQ_q, FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1E*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("pabsd") }, ID_PABSD, { { TQ_P, SQ_q, FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*20*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*21*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*22*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*23*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*24*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*25*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*26*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*27*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*28*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*29*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*30*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*31*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*32*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*33*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*34*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*35*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*36*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*37*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*38*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*39*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*40*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*41*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*42*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*43*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*44*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*45*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*46*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*47*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*48*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*49*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*50*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*51*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*52*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*53*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*54*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*55*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*56*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*57*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*58*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*59*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*60*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*61*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*62*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*63*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*64*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*65*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*66*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*67*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*68*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*69*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*70*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*71*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*72*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*73*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*74*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*75*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*76*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*77*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*78*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*79*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*80*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*81*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*82*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*83*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*84*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*85*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*86*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*87*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*88*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*89*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*8F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*90*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*91*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*92*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*93*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*94*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*95*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*96*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*97*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*98*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*99*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*9F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A2*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A7*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A8*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*A9*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AA*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AB*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AC*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AD*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AE*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*AF*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B2*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B7*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B8*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*B9*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BA*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BB*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BC*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BD*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BE*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*BF*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C2*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C7*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C8*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*C9*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CA*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CB*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CC*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CD*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CE*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*CF*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D2*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D7*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D8*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*D9*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DA*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DB*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DC*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DD*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DE*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*DF*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E0*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E1*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E2*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E3*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E4*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E5*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E6*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E7*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E8*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*E9*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EA*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EB*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EC*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*ED*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EE*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*EF*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F0*/ { GRP_GEN | GRP_DATAMOV, { _UT("movbe") }, ID_MOVBE, { { TQ_G, SQ_vqp, FLG_W }, { TQ_M, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_INTEL },
/*F1*/ { GRP_GEN | GRP_DATAMOV, { _UT("movbe") }, ID_MOVBE, { { TQ_M, SQ_vqp, FLG_W }, { TQ_G, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_INTEL },
};

static struct OPCODE_DESCRIPTOR opcodes_66_0F38[] = 
{
/*00*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("pshufb") }, ID_PSHUFB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*01*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("phaddw") }, ID_PHADDW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*02*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("phaddd") }, ID_PHADDD, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*03*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("phaddsw") }, ID_PHADDSW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*04*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("pmaddubsw") }, ID_PMADDUBSW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*05*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("phsubw") }, ID_PHSUBW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*06*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("phsubd") }, ID_PHSUBD, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*07*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("phsubsw") }, ID_PHSUBSW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*08*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("psignb") }, ID_PSIGNB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*09*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("psignw") }, ID_PSIGNW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0A*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("psignd") }, ID_PSIGND, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0B*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("pmulhrsw") }, ID_PMULHRSW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*10*/ { GRP_SSE41 | GRP_SIMDINT | GRP_DATAMOV, { _UT("pblendvb") }, ID_PBLENDVB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*11*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*12*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*13*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*14*/ { GRP_SSE41 | GRP_SIMDINT | GRP_DATAMOV, { _UT("blendvps") }, ID_BLENDVPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*15*/ { GRP_SSE41 | GRP_SIMDINT | GRP_DATAMOV, { _UT("blendvpd") }, ID_BLENDVPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*16*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*17*/ { GRP_SSE41, { _UT("ptest") }, ID_PTEST, { { TQ_V, SQ_dq, FLG_R }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x96, 0x0, ARCH_COMMON },
/*18*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*19*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1C*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("pabsb") }, ID_PABSB, { { TQ_V, SQ_dq, FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1D*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("pabsw") }, ID_PABSW, { { TQ_V, SQ_dq, FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1E*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("pabsd") }, ID_PABSD, { { TQ_V, SQ_dq, FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*20*/ { GRP_SSE41 | GRP_SIMDINT | GRP_CONVER, { _UT("pmovsxbw") }, ID_PMOVSXBW, { { TQ_V, SQ_dq, FLG_W }, { TQ_U, SQ_qdq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*21*/ { GRP_SSE41 | GRP_SIMDINT | GRP_CONVER, { _UT("pmovsxbd") }, ID_PMOVSXBD, { { TQ_V, SQ_dq, FLG_W }, { TQ_U, SQ_ddq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*22*/ { GRP_SSE41 | GRP_SIMDINT | GRP_CONVER, { _UT("pmovsxbq") }, ID_PMOVSXBQ, { { TQ_V, SQ_dq, FLG_W }, { TQ_U, SQ_wdq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*23*/ { GRP_SSE41 | GRP_SIMDINT | GRP_CONVER, { _UT("pmovsxwd") }, ID_PMOVSXWD, { { TQ_V, SQ_dq, FLG_W }, { TQ_U, SQ_qdq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*24*/ { GRP_SSE41 | GRP_SIMDINT | GRP_CONVER, { _UT("pmovsxwq") }, ID_PMOVSXWQ, { { TQ_V, SQ_dq, FLG_W }, { TQ_U, SQ_ddq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*25*/ { GRP_SSE41 | GRP_SIMDINT | GRP_CONVER, { _UT("pmovsxdq") }, ID_PMOVSXDQ, { { TQ_V, SQ_dq, FLG_W }, { TQ_U, SQ_qdq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*26*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*27*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*28*/ { GRP_SSE41 | GRP_SIMDINT | GRP_ARITH, { _UT("pmuldq") }, ID_PMULDQ, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*29*/ { GRP_SSE41 | GRP_SIMDINT | GRP_COMPAR, { _UT("pcmpeqq") }, ID_PCMPEQQ, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2A*/ { GRP_SSE41 | GRP_CACHECT, { _UT("movntdqa") }, ID_MOVNTDQA, { { TQ_V, SQ_dq, FLG_W }, { TQ_M, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2B*/ { GRP_SSE41 | GRP_SIMDINT | GRP_CONVER, { _UT("packusdw") }, ID_PACKUSDW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*30*/ { GRP_SSE41 | GRP_SIMDINT | GRP_CONVER, { _UT("pmovzxbw") }, ID_PMOVZXBW, { { TQ_V, SQ_dq, FLG_W }, { TQ_U, SQ_qdq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*31*/ { GRP_SSE41 | GRP_SIMDINT | GRP_CONVER, { _UT("pmovzxbd") }, ID_PMOVZXBD, { { TQ_V, SQ_dq, FLG_W }, { TQ_U, SQ_ddq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*32*/ { GRP_SSE41 | GRP_SIMDINT | GRP_CONVER, { _UT("pmovzxbq") }, ID_PMOVZXBQ, { { TQ_V, SQ_dq, FLG_W }, { TQ_U, SQ_wdq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*33*/ { GRP_SSE41 | GRP_SIMDINT | GRP_CONVER, { _UT("pmovzxwd") }, ID_PMOVZXWD, { { TQ_V, SQ_dq, FLG_W }, { TQ_U, SQ_qdq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*34*/ { GRP_SSE41 | GRP_SIMDINT | GRP_CONVER, { _UT("pmovzxwq") }, ID_PMOVZXWQ, { { TQ_V, SQ_dq, FLG_W }, { TQ_U, SQ_ddq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*35*/ { GRP_SSE41 | GRP_SIMDINT | GRP_CONVER, { _UT("pmovzxdq") }, ID_PMOVZXDQ, { { TQ_V, SQ_dq, FLG_W }, { TQ_U, SQ_qdq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*36*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*37*/ { GRP_SSE42 | GRP_SIMDINT | GRP_COMPAR, { _UT("pcmpgtq") }, ID_PCMPGTQ, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*38*/ { GRP_SSE41 | GRP_SIMDINT | GRP_COMPAR, { _UT("pminsb") }, ID_PMINSB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*39*/ { GRP_SSE41 | GRP_SIMDINT | GRP_COMPAR, { _UT("pminsd") }, ID_PMINSD, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3A*/ { GRP_SSE41 | GRP_SIMDINT | GRP_COMPAR, { _UT("pminuw") }, ID_PMINUW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3B*/ { GRP_SSE41 | GRP_SIMDINT | GRP_COMPAR, { _UT("pminud") }, ID_PMINUD, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3C*/ { GRP_SSE41 | GRP_SIMDINT | GRP_COMPAR, { _UT("pmaxsb") }, ID_PMAXSB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3D*/ { GRP_SSE41 | GRP_SIMDINT | GRP_COMPAR, { _UT("pmaxsd") }, ID_PMAXSD, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3E*/ { GRP_SSE41 | GRP_SIMDINT | GRP_COMPAR, { _UT("pmaxuw") }, ID_PMAXUW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3F*/ { GRP_SSE41 | GRP_SIMDINT | GRP_COMPAR, { _UT("pmaxud") }, ID_PMAXUD, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*40*/ { GRP_SSE41 | GRP_SIMDINT | GRP_ARITH, { _UT("pmulld") }, ID_PMULLD, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*41*/ { GRP_SSE41 | GRP_SIMDINT | GRP_COMPAR, { _UT("phminposuw") }, ID_PHMINPOSUW, { { TQ_V, SQ_dq, FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*42*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*43*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*44*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*45*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*46*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*47*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*48*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*49*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*50*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*51*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*52*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*53*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*54*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*55*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*56*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*57*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*58*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*59*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*60*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*61*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*62*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*63*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*64*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*65*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*66*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*67*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*68*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*69*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*6F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*70*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*71*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*72*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*73*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*74*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*75*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*76*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*77*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*78*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*79*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*7F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*80*/ { GRP_VMX, { _UT("invept") }, ID_INVEPT, { { TQ_G, SQ_dq64, FLG_R }, { TQ_M, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_INTEL },
/*81*/ { GRP_VMX, { _UT("invvpid") }, ID_INVVPID, { { TQ_G, SQ_dq64, FLG_R }, { TQ_M, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM | PROP_RING0, 0x0, 0x9F, 0x0, 0x0, 0x0, ARCH_INTEL },
};

static struct OPCODE_DESCRIPTOR opcodes_F2_0F38[] = 
{
/*F0*/ { GRP_SSE42, { _UT("crc32") }, ID_CRC32, { { TQ_G, SQ_dqp, FLG_R | FLG_W }, { TQ_E, SQ_b, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*F1*/ { GRP_SSE42, { _UT("crc32") }, ID_CRC32, { { TQ_G, SQ_dqp, FLG_R | FLG_W }, { TQ_E, SQ_vqp, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_0F_3A[] = 
{
/*0F*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("palignr") }, ID_PALIGNR, { { TQ_P, SQ_q, FLG_R | FLG_W }, { TQ_Q, SQ_q, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
};

static struct OPCODE_DESCRIPTOR opcodes_66_0F3A[] = 
{
/*08*/ { GRP_SSE41 | GRP_SIMDFP | GRP_CONVER, { _UT("roundps") }, ID_ROUNDPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*09*/ { GRP_SSE41 | GRP_SIMDFP | GRP_CONVER, { _UT("roundpd") }, ID_ROUNDPD, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0A*/ { GRP_SSE41 | GRP_SIMDFP | GRP_CONVER, { _UT("roundss") }, ID_ROUNDSS, { { TQ_V, SQ_ss, FLG_R | FLG_W }, { TQ_W, SQ_ss, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0B*/ { GRP_SSE41 | GRP_SIMDFP | GRP_CONVER, { _UT("roundsd") }, ID_ROUNDSD, { { TQ_V, SQ_sd, FLG_R | FLG_W }, { TQ_W, SQ_sd, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0C*/ { GRP_SSE41 | GRP_SIMDFP | GRP_DATAMOV, { _UT("blendps") }, ID_BLENDPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0D*/ { GRP_SSE41 | GRP_SIMDFP | GRP_DATAMOV, { _UT("blendpd") }, ID_BLENDPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0E*/ { GRP_SSE41 | GRP_SIMDINT | GRP_DATAMOV, { _UT("pblendw") }, ID_PBLENDW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*0F*/ { GRP_SSSE3 | GRP_SIMDINT, { _UT("palignr") }, ID_PALIGNR, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*10*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*11*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*12*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*13*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*14*/ { GRP_SSE41 | GRP_SIMDINT | GRP_DATAMOV, { _UT("pextrb") }, ID_PEXTRB, { { TQ_E, SQ_bdqp, FLG_W }, { TQ_V, SQ_dq, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*15*/ { GRP_SSE41 | GRP_SIMDINT | GRP_DATAMOV, { _UT("pextrw") }, ID_PEXTRW, { { TQ_E, SQ_wdqp, FLG_W }, { TQ_V, SQ_dq, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*16*/ { GRP_SSE41 | GRP_SIMDINT | GRP_DATAMOV, { _UT("pextrd") }, ID_PEXTRD, { { TQ_E, SQ_d, FLG_W }, { TQ_V, SQ_dq, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM | PROP_POST_PROC | POST_PROC_PEXTRD, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*17*/ { GRP_SSE41 | GRP_SIMDFP | GRP_DATAMOV, { _UT("extractps") }, ID_EXTRACTPS, { { TQ_E, SQ_d, FLG_W }, { TQ_V, SQ_dq, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*18*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*19*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*1F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*20*/ { GRP_SSE41 | GRP_SIMDINT | GRP_DATAMOV, { _UT("pinsrb") }, ID_PINSRB, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_bdqp, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*21*/ { GRP_SSE41 | GRP_SIMDFP | GRP_DATAMOV, { _UT("insertps") }, ID_INSERTPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_psd, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*22*/ { GRP_SSE41 | GRP_SIMDINT | GRP_DATAMOV, { _UT("pinsrd") }, ID_PINSRD, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_E, SQ_d, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM | PROP_POST_PROC | POST_PROC_PINSRD, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*23*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*24*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*25*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*26*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*27*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*28*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*29*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*2F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*30*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*31*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*32*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*33*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*34*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*35*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*36*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*37*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*38*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*39*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*3F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*40*/ { GRP_SSE41 | GRP_SIMDFP | GRP_ARITH, { _UT("dpps") }, ID_DPPS, { { TQ_V, SQ_ps, FLG_R | FLG_W }, { TQ_W, SQ_ps, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*41*/ { GRP_SSE41 | GRP_SIMDFP | GRP_ARITH, { _UT("dppd") }, ID_DPPD, { { TQ_V, SQ_pd, FLG_R | FLG_W }, { TQ_W, SQ_pd, FLG_R }, { TQ_NULL, SQ_NULL, 0 } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*42*/ { GRP_SSE41 | GRP_SIMDINT | GRP_ARITH, { _UT("mpsadbw") }, ID_MPSADBW, { { TQ_V, SQ_dq, FLG_R | FLG_W }, { TQ_W, SQ_dq, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*43*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*44*/ { GRP_AES, { _UT("pclmulqdq") }, ID_PCLMULQDQ, { { TQ_V, SQ_q, FLG_R | FLG_W }, { TQ_W, SQ_q, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*45*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*46*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*47*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*48*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*49*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*4F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*50*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*51*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*52*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*53*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*54*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*55*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*56*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*57*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*58*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*59*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5A*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5B*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5C*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5D*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5E*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*5F*/ { GRP_NULL, NULL, ID_NULL, { { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 }, { TQ_NULL, SQ_NULL, 0 } }, 0, 0x0, 0x0, 0x0, 0x0, 0x0, ARCH_COMMON },
/*60*/ { GRP_SSE42 | GRP_STRTXT, { _UT("pcmpestrm") }, ID_PCMPESTRM, { { TQ_V, SQ_dq, FLG_R }, { TQ_W, SQ_dq, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x6, 0x0, ARCH_COMMON },
/*61*/ { GRP_SSE42 | GRP_STRTXT, { _UT("pcmpestri") }, ID_PCMPESTRI, { { TQ_V, SQ_dq, FLG_R }, { TQ_W, SQ_dq, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x6, 0x0, ARCH_COMMON },
/*62*/ { GRP_SSE42 | GRP_STRTXT, { _UT("pcmpistrm") }, ID_PCMPISTRM, { { TQ_V, SQ_dq, FLG_R }, { TQ_W, SQ_dq, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x6, 0x0, ARCH_COMMON },
/*63*/ { GRP_SSE42 | GRP_STRTXT, { _UT("pcmpistri") }, ID_PCMPISTRI, { { TQ_V, SQ_dq, FLG_R }, { TQ_W, SQ_dq, FLG_R }, { TQ_I, SQ_b, FLG_R } }, PROP_MODRM, 0x0, 0x9F, 0x0, 0x6, 0x0, ARCH_COMMON },
};

/********************
* Tables descriptors.
*********************
*/
static struct TABLE_DESCRIPTOR tables[] =
{
/*0x0 IDX_1BYTE */
	//min //max //mask //shift //props         //table
	{ 0x0,  0xFF, 0xFF, 0x0,   0x0,            opcodes_1byte },
/*0x1 IDX_80 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x7,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_80 },
/*0x2 IDX_81 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x7,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_81 },
/*0x3 IDX_82 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x7,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_82 },
/*0x4 IDX_83 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x7,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_83 },
/*0x5 IDX_8F */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x0,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_8F },
/*0x6 IDX_C0 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x7,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_C0 },
/*0x7 IDX_C1 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x7,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_C1 },
/*0x8 IDX_C6 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x0,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_C6 },
/*0x9 IDX_C7 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x0,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_C7 },
/*0xA IDX_D0 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x7,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_D0 },
/*0xB IDX_D1 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x7,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_D1 },
/*0xC IDX_D2 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x7,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_D2 },
/*0xD IDX_D3 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x7,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_D3 },
/*0xE IDX_F6 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x7,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_F6 },
/*0xF IDX_F7 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x7,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_F7 },
/*0x10 IDX_FE */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x1,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_FE },
/*0x11 IDX_FF */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x6,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_FF },


/*0x12 IDX_D8_SWTCH */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x03, 0x3,  0x6,   TBL_PROP_MODRM, opcodes_D8_swtch },
/*0x13 IDX_D8_MEM */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x07, 0x7,  0x3,   TBL_PROP_MODRM, opcodes_D8_mem   },
/*0x14 IDX_D8_NOMEM */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x07, 0x7,  0x3,   TBL_PROP_MODRM, opcodes_D8_nomem },

/*0x15 IDX_D9_SWTCH */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x03, 0x3,  0x6,   TBL_PROP_MODRM, opcodes_D9_swtch },
/*0x16 IDX_D9_MEM */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x07, 0x7,  0x3,   TBL_PROP_MODRM, opcodes_D9_mem   },
/*0x17 IDX_D9_NOMEM */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x3F, 0x3F, 0x0,   TBL_PROP_MODRM, opcodes_D9_nomem },

/*0x18 IDX_DA_SWTCH */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x03, 0x3,  0x6,   TBL_PROP_MODRM, opcodes_DA_swtch },
/*0x19 IDX_DA_MEM */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x07, 0x7,  0x3,   TBL_PROP_MODRM, opcodes_DA_mem   },
/*0x1A IDX_DA_NOMEM */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x29, 0x3F, 0x0,   TBL_PROP_MODRM, opcodes_DA_nomem },

/*0x1B IDX_DB_SWTCH */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x03, 0x3,  0x6,   TBL_PROP_MODRM, opcodes_DB_swtch },
/*0x1C IDX_DB_MEM */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x07, 0x7,  0x3,   TBL_PROP_MODRM, opcodes_DB_mem   },
/*0x1D IDX_DB_NOMEM */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x37, 0x3F, 0x0,   TBL_PROP_MODRM, opcodes_DB_nomem },

/*0x1E IDX_DC_SWTCH */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x03, 0x3,  0x6,   TBL_PROP_MODRM, opcodes_DC_swtch },
/*0x1F IDX_DC_MEM */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x07, 0x7,  0x3,   TBL_PROP_MODRM, opcodes_DC_mem   },
/*0x20 IDX_DC_NOMEM */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x07, 0x7,  0x3,   TBL_PROP_MODRM, opcodes_DC_nomem },

/*0x21 IDX_DD_SWTCH */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x03, 0x3,  0x6,   TBL_PROP_MODRM, opcodes_DD_swtch },
/*0x22 IDX_DD_MEM */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x07, 0x7,  0x3,   TBL_PROP_MODRM, opcodes_DD_mem   },
/*0x23 IDX_DD_NOMEM */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x05, 0x7,  0x3,   TBL_PROP_MODRM, opcodes_DD_nomem },

/*0x24 IDX_DE_SWTCH */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x03, 0x3,  0x6,   TBL_PROP_MODRM, opcodes_DE_swtch },
/*0x25 IDX_DE_MEM */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x07, 0x7,  0x3,   TBL_PROP_MODRM, opcodes_DE_mem   },
/*0x26 IDX_DE_NOMEM */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x3F, 0x3F, 0x0,   TBL_PROP_MODRM, opcodes_DE_nomem },

/*0x27 IDX_DF_SWTCH */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x03, 0x3,  0x6,   TBL_PROP_MODRM, opcodes_DF_swtch },
/*0x28 IDX_DF_MEM */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x07, 0x7,  0x3,   TBL_PROP_MODRM, opcodes_DF_mem   },
/*0x29 IDX_DF_NOMEM */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x37, 0x3F, 0x0,   TBL_PROP_MODRM, opcodes_DF_nomem },			


/*0x2A IDX_0F*/
	//min //max //mask //shift //props         //table
	{ 0x0,  0xFE, 0xFF, 0x0,   0x0,            opcodes_0F      },
/*0x2B IDX_0F_00 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x05, 0x07, 0x3,   TBL_PROP_MODRM, opcodes_0F_00   },
/*0x2C IDX_0F_01_SWTCH */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x03, 0x03, 0x6,   TBL_PROP_MODRM, opcodes_0F_01_swtch },
/*0x2D IDX_0F_01_MEM */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x07, 0x07, 0x3,   TBL_PROP_MODRM, opcodes_0F_01_mem   },
/*0x2E IDX_0F_01_NOMEM_SWTCH */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x07, 0x07, 0x3,   TBL_PROP_MODRM, opcodes_0F_01_nomem_swtch },
/*0x2F IDX_0F_01_NOMEM_00 */
	//min //max //mask //shift //props         //table
	{ 0x1,  0x04, 0x07, 0x0,   TBL_PROP_MODRM, opcodes_0F_01_nomem_00 },
/*0x30 IDX_0F_01_NOMEM_01 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x02, 0x07, 0x0,   TBL_PROP_MODRM, opcodes_0F_01_nomem_01 },
/*0x31 IDX_0F_01_NOMEM_02 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x02, 0x07, 0x0,   TBL_PROP_MODRM, opcodes_0F_01_nomem_02 },
/*0x32 IDX_0F_01_NOMEM_03 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x07, 0x07, 0x0,   TBL_PROP_MODRM, opcodes_0F_01_nomem_03 },
/*0x33 IDX_0F_01_NOMEM_07 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x02, 0x07, 0x0,   TBL_PROP_MODRM, opcodes_0F_01_nomem_07 },			
/*0x34 IDX_0F_12 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x4,  0x3,  0x6,   TBL_PROP_MODRM, opcodes_0F_12   },
/*0x35 IDX_0F_16 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x4,  0x3,  0x6,   TBL_PROP_MODRM, opcodes_0F_16   },		
/*0x36 IDX_0F_18 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x7,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_0F_18   },
/*0x37 IDX_0F_19 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x7,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_0F_19   },
/*0x38 IDX_0F_71 */
	//min //max //mask //shift //props         //table
	{ 0x2,  0x6,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_0F_71   },
/*0x39 IDX_0F_72 */
	//min //max //mask //shift //props         //table
	{ 0x2,  0x6,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_0F_72   },
/*0x3A IDX_0F_73 */
	//min //max //mask //shift //props         //table
	{ 0x2,  0x6,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_0F_73   },
/*0x3B IDX_0F_AE_SWTCH */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x4,  0x3,  0x6,   TBL_PROP_MODRM, opcodes_0F_AE_swtch },
/*0x3C IDX_0F_AE_MEM */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x7,  0x7,  0x3,  TBL_PROP_MODRM, opcodes_0F_AE_mem   },
/*0x3D IDX_0F_AE_NOMEM */
	//min //max //mask //shift //props         //table
	{ 0x5,  0x7,  0x7,  0x3,  TBL_PROP_MODRM, opcodes_0F_AE_nomem },		
/*0x3E IDX_0F_BA */
	//min //max //mask //shift //props         //table
	{ 0x4,  0x07, 0x7,  0x3,   TBL_PROP_MODRM, opcodes_0F_BA   },
/*0x3F IDX_0F_C7 */
	//min //max //mask //shift //props         //table
	{ 0x1,  0x07, 0x7,  0x3,   TBL_PROP_MODRM, opcodes_0F_C7   },
/*0x40 IDX_66_0F_JMP */
	//min //max //mask //shift //props         //table
	{ 0xF, 0xF, 0xFF,  0x0,    0x0,            opcodes_66_0F_jmp },
/*0x41 IDX_66_0F */
	//min //max //mask //shift //props         //table
	{ 0x10, 0xFE, 0xFF, 0x0,   0x0,            opcodes_66_0F   },	
/*0x42 IDX_66_0F71 */
	//min //max //mask //shift //props         //table
	{ 0x2,  0x06, 0x7,  0x3,   TBL_PROP_MODRM, opcodes_66_0F71 },
/*0x43 IDX_66_0F72 */
	//min //max //mask //shift //props         //table
	{ 0x2,  0x6,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_66_0F72 },
/*0x44 IDX_66_0F73 */
	//min //max //mask //shift //props         //table
	{ 0x2,  0x7,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_66_0F73 },
/*0x45 IDX_66_0F78 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x1,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_66_0F78 },	
/*0x46 IDX_66_0FC7 */
	//min //max //mask //shift //props         //table
	{ 0x6,  0x6,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_66_0FC7 },
/*0x47 IDX_F2_0F_JMP */
	//min //max //mask //shift //props         //table
	{ 0xF, 0xF,  0xFF, 0x0,    0x0,            opcodes_F2_0F_jmp },
/*0x48 IDX_F2_0F */
	//min //max //mask //shift //props         //table
	{ 0x10, 0xF0, 0xFF, 0x0,   0x0,            opcodes_F2_0F     },
/*0x49 IDX_F3_0F_JMP */
	//min //max //mask //shift //props         //table
	{ 0xF, 0xF,  0xFF, 0x0,    0x0,            opcodes_F3_0F_jmp },	
/*0x4A IDX_F3_0F */
	//min //max //mask //shift //props         //table
	{ 0x10, 0xE6, 0xFF,  0x0,  0x0,            opcodes_F3_0F   },
/*0x4B IDX_F3_0FC7 */
	//min //max //mask //shift //props         //table
	{ 0x6,  0x6,  0x7,  0x3,   TBL_PROP_MODRM, opcodes_F3_0FC7 },
/*0x4C IDX_0F_38 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0xF1, 0xFF, 0x0,   0x0,            opcodes_0F_38   },
/*0x4D IDX_66_0F38 */
	//min //max //mask //shift //props         //table
	{ 0x0,  0x81, 0xFF, 0x0,   0x0,            opcodes_66_0F38 },
/*0x4E IDX_F2_0F38 */
	//min //max //mask //shift //props         //table
	{ 0xF0, 0xF1, 0xFF, 0x0,   0x0,            opcodes_F2_0F38 },
/*0x4F IDX_0F_3A */
	//min //max //mask //shift //props         //table
	{ 0xF,  0xF,  0xFF, 0x0,   0x0,            opcodes_0F_3A   },
/*0x50 IDX_66_0F3A */
	//min //max //mask //shift //props         //table
	{ 0x8,  0x63, 0xFF, 0x0,   0x0,            opcodes_66_0F3A }
};

