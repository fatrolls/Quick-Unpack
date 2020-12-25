#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mediana.h"

#define OUT_BUFF_SIZE 0x200
#define IN_BUFF_SIZE  14231285
#define SEEK_TO       0x0

//User-defined dumping routine.
int MEDIANA_API user_general_reg(struct DUMP_HANDLERS * dump_handlers, struct STREAM *stream, uint8_t code, uint16_t size)
{
    safe_unistrncpy(stream, _UT("<b>"));
    //Call default handler.
    dump_reg_gen(dump_handlers, stream, code, size);
    safe_unistrncpy(stream, _UT("</b>"));

    return 1;
}

//User-defined dumping routine.
int MEDIANA_API user_prefixes_mnem_delimiter(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION *instr)
{
    //Write '\t' instead of ' '.
    safe_insert_unichar(stream, _UT('\t'));

    return 1;
}

//User-defined dumping routine.
int MEDIANA_API user_addr_base_reg(struct DUMP_HANDLERS *dump_handlers, struct STREAM *stream, const struct INSTRUCTION *instr, int op_index)
{
    safe_unistrncpy(stream, _UT("<s>"));
    //Call default handler.
    dump_addr_base_reg(dump_handlers, stream, instr, op_index);
    safe_unistrncpy(stream, _UT("</s>"));

    return 1;
}

int main()
{
    unsigned int                res;
    size_t                      reallen;
    uint8_t                    *base, *ptr, *end;
    uint8_t                     sf_prefixes[MAX_INSTRUCTION_LEN];
    unichar_t                   buff[OUT_BUFF_SIZE];
    FILE                       *fp;
    struct INSTRUCTION          instr;
    struct DISASM_PARAMS        params;
    struct DUMP_HANDLERS        dump_handlers;
    struct DUMP_HANDLERS        dump_handlers2;
    struct DUMP_HANDLERS        dump_handlers3;
    struct DUMP_HANDLERS_REG    dump_handlers_reg;

    int (MEDIANA_API *dump_handlers_instr[])(struct DUMP_HANDLERS *, struct STREAM *, const struct INSTRUCTION *) =
    {
        dump_prefixes,
        dump_prefixes_mnem_delimiter,
        dump_mnemonic,
        user_prefixes_mnem_delimiter,
        dump_operand0,
        dump_op0_op1_delimiter,
        dump_operand1,
        dump_op1_op2_delimiter,
        dump_operand2
    };

    int (MEDIANA_API *dump_handlers_addr[])(struct DUMP_HANDLERS *, struct STREAM *, const struct INSTRUCTION *, int) =
    {
        dump_addr_ptr_size,
        dump_addr_seg_reg,
        dump_addr_open_brace,
        user_addr_base_reg,
        dump_addr_base_idx_delimiter,
        dump_addr_idx,
        dump_addr_idx_mltplr_delimiter,
        dump_addr_idx_mltplr,
        dump_addr_mltplr_disp_delimiter,
        dump_addr_disp,
        dump_addr_close_brace
    };

    params.arch = ARCH_ALL;
    params.sf_prefixes = sf_prefixes;
    params.mode = DISASSEMBLE_MODE_32;
    params.options = DISASM_OPTION_APPLY_REL | DISASM_OPTION_OPTIMIZE_DISP;
    //params.options = 0;
    params.base = 0x00401000;

    //Set all handlers to default handlers.
    dump_handlers.dump_handlers_instr = NULL;
    dump_handlers.instr_handlers_len = 0;
    dump_handlers.dump_handlers_reg = NULL;
    dump_handlers.dump_handlers_addr = NULL;
    dump_handlers.addr_handlers_len = 0;
    dump_handlers.dump_handler_imm = NULL;
    dump_handlers.dump_handler_dir = NULL;

    //Set user-defined handler for dumping general registers.
    memset(&dump_handlers_reg, 0, sizeof(struct DUMP_HANDLERS_REG));
    dump_handlers_reg.dump_reg_gen = user_general_reg;

    dump_handlers2.dump_handlers_instr  = NULL;
    dump_handlers2.instr_handlers_len = 0;
    dump_handlers2.dump_handlers_reg = &dump_handlers_reg;
    dump_handlers2.dump_handlers_addr = NULL;
    dump_handlers2.addr_handlers_len = 0;
    dump_handlers2.dump_handler_imm = NULL;
    dump_handlers2.dump_handler_dir = NULL;

    //Set user-defined handler for dumping instruction, general registers and base register of an address.
    dump_handlers3.dump_handlers_instr = dump_handlers_instr;
    dump_handlers3.instr_handlers_len = sizeof(dump_handlers_instr) / sizeof(dump_handlers_instr[0]);
    dump_handlers3.dump_handlers_reg = &dump_handlers_reg;
    dump_handlers3.dump_handlers_addr = dump_handlers_addr;
    dump_handlers3.addr_handlers_len = sizeof(dump_handlers_addr) / sizeof(dump_handlers_addr[0]);
    dump_handlers3.dump_handler_imm = NULL;
    dump_handlers3.dump_handler_dir = NULL;

    base = malloc(IN_BUFF_SIZE);
    ptr = base;
    end = ptr + IN_BUFF_SIZE;

    fp = fopen("../Tests/asm_com2.bin", "rb");
    fseek(fp, SEEK_TO, SEEK_SET);
    fread(base, IN_BUFF_SIZE, 1, fp);
    fclose(fp);

    while(ptr < end)
    {
        res = medi_disassemble(ptr, BUFSIZ_INFINITY, &instr, &params);
        if (res != DASM_ERR_OK)
        {
            printf("%X: fail: %d, len: %d\n", ptr - base, res, instr.length);
            if (instr.length == 0)
                instr.length++;
        }
        else
        {
            reallen = medi_dump(&instr, buff, OUT_BUFF_SIZE, NULL);
            if (reallen > OUT_BUFF_SIZE)
                buff[OUT_BUFF_SIZE - 1] = 0;
            else
                buff[reallen] = 0;
            //printf("%X: %s\n", ptr - base, buff);
            wprintf(_UT("%X: %s\n"), ptr - base, buff);

            reallen = medi_dump(&instr, buff, OUT_BUFF_SIZE, &dump_handlers);
            if (reallen > OUT_BUFF_SIZE)
                buff[OUT_BUFF_SIZE - 1] = 0;
            else
                buff[reallen] = 0;
            //printf("%X: %s\n", ptr - base, buff);
            wprintf(_UT("%X: %s\n"), ptr - base, buff);

            reallen = medi_dump(&instr, buff, OUT_BUFF_SIZE, &dump_handlers2);
            if (reallen > OUT_BUFF_SIZE)
                buff[OUT_BUFF_SIZE - 1] = 0;
            else
                buff[reallen] = 0;
            //printf("%X: %s\n", ptr - base, buff);
            wprintf(_UT("%X: %s\n"), ptr - base, buff);

            reallen = medi_dump(&instr, buff, OUT_BUFF_SIZE, &dump_handlers3);
            if (reallen > OUT_BUFF_SIZE)
                buff[OUT_BUFF_SIZE - 1] = 0;
            else
                buff[reallen] = 0;
            //printf("%X: %s\n", ptr - base, buff);
            wprintf(_UT("%X: %s\n"), ptr - base, buff);
        }
        ptr += instr.length;
        params.base += instr.length;
    }

    return 0;
}