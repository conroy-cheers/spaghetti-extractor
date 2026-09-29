#ifndef SPX_JQ_IR_INPUTS_H
#define SPX_JQ_IR_INPUTS_H
#include "ir-api.h"
struct spx_opaque_ir_input_v5 {
    block block0;
    block block1;
    block block2;
    block block3;
    block block4;
    block * owner0;
    opcode opcode0;
    int integer0;
    jv value0;
    const char * text0;
    const char * text1;
    struct locfile * file0;
    location location0;
    const struct cfunction * functions0;
};
struct spx_opaque_ir_output_v5 { block block; jv value; int integer; jv_kind kind; };
#endif
