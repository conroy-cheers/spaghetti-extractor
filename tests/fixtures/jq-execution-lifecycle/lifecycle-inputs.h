#ifndef SPX_JQ_LIFECYCLE_INPUTS_H
#define SPX_JQ_LIFECYCLE_INPUTS_H
#include "lifecycle-api.h"
struct spx_opaque_lifecycle_input_v5 {
    jq_state * state0;
    jq_state ** owner0;
    jq_msg_cb message_callback0;
    jq_msg_cb * message_callback_out0;
    jq_input_cb input_callback0;
    jq_input_cb * input_callback_out0;
    spx_nomem_handler handler0;
    void * data0;
    void ** data_out0;
    const char * text0;
    jv value0;
    jv value1;
    jv value2;
    int integer0;
};
struct spx_opaque_lifecycle_output_v5 { jq_state *state; jv value; int integer; };
#endif
