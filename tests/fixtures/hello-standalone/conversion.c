#include "services.h"
#include "windows-1252.h"
#include "portable-component-implementation.h"
#include "multibyte-objects.h"

typedef struct spx_opaque_mb_bytes_v5 Bytes;
typedef struct spx_opaque_mb_state_v5 State;
typedef struct spx_opaque_mb_word16_v5 Word;
static uint32_t decode(void *context, Word *out, Bytes *input, uint32_t size, State *state) {
    (void)context;
    return spx_target_decode16(out ? out->value : 0, input->data, size, state->data);
}
static void error_number(void *context, uint32_t value) { (void)context; hello_runtime.target_errno=value; }
static void invalid(void *context) { (void)context; hello_invalid_state(); }
static Bytes *charset(void *context) {
    (void)context;
    static Bytes name = {(const unsigned char *)"CP1252"};
    return &name;
}
void hello_reset(unsigned char state[4]) {
    State actual = {state}; ++hello_runtime.resets;
    multibyte_reset(0, &actual);
}
uint32_t hello_decode16(uint16_t *output, const unsigned char *input,
                        uint32_t size, unsigned char state[4]) {
    spx_multibyte_conversion_services_v5 services = {
        .lower_decode16=decode, .set_errno=error_number, .invalid_state=invalid, .charset=charset};
    State implicit16={hello_runtime.implicit16}, implicit32={hello_runtime.implicit32}, explicit={state};
    spx_multibyte_conversion_context_v5 context = {
        .services=&services, .state={.implicit16=&implicit16, .implicit32=&implicit32}};
    Word out={output}; Bytes in={input}; ++hello_runtime.decodes;
    return multibyte_decode16(&context, output ? &out : 0, input ? &in : 0, size, state ? &explicit : 0);
}
