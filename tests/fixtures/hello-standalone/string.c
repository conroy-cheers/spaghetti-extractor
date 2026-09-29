#include "services.h"
#include "portable-component-implementation.h"
#include "string-objects.h"

typedef struct spx_opaque_mb_bytes_v5 Bytes;
typedef struct spx_opaque_mb_state_v5 State;
typedef struct spx_opaque_mb_word16_v5 Word;
static uint32_t decode(void *context, Word *out, Bytes *input, uint32_t size, State *state) {
    (void)context;
    return hello_decode16(out ? out->value : 0, input->data, size, state->data);
}
static void error_number(void *context, uint32_t value) { (void)context; hello_runtime.target_errno=value; }
static void invalid(void *context) { (void)context; hello_invalid_state(); }
uint32_t hello_convert(uint16_t *output, const unsigned char **input,
                       uint32_t limit, unsigned char state[4]) {
    spx_string_conversion_services_v5 services = {
        .decode16=decode, .set_errno=error_number, .invalid_state=invalid};
    State implicit={hello_runtime.implicit_string}, explicit={state};
    spx_string_conversion_context_v5 context = {.services=&services, .state={.implicit=&implicit}};
    Word out={output}; struct spx_opaque_mb_cursor_v5 cursor={input};
    ++hello_runtime.conversions;
    uint32_t result=string_convert(&context, &out, &cursor, limit, &explicit);
    hello_runtime.converted=result; hello_runtime.cursor_null=*input==0;
    for (unsigned i=0;i<4;++i) hello_runtime.conversion_state[i]=state[i];
    uint32_t hash=2166136261U;
    if (result<limit) for (uint32_t i=0; i<=result; ++i) hash=(hash ^ output[i])*16777619U;
    if (result<limit) {
        hello_runtime.word_count=result+1<16 ? result+1 : 16;
        for (unsigned i=0;i<hello_runtime.word_count;++i) hello_runtime.first_words[i]=output[i];
    }
    hello_runtime.word_hash=hash;
    return result;
}
