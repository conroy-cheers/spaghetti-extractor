/* SPDX-License-Identifier: GPL-3.0-or-later
 * Authored from the pinned Hello PE32 operation and its observed service ABI.
 * See COPYING.hello for the original program's license. */
#include "portable-component-implementation.h"
#include "string-objects.h"

typedef spx_string_conversion_context_v5 Context;
typedef struct spx_opaque_mb_bytes_v5 Bytes;
typedef struct spx_opaque_mb_state_v5 State;
typedef struct spx_opaque_mb_word16_v5 Word16;
typedef struct spx_opaque_mb_cursor_v5 Cursor;

uint32_t string_convert(Context *context, Word16 *output, Cursor *input,
                        uint32_t limit, State *state) {
    const spx_string_conversion_services_v5 *services = context->services;
    if (!state) state = context->state.implicit;
    unsigned char saved[4];
    State counting = {saved};
    if (!output) {
        for (uint32_t i=0; i<4; ++i) saved[i] = state->data[i];
        state = &counting;
    }
    Bytes remaining = {*input->value};
    uint32_t count = 0;
    while (!output || count < limit) {
        /* The reviewed target offers at most five bytes, including the first
         * NUL. strnlen1(p+4, 1) is always one on the admitted readable input. */
        uint32_t size = 1;
        while (size < 5 && remaining.data[size-1]) ++size;
        Word16 next = {output ? output->value + count : 0};
        uint32_t result = services->decode16(services->context,
            output ? &next : 0, &remaining, size, state);
        if (result == UINT32_MAX-1U) {
            services->invalid_state(services->context);
            return 0; /* Admitted abort service does not return. */
        }
        if (result == UINT32_MAX) {
            if (output) *input->value = remaining.data;
            services->set_errno(services->context, 42);
            return UINT32_MAX;
        }
        if (!result) {
            if (output) *input->value = 0;
            return count;
        }
        remaining.data += result;
        ++count;
    }
    *input->value = remaining.data;
    return count;
}
