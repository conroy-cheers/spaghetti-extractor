/* SPDX-License-Identifier: GPL-3.0-or-later
 * Source-assisted authoring of the pinned Hello conversion algorithms.
 * References: GNU Hello 2.12.3 mbrtoc32.c, mbrtowc.c, mbrtowc-impl-utf8.h,
 * mbsinit.c and mbszero.c; Bruno Haible and other GNU contributors.
 * Copyright (C) 1999-2002, 2005-2026 Free Software Foundation, Inc.
 * Distributed under GPL version 3 or later, WITHOUT ANY WARRANTY.
 * See COPYING.hello. The actual PE32 routines remain the independent oracle. */
#include "portable-component-implementation.h"
#include "multibyte-objects.h"

typedef spx_multibyte_conversion_context_v5 Context;
typedef struct spx_opaque_mb_bytes_v5 Bytes;
typedef struct spx_opaque_mb_state_v5 State;
typedef struct spx_opaque_mb_word16_v5 Word16;
typedef struct spx_opaque_mb_word32_v5 Word32;

uint32_t multibyte_initial(Context *context, State *state) {
    (void)context;
    if (!state) return 1;
    for (uint32_t i=0; i<4; ++i) if (state->data[i]) return 0;
    return 1;
}
void multibyte_reset(Context *context, State *state) {
    (void)context;
    for (uint32_t i=0; i<4; ++i) state->data[i]=0;
}
uint32_t multibyte_decode16(Context *context, Word16 *output, Bytes *input,
                          uint32_t size, State *state) {
    const spx_multibyte_conversion_services_v5 *services=context->services;
    Bytes empty={(const unsigned char *)""};
    if (!input) { output=0; input=&empty; size=1; }
    if (!size) return UINT32_MAX-1U;
    if (!state) state=context->state.implicit16;
    uint16_t character=0;
    Word16 temporary={&character};
    if (!multibyte_initial(context,state)) {
        for (uint32_t count=0; count<size; ++count) {
            Bytes next={input->data+count};
            uint32_t result=services->lower_decode16(services->context,&temporary,&next,1,state);
            if (result==UINT32_MAX) return result;
            if (result!=UINT32_MAX-1U) {
                if (output) *output->value=character;
                return character ? count+1 : 0;
            }
        }
        return UINT32_MAX-1U;
    }
    uint32_t result=services->lower_decode16(services->context,&temporary,input,size,state);
    if (result<UINT32_MAX-1U && output) *output->value=character;
    return result;
}

static int utf8(Bytes *charset) {
    const unsigned char *p=charset->data;
    const char *name="UTF-8";
    for (uint32_t i=0; i<6; ++i) if (p[i]!=(unsigned char)name[i]) return 0;
    return 1;
}

uint32_t multibyte_decode32(Context *context, Word32 *output, Bytes *input,
                          uint32_t size, State *state) {
    const spx_multibyte_conversion_services_v5 *services=context->services;
    Bytes empty={(const unsigned char *)""};
    if (!input) { output=0; input=&empty; size=1; }
    if (!size) return UINT32_MAX-1U;
    if (!state) state=context->state.implicit32;
    if (!utf8(services->charset(services->context))) {
        uint16_t character=0;
        Word16 temporary={&character};
        uint32_t result=multibyte_decode16(context,&temporary,input,size,state);
        if (result<UINT32_MAX-1U && output) *output->value=character;
        return result;
    }
    uint32_t pending=state->data[0];
    if (pending>3) {
        services->set_errno(services->context,22); /* Target EINVAL. */
        return UINT32_MAX;
    }
    unsigned char joined[4];
    const unsigned char *bytes=input->data;
    uint32_t count=size;
    if (pending) {
        for (uint32_t i=0; i<pending; ++i) joined[i]=state->data[i+1];
        count=pending;
        for (uint32_t i=0; i<size && count<4; ++i) joined[count++]=input->data[i];
        bytes=joined;
    }
    uint32_t first=bytes[0], width, character;
    if (first<0x80) { width=first ? 1 : 0; character=first; goto success; }
    if (first<0xc2 || first>0xf4) goto invalid;
    width=first<0xe0 ? 2 : first<0xf0 ? 3 : 4;
    character=first & (width==2 ? 0x1fU : width==3 ? 0x0fU : 0x07U);
    for (uint32_t i=1; i<width; ++i) {
        if (count==i) goto incomplete;
        uint32_t next=bytes[i];
        if (next<0x80 || next>0xbf) goto invalid;
        if (i==1 && ((first==0xe0 && next<0xa0) || (first==0xed && next>=0xa0) ||
                     (first==0xf0 && next<0x90) || (first==0xf4 && next>=0x90))) goto invalid;
        character=(character<<6) | (next & 0x3fU);
    }
success:
    if (output) *output->value=character;
    if (pending >= (width ? width : 1U)) {
        services->invalid_state(services->context);
        return 0; /* Admitted service does not return. */
    }
    multibyte_reset(context,state);
    return width-pending;
incomplete:
    /* Re-read input in the original write order: it may alias state. */
    for (uint32_t i=pending; i<count; ++i) state->data[i+1]=input->data[i-pending];
    state->data[0]=(unsigned char)count;
    return UINT32_MAX-1U;
invalid:
    services->set_errno(services->context,42); /* Target EILSEQ. */
    return UINT32_MAX;
}
