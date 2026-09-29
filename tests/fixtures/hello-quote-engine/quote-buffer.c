/* SPDX-License-Identifier: GPL-3.0-or-later
 * Portable authoring of Hello's complete quoting loop. Algorithm reference:
 * GNU Hello 2.12.3 lib/quotearg.c, written by Paul Eggert.
 * Copyright (C) 1998-2002, 2004-2026 Free Software Foundation, Inc.
 * This program is free software: you can redistribute it and/or modify it under
 * the GNU General Public License, version 3 or (at your option) any later version.
 * It is distributed WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See COPYING.hello.
 * The pinned native implementation, not the reference source, is the oracle. */
#include "portable-component-implementation.h"
#include "quote-buffer-objects.h"

typedef spx_quote_buffer_context_v5 Context;
typedef struct spx_opaque_quote_bytes_v5 Bytes;
typedef struct spx_opaque_quote_mask_v5 Mask;
typedef struct spx_opaque_quote_conversion_v5 Conversion;
enum Style { LITERAL, SHELL, SHELL_ALWAYS, SHELL_ESCAPE, SHELL_ESCAPE_ALWAYS,
    C_STYLE, C_MAYBE, ESCAPE, LOCALE, C_LOCALE, CUSTOM };
enum Flags { ELIDE_NULLS=1, ELIDE_OUTER=2, SPLIT_TRIGRAPHS=4 };
struct Writer { unsigned char *data; uint32_t capacity, length; };

static void put(struct Writer *writer, unsigned char byte) {
    if (writer->length < writer->capacity) writer->data[writer->length] = byte;
    ++writer->length;
}
static uint32_t length(const unsigned char *text) {
    uint32_t n=0; while (text[n]) ++n; return n;
}
static int equal(const unsigned char *a, const unsigned char *b, uint32_t n) {
    for (uint32_t i=0; i<n; ++i) if (a[i]!=b[i]) return 0;
    return 1;
}
static int contains(const char *set, unsigned char byte) {
    for (uint32_t i=0; set[i]; ++i) if ((unsigned char)set[i]==byte) return 1;
    return 0;
}
static void start_escape(struct Writer *writer, uint32_t style, int *escaping, int *pending) {
    *escaping=1;
    if (style==SHELL_ALWAYS && !*pending) {
        put(writer,'\''); put(writer,'$'); put(writer,'\''); *pending=1;
    }
    put(writer,'\\');
}
static void end_escape(struct Writer *writer, int escaping, int *pending) {
    if (*pending && !escaping) { put(writer,'\''); put(writer,'\''); *pending=0; }
}

uint32_t quote_buffer(Context *context, Bytes *output, uint32_t capacity,
    Bytes *argument, uint32_t argument_size, uint32_t style, uint32_t flags,
    Mask *mask, Bytes *left_quote, Bytes *right_quote) {
    const spx_quote_buffer_services_v5 *services=context->services;
    void *environment=services->context;
    int unibyte=services->mb_cur_max(environment)==1;
    unsigned char *arg=argument?argument->data:0;
    struct Writer writer={output?output->data:0,capacity,0};
    uint32_t original_capacity=0, quote_length=0;
    const unsigned char *quote=0;
    int backslash=0, elide=(flags & ELIDE_OUTER)!=0, encountered_quote=0, compatible=1;
    int pending;

process_input:
    pending=0;
    switch (style) {
    case C_MAYBE: style=C_STYLE; elide=1; /* fall through */
    case C_STYLE:
        if (!elide) put(&writer,'"');
        backslash=1; quote=(const unsigned char *)"\""; quote_length=1; break;
    case ESCAPE: backslash=1; elide=0; break;
    case LOCALE: case C_LOCALE: case CUSTOM:
        if (style!=CUSTOM) {
            left_quote=services->locale_quote(environment,0,style);
            right_quote=services->locale_quote(environment,1,style);
        }
        if (!elide) for (uint32_t i=0; left_quote->data[i]; ++i) put(&writer,left_quote->data[i]);
        backslash=1; quote=right_quote->data; quote_length=length(quote); break;
    case SHELL_ESCAPE: backslash=1; /* fall through */
    case SHELL: elide=1; /* fall through */
    case SHELL_ESCAPE_ALWAYS: if (!elide) backslash=1; /* fall through */
    case SHELL_ALWAYS:
        style=SHELL_ALWAYS;
        if (!elide) put(&writer,'\'');
        quote=(const unsigned char *)"'"; quote_length=1; break;
    case LITERAL: elide=0; break;
    default: services->invalid_style(environment); return 0;
    }

    for (uint32_t i=0; !(argument_size==UINT32_MAX ? arg[i]==0 : i==argument_size); ++i) {
        int right=0, escaping=0, byte_compatible=0;
        if (backslash && style!=SHELL_ALWAYS && quote_length) {
            if (argument_size==UINT32_MAX && quote_length>1) argument_size=length(arg);
            if (i+quote_length<=argument_size && equal(arg+i,quote,quote_length)) {
                if (elide) goto force_outer;
                right=1;
            }
        }
        unsigned char c=arg[i], escape=0;
        switch (c) {
        case 0:
            if (backslash) {
                if (elide) goto force_outer;
                start_escape(&writer,style,&escaping,&pending);
                if (style!=SHELL_ALWAYS && i+1<argument_size && arg[i+1]>='0' && arg[i+1]<='9') {
                    put(&writer,'0'); put(&writer,'0');
                }
                c='0';
            } else if (flags & ELIDE_NULLS) continue;
            break;
        case '?':
            if (style==SHELL_ALWAYS && elide) goto force_outer;
            if (style==C_STYLE && (flags & SPLIT_TRIGRAPHS) && i+2<argument_size &&
                arg[i+1]=='?' && contains("!'()-/<=>",arg[i+2])) {
                if (elide) goto force_outer;
                c=arg[i+2]; i+=2;
                put(&writer,'?'); put(&writer,'"'); put(&writer,'"'); put(&writer,'?');
            }
            break;
        case '\a': escape='a'; goto c_escape;
        case '\b': escape='b'; goto c_escape;
        case '\f': escape='f'; goto c_escape;
        case '\v': escape='v'; goto c_escape;
        case '\n': escape='n'; goto shell_escape;
        case '\r': escape='r'; goto shell_escape;
        case '\t': escape='t'; goto shell_escape;
        case '\\':
            escape=c;
            if (style==SHELL_ALWAYS) { if (elide) goto force_outer; goto store; }
            if (backslash && elide && quote_length) goto store;
shell_escape:
            if (style==SHELL_ALWAYS && elide) goto force_outer;
c_escape:
            if (backslash) { c=escape; goto store_escape; }
            break;
        case '{': case '}':
            if (!(argument_size==UINT32_MAX ? arg[1]==0 : argument_size==1)) break;
            /* fall through */
        case '#': case '~':
            if (i!=0) break;
            /* fall through */
        case ' ': byte_compatible=1; /* fall through */
        case '!': case '"': case '$': case '&': case '(': case ')': case '*': case ';':
        case '<': case '=': case '>': case '[': case '^': case '`': case '|':
            if (style==SHELL_ALWAYS && elide) goto force_outer;
            break;
        case '\'':
            encountered_quote=1; byte_compatible=1;
            if (style==SHELL_ALWAYS) {
                if (elide) goto force_outer;
                if (writer.capacity && !original_capacity) {
                    original_capacity=writer.capacity; writer.capacity=0;
                }
                put(&writer,'\''); put(&writer,'\\'); put(&writer,'\''); pending=0;
            }
            break;
        default:
            if (contains("%+,-./0123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ]_abcdefghijklmnopqrstuvwxyz",c)) {
                byte_compatible=1; break;
            }
            uint32_t count;
            int printable;
            if (unibyte) { count=1; printable=services->byte_printable(environment,c)!=0; }
            else {
                Conversion conversion={0,0};
                services->conversion_reset(environment,&conversion);
                count=0; printable=1;
                if (argument_size==UINT32_MAX) argument_size=length(arg);
                for (;;) {
                    uint32_t bytes=services->decode(environment,&conversion,argument,i+count,argument_size-(i+count));
                    if (!bytes) break;
                    if (bytes==UINT32_MAX) { printable=0; break; }
                    if (bytes==UINT32_MAX-1U) {
                        printable=0;
                        while (i+count<argument_size && arg[i+count]) ++count;
                        break;
                    }
                    if (bytes==UINT32_MAX-2U) bytes=0;
                    if (elide && style==SHELL_ALWAYS)
                        for (uint32_t j=1; j<bytes; ++j)
                            if (contains("[\\^`|",arg[i+count+j])) goto force_outer;
                    if (!services->character_printable(environment,conversion.character)) printable=0;
                    count+=bytes;
                    if (services->conversion_initial(environment,&conversion)) break;
                }
            }
            byte_compatible=printable;
            if (count>1 || (backslash && !printable)) {
                uint32_t limit=i+count;
                for (;;) {
                    if (backslash && !printable) {
                        if (elide) goto force_outer;
                        start_escape(&writer,style,&escaping,&pending);
                        put(&writer,(unsigned char)('0'+(c>>6)));
                        put(&writer,(unsigned char)('0'+((c>>3)&7))); c=(unsigned char)('0'+(c&7));
                    } else if (right) { put(&writer,'\\'); right=0; }
                    if (limit<=i+1) break;
                    end_escape(&writer,escaping,&pending); put(&writer,c); c=arg[++i];
                }
                goto store;
            }
        }
        if (!((((backslash && style!=SHELL_ALWAYS) || elide) && mask &&
                ((mask->words[c/32]>>(c%32))&1)) || right)) goto store;
store_escape:
        if (elide) goto force_outer;
        start_escape(&writer,style,&escaping,&pending);
store:
        end_escape(&writer,escaping,&pending); put(&writer,c);
        if (!byte_compatible) compatible=0;
    }
    if (!writer.length && style==SHELL_ALWAYS && elide) goto force_outer;
    if (style==SHELL_ALWAYS && !elide && encountered_quote) {
        if (compatible) return quote_buffer(context,output,original_capacity,argument,argument_size,
            C_STYLE,flags,mask,left_quote,right_quote);
        if (!writer.capacity && original_capacity) {
            writer.capacity=original_capacity; writer.length=0; goto process_input;
        }
    }
    if (quote && !elide) for (uint32_t i=0; quote[i]; ++i) put(&writer,quote[i]);
    if (writer.length<writer.capacity) writer.data[writer.length]=0;
    return writer.length;
force_outer:
    if (style==SHELL_ALWAYS && backslash) style=SHELL_ESCAPE_ALWAYS;
    return quote_buffer(context,output,writer.capacity,argument,argument_size,style,
        flags & ~UINT32_C(2),0,left_quote,right_quote);
}
