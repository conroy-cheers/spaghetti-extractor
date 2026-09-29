#ifndef DXBALL_WAVE_STATE_H
#define DXBALL_WAVE_STATE_H
#include "audio-state.h"

typedef struct spx_opaque_wave_bytes_v5 { unsigned char *bytes; } wave_bytes;
typedef struct spx_opaque_wave_result_v5 {
    const unsigned char *format, *data;
    uint32_t length;
} wave_result;
typedef struct spx_opaque_wave_history_v5 { const unsigned char *format; } wave_history;
typedef struct spx_opaque_wave_locked_v5 {
    unsigned char *first, *second;
    uint32_t first_bytes, second_bytes;
} wave_locked;
typedef struct spx_opaque_wave_word_v5 { unsigned char *bytes; } wave_word;
typedef struct spx_opaque_wave_buffer_spec_v5 {
    uint32_t size, flags, bytes, reserved;
    const unsigned char *format;
} wave_buffer_spec;
#endif
