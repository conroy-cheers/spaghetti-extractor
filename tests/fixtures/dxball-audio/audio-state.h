#ifndef DXBALL_AUDIO_STATE_H
#define DXBALL_AUDIO_STATE_H
#include <stdint.h>

typedef struct spx_opaque_audio_device_v5 audio_device;
typedef struct spx_opaque_audio_buffer_v5 audio_buffer;
typedef struct spx_opaque_audio_sample_v5 {
    audio_buffer *buffer;
    unsigned char payload[33]; /* Saved name and provider metadata, in original byte order. */
} audio_sample;
typedef struct spx_opaque_audio_state_v5 {
    audio_device *device;
    audio_buffer *primary;
    audio_sample *slots[50];
} audio_state;
typedef struct spx_opaque_audio_history_v5 { uint32_t restore_status; } audio_history;
typedef struct spx_opaque_audio_status_v5 { uint32_t flags; } audio_status_word;
typedef struct spx_opaque_audio_name_v5 { const char *text; } audio_name;
#endif
