#ifndef DXBALL_AUDIO_SETUP_STATE_H
#define DXBALL_AUDIO_SETUP_STATE_H
#include "audio-state.h"
#include "shell-state.h"
typedef struct spx_opaque_audio_format_v5 audio_format;
typedef struct spx_opaque_audio_buffer_spec_v5 {
    uint32_t size,flags,bytes,reserved;
    audio_format *format;
} audio_buffer_spec;
typedef struct spx_opaque_audio_setup_state_v5 {
    audio_state *bank;
    shell_state *application;
} audio_setup_state;
#endif
