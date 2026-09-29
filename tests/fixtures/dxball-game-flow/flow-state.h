#ifndef DXBALL_FLOW_STATE_H
#define DXBALL_FLOW_STATE_H
#include "asset-state.h"
typedef struct spx_opaque_flow_audio_v5 flow_audio;
typedef struct spx_opaque_flow_state_v5 {
    uint32_t first_frame, scene, next_scene, transition_pending;
    uint32_t windowed, refresh_needed, audio_enabled;
    flow_audio *audio;
    font_surface *primary, *back, *overlay;
    asset_state *sprites;
} flow_state;
#endif
