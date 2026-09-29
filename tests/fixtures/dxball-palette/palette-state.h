#ifndef DXBALL_PALETTE_STATE_H
#define DXBALL_PALETTE_STATE_H
#include "pcx-state.h"
#include "flow-state.h"
typedef struct spx_opaque_palette_state_v5 {
    pcx_state *colors;
    flow_state *flow;
} palette_state;
typedef struct spx_opaque_palette_sequence_v5 { uint32_t *values; } palette_sequence;
#endif
