#ifndef DXBALL_RUNTIME_STATE_H
#define DXBALL_RUNTIME_STATE_H
#include "bootstrap-state.h"
typedef struct spx_opaque_runtime_sample_v5 { uint32_t low,high; } runtime_sample;
typedef struct spx_opaque_runtime_version_v5 { uint32_t size,platform; } runtime_version_query;
typedef struct spx_opaque_runtime_state_v5 {
    bootstrap_state *bootstrap;
    uint32_t counter_enabled,counter_divisor,random_seed;
} runtime_state;
#endif
