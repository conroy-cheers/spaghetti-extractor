#ifndef DXBALL_BOOTSTRAP_STATE_H
#define DXBALL_BOOTSTRAP_STATE_H
#include "display-state.h"
typedef struct spx_opaque_bootstrap_state_v5 {
    shell_state *application;
    uint32_t last_refresh;
} bootstrap_state;
#endif
