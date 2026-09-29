#ifndef DXBALL_PCX_STATE_H
#define DXBALL_PCX_STATE_H
#include "asset-state.h"
typedef struct spx_opaque_pcx_file_v5 {
    const unsigned char *cursor;
    uint32_t available;
} pcx_file;
typedef struct spx_opaque_pcx_view_v5 {
    asset_view image;
    uint32_t width, height;
} pcx_view;
typedef struct spx_opaque_pcx_state_v5 {
    unsigned char current[256][4], staged[256][4];
} pcx_state;
#endif
