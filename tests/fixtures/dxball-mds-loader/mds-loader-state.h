#ifndef DXBALL_MDS_LOADER_STATE_H
#define DXBALL_MDS_LOADER_STATE_H
#include "mds-state.h"
typedef struct spx_opaque_mds_output_v5 { mds_info *value; } mds_output;
typedef struct spx_opaque_mds_input_v5 { const unsigned char *data; } mds_input;
typedef struct spx_opaque_mds_handle_v5 { uintptr_t value; } mds_handle;
#endif
