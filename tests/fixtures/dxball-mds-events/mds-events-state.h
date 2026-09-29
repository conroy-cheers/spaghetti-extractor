#ifndef DXBALL_MDS_EVENTS_STATE_H
#define DXBALL_MDS_EVENTS_STATE_H
#include <stdint.h>

typedef struct spx_opaque_mds_event_block_v5 {
    unsigned char *data;
    uint32_t capacity, used;
} mds_event_block;
#endif
