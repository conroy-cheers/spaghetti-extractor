#ifndef DXBALL_MDS_STATE_H
#define DXBALL_MDS_STATE_H
#include "mds-events-state.h"
typedef struct spx_opaque_mds_info_v5 mds_info;
typedef struct spx_opaque_mds_memory_v5 mds_memory;
typedef struct mds_buffer {
    mds_event_block event;
    unsigned char *payload;
    mds_info *owner;
    uint32_t flags;
    struct mds_buffer *next;
} mds_buffer;
typedef struct spx_opaque_mds_buffers_v5 { mds_buffer *headers; } mds_buffers;
struct spx_opaque_mds_info_v5 {
    uint32_t signature,division,capacity,format;
    mds_buffers *buffers;
    uintptr_t stream;
    uint32_t flags,count,pending;
};
typedef struct spx_opaque_mds_file_v5 { const unsigned char *data; } mds_file;
#endif
