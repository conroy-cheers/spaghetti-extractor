#ifndef DXBALL_REGIONS_STATE_H
#define DXBALL_REGIONS_STATE_H
#include "editor-state.h"

/* A borrowed view of the editor's existing storage, not a second table. */
typedef struct spx_opaque_region_table_v5 {
    uint32_t *count;
    editor_region *records;
    uint32_t capacity;
} region_table;
#endif
