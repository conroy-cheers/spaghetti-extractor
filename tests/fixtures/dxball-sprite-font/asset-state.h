#ifndef DXBALL_ASSET_STATE_H
#define DXBALL_ASSET_STATE_H
#include "font-state.h"
struct spx_opaque_asset_file_v5;
struct spx_opaque_asset_state_v5 {
    struct spx_opaque_cleanup_state_v5 *objects;
    struct spx_opaque_asset_file_v5 *file;
};
struct spx_opaque_asset_name_v5 { const char *text; };
struct spx_opaque_asset_buffer_v5 { unsigned char *data; uint32_t size; };
struct spx_opaque_asset_view_v5 { unsigned char *pixels; uint32_t pitch; };
typedef struct spx_opaque_asset_state_v5 asset_state;
typedef struct spx_opaque_asset_file_v5 asset_file;
typedef struct spx_opaque_asset_name_v5 asset_name;
typedef struct spx_opaque_asset_buffer_v5 asset_buffer;
typedef struct spx_opaque_asset_view_v5 asset_view;

static inline void asset_set_word(font_sprite *sprite, unsigned offset, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) sprite->retained[offset - 4 + i] = (unsigned char)(value >> (8 * i));
}
#endif
