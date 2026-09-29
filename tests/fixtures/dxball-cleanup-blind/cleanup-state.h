#ifndef DX_CLEANUP_STATE_H
#define DX_CLEANUP_STATE_H
#include <stdint.h>

/* Operator reconstruction from the pinned PE, not original game declarations.
 * Object identity/lifetime belongs to the environment; these are live views. */
struct spx_opaque_cleanup_surface_v5 { uint32_t identity; };
struct spx_opaque_cleanup_sprite_v5 {
    struct spx_opaque_cleanup_surface_v5 *surface;
    unsigned char retained[41];
};
struct cleanup_bank {
    struct spx_opaque_cleanup_sprite_v5 *slots[255];
    uint32_t count;
    uint32_t retained[6];
};
struct spx_opaque_cleanup_state_v5 {
    struct cleanup_bank banks[3];
    uint32_t current_bank;
};
#endif
