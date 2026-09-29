#ifndef DXBALL_FONT_STATE_H
#define DXBALL_FONT_STATE_H
#include "cleanup-state.h"
typedef struct spx_opaque_cleanup_sprite_v5 font_sprite;
typedef struct spx_opaque_cleanup_surface_v5 font_surface;
struct spx_opaque_font_state_v5 {
    struct spx_opaque_cleanup_state_v5 *objects;
    uint32_t bank, spacing;
    font_surface *destination;
};
struct spx_opaque_font_bytes_v5 { const unsigned char *data; };
struct spx_opaque_font_rect_v5 { uint32_t left, top, right, bottom; };
typedef struct spx_opaque_font_state_v5 font_state;
typedef struct spx_opaque_font_bytes_v5 font_bytes;
typedef struct spx_opaque_font_rect_v5 font_rect;

/* This serialized metadata preserves the cleanup component's existing object
 * representation. Only the newly understood fields are named here. */
static inline uint32_t font_word(const font_sprite *sprite, unsigned offset) {
    const unsigned char *p = sprite->retained + offset - 4;
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static inline uint32_t font_width(const font_sprite *s) { return font_word(s, 8); }
static inline uint32_t font_height(const font_sprite *s) { return font_word(s, 12); }
static inline uint32_t font_baseline(const font_sprite *s) { return font_word(s, 40); }
static inline unsigned char font_character(const font_sprite *s) { return s->retained[32]; }
static inline int64_t font_signed(uint32_t word) {
    return word < UINT32_C(0x80000000) ? (int64_t)word : (int64_t)word - INT64_C(0x100000000);
}
static inline uint32_t font_half(uint32_t word) { return (uint32_t)(font_signed(word) / 2); }
#endif
