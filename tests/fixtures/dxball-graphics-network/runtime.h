#ifndef DXBALL_GRAPHICS_RUNTIME_H
#define DXBALL_GRAPHICS_RUNTIME_H
#include "graphics-state.h"
typedef struct spx_opaque_dx_graphics_v5 dx_graphics;

void dx_require(int condition);
void dx_enter(unsigned unit);
void dx_check_selected(unsigned unit, int success);
int32_t dx_create_draw(void *, dx_graphics *);
int32_t dx_cooperative(void *, dx_graphics *, uint32_t, uint32_t, uint32_t);
uint32_t dx_caps(void *, dx_graphics *, uint32_t);
int32_t dx_create_surface(void *, dx_graphics *, uint32_t, uint32_t);
int32_t dx_create_clipper(void *, dx_graphics *, uint32_t);
int32_t dx_clipper_window(void *, dx_graphics *, uint32_t, uint32_t);
int32_t dx_attach(void *, dx_graphics *, uint32_t, uint32_t);
void dx_hide(void *, dx_graphics *, uint32_t);
uint32_t dx_message(void *, dx_graphics *, uint32_t, uint32_t);
void dx_destroy(void *, dx_graphics *, uint32_t);
uint32_t dx_blit_fast(void *, dx_graphics *, uint32_t, uint32_t, uint32_t,
    uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
void dx_reset(void *, dx_graphics *);
void dx_bind(void *, dx_graphics *, uint32_t);
void fixture_graphics_reset(dx_graphics *);
void fixture_graphics_bind(dx_graphics *, uint32_t);
uint32_t fixture_graphics_blit(dx_graphics *, uint32_t, uint32_t, uint32_t);
uint32_t fixture_graphics_initialize(dx_graphics *);

/* The selected oracle executes either retained machine-derived C or the pinned
 * original x86 bodies. Both include the initializer's two actual callees. */
void original_reset(dx_graphics *);
void original_bind(dx_graphics *, uint32_t);
uint32_t original_blit(dx_graphics *, uint32_t, uint32_t, uint32_t);
uint32_t original_initialize(dx_graphics *);
dx_graphics *dx_setup(uint32_t seed, unsigned failure, int positive,
    unsigned clipper_mode, unsigned callback, unsigned caps_failure);
void dx_seed_live_resources(dx_graphics *);
void dx_load_sprite(dx_graphics *, unsigned bank, unsigned slot);
void dx_observe(dx_graphics *, const uint32_t *, unsigned);
#endif
