#ifndef DXBALL_LIFECYCLE_RUNTIME_H
#define DXBALL_LIFECYCLE_RUNTIME_H
#include "asset-runtime.h"
void lifecycle_enter(unsigned);
uint32_t fixture_sprite_capture(asset_state *, font_state *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
void fixture_sprite_restore(asset_state *);
uint32_t lifecycle_copy(void *, asset_state *, font_state *, font_sprite *, font_rect *);
uint32_t lifecycle_restore_surface(void *, asset_state *, font_surface *);
void lifecycle_reload(void *, asset_state *, uint32_t);
#endif
