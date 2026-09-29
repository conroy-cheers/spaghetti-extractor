#ifndef DXBALL_ASSET_RUNTIME_H
#define DXBALL_ASSET_RUNTIME_H
#include "font-runtime.h"
#include "asset-state.h"
void asset_enter(void);
void fixture_sprite_load(asset_state *, uint32_t, uint32_t, asset_name *);
asset_file *asset_open(void *, asset_state *, asset_name *);
uint32_t asset_read(void *, asset_state *, asset_buffer *, uint32_t, uint32_t);
void asset_close(void *, asset_state *);
asset_buffer *asset_allocate_pixels(void *, asset_state *, uint32_t);
font_sprite *asset_allocate_sprite(void *, asset_state *);
void asset_free_pixels(void *, asset_state *, asset_buffer *);
uint32_t asset_create(void *, asset_state *, font_sprite *, uint32_t);
void asset_color_key(void *, asset_state *, font_surface *);
uint32_t asset_describe(void *, asset_state *, font_surface *, asset_view *);
uint32_t asset_lock(void *, asset_state *, font_surface *, asset_view *);
void asset_unlock(void *, asset_state *, font_surface *);
#endif
