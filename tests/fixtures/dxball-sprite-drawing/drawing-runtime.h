#ifndef DXBALL_DRAWING_RUNTIME_H
#define DXBALL_DRAWING_RUNTIME_H
#include "font-runtime.h"
void drawing_enter(unsigned);
void fixture_sprite_destination(font_state *, font_surface *);
uint32_t fixture_sprite_transparent(font_state *, uint32_t, uint32_t, uint32_t);
uint32_t fixture_sprite_opaque(font_state *, uint32_t, uint32_t, uint32_t);
uint32_t drawing_blit_fast(void *, font_state *, font_sprite *, uint32_t, uint32_t, uint32_t);
#endif
