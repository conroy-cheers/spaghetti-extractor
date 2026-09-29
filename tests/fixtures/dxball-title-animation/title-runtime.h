#ifndef DXBALL_TITLE_RUNTIME_H
#define DXBALL_TITLE_RUNTIME_H
#include "title-state.h"
void title_enter(unsigned);
void fixture_title_scroll(title_state *);
void fixture_title_wave(title_state *);
void fixture_title_wobble(title_state *);
void fixture_title_cycle(title_state *);
void title_select_font(void *, font_state *, uint32_t);
void title_destination(void *, font_state *, font_surface *);
uint32_t title_glyph(void *, font_state *, uint32_t, uint32_t, uint32_t);
void title_blit_fast(void *, title_state *, font_surface *, uint32_t, uint32_t, font_surface *, font_rect *, uint32_t);
void title_apply_palette(void *, title_state *, uint32_t, uint32_t);
#endif
