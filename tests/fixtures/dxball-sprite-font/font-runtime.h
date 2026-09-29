#ifndef DXBALL_FONT_RUNTIME_H
#define DXBALL_FONT_RUNTIME_H
#include "runtime.h"
#include "font-state.h"
void font_enter(unsigned operation);
void fixture_font_select(font_state *, uint32_t);
uint32_t fixture_font_find(font_state *, uint32_t);
uint32_t fixture_font_measure(font_state *, uint32_t, font_bytes *);
uint32_t fixture_font_glyph(font_state *, uint32_t, uint32_t, uint32_t);
uint32_t fixture_font_line(font_state *, uint32_t, uint32_t, uint32_t, font_bytes *);
uint32_t fixture_font_center(font_state *, uint32_t, uint32_t, uint32_t, font_bytes *);
uint32_t font_service_find(void *, font_state *, uint32_t);
uint32_t font_service_measure(void *, font_state *, uint32_t, font_bytes *);
void font_service_blit(void *, font_state *, font_rect *, font_surface *, font_rect *);
#endif
