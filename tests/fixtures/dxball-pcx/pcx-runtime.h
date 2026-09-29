#ifndef DXBALL_PCX_RUNTIME_H
#define DXBALL_PCX_RUNTIME_H
#include "pcx-state.h"
void pcx_enter(unsigned);
void fixture_pcx_draw(pcx_state *, font_surface *, asset_name *, uint32_t, uint32_t, uint32_t);
void fixture_pcx_palette_current(pcx_state *, asset_name *);
void fixture_pcx_palette_staged(pcx_state *, asset_name *);
pcx_file *pcx_open(void *, asset_name *);
uint32_t pcx_refill(void *, pcx_file *);
void pcx_seek(void *, pcx_file *, uint32_t, uint32_t);
void pcx_close(void *, pcx_file *);
void pcx_describe(void *, font_surface *, pcx_view *);
uint32_t pcx_lock(void *, font_surface *, pcx_view *);
void pcx_unlock(void *, font_surface *);
void pcx_apply(void *, pcx_state *);
#endif
