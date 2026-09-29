#ifndef DXBALL_GRAPHICS_STATE_H
#define DXBALL_GRAPHICS_STATE_H
#include <stdint.h>

/* Private portable storage. Pointers denote actual fixture-owned sprite objects;
 * adapters transport their contents and aliases, not just their PE addresses. */
struct dx_sprite {
  uint32_t surface;
  uint32_t rectangle[4];
};
struct dx_sprite_bank {
  struct dx_sprite *slots[255];
  uint32_t count;
  uint32_t retained[6];
};
struct spx_opaque_dx_graphics_v5 {
  uint32_t window, directdraw, primary, backbuffer, clipper;
  uint32_t clipper_mode, capability_mode, initialized, video_memory;
  uint32_t current_surface, bank_index;
  struct dx_sprite_bank banks[3];
};
#endif
