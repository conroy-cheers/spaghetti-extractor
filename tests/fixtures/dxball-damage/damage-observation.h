#ifndef DXBALL_DAMAGE_OBSERVATION_H
#define DXBALL_DAMAGE_OBSERVATION_H
#include "damage-state.h"
/* Reset and setter boundaries can precede surface allocation. Observing those
 * states must not invoke a graphics service on an absent surface. */
static inline uint64_t damage_observe_surface(font_surface *surface,uint64_t (*read_pixels)(font_surface *)) {
    return surface ? read_pixels(surface) : 0;
}
#endif
