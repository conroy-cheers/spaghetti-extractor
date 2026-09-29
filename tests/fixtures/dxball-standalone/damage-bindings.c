#include "program-state.h"
#include "damage-runtime.h"
#include "menu-runtime.h"
#include "screen-runtime.h"
#include "paddle-runtime.h"
#include "power-runtime.h"
#include "progress-runtime.h"
#include "warning-runtime.h"
#include "particle-runtime.h"
#include "portable-component-implementation.h"

/* These two operations have no services. The original 401350 records both
 * pages when mirroring; 401200 records the current page only. Keep the call
 * site distinction even though their C parameter types are identical. */
#define BOTH_PAGES(name, type, member) \
void name(void *u, type *s, font_rect *rectangle) { \
    (void)u; spx_damage_tracking_context_v5 context = {0}; \
    lifted_damage_damage(&context, &DXBALL_OWNER(s, member)->damage, rectangle); \
}
BOTH_PAGES(menu_damage, menu_state, menu)
BOTH_PAGES(progress_damage, progression_state, progression)
BOTH_PAGES(power_damage, powerup_state, powers)
#undef BOTH_PAGES

#define CURRENT_PAGE(name, type, member) \
void name(void *u, type *s, font_rect *rectangle) { \
    (void)u; spx_damage_tracking_context_v5 context = {0}; \
    lifted_damage_mark(&context, &DXBALL_OWNER(s, member)->damage, rectangle); \
}
CURRENT_PAGE(paddle_damage, paddle_state, paddle)
CURRENT_PAGE(screen_damage, score_screen, screen)
CURRENT_PAGE(warning_damage, warning_state, warning)
CURRENT_PAGE(particle_damage, particle_state, particles)
#undef CURRENT_PAGE
