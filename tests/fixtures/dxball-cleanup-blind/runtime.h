#ifndef DX_CLEANUP_RUNTIME_H
#define DX_CLEANUP_RUNTIME_H
#include "cleanup-state.h"
typedef struct spx_opaque_cleanup_state_v5 cleanup_state;
typedef struct spx_opaque_cleanup_sprite_v5 cleanup_sprite;
typedef struct spx_opaque_cleanup_surface_v5 cleanup_surface;
void trial_require(int, const char *, unsigned);
#define REQUIRE(test) trial_require(!!(test), #test, __LINE__)
void trial_enter(unsigned);
void fixture_select(cleanup_state *, uint32_t);
void fixture_dispose(cleanup_state *, uint32_t);
void fixture_clear(cleanup_state *);
void trial_select(void *, cleanup_state *, uint32_t);
void trial_dispose(void *, cleanup_state *, uint32_t);
void trial_release(void *, cleanup_state *, cleanup_surface *);
void trial_free_sprite(void *, cleanup_state *, cleanup_sprite *);
#endif
