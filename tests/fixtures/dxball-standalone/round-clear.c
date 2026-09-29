#include "program-state.h"
#include "round-runtime.h"
#include "portable-component-implementation.h"

/* Clear's service closure consists solely of freeing the unlinked record.
 * Use its exported API without importing leave's unrelated graphics/audio. */
void dxball_program_clear_objects(dxball_program *p) {
    spx_round_cleanup_services_v5 services = {.free = round_free};
    spx_round_cleanup_context_v5 context = {.services = &services};
    lifted_round_clear(&context, &p->round);
    dxball_program_refresh_views(p);
}
