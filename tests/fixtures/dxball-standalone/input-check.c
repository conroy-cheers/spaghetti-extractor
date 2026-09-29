/* Exercise the production owner/input adapters without a window or fake
 * rendering backend. The two selected operations declare no services. */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "program-state.h"

int main(int argc, char **argv) {
    if (argc != 7) return 2;
    dxball_program *p = malloc(sizeof(*p)), *other = malloc(sizeof(*other));
    if (!p || !other) { free(p); free(other); return 3; }
    dxball_program_initialize(p, NULL);
    dxball_program_initialize(other, NULL);
    p->application.control = (uint32_t)strtoul(argv[2], NULL, 0);
    p->application.shift = (uint32_t)strtoul(argv[3], NULL, 0);
    uint32_t key = (uint32_t)strtoul(argv[4], NULL, 0);
    p->flow.transition_pending = (uint32_t)strtoul(argv[5], NULL, 0);
    p->flow.next_scene = (uint32_t)strtoul(argv[6], NULL, 0);
    /* A stale read view must not override its writer, in either direction. */
    p->menu.input_ready = !p->application.control;
    p->screen.shift = !p->application.shift;
    if (!strcmp(argv[1], "menu")) dxball_program_menu_key(p, key);
    else if (!strcmp(argv[1], "title")) dxball_program_title_key(p, key);
    else { free(p); free(other); return 2; }
    printf("{\"pending\":%" PRIu32 ",\"next\":%" PRIu32
           ",\"control\":%" PRIu32 ",\"shift\":%" PRIu32
           ",\"reader_control\":%" PRIu32 ",\"reader_shift\":%" PRIu32
           ",\"other_unchanged\":%s}\n",
        p->flow.transition_pending, p->flow.next_scene, p->application.control,
        p->application.shift, p->menu.input_ready, p->screen.shift,
        !other->application.control && !other->application.shift && !other->menu.input_ready &&
        !other->screen.shift && !other->flow.transition_pending && !other->flow.next_scene ? "true" : "false");
    free(p); free(other);
    return 0;
}
