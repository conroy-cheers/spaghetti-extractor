/* Actual neighbor connections, used by the source program and its comparison
 * consumer. Platform-facing services are supplied by the selected backend. */
#include "program-state.h"
#include "bootstrap-runtime.h"
#include "scores-runtime.h"
#include "board-runtime.h"
#include "runtime-support.h"
#include "math-runtime.h"
#include "shell-runtime.h"
#include "display-runtime.h"
#include "palette-runtime.h"

void bootstrap_scores_initialize(void *u, bootstrap_state *s) {
    (void)u;
    fixture_scores_initialize(&DXBALL_OWNER(s, bootstrap)->scores);
}
void bootstrap_scores_load(void *u, bootstrap_state *s) {
    (void)u;
    fixture_scores_load(&DXBALL_OWNER(s, bootstrap)->scores);
}
void bootstrap_boards_load(void *u, bootstrap_state *s, asset_name *name) {
    (void)u;
    board_name path = {name->text};
    fixture_board_load(&DXBALL_OWNER(s, bootstrap)->boards, &path);
}
void bootstrap_seed_random(void *u, bootstrap_state *s) {
    (void)u;
    fixture_runtime_seed(&DXBALL_OWNER(s, bootstrap)->runtime);
}
uint32_t bootstrap_now(void *u, bootstrap_state *s) {
    (void)u;
    dxball_program *p = DXBALL_OWNER(s, bootstrap);
    return fixture_runtime_now(&p->runtime, &p->clock_history);
}
uint32_t runtime_now(void *u, runtime_state *s) {
    (void)u;
    return fixture_runtime_now(s, &DXBALL_OWNER(s, runtime)->clock_history);
}
void runtime_vertical_blank(void *u, runtime_state *s, shell_device *device, uint32_t flags) {
    (void)u;
    bootstrap_vertical_blank(NULL, s->bootstrap, device, flags);
}
void shell_initialize_clock(void *u, shell_state *s) {
    (void)u;
    dxball_program *p = DXBALL_OWNER(s, application);
    fixture_runtime_clock_init(&p->runtime, p->version_history);
}
void shell_initialize_trig(void *u, shell_state *s) {
    (void)u;
    fixture_math_initialize(&DXBALL_OWNER(s, application)->math);
}
uint32_t shell_windowed_graphics(void *u, shell_state *s, shell_handle *instance, uint32_t show) {
    (void)u;
    dxball_program *p = DXBALL_OWNER(s, application);
    uint32_t result = fixture_display_windowed(&p->display, instance, show, &p->graphics_history);
    dxball_program_display_published(p);
    return result;
}
uint32_t shell_fullscreen_graphics(void *u, shell_state *s, shell_handle *instance, uint32_t show) {
    (void)u;
    dxball_program *p = DXBALL_OWNER(s, application);
    uint32_t result = fixture_display_fullscreen(&p->display, instance, show, &p->graphics_history);
    dxball_program_display_published(p);
    return result;
}
void palette_wait(void *u, palette_state *s, uint32_t count) {
    (void)u;
    fixture_runtime_wait(&DXBALL_OWNER(s, palette)->runtime, count);
}
