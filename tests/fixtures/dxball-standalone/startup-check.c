/* Exercise production owner/connections against retained native startup data.
 * This is an assembly check, not the application's entry point or a platform
 * emulator. No missing application/platform method is replaced with a stub. */
#include "program-state.h"
#include "bootstrap-runtime.h"
#include "shell-runtime.h"
#include "board-runtime.h"
#include "spx-observation.h"
#include <stdio.h>
#include <stdlib.h>

static unsigned selected[3];
void scores_enter(unsigned operation) { (void)operation; ++selected[0]; }
void board_enter(unsigned operation) { (void)operation; ++selected[1]; }
void math_enter(unsigned operation) { (void)operation; ++selected[2]; }

int main(void) {
    dxball_program *p = malloc(sizeof(*p));
    dxball_program *other = malloc(sizeof(*other));
    if (!p || !other) return 2;
    dxball_program_initialize(p, NULL);
    dxball_program_initialize(other, NULL);
    spx_observer out = spx_observe_begin(stdout);
    spx_observe_bytes(&out, "message", p->title.message, strlen((const char *)p->title.message)+1);
    spx_observe_u32s(&out, "palette_cycle", p->scene.palette_cycle, 66);
    bootstrap_scores_initialize(NULL, &p->bootstrap);
    spx_observe_bytes(&out, "scores_initialized", p->scores.entries, sizeof(p->scores.entries));
    bootstrap_scores_load(NULL, &p->bootstrap);
    spx_observe_bytes(&out, "scores_loaded", p->screen.scores->entries, sizeof(p->scores.entries));
    asset_name name = {"default.bds"};
    bootstrap_boards_load(NULL, &p->bootstrap, &name);
    spx_observe_bytes(&out, "boards", &p->boards.current, sizeof(board));
    spx_observe_bytes(&out, "saved_boards", p->editor.boards->saved, sizeof(p->boards.saved));
    fixture_board_select(p->renderer.boards, 0);
    spx_observe_bytes(&out, "selected_board", p->game.progression->paddle->pickups->motion->board, sizeof(board));
    shell_initialize_trig(NULL, &p->application);
    spx_observe_u32s(&out, "sine", (const uint32_t *)p->title.sine, 361);
    spx_observe_u32s(&out, "cosine", (const uint32_t *)p->play.cosine, 361);
    font_surface primary = {7}, back = {9};
    p->title.primary = &primary; p->title.back = &back;
    dxball_program_display_published(p);
    unsigned char clean[sizeof(board)] = {0};
    uint32_t aliases[] = {
        p->flow.primary == &primary && p->flow.back == &back,
        p->font.objects == p->assets.objects,
        p->regions.records == p->editor.regions && p->regions.count == &p->editor.region_count,
        p->particles.destination == &p->title.software,
        p->explosions.roots == &p->play.explosions,
        p->screen.menu->scene->animation->flow == &p->flow,
        other->menu.scene == &other->scene && other->font.objects == &other->objects,
        !memcmp(&other->boards.current, clean, sizeof(clean)) && !other->math.cosine[0],
    };
    spx_observe_u32s(&out, "shared_owners", aliases, sizeof(aliases)/sizeof(aliases[0]));
    spx_observe_u32s(&out, "selected", selected, 3);
    int good = spx_observe_finish(&out);
    dxball_program_dispose_files(p);
    dxball_program_dispose_files(other);
    free(other); free(p);
    return good ? 0 : 3;
}
