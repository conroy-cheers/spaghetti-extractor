/* Exercise real assembly calls and malloc/free ownership. No native image,
 * mock renderer or replacement implementations are linked into this check. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "program-state.h"
#include "menu-runtime.h"
#include "screen-runtime.h"
#include "paddle-runtime.h"
#include "particle-runtime.h"
#include "explosion-runtime.h"
#include "motion-runtime.h"
#include "brick-runtime.h"
#include "pickup-runtime.h"
#include "shot-runtime.h"
#include "power-runtime.h"
#include "progress-runtime.h"
#include "warning-runtime.h"

#define REQUIRE(test) do { if (!(test)) { fprintf(stderr, "ownership check: %s:%d: %s\n", __FILE__, __LINE__, #test); exit(1); } } while (0)

static void damage_routing(dxball_program *p) {
    p->scene.presentation_mode = 0;
    p->title.fast = 0;
    p->damage.capability = 1;
    font_rect rectangle = {11, 13, 47, 53};
    for (uint32_t page = 0; page < 2; ++page) {
        p->damage.page = page;
#define DAMAGE(call, both) do { \
    p->damage.count[0] = p->damage.count[1] = p->damage.pending_count = 0; \
    call; \
    REQUIRE(p->damage.count[page] == 1); REQUIRE(p->damage.count[1-page] == (both)); \
    REQUIRE(!memcmp(&p->damage.history[0][page], &rectangle, sizeof(rectangle))); \
    if (both) REQUIRE(!memcmp(&p->damage.history[0][1-page], &rectangle, sizeof(rectangle))); \
    REQUIRE(!p->damage.pending_count); \
} while (0)
        /* Address-reviewed callers: 401350 vs 401200. */
        DAMAGE(menu_damage(NULL, &p->menu, &rectangle), 1);
        DAMAGE(screen_damage(NULL, &p->screen, &rectangle), 0);
        DAMAGE(progress_damage(NULL, &p->progression, &rectangle), 1);
        DAMAGE(power_damage(NULL, &p->powers, &rectangle), 1);
        DAMAGE(paddle_damage(NULL, &p->paddle, &rectangle), 0);
        DAMAGE(particle_damage(NULL, &p->particles, &rectangle), 0);
        DAMAGE(warning_damage(NULL, &p->warning, &rectangle), 0);
#undef DAMAGE
    }
}

static void populate(dxball_program *p) {
#define PAIR(type, roots, allocate) do { \
    type *first = (void *)(allocate), *last = (void *)(allocate); \
    REQUIRE(first && last); *first = (type){0}; *last = (type){0}; \
    first->next = last; last->previous = first; \
    (roots).first = (roots).current = first; (roots).last = last; \
} while (0)
    PAIR(play_shot, p->play.shots, shot_allocate(NULL, &p->motion));
    PAIR(play_ball, p->play.balls, motion_allocate(NULL, &p->motion));
    PAIR(brick_effect, p->bricks, brick_allocate_effect(NULL, &p->bricks));
    PAIR(play_event, p->play.events, brick_allocate_event(NULL, &p->bricks));
    PAIR(pickup, p->pickups, pickup_allocate(NULL, &p->pickups));
    PAIR(particle, p->particles, particle_allocate(NULL, &p->particles));
    PAIR(play_ball, p->powers.staged_balls, power_allocate_ball(NULL, &p->powers));
    PAIR(play_event, p->powers.queued_cells, power_allocate_cell(NULL, &p->powers));
#undef PAIR
    explosion *first = explosion_allocate(NULL, &p->explosions);
    explosion *last = explosion_allocate(NULL, &p->explosions);
    REQUIRE(first && last);
    *first = (explosion){.next = last}; *last = (explosion){.previous = first};
    p->play.explosions.first = p->play.explosions.current = (void *)first;
    p->explosions.last = last;
    /* Roots retain their original non-pointer words when nodes are removed. */
    p->play.balls.retained = 0x12345678;
    p->powers.queued_cells.retained = 0xabcdef01;
    p->explosions.retained = 0x98765432;
}

static void empty(dxball_program *p) {
#define EMPTY(roots) REQUIRE(!(roots).current && !(roots).first && !(roots).last)
    EMPTY(p->play.shots); EMPTY(p->play.balls); EMPTY(p->bricks); EMPTY(p->play.events);
    EMPTY(p->pickups); EMPTY(p->particles); EMPTY(p->powers.staged_balls); EMPTY(p->powers.queued_cells);
#undef EMPTY
    REQUIRE(!p->play.explosions.current && !p->play.explosions.first && !p->explosions.last);
    REQUIRE(!p->play.brick_effects.current && !p->play.brick_effects.first);
    REQUIRE(p->play.balls.retained == 0x12345678);
    REQUIRE(p->powers.queued_cells.retained == 0xabcdef01);
    REQUIRE(p->explosions.retained == 0x98765432);
}

int main(void) {
    dxball_program *p = malloc(sizeof(*p)), *other = malloc(sizeof(*other));
    REQUIRE(p && other);
    dxball_program_initialize(p, NULL); dxball_program_initialize(other, NULL);
    damage_routing(p);
    populate(p); populate(other);
    dxball_program_refresh_views(p);
    REQUIRE((void *)p->play.brick_effects.current == p->bricks.current);
    REQUIRE((void *)p->play.brick_effects.first == p->bricks.first);
    /* Real application call: progression -> round cleanup -> the allocation
     * owner. The second program still has its independent, live node graph. */
    progress_clear_objects(NULL, &p->progression);
    empty(p);
    REQUIRE(other->play.balls.first && other->bricks.first && other->play.explosions.first);
    REQUIRE(other->play.balls.first->next == other->play.balls.last);
    progress_clear_objects(NULL, &other->progression);
    empty(other);
    free(p); free(other);
    puts("{\"damage_routes\":14,\"program_owners\":2,\"cleared_nodes\":36,\"shared_brick_roots\":true,\"retained_words\":true}");
    return 0;
}
