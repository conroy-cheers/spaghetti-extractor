#include "program-state.h"
#include "program-seed.h"

void dxball_program_initialize(dxball_program *p, void *platform) {
    *p = (dxball_program){0};
    p->platform = platform;
    p->font.objects = p->assets.objects = &p->objects;
    p->flow.sprites = &p->assets;
    p->title.font = &p->font;
    p->title.palettes = &p->colors;
    p->title.flow = &p->flow;
    p->title.message = dxball_title_message;
    p->math = (math_tables){p->math_storage, p->math_storage + 362};
    p->title.sine = p->play.sine = p->math.sine;
    p->menu.cosine = p->play.cosine = p->math.cosine;
    p->scene.animation = &p->title;
    p->application.scene = &p->scene;
    p->display.application = &p->application;
    p->display.damage = &p->damage;
    p->bootstrap.application = &p->application;
    p->runtime.bootstrap = &p->bootstrap;
    p->palette = (palette_state){&p->colors, &p->flow};
    p->menu.scene = &p->scene;
    p->screen.menu = &p->menu;
    p->screen.scores = &p->scores;
    p->editor.menu = &p->menu;
    p->editor.boards = &p->boards;
    p->renderer = (board_renderer){&p->menu, &p->boards};
    p->regions = (region_table){&p->editor.region_count, p->editor.regions, 25};
    p->damage.scene = &p->scene;
    p->play.menu = &p->menu;
    p->motion.play = &p->play;
    p->motion.board = &p->boards.current;
    p->bricks.motion = &p->motion;
    p->pickups.motion = &p->motion;
    p->paddle.pickups = &p->pickups;
    p->particles.destination = &p->title.software;
    p->explosions.roots = &p->play.explosions;
    p->powers.motion = &p->motion;
    p->progression.paddle = &p->paddle;
    p->progression.bricks = &p->bricks;
    p->round = (round_state){&p->progression, &p->powers, &p->particles, &p->explosions};
    p->warning.progression = &p->progression;
    p->game.progression = &p->progression;
    p->game.damage = &p->damage;
    p->audio_setup = (audio_setup_state){&p->audio, &p->application};
    dxball_seed_state(p);
    dxball_program_refresh_views(p);
}

void dxball_program_display_published(dxball_program *p) {
    p->flow.primary = p->title.primary;
    p->flow.back = p->title.back;
}

void dxball_program_refresh_views(dxball_program *p) {
    p->menu.input_ready = p->application.control;
    p->screen.shift = p->application.shift;
    /* Brick payloads are owned by brick_state; the frame only copies/tests
     * their opaque identities. Both original views named these same roots. */
    p->play.brick_effects.current = (void *)p->bricks.current;
    p->play.brick_effects.first = (void *)p->bricks.first;
    /* Flow only tests the original device cell for nonzero; the bank owns
     * the actual device and primary-buffer identities. */
    p->flow.audio_enabled = p->audio.device != NULL;
    p->flow.audio = (void *)p->audio.primary;
    dxball_program_display_published(p);
}
