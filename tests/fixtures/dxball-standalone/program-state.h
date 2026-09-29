#ifndef DXBALL_PROGRAM_STATE_H
#define DXBALL_PROGRAM_STATE_H

#include <stddef.h>
#include "runtime-state.h"
#include "math-state.h"
#include "palette-state.h"
#include "round-state.h"
#include "screen-state.h"
#include "regions-state.h"
#include "render-state.h"
#include "warning-state.h"
#include "setup-state.h"
#include "music-state.h"
#include "wave-state.h"
#include "game-scene/game-state.h"
#include "warning-history.h"

/* One owner for the existing component views. Resource handles and dynamic
 * nodes keep their own backend/allocation lifetimes. Construct in final storage;
 * copying this aggregate would copy pointers into the old owner. */
typedef struct dxball_program {
    struct spx_opaque_cleanup_state_v5 objects;
    font_state font;
    asset_state assets;
    pcx_state colors;
    flow_state flow;
    title_state title;
    scene_state scene;
    shell_state application;
    display_state display;
    display_history graphics_history;
    bootstrap_state bootstrap;
    runtime_state runtime;
    runtime_sample clock_history;
    uint32_t version_history;
    math_tables math;
    int32_t math_storage[851];
    palette_state palette;
    menu_state menu;
    scores_state scores;
    score_screen screen;
    board_set boards;
    board_editor editor;
    board_renderer renderer;
    region_table regions;
    damage_state damage;
    play_state play;
    motion_state motion;
    brick_state bricks;
    pickup_state pickups;
    paddle_state paddle;
    particle_state particles;
    explosion_state explosions;
    powerup_state powers;
    progression_state progression;
    round_state round;
    warning_state warning;
    warning_frame_history frame_history;
    game_scene_state game;
    audio_state audio;
    audio_history audio_history;
    wave_history wave_history;
    audio_setup_state audio_setup;
    music_state music;
    struct dxball_program_file *files;
    struct dxball_program_bytes *file_bytes;
    void *platform;
} dxball_program;

#define DXBALL_OWNER(pointer, member) \
    ((dxball_program *)((unsigned char *)(pointer) - offsetof(dxball_program, member)))

/* Call once, before resources or callbacks exist. Seed data is extracted from
 * the pinned image at export time; the runtime never loads that image. */
void dxball_program_initialize(dxball_program *program, void *platform);

/* These two boundary views name the same original surface roots. A display
 * initializer publishes through title; flow callers then borrow those roots. */
void dxball_program_display_published(dxball_program *program);
/* Shell is the sole writer of modifier flags. Read views must be current on
 * entry to a scene and after every synchronous platform event callback. */
void dxball_program_refresh_views(dxball_program *program);
uint32_t dxball_program_event(dxball_program *, shell_handle *, uint32_t, uint32_t, uint32_t);
void dxball_program_menu_key(dxball_program *, uint32_t);
void dxball_program_title_key(dxball_program *, uint32_t);
void dxball_program_clear_objects(dxball_program *);
void dxball_program_dispose_files(dxball_program *program);

#endif
