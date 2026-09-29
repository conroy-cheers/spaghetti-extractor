#ifndef DXBALL_PLAY_STATE_H
#define DXBALL_PLAY_STATE_H
#include "menu-state.h"

typedef struct spx_opaque_play_ball_v5 play_ball;
struct spx_opaque_play_ball_v5 {
    uint32_t x,y,old_x,old_y,dx,dy,sprite,angle,speed,retained,attached,auxiliary,tick;
    play_ball *next,*previous;
};
typedef struct play_shot play_shot;
struct play_shot { uint32_t x,y,old_x,old_y; play_shot *next,*previous; };
typedef struct spx_opaque_play_event_v5 play_event;
struct spx_opaque_play_event_v5 { uint32_t kind,column,row; play_event *next,*previous; };
typedef struct play_effect play_effect;
typedef struct { play_ball *current,*first,*last; uint32_t retained; } play_balls;
typedef struct { play_shot *current,*first,*last; uint32_t retained; } play_shots;
typedef struct { play_event *current,*first,*last; uint32_t retained; } play_events;
typedef struct { play_effect *current,*first; } play_effects;

typedef struct spx_opaque_play_state_v5 {
    menu_state *menu;
    play_balls balls;
    play_shots shots;
    play_events events;
    play_effects brick_effects,explosions;
    const int32_t *sine,*cosine;
    unsigned char pending_cells[400];
    uint32_t paused,last_tick,changed,paddle_x,paddle_y,old_paddle_x,old_paddle_y;
    uint32_t remaining_bricks,warning_sound,voice_pending,slow_balls,speedup_balls;
    uint32_t fire_balls,split_balls,power_balls,launch_pressed,gun,shot_count;
} play_state;

static inline int64_t play_signed(uint32_t value) {
    return value<0x80000000 ? (int64_t)value : (int64_t)value-INT64_C(0x100000000);
}
#endif
