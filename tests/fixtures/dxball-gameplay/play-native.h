/* Shared native transport. Object adapters preserve payloads, links and lifetime. */
#define PLAY_WORDS(X) \
    X(paused,0x431c74) X(last_tick,0x431cac) X(changed,0x42ca58) \
    X(paddle_x,0x42cdec) X(paddle_y,0x42cdf0) X(old_paddle_x,0x431c60) X(old_paddle_y,0x431c68) \
    X(remaining_bricks,0x431c48) X(warning_sound,0x42cdd4) X(voice_pending,0x431cc4) \
    X(slow_balls,0x42ca20) X(speedup_balls,0x431c4c) X(fire_balls,0x42cdcc) \
    X(split_balls,0x431c80) X(power_balls,0x431cb4) X(launch_pressed,0x431c88) \
    X(gun,0x431c6c) X(shot_count,0x42cde8)
static uint32_t *play_word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
static void play_to_native(void) {
    play_parent_to_native();
#define PUT(name,address) *play_word(address)=play.name;
    PLAY_WORDS(PUT)
#undef PUT
#define LIST(name,address,singular) do { uint32_t *p=play_word(address); \
    p[0]=singular##_address(play.name.current); p[1]=singular##_address(play.name.first); \
    p[2]=singular##_address(play.name.last); p[3]=play.name.retained; } while (0)
    LIST(balls,0x431c20,ball); LIST(shots,0x42cdd8,shot); LIST(events,0x431c38,event);
#undef LIST
    *play_word(0x42cbf8)=effect_address(play.brick_effects.current); *play_word(0x42cbfc)=effect_address(play.brick_effects.first);
    *play_word(0x42cdb8)=effect_address(play.explosions.current); *play_word(0x42cdbc)=effect_address(play.explosions.first);
    memcpy((void *)0x42cc10,play.pending_cells,400);
    memcpy((void *)0x4351a8,play.sine,361*4); memcpy((void *)0x435750,play.cosine,361*4);
    play_objects_to_native();
}
static void play_from_native(void) {
    play_parent_from_native();
    play_objects_from_native();
#define GET(name,address) play.name=*play_word(address);
    PLAY_WORDS(GET)
#undef GET
#define LIST(name,address,singular) do { const uint32_t *p=play_word(address); \
    play.name.current=singular##_view(p[0]); play.name.first=singular##_view(p[1]); \
    play.name.last=singular##_view(p[2]); play.name.retained=p[3]; } while (0)
    LIST(balls,0x431c20,ball); LIST(shots,0x42cdd8,shot); LIST(events,0x431c38,event);
#undef LIST
    play.brick_effects.current=effect_view(*play_word(0x42cbf8)); play.brick_effects.first=effect_view(*play_word(0x42cbfc));
    play.explosions.current=effect_view(*play_word(0x42cdb8)); play.explosions.first=effect_view(*play_word(0x42cdbc));
    memcpy(play.pending_cells,(void *)0x42cc10,400);
    memcpy(sine,(void *)0x4351a8,361*4); memcpy(cosine,(void *)0x435750,361*4);
}
