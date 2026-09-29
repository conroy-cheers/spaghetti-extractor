#include "program-state.h"
#include "audio-runtime.h"
#include "setup-runtime.h"
#include "wave-runtime.h"
#include "music-runtime.h"
#include "shell-runtime.h"
#include "display-runtime.h"
#include "scene-runtime.h"
#include "flow-runtime.h"
#include "play-runtime.h"
#include "motion-runtime.h"
#include "brick-runtime.h"
#include "pickup-runtime.h"
#include "shot-runtime.h"
#include "power-runtime.h"
#include "progress-runtime.h"
#include "round-runtime.h"
#include "warning-runtime.h"
#include "runtime.h"

/* History operands are explicit environment inputs. Their zero-initialized
 * constructor values do not claim to reproduce failed native status writes or
 * a malformed WAV's missing format pointer. Complete backends must bind those
 * inputs when exercising such cases. */
#define OWNER(member) (void)u; dxball_program *p = DXBALL_OWNER(s, member); dxball_program_refresh_views(p)
#define DONE() dxball_program_refresh_views(p)
#define SOUND(prefix, type, member) \
void prefix##_stop_sound(void *u, type *s, uint32_t slot) { OWNER(member); \
    fixture_audio_stop(&p->audio, &p->audio_history, slot); DONE(); } \
void prefix##_play_sound(void *u, type *s, uint32_t slot, uint32_t frequency, uint32_t pan, uint32_t volume) { OWNER(member); \
    fixture_audio_play(&p->audio, &p->audio_history, slot, frequency, pan, volume); DONE(); }
SOUND(play, play_state, play)
SOUND(motion, motion_state, motion)
SOUND(brick, brick_state, bricks)
SOUND(pickup, pickup_state, pickups)
SOUND(shot, motion_state, motion)
SOUND(power, powerup_state, powers)
SOUND(progress, progression_state, progression)
SOUND(warning, warning_state, warning)
#undef SOUND
void scene_stop_sound(void *u, scene_state *s, uint32_t slot) {
    OWNER(scene); fixture_audio_stop(&p->audio, &p->audio_history, slot); DONE();
}
/* Title's 4032b0 is looping playback; the other play calls above use 403210. */
void scene_play_sound(void *u, scene_state *s, uint32_t slot, uint32_t frequency, uint32_t pan, uint32_t volume) {
    OWNER(scene); fixture_audio_loop(&p->audio, &p->audio_history, slot, frequency, pan, volume); DONE();
}
void warning_loop_sound(void *u, warning_state *s, uint32_t slot, uint32_t frequency, uint32_t pan, uint32_t volume) {
    OWNER(warning); fixture_audio_loop(&p->audio, &p->audio_history, slot, frequency, pan, volume); DONE();
}
#define RELEASE(name, type, member) \
void name(void *u, type *s) { OWNER(member); fixture_audio_release_all(&p->audio, &p->audio_history); DONE(); }
RELEASE(scene_release_sounds, scene_state, scene)
RELEASE(round_release_sounds, round_state, round)
RELEASE(setup_release_all, audio_setup_state, audio_setup)
#undef RELEASE
void scene_load_sound(void *u, scene_state *s, uint32_t slot, asset_name *name) {
    OWNER(scene); audio_name path = {name->text};
    fixture_wave_load(&p->audio, &p->wave_history, slot, &path); DONE();
}
void audio_load_sample(void *u, audio_state *s, uint32_t slot, audio_name *name) {
    OWNER(audio); fixture_wave_load(s, &p->wave_history, slot, name); DONE();
}
void setup_load_sample(void *u, audio_setup_state *s, uint32_t slot, audio_name *name) {
    OWNER(audio_setup); fixture_wave_load(&p->audio, &p->wave_history, slot, name); DONE();
}
void wave_release_one(void *u, audio_state *s, uint32_t slot) {
    OWNER(audio); fixture_audio_release_one(s, &p->audio_history, slot); DONE();
}
void display_initialize_sound(void *u, display_state *s, shell_handle *window) {
    OWNER(display); fixture_setup_initialize(&p->audio_setup, window); DONE();
}
void shell_focus_sounds(void *u, shell_state *s, shell_handle *window) {
    OWNER(application); fixture_setup_focus(&p->audio_setup, window); DONE();
}
void shell_stop_sounds(void *u, shell_state *s) {
    OWNER(application); fixture_audio_shutdown(&p->audio, &p->audio_history); DONE();
}
void shell_suspend_sounds(void *u, shell_state *s) {
    OWNER(application); fixture_audio_suspend(&p->audio, &p->audio_history); DONE();
}
void shell_clear_sprites(void *u, shell_state *s) {
    OWNER(application); fixture_clear(&p->objects); DONE();
}
void shell_stop_music(void *u, shell_state *s) {
    OWNER(application); fixture_music_stop(&p->music); DONE();
}
void shell_resume_music(void *u, shell_state *s) {
    OWNER(application); fixture_music_resume(&p->music); DONE();
}
void shell_pause_music(void *u, shell_state *s) {
    OWNER(application); fixture_music_pause(&p->music); DONE();
}
void setup_release_buffer(void *u, audio_setup_state *s, audio_buffer *buffer) {
    OWNER(audio_setup); audio_release_buffer(NULL, &p->audio, buffer); DONE();
}
void setup_release_device(void *u, audio_setup_state *s, audio_device *device) {
    OWNER(audio_setup); audio_release_device(NULL, &p->audio, device); DONE();
}
uint32_t setup_play_primary(void *u, audio_setup_state *s, audio_buffer *buffer, uint32_t flags) {
    OWNER(audio_setup); uint32_t result = audio_play(NULL, &p->audio, buffer, flags); DONE(); return result;
}
void flow_audio_restore(void *u, flow_state *s, flow_audio *audio) {
    OWNER(flow); (void)audio_restore_buffer(NULL, &p->audio, (void *)audio); DONE();
}
