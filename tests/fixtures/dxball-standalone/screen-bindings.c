#include "program-state.h"
#include "screen-runtime.h"
#include "font-runtime.h"
#include "damage-runtime.h"

#define SCREEN_PUSH() ((void)0)
#define SCREEN_PULL() ((void)0)
#include "screen-common.h"

uint32_t screen_measure(void *u, font_state *s, uint32_t length, font_bytes *bytes) {
    (void)u; return fixture_font_measure(s, length, bytes);
}
void screen_load_scores(void *u, scores_state *s) { (void)u; fixture_scores_load(s); }
uint32_t screen_insert_score(void *u, scores_state *s, scores_name *name, uint32_t score) {
    (void)u; return fixture_scores_insert(s, name, score);
}
