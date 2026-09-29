#include "portable-component-implementation.h"
#include "damage-state.h"
#include <string.h>

static void remember(damage_state *state, uint32_t page, font_rect rectangle) {
    if (state->count[page] < 1000)
        state->history[state->count[page]++][page] = rectangle;
}
static void pending(damage_state *state, font_rect rectangle) {
    if (state->scene->animation->fast == 1 && state->pending_count < 2000)
        state->pending[state->pending_count++] = rectangle;
}
static int mirror(const damage_state *state) {
    return !state->scene->presentation_mode && font_signed(state->capability) > 0
        && !state->scene->animation->fast;
}
static int clip(font_rect *rectangle) {
    if (font_signed(rectangle->top) > 480 || font_signed(rectangle->bottom) < 0
        || font_signed(rectangle->left) > 640 || font_signed(rectangle->right) < 0) return 0;
    if (font_signed(rectangle->top) < 0) rectangle->top = 0;
    if (font_signed(rectangle->bottom) > 480) rectangle->bottom = 480;
    if (font_signed(rectangle->left) < 0) rectangle->left = 0;
    if (font_signed(rectangle->right) > 640) rectangle->right = 640;
    return 1;
}

void lifted_damage_reset(spx_damage_tracking_context_v5 *context, damage_state *state) {
    (void)context;
    memset(state->history, 0, sizeof(state->history));
    memset(state->pending, 0, sizeof(state->pending));
    state->count[0] = state->count[1] = state->pending_count = state->page = 0;
}
static void sprite(spx_damage_tracking_context_v5 *context, damage_state *state,
                   uint32_t slot, uint32_t x, uint32_t y, uint32_t flags) {
    title_state *title = state->scene->animation;
    struct spx_opaque_cleanup_state_v5 *objects = title->font->objects;
    font_sprite *object = objects->banks[objects->current_bank].slots[slot];
    font_rect rectangle = {x, y, x + font_width(object), y + font_height(object)};
    context->services->sprite_blit(context->services->context, state,
        title->software, object, x, y, flags);
    remember(state, state->page, rectangle);
    pending(state, rectangle);
}
void lifted_damage_transparent(spx_damage_tracking_context_v5 *context, damage_state *state,
                               uint32_t slot, uint32_t x, uint32_t y) {
    sprite(context, state, slot, x, y, 0x11);
}
void lifted_damage_opaque(spx_damage_tracking_context_v5 *context, damage_state *state,
                          uint32_t slot, uint32_t x, uint32_t y) {
    sprite(context, state, slot, x, y, 0x10);
}
void lifted_damage_mark(spx_damage_tracking_context_v5 *context, damage_state *state, font_rect *input) {
    (void)context; font_rect rectangle = *input;
    remember(state, state->page, rectangle);
    pending(state, rectangle);
}
void lifted_damage_erase(spx_damage_tracking_context_v5 *context, damage_state *state, font_rect *input) {
    font_rect rectangle = *input;
    context->services->blit(context->services->context, state,
        state->scene->animation->software, &rectangle, state->background, &rectangle, 0x01000000);
    if (mirror(state)) remember(state, 1 - state->page, rectangle);
    pending(state, rectangle);
}
void lifted_damage_damage(spx_damage_tracking_context_v5 *context, damage_state *state, font_rect *input) {
    (void)context; font_rect rectangle = *input;
    remember(state, state->page, rectangle);
    if (mirror(state)) remember(state, 1 - state->page, rectangle);
    pending(state, rectangle);
}
void lifted_damage_restore(spx_damage_tracking_context_v5 *context, damage_state *state) {
    const spx_damage_tracking_services_v5 *services = context->services;
    title_state *title = state->scene->animation;
    int clipped = state->clipped == 1;
    for (uint32_t i = 0; i < state->count[state->page]; ++i) {
        font_rect *rectangle = &state->history[i][state->page];
        if (clipped) {
            if (!clip(rectangle)) continue;
            services->blit(services->context, state, title->software, rectangle,
                state->background, rectangle, 0x01000000);
        } else {
            services->blit_fast(services->context, state, title->software,
                rectangle->left, rectangle->top, state->background, rectangle, 0x10);
        }
        /* A callback can select another page, modify this rectangle or append
         * work. The machine rereads the shared page and count after the call. */
        pending(state, state->history[i][state->page]);
    }
    state->count[state->page] = 0;
}
void lifted_damage_background(spx_damage_tracking_context_v5 *context, damage_state *state, font_surface *surface) {
    (void)context; state->background = surface;
}
void lifted_damage_destination(spx_damage_tracking_context_v5 *context, damage_state *state, font_surface *surface) {
    (void)context; state->scene->animation->software = surface;
}

static uint32_t absolute_word(uint32_t value) { return font_signed(value) < 0 ? 0 - value : value; }
uint32_t lifted_damage_overlap(spx_damage_tracking_context_v5 *context, damage_state *state,
                               font_rect *a, font_rect *b) {
    (void)context; (void)state;
    uint32_t aw = a->right - a->left, ah = a->bottom - a->top;
    uint32_t bw = b->right - b->left, bh = b->bottom - b->top;
    uint32_t dx = absolute_word(a->left - font_half(bw) - b->left + font_half(aw));
    uint32_t dy = absolute_word(a->top - font_half(bh) - b->top + font_half(ah));
    /* Preserve the executable's signed, wrapping center/extent calculation,
     * including odd or inverted extents. It is not ordinary AABB intersection. */
    return (font_signed(dx) <= font_signed(font_half(bw + aw))
            && font_signed(dy) <= font_signed(font_half(bh + ah)))
        || (font_signed(dx) < font_signed(font_half(aw))
            && font_signed(dy) < font_signed(font_half(ah)));
}
void lifted_damage_sort(spx_damage_tracking_context_v5 *context, damage_state *state,
                        uint32_t first, uint32_t last) {
    (void)context;
    for (uint32_t i = first; font_signed(i) < font_signed(last); ++i) {
        uint32_t least = i;
        for (uint32_t j = i; j <= last; ++j)
            if (font_signed(state->keys[j]) < font_signed(state->keys[least])) least = j;
        if (least != i) {
            uint32_t key = state->keys[i]; state->keys[i] = state->keys[least]; state->keys[least] = key;
            font_rect rectangle = state->pending[i];
            state->pending[i] = state->pending[least]; state->pending[least] = rectangle;
        }
    }
}
void lifted_damage_flush(spx_damage_tracking_context_v5 *context, damage_state *state) {
    for (uint32_t i = 0; i < state->pending_count; ++i)
        state->keys[i] = state->pending[i].left + state->pending[i].top;
    if (state->pending_count) lifted_damage_sort(context, state, 0, state->pending_count - 1);
    uint32_t anchor = 0;
    for (uint32_t i = 1; i < state->pending_count; ++i) {
        font_rect expanded = state->pending[anchor]; ++expanded.right; ++expanded.bottom;
        font_rect *a = &state->pending[anchor], *b = &state->pending[i];
        if (lifted_damage_overlap(context, state, &expanded, b)) {
            if (font_signed(b->left) < font_signed(a->left)) a->left = b->left;
            if (font_signed(b->top) < font_signed(a->top)) a->top = b->top;
            if (font_signed(b->right) > font_signed(a->right)) a->right = b->right;
            if (font_signed(b->bottom) > font_signed(a->bottom)) a->bottom = b->bottom;
            b->top = 9999;
        } else anchor = i;
    }
    int clipped = state->clipped == 1;
    for (uint32_t i = 0; i < state->pending_count; ++i) {
        font_rect *rectangle = &state->pending[i];
        if (rectangle->top == 9999 || (clipped && !clip(rectangle))) continue;
        context->services->blit(context->services->context, state,
            state->scene->animation->primary, rectangle, state->scene->flip, rectangle, 0x01000000);
    }
    state->pending_count = 0;
}
void lifted_damage_present(spx_damage_tracking_context_v5 *context, damage_state *state) {
    const spx_damage_tracking_services_v5 *services = context->services;
    void *user = services->context;
    if (state->scene->animation->fast) {
        services->wait(user, state, 1);
        lifted_damage_flush(context, state);
        return;
    }
    if (!state->last_tick) state->last_tick = services->now(user, state) + 16;
    if (!services->elapsed(user, state, state->last_tick, 10)) services->wait(user, state, 1);
    state->last_tick = services->now(user, state);
    uint32_t result;
    do {
        result = services->flip(user, state, state->scene->animation->primary);
        if (result == UINT32_C(0x887601c2)) services->recover(user, state);
    } while (result == UINT32_C(0x8876021c));
    if (result) return;
    state->page = 1 - state->page;
    if (!state->scene->refresh_ok) services->wait(user, state, 1);
}
