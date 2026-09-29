#include <string.h>
#include "portable-component-implementation.h"
#include "scene-state.h"
#include "scene-text.h"

static void text(spx_title_scene_context_v5 *context, scene_state *state, uint32_t x, uint32_t y,
                 const unsigned char *data, uint32_t length, int centered) {
    font_bytes bytes = {data};
    if (centered) context->services->center(context->services->context, state, x, y, length, &bytes);
    else context->services->text(context->services->context, state, x, y, length, &bytes);
}

void lifted_scene_enter(spx_title_scene_context_v5 *context, scene_state *state) {
    const spx_title_scene_services_v5 *services = context->services;
    void *user = services->context; title_state *title = state->animation;
    services->reset_damage(user, state);
    services->clear(user, state, title->flow->overlay, 0);
    asset_name image = {"intro.pcx"}, candy = {"candy.sbk"}, chisel = {"chisel2.sbk"}, sound = {"whine.wav"};
    services->image(user, state, title->flow->overlay, &image, 2, 0, 0);
    services->load_bank(user, state, 0, 0, &candy);
    services->load_bank(user, state, 1, 0, &chisel);
    services->select_bank(user, state, 0); services->select_font(user, state, 1);
    services->load_sound(user, state, 0, &sound);
    services->damage_background(user, state, title->back);
    services->damage_destination(user, state, state->presentation_mode ? title->primary : state->flip);
    state->scroll_auxiliary = 0; title->index = 0;
    title->length = (uint32_t)strlen((const char *)title->message);
    title->advance = title->glyph_width = title->first_offset = title->second_offset = title->wobble_phase = 0;
    services->color_key(user, state, title->back, 0, 0);
    services->redraw_scene(user, state);
    services->play_sound(user, state, 0, 0, 0, 0);
    for (uint32_t i = 48; i <= title->palette_width + 48; ++i)
        for (unsigned channel = 0; channel < 3; ++channel) title->palettes->staged[i][channel] = 0;
    services->fade(user, state, 1, 6, 0, 255, 1);
}

void lifted_scene_redraw(spx_title_scene_context_v5 *context, scene_state *state) {
    const spx_title_scene_services_v5 *services = context->services;
    void *user = services->context; title_state *title = state->animation;
    font_rect full = {0, 0, 640, 480}, banner = {0, 19, 639, 169};
    services->clear(user, state, title->primary, 0);
    if (!state->presentation_mode) services->fill(user, state, state->flip, 0, 0, 639, 479, 0);
    services->clear(user, state, title->back, 0);
    services->blit(user, state, title->back, &full, title->flow->overlay, &full, 0x01000000);
    services->blit(user, state, title->primary, &banner, title->back, &banner, 0x01000000);
    if (!state->presentation_mode) {
        services->damage_destination(user, state, title->primary);
        services->wobble(user, state);
        services->damage_destination(user, state, state->flip);
    }
    for (uint32_t y = 155; font_signed(y) <= font_signed(title->palette_width * 2 + 155); y += 2) {
        uint32_t color = (y - 155) / 2 + 48;
        services->line(user, state, title->primary, 0, y, 639, y, color);
        services->line(user, state, title->primary, 0, y + 1, 639, y + 1, color);
    }
    services->sprite_destination(user, state, title->primary); services->select_font(user, state, 0);
#define TEXT(x, y, name, centered) text(context, state, x, y, scene_text_##name, sizeof(scene_text_##name), centered)
    TEXT(20, 190, video_card, 0);
    if (state->no_hardware) TEXT(180, 190, no_hardware, 0);
    else if (state->low_memory) TEXT(180, 190, low_memory, 0);
    else if (!state->refresh_ok) TEXT(180, 190, high_refresh, 0);
    else { TEXT(180, 190, hardware, 0); TEXT(210, 210, supported, 0); goto credits; }
    TEXT(210, 210, compatible, 0);
credits:
    TEXT(20, 245, author, 0); TEXT(180, 245, author_name, 0);
    TEXT(20, 265, graphics, 0); TEXT(180, 265, graphics_name, 0);
    TEXT(20, 300, email, 0); TEXT(180, 300, email_address, 0);
    TEXT(320, 330, website, 1); TEXT(320, 350, website_info, 1);
#undef TEXT
    if (!state->presentation_mode) services->blit(user, state, state->flip, &full, title->primary, &full, 0x01000000);
}

void lifted_scene_update(spx_title_scene_context_v5 *context, scene_state *state) {
    const spx_title_scene_services_v5 *services = context->services;
    void *user = services->context;
    services->play_sound(user, state, 0, 0, 0, 0);
    if (state->presentation_mode) services->wait(user, state, 1);
    services->restore_damage(user, state);
    state->cursor_x = state->mouse_x; state->cursor_y = state->mouse_y;
    if (font_signed(state->cursor_x) > 599) state->cursor_x = 599;
    if (font_signed(state->cursor_x) < 8) state->cursor_x = 8;
    if (font_signed(state->cursor_y) > 447) state->cursor_y = 447;
    services->scroll(user, state); services->wave(user, state);
    if (!state->presentation_mode) services->present(user, state);
    services->rotate_palette(user, state, 189, 66);
    services->cycle(user, state);
    if (state->mouse_buttons == 1) {
        state->animation->flow->transition_pending = 1;
        state->animation->flow->next_scene = 0;
        state->mouse_buttons = 0;
    } else if (state->mouse_buttons == 2) state->mouse_buttons = 0;
}

void lifted_scene_key(spx_title_scene_context_v5 *context, scene_state *state, uint32_t key) {
    (void)context; (void)key;
    state->animation->flow->transition_pending = 1;
    state->animation->flow->next_scene = 0;
}

void lifted_scene_leave(spx_title_scene_context_v5 *context, scene_state *state, uint32_t reason) {
    const spx_title_scene_services_v5 *services = context->services;
    void *user = services->context; title_state *title = state->animation;
    font_rect full = {0, 0, 640, 480};
    services->stop_sound(user, state, 0);
    if (!reason) return;
    services->fade(user, state, 1, 6, 0, 255, 0);
    services->clear(user, state, title->back, 0); services->clear(user, state, title->primary, 0);
    if (!state->presentation_mode) services->blit(user, state, state->flip, &full, title->back, &full, 0x01000000);
    services->release_banks(user, state); services->release_sounds(user, state); services->release_track(user, state);
}
