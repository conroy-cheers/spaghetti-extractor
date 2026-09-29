#include <stdlib.h>
#include "portable-component-implementation.h"
#include "asset-state.h"

static font_sprite *current_sprite(asset_state *state, uint32_t slot) {
    return state->objects->banks[state->objects->current_bank].slots[slot];
}
static uint32_t read_word(spx_sprite_loader_context_v5 *context, asset_state *state) {
    unsigned char data[4]; asset_buffer buffer = {data, 4};
    context->services->read(context->services->context, state, &buffer, 4, 1);
    return (uint32_t)data[0] | (uint32_t)data[1] << 8 | (uint32_t)data[2] << 16 | (uint32_t)data[3] << 24;
}
void lifted_sprite_load(spx_sprite_loader_context_v5 *context, asset_state *state,
                        uint32_t bank, uint32_t mode, asset_name *name) {
    const spx_sprite_loader_services_v5 *services = context->services;
    void *user = services->context;
    uint32_t previous = state->objects->current_bank;
    services->select(user, state->objects, bank);
    /* The native loop deliberately leaves slots 0 and 254 alone. */
    for (uint32_t slot = 1; slot < 254; ++slot) services->dispose(user, state->objects, slot);
    state->file = services->open(user, state, name);
    if (!state->file) exit(1);
    uint32_t count = read_word(context, state);
    for (uint32_t slot = 1; font_signed(slot) < font_signed(count + 1); ++slot) {
        uint32_t width = read_word(context, state), height = read_word(context, state);
        unsigned char character; asset_buffer character_buffer = {&character, 1};
        services->read(user, state, &character_buffer, 1, 1);
        uint32_t baseline = read_word(context, state);
        uint32_t bytes = width * height;
        asset_buffer *pixels = services->allocate_pixels(user, state, bytes + 3);
        if (!pixels) exit(1);
        font_sprite *sprite = services->allocate_sprite(user, state);
        if (!sprite) exit(1);
        state->objects->banks[state->objects->current_bank].slots[slot] = sprite;
        services->read(user, state, pixels, 1, bytes);
        struct cleanup_bank *row = &state->objects->banks[state->objects->current_bank];
        row->count = count; row->retained[0] = mode;
        /* Name bytes are serialized in the existing bank metadata. The reviewed
         * input domain has names shorter than its 20-byte native field. */
        for (uint32_t i = 0;; ++i) {
            uint32_t word = 1 + i / 4, shift = 8 * (i % 4);
            unsigned char value = (unsigned char)name->text[i];
            row->retained[word] = (row->retained[word] & ~(UINT32_C(255) << shift)) | (uint32_t)value << shift;
            if (!value) break;
        }
        sprite = current_sprite(state, slot);
        asset_set_word(sprite, 8, width); asset_set_word(sprite, 12, height);
        sprite->retained[32] = character; asset_set_word(sprite, 40, baseline);
        asset_set_word(sprite, 20, 0); asset_set_word(sprite, 24, 0);
        asset_set_word(sprite, 28, width); asset_set_word(sprite, 32, height);
        uint32_t caps = row->retained[0] == 1 ? 0x40 : 0x840;
        if (services->create(user, state, current_sprite(state, slot), caps))
            return; /* Preserve native partial initialization and leaked inputs. */
        services->color_key(user, state, current_sprite(state, slot)->surface);
        asset_view view;
        while (services->describe(user, state, current_sprite(state, slot)->surface, &view)) {}
        uint32_t pitch = view.pitch;
        asset_set_word(current_sprite(state, slot), 16, pitch);
        while (services->lock(user, state, current_sprite(state, slot)->surface, &view)) {}
        for (uint32_t y = 0; y < height; ++y)
            for (uint32_t x = 0; x < width; ++x)
                view.pixels[(height - 1 - y) * pitch + x] = pixels->data[y * width + x];
        services->unlock(user, state, current_sprite(state, slot)->surface);
        services->free_pixels(user, state, pixels);
    }
    services->close(user, state);
    services->select(user, state->objects, previous);
}
