#include "portable-component-implementation.h"
#include "pcx-state.h"

static unsigned char read_byte(spx_pcx_image_context_v5 *context, pcx_file *file) {
    --file->available;
    if (font_signed(file->available) >= 0) return *file->cursor++;
    return (unsigned char)context->services->refill(context->services->context, file);
}

static int32_t signed_short(const unsigned char *bytes) {
    uint32_t value = bytes[0] | (uint32_t)bytes[1] << 8;
    return value < 32768 ? (int32_t)value : (int32_t)value - 65536;
}

static void read_palette(spx_pcx_image_context_v5 *context, asset_name *name,
                         unsigned char entries[256][4]) {
    const spx_pcx_image_services_v5 *services = context->services;
    void *user = services->context;
    pcx_file *file = services->open(user, name);
    services->seek(user, file, UINT32_C(0xfffffd00), 2);
    for (unsigned i = 0; i < 256; ++i)
        for (unsigned channel = 0; channel < 3; ++channel)
            entries[i][channel] = read_byte(context, file);
    services->close(user, file);
}

void lifted_pcx_palette_current(spx_pcx_image_context_v5 *context, pcx_state *state, asset_name *name) {
    read_palette(context, name, state->current);
    context->services->apply(context->services->context, state);
}

void lifted_pcx_palette_staged(spx_pcx_image_context_v5 *context, pcx_state *state, asset_name *name) {
    read_palette(context, name, state->staged);
}

void lifted_pcx_draw(spx_pcx_image_context_v5 *context, pcx_state *state,
        font_surface *surface, asset_name *name, uint32_t palette, uint32_t x, uint32_t y) {
    const spx_pcx_image_services_v5 *services = context->services;
    void *user = services->context;
    pcx_view view;
    services->describe(user, surface, &view);
    uint32_t width = view.width, height = view.height, pitch = view.image.pitch;
    pcx_file *file = services->open(user, name);
    unsigned char header[128];
    for (unsigned i = 0; i < sizeof(header); ++i) header[i] = read_byte(context, file);
    int32_t end_x = signed_short(header+8), end_y = signed_short(header+10);
    while (services->lock(user, surface, &view)) {}
    int32_t limit = end_x * end_y;
    uint32_t decoded = 0, column = 0, start_x = x;
    while (font_signed(decoded) <= limit) {
        unsigned char value = read_byte(context, file);
        uint32_t run = 1;
        if (value >= 0xc0) {
            run = value - 0xc0;
            value = read_byte(context, file);
        }
        decoded += run;
        for (uint32_t i = 0; i < run; ++i) {
            if (font_signed(column) > end_x) { column = 0; x = start_x; ++y; }
            if (font_signed(x) < font_signed(width) && font_signed(y) < font_signed(height) &&
                    font_signed(x) >= 0 && font_signed(y) >= 0)
                view.image.pixels[y * pitch + x] = value;
            ++x; ++column;
        }
    }
    services->unlock(user, surface);
    services->close(user, file);
    if (palette == 1) lifted_pcx_palette_current(context, state, name);
    if (palette == 2) lifted_pcx_palette_staged(context, state, name);
}
