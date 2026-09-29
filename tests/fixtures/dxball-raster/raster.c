#include "portable-component-implementation.h"
#include "pcx-state.h"

void lifted_raster_line(spx_raster_drawing_context_v5 *context, font_surface *surface,
        uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2, uint32_t color) {
    const spx_raster_drawing_services_v5 *services = context->services;
    void *user = services->context;
    pcx_view view;
    services->describe(user, surface, &view);
    while (services->lock(user, surface, &view)) {}
    uint32_t offset = y1 * view.image.pitch + x1;
    uint32_t dx = x2 - x1, dy = y2 - y1, x_step = 1, y_step = view.image.pitch;
    if (font_signed(dx) < 0) { dx = 0u - dx; x_step = UINT32_MAX; }
    if (font_signed(dy) < 0) { dy = 0u - dy; y_step = 0u - y_step; }
    uint32_t error = 0;
    if (font_signed(dx) > font_signed(dy)) {
        if (font_signed(dx) >= 0) for (uint32_t remaining = dx + 1; remaining; --remaining) {
            error += dy;
            view.image.pixels[font_signed(offset)] = (unsigned char)color;
            if (font_signed(error) > font_signed(dx)) { error -= dx; offset += y_step; }
            offset += x_step;
        }
    } else if (font_signed(dy) >= 0) for (uint32_t remaining = dy + 1; remaining; --remaining) {
        error += dx;
        view.image.pixels[font_signed(offset)] = (unsigned char)color;
        if (font_signed(error) > 0) { error -= dy; offset += x_step; }
        offset += y_step;
    }
    services->unlock(user, surface);
}

void lifted_raster_fill(spx_raster_drawing_context_v5 *context, font_surface *surface,
        uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2, uint32_t color) {
    font_rect rectangle = {x1, y1, x2, y2};
    context->services->fill(context->services->context, surface, &rectangle, 100, 0x400, color);
}
