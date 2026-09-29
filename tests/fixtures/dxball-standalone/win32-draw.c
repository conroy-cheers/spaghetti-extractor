/* Application views mapped to ordinary SDK interfaces. The platform owns COM
 * objects; aliases in component state retain the same interface pointer. */
#include <stdlib.h>
#include <string.h>
#include "win32-platform.h"
#include "display-runtime.h"
#include "bootstrap-runtime.h"
#include "asset-runtime.h"
#include "lifecycle-runtime.h"
#include "drawing-runtime.h"
#include "damage-runtime.h"
#include "flow-runtime.h"
#include "palette-runtime.h"
#include "pcx-runtime.h"
#include "raster-runtime.h"
#include "particle-runtime.h"
#include "title-runtime.h"

static RECT rectangle(const font_rect *r) {
    return (RECT){(LONG)r->left, (LONG)r->top, (LONG)r->right, (LONG)r->bottom};
}
static font_rect sprite_rectangle(const font_sprite *s) {
    return (font_rect){font_word(s, 20), font_word(s, 24), font_word(s, 28), font_word(s, 32)};
}
static uint32_t blit(font_surface *destination, font_rect *dr, font_surface *source, font_rect *sr, uint32_t flags) {
    RECT d, r;
    if (dr) d = rectangle(dr);
    if (sr) r = rectangle(sr);
    return (uint32_t)IDirectDrawSurface_Blt(SURFACE(destination), dr ? &d : NULL,
        SURFACE(source), sr ? &r : NULL, flags, NULL);
}
static uint32_t blit_fast(font_surface *destination, uint32_t x, uint32_t y,
                         font_surface *source, font_rect *sr, uint32_t flags) {
    RECT r = rectangle(sr);
    return (uint32_t)IDirectDrawSurface_BltFast(SURFACE(destination), x, y, SURFACE(source), &r, flags);
}
static uint32_t fill(font_surface *surface, font_rect *r, uint32_t size, uint32_t flags, uint32_t color) {
    RECT bounds = rectangle(r);
    DDBLTFX effects = {.dwSize=size, .dwFillColor=color};
    return (uint32_t)IDirectDrawSurface_Blt(SURFACE(surface), &bounds, NULL, NULL, flags, &effects);
}
static DDSURFACEDESC descriptor(const display_surface *d) {
    return (DDSURFACEDESC){.dwSize=d->size, .dwFlags=d->flags, .dwHeight=d->height,
        .dwWidth=d->width, .dwBackBufferCount=d->backbuffers, .ddsCaps={d->caps}};
}
static uint32_t create_surface(shell_device *draw, DDSURFACEDESC *desc, void *output) {
    IDirectDrawSurface *surface;
    /* Preserve failure-side bytes without evaluating an uninitialized pointer. */
    memcpy(&surface, output, sizeof(surface));
    HRESULT result = IDirectDraw_CreateSurface(DRAW(draw), desc, &surface, NULL);
    memcpy(output, &surface, sizeof(surface));
    return (uint32_t)result;
}
uint32_t display_create_draw(void *u, display_state *s) {
    (void)u;
    IDirectDraw *draw = DRAW(s->application->graphics);
    HRESULT result = DirectDrawCreate(NULL, &draw, NULL);
    s->application->graphics = (void *)draw;
    return (uint32_t)result;
}
uint32_t display_cooperative(void *u, display_state *s, shell_device *draw, shell_handle *window, uint32_t flags) {
    (void)u; (void)s; return (uint32_t)IDirectDraw_SetCooperativeLevel(DRAW(draw), (HWND)window, flags);
}
uint32_t display_display_mode(void *u, display_state *s, shell_device *draw, uint32_t width, uint32_t height, uint32_t bits) {
    (void)u; (void)s; return (uint32_t)IDirectDraw_SetDisplayMode(DRAW(draw), width, height, bits);
}
void display_capabilities(void *u, display_state *s, shell_device *draw, display_caps *out) {
    (void)u; (void)s;
    DDCAPS caps = {.dwSize=out->size, .dwCaps=out->flags, .dwVidMemTotal=out->video_memory};
    IDirectDraw_GetCaps(DRAW(draw), &caps, NULL);
    out->flags=caps.dwCaps; out->video_memory=caps.dwVidMemTotal;
}
uint32_t display_create_surface(void *u, display_state *s, shell_device *draw, display_surface *view, uint32_t kind) {
    (void)u;
    DDSURFACEDESC desc = descriptor(view);
    title_state *title = s->application->scene->animation;
    return create_surface(draw, &desc, kind ? &title->back : &title->primary);
}
uint32_t display_attached_surface(void *u, display_state *s, font_surface *surface, uint32_t caps) {
    (void)u;
    DDSCAPS wanted = {caps};
    IDirectDrawSurface *attached = SURFACE(s->application->scene->flip);
    HRESULT result = IDirectDrawSurface_GetAttachedSurface(SURFACE(surface), &wanted, &attached);
    s->application->scene->flip = (void *)attached;
    return (uint32_t)result;
}
uint32_t display_create_clipper(void *u, display_state *s, shell_device *draw) {
    (void)u;
    IDirectDrawClipper *clipper = CLIPPER(s->clipper);
    HRESULT result = IDirectDraw_CreateClipper(DRAW(draw), 0, &clipper, NULL);
    s->clipper = (void *)clipper;
    return (uint32_t)result;
}
uint32_t display_clipper_window(void *u, display_state *s, display_clipper *clipper, shell_handle *window, uint32_t flags) {
    (void)u; (void)s; return (uint32_t)IDirectDrawClipper_SetHWnd(CLIPPER(clipper), flags, (HWND)window);
}
uint32_t display_attach_clipper(void *u, display_state *s, font_surface *surface, display_clipper *clipper) {
    (void)u; (void)s; return (uint32_t)IDirectDrawSurface_SetClipper(SURFACE(surface), CLIPPER(clipper));
}
uint32_t bootstrap_create_overlay(void *u, bootstrap_state *s, shell_device *draw, display_surface *view) {
    (void)u; DDSURFACEDESC desc = descriptor(view);
    return create_surface(draw, &desc, &s->application->scene->animation->flow->overlay);
}
void bootstrap_terminate(void *u, bootstrap_state *s, uint32_t status) { (void)u; (void)s; exit((int)status); }
uint32_t bootstrap_create_palette(void *u, bootstrap_state *s, shell_device *draw, uint32_t flags) {
    (void)u;
    IDirectDrawPalette *palette = PALETTE(s->application->palette);
    HRESULT result = IDirectDraw_CreatePalette(DRAW(draw), flags,
        (PALETTEENTRY *)s->application->scene->animation->palettes->current, &palette, NULL);
    s->application->palette = (void *)palette;
    return (uint32_t)result;
}
void bootstrap_attach_palette(void *u, bootstrap_state *s, font_surface *surface, shell_palette *palette) {
    (void)u; (void)s; IDirectDrawSurface_SetPalette(SURFACE(surface), PALETTE(palette));
}
void bootstrap_vertical_blank(void *u, bootstrap_state *s, shell_device *draw, uint32_t flags) {
    (void)u; (void)s; IDirectDraw_WaitForVerticalBlank(DRAW(draw), flags, NULL);
}
void bootstrap_fill(void *u, bootstrap_state *s, font_surface *surface, font_rect *r, uint32_t size, uint32_t flags, uint32_t color) {
    (void)u; (void)s; (void)fill(surface, r, size, flags, color);
}
void shell_release_surface(void *u, shell_state *s, font_surface *surface) { (void)u; (void)s; IDirectDrawSurface_Release(SURFACE(surface)); }
void shell_release_palette(void *u, shell_state *s, shell_palette *palette) { (void)u; (void)s; IDirectDrawPalette_Release(PALETTE(palette)); }
void shell_palette_entries(void *u, shell_state *s, shell_palette *palette, pcx_state *colors) {
    (void)u; (void)s; IDirectDrawPalette_SetEntries(PALETTE(palette), 0, 0, 256, (PALETTEENTRY *)colors->current);
}
void palette_apply(void *u, palette_state *s, uint32_t first, uint32_t count) {
    (void)u;
    IDirectDrawPalette_SetEntries(PALETTE(DXBALL_OWNER(s, palette)->application.palette), 0, first, count,
                                 (PALETTEENTRY *)s->colors->current[first]);
}
void pcx_apply(void *u, pcx_state *s) {
    dxball_program *p = DXBALL_OWNER(s, colors);
    shell_palette_entries(u, &p->application, p->application.palette, s);
}
uint32_t asset_create(void *u, asset_state *s, font_sprite *sprite, uint32_t caps) {
    (void)u;
    DDSURFACEDESC desc = {.dwSize=108, .dwFlags=0xf, .dwHeight=font_height(sprite),
        .dwWidth=font_width(sprite), .ddsCaps={caps}};
    return create_surface(DXBALL_OWNER(s, assets)->application.graphics, &desc, &sprite->surface);
}
void asset_color_key(void *u, asset_state *s, font_surface *surface) {
    (void)u; (void)s; DDCOLORKEY key = {0, 0}; IDirectDrawSurface_SetColorKey(SURFACE(surface), 8, &key);
}
void scene_color_key(void *u, scene_state *s, font_surface *surface, uint32_t low, uint32_t high) {
    (void)u; (void)s; DDCOLORKEY key = {low, high}; IDirectDrawSurface_SetColorKey(SURFACE(surface), 8, &key);
}
static void view_read(pcx_view *view, const DDSURFACEDESC *desc) {
    view->width=desc->dwWidth; view->height=desc->dwHeight;
    view->image.pitch=(uint32_t)desc->lPitch; view->image.pixels=desc->lpSurface;
}
static uint32_t describe(font_surface *surface, pcx_view *view) {
    DDSURFACEDESC desc = {.dwSize=108, .dwFlags=0x1ff9ee};
    HRESULT result = IDirectDrawSurface_GetSurfaceDesc(SURFACE(surface), &desc);
    view_read(view, &desc); return (uint32_t)result;
}
static uint32_t lock(font_surface *surface, pcx_view *view) {
    DDSURFACEDESC desc = {.dwSize=108};
    HRESULT result = IDirectDrawSurface_Lock(SURFACE(surface), NULL, &desc, 0, NULL);
    view_read(view, &desc); return (uint32_t)result;
}
typedef struct descriptor_lease {
    pcx_view *view;
    font_surface *surface;
    DDSURFACEDESC descriptor;
    warning_frame_history *history;
    struct descriptor_lease *next;
} descriptor_lease;
/* The existing PCX/raster/particle interfaces carry a view through describe,
 * every lock retry, and unlock. Retain the rest of that same SDK descriptor. */
static _Thread_local descriptor_lease *descriptors;
_Static_assert(sizeof(DDSURFACEDESC)==108, "original DirectDraw descriptor ABI");
static void history_read(descriptor_lease *lease) {
    if (lease->history) {
        uint32_t words[27]; memcpy(words, &lease->descriptor, sizeof(words));
        warning_history_from_descriptor(lease->history, words);
    }
}
static uint32_t describe_lease(font_surface *surface, pcx_view *view, warning_frame_history *history) {
    descriptor_lease *lease = calloc(1, sizeof(*lease));
    if (!lease) abort();
    lease->view=view; lease->surface=surface; lease->history=history;
    lease->descriptor.dwSize=108; lease->descriptor.dwFlags=14;
    if (history) {
        uint32_t words[27]; memcpy(words, &lease->descriptor, sizeof(words));
        warning_history_to_descriptor(history, words);
        memcpy(&lease->descriptor, words, sizeof(words));
    }
    lease->next=descriptors; descriptors=lease;
    HRESULT result=IDirectDrawSurface_GetSurfaceDesc(SURFACE(surface), &lease->descriptor);
    history_read(lease); view_read(view, &lease->descriptor);
    return (uint32_t)result;
}
static uint32_t lock_lease(font_surface *surface, pcx_view *view) {
    descriptor_lease *lease=descriptors;
    while (lease && lease->view!=view) lease=lease->next;
    if (!lease || lease->surface!=surface) abort();
    HRESULT result=IDirectDrawSurface_Lock(SURFACE(surface), NULL, &lease->descriptor, 0, NULL);
    history_read(lease); view_read(view, &lease->descriptor);
    return (uint32_t)result;
}
static uint32_t unlock_lease(font_surface *surface) {
    descriptor_lease **link=&descriptors;
    while (*link && (*link)->surface!=surface) link=&(*link)->next;
    if (!*link) abort();
    descriptor_lease *lease=*link;
    HRESULT result=IDirectDrawSurface_Unlock(SURFACE(surface), NULL);
    history_read(lease); *link=lease->next; free(lease);
    return (uint32_t)result;
}
uint32_t asset_describe(void *u, asset_state *s, font_surface *surface, asset_view *view) {
    (void)u; (void)s; pcx_view desc; uint32_t result=describe(surface, &desc); view->pitch=desc.image.pitch; return result;
}
uint32_t asset_lock(void *u, asset_state *s, font_surface *surface, asset_view *view) {
    (void)u; (void)s; pcx_view desc; uint32_t result=lock(surface, &desc); *view=desc.image; return result;
}
void asset_unlock(void *u, asset_state *s, font_surface *surface) { (void)u; (void)s; IDirectDrawSurface_Unlock(SURFACE(surface), NULL); }
void pcx_describe(void *u, font_surface *surface, pcx_view *view) { (void)u; (void)describe_lease(surface, view, NULL); view->image.pixels=NULL; }
uint32_t pcx_lock(void *u, font_surface *surface, pcx_view *view) { (void)u; return lock_lease(surface, view); }
void pcx_unlock(void *u, font_surface *surface) { (void)u; (void)unlock_lease(surface); }
uint32_t raster_describe(void *u, font_surface *surface, pcx_view *view) { (void)u; return describe_lease(surface, view, NULL); }
uint32_t raster_lock(void *u, font_surface *surface, pcx_view *view) { (void)u; return lock_lease(surface, view); }
uint32_t raster_unlock(void *u, font_surface *surface) { (void)u; return unlock_lease(surface); }
uint32_t raster_fill(void *u, font_surface *surface, font_rect *r, uint32_t size, uint32_t flags, uint32_t color) { (void)u; return fill(surface, r, size, flags, color); }
void particle_describe(void *u, particle_state *s, font_surface *surface, pcx_view *view) {
    (void)u; (void)describe_lease(surface, view, &DXBALL_OWNER(s, particles)->frame_history); view->image.pixels=NULL;
}
uint32_t particle_lock(void *u, particle_state *s, font_surface *surface, pcx_view *view) { (void)s; return pcx_lock(u, surface, view); }
void particle_unlock(void *u, particle_state *s, font_surface *surface) { (void)s; pcx_unlock(u, surface); }
uint32_t lifecycle_copy(void *u, asset_state *s, font_state *drawing, font_sprite *sprite, font_rect *source) {
    (void)u; (void)s; font_rect target=sprite_rectangle(sprite); return blit(sprite->surface, &target, drawing->destination, source, 0x01000000);
}
uint32_t lifecycle_restore_surface(void *u, asset_state *s, font_surface *surface) { (void)u; (void)s; return (uint32_t)IDirectDrawSurface_Restore(SURFACE(surface)); }
void lifecycle_reload(void *u, asset_state *s, uint32_t bank) {
    (void)u;
    /* The existing serialized bank name aliases this bank throughout loading. */
    asset_name name = {(const char *)&s->objects->banks[bank].retained[1]};
    fixture_sprite_load(s, bank, 1, &name);
}
void trial_release(void *u, cleanup_state *s, cleanup_surface *surface) { (void)u; (void)s; IDirectDrawSurface_Release(SURFACE(surface)); }
void flow_release(void *u, flow_state *s, font_surface *surface) { (void)u; (void)s; IDirectDrawSurface_Release(SURFACE(surface)); }
uint32_t flow_surface_status(void *u, flow_state *s, font_surface *surface) { (void)u; (void)s; return (uint32_t)IDirectDrawSurface_GetBltStatus(SURFACE(surface), 1); }
uint32_t flow_surface_restore(void *u, flow_state *s, font_surface *surface) { (void)u; (void)s; return (uint32_t)IDirectDrawSurface_Restore(SURFACE(surface)); }
void font_service_blit(void *u, font_state *s, font_rect *destination, font_surface *surface, font_rect *source) {
    (void)u; (void)blit(s->destination, destination, surface, source, 0x01008000);
}
uint32_t drawing_blit_fast(void *u, font_state *s, font_sprite *sprite, uint32_t x, uint32_t y, uint32_t flags) {
    (void)u; font_rect source=sprite_rectangle(sprite); return blit_fast(s->destination, x, y, sprite->surface, &source, flags);
}
void damage_sprite_blit(void *u, damage_state *s, font_surface *destination, font_sprite *sprite, uint32_t x, uint32_t y, uint32_t flags) {
    (void)u; (void)s; font_rect source=sprite_rectangle(sprite); (void)blit_fast(destination, x, y, sprite->surface, &source, flags);
}
#define BLIT_FAST(name, type) \
void name(void *u, type *s, font_surface *destination, uint32_t x, uint32_t y, font_surface *source, font_rect *r, uint32_t flags) { \
    (void)u; (void)s; (void)blit_fast(destination, x, y, source, r, flags); }
BLIT_FAST(damage_blit_fast, damage_state)
BLIT_FAST(title_blit_fast, title_state)
#undef BLIT_FAST
#define BLIT(name, type) \
void name(void *u, type *s, font_surface *destination, font_rect *dr, font_surface *source, font_rect *sr, uint32_t flags) { \
    (void)u; (void)s; (void)blit(destination, dr, source, sr, flags); }
BLIT(damage_blit, damage_state)
BLIT(scene_blit, scene_state)
#undef BLIT
uint32_t damage_flip(void *u, damage_state *s, font_surface *surface) { (void)u; (void)s; return (uint32_t)IDirectDrawSurface_Flip(SURFACE(surface), NULL, 0); }
