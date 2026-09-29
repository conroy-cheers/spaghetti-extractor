/* Included by spx-wine-draw.c only. SDK signatures define the native ABI. */
_Static_assert(sizeof(DDSURFACEDESC)==108,"legacy PE32 surface descriptor");
_Static_assert(sizeof(DDBLTFX)==100,"legacy PE32 blit effects");
_Static_assert(sizeof(RECT)==16,"PE32 rectangle");
typedef HRESULT (WINAPI *draw_factory)(GUID *,LPDIRECTDRAW *,IUnknown *);
typedef struct { spx_fixture_import_hook factory; } draw_hooks;
static spx_wine_env *draw_installed;
static spx_wine_surface_desc from_sdk(const DDSURFACEDESC *d) {
    require(d && d->dwSize==108,"SDK legacy surface descriptor");
    spx_wine_surface_desc result;memcpy(result.words,d,108);result.pixels=d->lpSurface;result.words[9]=0;return result;
}
static DDSURFACEDESC to_sdk(const spx_wine_surface_desc *d) {
    require(d && d->words[0]==108 && !d->words[9],"portable surface descriptor");
    DDSURFACEDESC result;memcpy(&result,d->words,108);result.lpSurface=d->pixels;return result;
}
static void update_sdk(DDSURFACEDESC *out,const spx_wine_surface_desc *d) { *out=to_sdk(d); }
static spx_wine_object *draw_object(void *self) { require(self!=NULL,"null DirectDraw interface");return self; }
static HRESULT WINAPI draw_create(GUID *guid,LPDIRECTDRAW *out,IUnknown *outer) {
    require(draw_installed && !outer,"DirectDraw factory environment or aggregation");
    spx_wine_call c={0};c.api=SPX_DD_CREATE;c.input=guid;c.output=out;
    return (HRESULT)spx_wine_invoke(draw_installed,c);
}
static HRESULT draw_query(spx_wine_object *o,REFIID iid,void **out) {
    spx_wine_call c={0};c.api=SPX_COM_QUERY;c.receiver=o;c.input=iid;c.output=out;
    return (HRESULT)spx_wine_invoke(o->owner,c);
}
static HRESULT WINAPI draw_query_device(IDirectDraw *self,REFIID iid,void **out) { return draw_query(draw_object(self),iid,out); }
static HRESULT WINAPI draw_query_surface(IDirectDrawSurface *self,REFIID iid,void **out) { return draw_query(draw_object(self),iid,out); }
static ULONG WINAPI draw_addref_device(IDirectDraw *self) { spx_wine_object *o=draw_object(self);return spx_wine_method(o->owner,SPX_COM_ADDREF,o,0); }
static ULONG WINAPI draw_release_device(IDirectDraw *self) { spx_wine_object *o=draw_object(self);return spx_wine_method(o->owner,SPX_COM_RELEASE,o,0); }
static ULONG WINAPI draw_addref_surface(IDirectDrawSurface *self) { spx_wine_object *o=draw_object(self);return spx_wine_method(o->owner,SPX_COM_ADDREF,o,0); }
static ULONG WINAPI draw_release_surface(IDirectDrawSurface *self) { spx_wine_object *o=draw_object(self);return spx_wine_method(o->owner,SPX_COM_RELEASE,o,0); }
static HRESULT WINAPI draw_cooperative(IDirectDraw *self,HWND window,DWORD flags) {
    spx_wine_object *o=draw_object(self);spx_wine_call c={0};c.api=SPX_DD_COOPERATIVE;c.receiver=o;
    c.window=(uintptr_t)window;c.arguments[0]=flags;c.argument_count=1;return (HRESULT)spx_wine_invoke(o->owner,c);
}
static HRESULT WINAPI draw_create_surface(IDirectDraw *self,DDSURFACEDESC *desc,IDirectDrawSurface **out,IUnknown *outer) {
    require(!outer,"DirectDraw surface aggregation");spx_wine_object *o=draw_object(self);
    spx_wine_surface_desc view=from_sdk(desc);spx_wine_call c={0};c.api=SPX_DD_CREATE_SURFACE;c.receiver=o;c.input=&view;c.output=out;
    return (HRESULT)spx_wine_invoke(o->owner,c);
}
static HRESULT WINAPI draw_describe(IDirectDrawSurface *self,DDSURFACEDESC *out) {
    spx_wine_object *o=draw_object(self);spx_wine_surface_desc view=from_sdk(out);
    spx_wine_call c={0};c.api=SPX_DD_DESCRIBE;c.receiver=o;c.output=&view;
    uint32_t result=spx_wine_invoke(o->owner,c);update_sdk(out,&view);return (HRESULT)result;
}
static HRESULT WINAPI draw_lock(IDirectDrawSurface *self,RECT *rect,DDSURFACEDESC *out,DWORD flags,HANDLE event) {
    spx_wine_object *o=draw_object(self);spx_wine_surface_desc view=from_sdk(out);spx_wine_rect r;
    if(rect)memcpy(&r,rect,16);
    spx_wine_call c={0};c.api=SPX_DD_LOCK;c.receiver=o;c.output=&view;c.input=rect ? &r : NULL;
    c.arguments[0]=flags;c.argument_count=1;c.handle=(uintptr_t)event;
    uint32_t result=spx_wine_invoke(o->owner,c);update_sdk(out,&view);return (HRESULT)result;
}
static HRESULT WINAPI draw_unlock(IDirectDrawSurface *self,void *pixels) {
    spx_wine_object *o=draw_object(self);spx_wine_call c={0};c.api=SPX_DD_UNLOCK;c.receiver=o;c.buffer=pixels;
    return (HRESULT)spx_wine_invoke(o->owner,c);
}
static HRESULT WINAPI draw_blt(IDirectDrawSurface *self,RECT *destination,IDirectDrawSurface *source,RECT *source_rect,DWORD flags,DDBLTFX *effects) {
    require(effects && (flags&0x400),"DirectDraw fill effects");
    spx_wine_rect d,s;if(destination)memcpy(&d,destination,16);if(source_rect)memcpy(&s,source_rect,16);
    spx_wine_blt b={destination ? &d : NULL,(void *)source,source_rect ? &s : NULL,flags,effects->dwSize,effects->dwFillColor};
    spx_wine_object *o=draw_object(self);spx_wine_call c={0};c.api=SPX_DD_BLT;c.receiver=o;c.input=&b;
    return (HRESULT)spx_wine_invoke(o->owner,c);
}
/* Every remaining SDK slot below reports its capability gap explicitly. */
static HRESULT WINAPI draw_unsupported_device_Compact(IDirectDraw *self) { (void)self;spx_wine_unavailable("IDirectDraw.Compact");return 0; }
static HRESULT WINAPI draw_unsupported_device_CreateClipper(IDirectDraw *self, DWORD dwFlags, LPDIRECTDRAWCLIPPER *lplpDDClipper, IUnknown *pUnkOuter) { (void)self;(void)dwFlags;(void)lplpDDClipper;(void)pUnkOuter;spx_wine_unavailable("IDirectDraw.CreateClipper");return 0; }
static HRESULT WINAPI draw_unsupported_device_CreatePalette(IDirectDraw *self, DWORD dwFlags, LPPALETTEENTRY lpColorTable, LPDIRECTDRAWPALETTE *lplpDDPalette, IUnknown *pUnkOuter) { (void)self;(void)dwFlags;(void)lpColorTable;(void)lplpDDPalette;(void)pUnkOuter;spx_wine_unavailable("IDirectDraw.CreatePalette");return 0; }
static HRESULT WINAPI draw_unsupported_device_DuplicateSurface(IDirectDraw *self, LPDIRECTDRAWSURFACE lpDDSurface, LPDIRECTDRAWSURFACE *lplpDupDDSurface) { (void)self;(void)lpDDSurface;(void)lplpDupDDSurface;spx_wine_unavailable("IDirectDraw.DuplicateSurface");return 0; }
static HRESULT WINAPI draw_unsupported_device_EnumDisplayModes(IDirectDraw *self, DWORD dwFlags, LPDDSURFACEDESC lpDDSurfaceDesc, LPVOID lpContext, LPDDENUMMODESCALLBACK lpEnumModesCallback) { (void)self;(void)dwFlags;(void)lpDDSurfaceDesc;(void)lpContext;(void)lpEnumModesCallback;spx_wine_unavailable("IDirectDraw.EnumDisplayModes");return 0; }
static HRESULT WINAPI draw_unsupported_device_EnumSurfaces(IDirectDraw *self, DWORD dwFlags, LPDDSURFACEDESC lpDDSD, LPVOID lpContext, LPDDENUMSURFACESCALLBACK lpEnumSurfacesCallback) { (void)self;(void)dwFlags;(void)lpDDSD;(void)lpContext;(void)lpEnumSurfacesCallback;spx_wine_unavailable("IDirectDraw.EnumSurfaces");return 0; }
static HRESULT WINAPI draw_unsupported_device_FlipToGDISurface(IDirectDraw *self) { (void)self;spx_wine_unavailable("IDirectDraw.FlipToGDISurface");return 0; }
static HRESULT WINAPI draw_unsupported_device_GetCaps(IDirectDraw *self, LPDDCAPS lpDDDriverCaps, LPDDCAPS lpDDHELCaps) { (void)self;(void)lpDDDriverCaps;(void)lpDDHELCaps;spx_wine_unavailable("IDirectDraw.GetCaps");return 0; }
static HRESULT WINAPI draw_unsupported_device_GetDisplayMode(IDirectDraw *self, LPDDSURFACEDESC lpDDSurfaceDesc) { (void)self;(void)lpDDSurfaceDesc;spx_wine_unavailable("IDirectDraw.GetDisplayMode");return 0; }
static HRESULT WINAPI draw_unsupported_device_GetFourCCCodes(IDirectDraw *self, LPDWORD lpNumCodes, LPDWORD lpCodes) { (void)self;(void)lpNumCodes;(void)lpCodes;spx_wine_unavailable("IDirectDraw.GetFourCCCodes");return 0; }
static HRESULT WINAPI draw_unsupported_device_GetGDISurface(IDirectDraw *self, LPDIRECTDRAWSURFACE *lplpGDIDDSurface) { (void)self;(void)lplpGDIDDSurface;spx_wine_unavailable("IDirectDraw.GetGDISurface");return 0; }
static HRESULT WINAPI draw_unsupported_device_GetMonitorFrequency(IDirectDraw *self, LPDWORD lpdwFrequency) { (void)self;(void)lpdwFrequency;spx_wine_unavailable("IDirectDraw.GetMonitorFrequency");return 0; }
static HRESULT WINAPI draw_unsupported_device_GetScanLine(IDirectDraw *self, LPDWORD lpdwScanLine) { (void)self;(void)lpdwScanLine;spx_wine_unavailable("IDirectDraw.GetScanLine");return 0; }
static HRESULT WINAPI draw_unsupported_device_GetVerticalBlankStatus(IDirectDraw *self, WINBOOL *lpbIsInVB) { (void)self;(void)lpbIsInVB;spx_wine_unavailable("IDirectDraw.GetVerticalBlankStatus");return 0; }
static HRESULT WINAPI draw_unsupported_device_Initialize(IDirectDraw *self, GUID *lpGUID) { (void)self;(void)lpGUID;spx_wine_unavailable("IDirectDraw.Initialize");return 0; }
static HRESULT WINAPI draw_unsupported_device_RestoreDisplayMode(IDirectDraw *self) { (void)self;spx_wine_unavailable("IDirectDraw.RestoreDisplayMode");return 0; }
static HRESULT WINAPI draw_unsupported_device_SetDisplayMode(IDirectDraw *self, DWORD dwWidth, DWORD dwHeight, DWORD dwBPP) { (void)self;(void)dwWidth;(void)dwHeight;(void)dwBPP;spx_wine_unavailable("IDirectDraw.SetDisplayMode");return 0; }
static HRESULT WINAPI draw_unsupported_device_WaitForVerticalBlank(IDirectDraw *self, DWORD dwFlags, HANDLE hEvent) { (void)self;(void)dwFlags;(void)hEvent;spx_wine_unavailable("IDirectDraw.WaitForVerticalBlank");return 0; }
static const IDirectDrawVtbl draw_device_vtable={
    .QueryInterface=draw_query_device,
    .AddRef=draw_addref_device,
    .Release=draw_release_device,
    .Compact=draw_unsupported_device_Compact,
    .CreateClipper=draw_unsupported_device_CreateClipper,
    .CreatePalette=draw_unsupported_device_CreatePalette,
    .CreateSurface=draw_create_surface,
    .DuplicateSurface=draw_unsupported_device_DuplicateSurface,
    .EnumDisplayModes=draw_unsupported_device_EnumDisplayModes,
    .EnumSurfaces=draw_unsupported_device_EnumSurfaces,
    .FlipToGDISurface=draw_unsupported_device_FlipToGDISurface,
    .GetCaps=draw_unsupported_device_GetCaps,
    .GetDisplayMode=draw_unsupported_device_GetDisplayMode,
    .GetFourCCCodes=draw_unsupported_device_GetFourCCCodes,
    .GetGDISurface=draw_unsupported_device_GetGDISurface,
    .GetMonitorFrequency=draw_unsupported_device_GetMonitorFrequency,
    .GetScanLine=draw_unsupported_device_GetScanLine,
    .GetVerticalBlankStatus=draw_unsupported_device_GetVerticalBlankStatus,
    .Initialize=draw_unsupported_device_Initialize,
    .RestoreDisplayMode=draw_unsupported_device_RestoreDisplayMode,
    .SetCooperativeLevel=draw_cooperative,
    .SetDisplayMode=draw_unsupported_device_SetDisplayMode,
    .WaitForVerticalBlank=draw_unsupported_device_WaitForVerticalBlank
};
static HRESULT WINAPI draw_unsupported_surface_AddAttachedSurface(IDirectDrawSurface *self, LPDIRECTDRAWSURFACE lpDDSAttachedSurface) { (void)self;(void)lpDDSAttachedSurface;spx_wine_unavailable("IDirectDrawSurface.AddAttachedSurface");return 0; }
static HRESULT WINAPI draw_unsupported_surface_AddOverlayDirtyRect(IDirectDrawSurface *self, LPRECT lpRect) { (void)self;(void)lpRect;spx_wine_unavailable("IDirectDrawSurface.AddOverlayDirtyRect");return 0; }
static HRESULT WINAPI draw_unsupported_surface_BltBatch(IDirectDrawSurface *self, LPDDBLTBATCH lpDDBltBatch, DWORD dwCount, DWORD dwFlags) { (void)self;(void)lpDDBltBatch;(void)dwCount;(void)dwFlags;spx_wine_unavailable("IDirectDrawSurface.BltBatch");return 0; }
static HRESULT WINAPI draw_unsupported_surface_BltFast(IDirectDrawSurface *self, DWORD dwX, DWORD dwY, LPDIRECTDRAWSURFACE lpDDSrcSurface, LPRECT lpSrcRect, DWORD dwTrans) { (void)self;(void)dwX;(void)dwY;(void)lpDDSrcSurface;(void)lpSrcRect;(void)dwTrans;spx_wine_unavailable("IDirectDrawSurface.BltFast");return 0; }
static HRESULT WINAPI draw_unsupported_surface_DeleteAttachedSurface(IDirectDrawSurface *self, DWORD dwFlags, LPDIRECTDRAWSURFACE lpDDSAttachedSurface) { (void)self;(void)dwFlags;(void)lpDDSAttachedSurface;spx_wine_unavailable("IDirectDrawSurface.DeleteAttachedSurface");return 0; }
static HRESULT WINAPI draw_unsupported_surface_EnumAttachedSurfaces(IDirectDrawSurface *self, LPVOID lpContext, LPDDENUMSURFACESCALLBACK lpEnumSurfacesCallback) { (void)self;(void)lpContext;(void)lpEnumSurfacesCallback;spx_wine_unavailable("IDirectDrawSurface.EnumAttachedSurfaces");return 0; }
static HRESULT WINAPI draw_unsupported_surface_EnumOverlayZOrders(IDirectDrawSurface *self, DWORD dwFlags, LPVOID lpContext, LPDDENUMSURFACESCALLBACK lpfnCallback) { (void)self;(void)dwFlags;(void)lpContext;(void)lpfnCallback;spx_wine_unavailable("IDirectDrawSurface.EnumOverlayZOrders");return 0; }
static HRESULT WINAPI draw_unsupported_surface_Flip(IDirectDrawSurface *self, LPDIRECTDRAWSURFACE lpDDSurfaceTargetOverride, DWORD dwFlags) { (void)self;(void)lpDDSurfaceTargetOverride;(void)dwFlags;spx_wine_unavailable("IDirectDrawSurface.Flip");return 0; }
static HRESULT WINAPI draw_unsupported_surface_GetAttachedSurface(IDirectDrawSurface *self, LPDDSCAPS lpDDSCaps, LPDIRECTDRAWSURFACE *lplpDDAttachedSurface) { (void)self;(void)lpDDSCaps;(void)lplpDDAttachedSurface;spx_wine_unavailable("IDirectDrawSurface.GetAttachedSurface");return 0; }
static HRESULT WINAPI draw_unsupported_surface_GetBltStatus(IDirectDrawSurface *self, DWORD dwFlags) { (void)self;(void)dwFlags;spx_wine_unavailable("IDirectDrawSurface.GetBltStatus");return 0; }
static HRESULT WINAPI draw_unsupported_surface_GetCaps(IDirectDrawSurface *self, LPDDSCAPS lpDDSCaps) { (void)self;(void)lpDDSCaps;spx_wine_unavailable("IDirectDrawSurface.GetCaps");return 0; }
static HRESULT WINAPI draw_unsupported_surface_GetClipper(IDirectDrawSurface *self, LPDIRECTDRAWCLIPPER *lplpDDClipper) { (void)self;(void)lplpDDClipper;spx_wine_unavailable("IDirectDrawSurface.GetClipper");return 0; }
static HRESULT WINAPI draw_unsupported_surface_GetColorKey(IDirectDrawSurface *self, DWORD dwFlags, LPDDCOLORKEY lpDDColorKey) { (void)self;(void)dwFlags;(void)lpDDColorKey;spx_wine_unavailable("IDirectDrawSurface.GetColorKey");return 0; }
static HRESULT WINAPI draw_unsupported_surface_GetDC(IDirectDrawSurface *self, HDC *lphDC) { (void)self;(void)lphDC;spx_wine_unavailable("IDirectDrawSurface.GetDC");return 0; }
static HRESULT WINAPI draw_unsupported_surface_GetFlipStatus(IDirectDrawSurface *self, DWORD dwFlags) { (void)self;(void)dwFlags;spx_wine_unavailable("IDirectDrawSurface.GetFlipStatus");return 0; }
static HRESULT WINAPI draw_unsupported_surface_GetOverlayPosition(IDirectDrawSurface *self, LPLONG lplX, LPLONG lplY) { (void)self;(void)lplX;(void)lplY;spx_wine_unavailable("IDirectDrawSurface.GetOverlayPosition");return 0; }
static HRESULT WINAPI draw_unsupported_surface_GetPalette(IDirectDrawSurface *self, LPDIRECTDRAWPALETTE *lplpDDPalette) { (void)self;(void)lplpDDPalette;spx_wine_unavailable("IDirectDrawSurface.GetPalette");return 0; }
static HRESULT WINAPI draw_unsupported_surface_GetPixelFormat(IDirectDrawSurface *self, LPDDPIXELFORMAT lpDDPixelFormat) { (void)self;(void)lpDDPixelFormat;spx_wine_unavailable("IDirectDrawSurface.GetPixelFormat");return 0; }
static HRESULT WINAPI draw_unsupported_surface_Initialize(IDirectDrawSurface *self, LPDIRECTDRAW lpDD, LPDDSURFACEDESC lpDDSurfaceDesc) { (void)self;(void)lpDD;(void)lpDDSurfaceDesc;spx_wine_unavailable("IDirectDrawSurface.Initialize");return 0; }
static HRESULT WINAPI draw_unsupported_surface_IsLost(IDirectDrawSurface *self) { (void)self;spx_wine_unavailable("IDirectDrawSurface.IsLost");return 0; }
static HRESULT WINAPI draw_unsupported_surface_ReleaseDC(IDirectDrawSurface *self, HDC hDC) { (void)self;(void)hDC;spx_wine_unavailable("IDirectDrawSurface.ReleaseDC");return 0; }
static HRESULT WINAPI draw_unsupported_surface_Restore(IDirectDrawSurface *self) { (void)self;spx_wine_unavailable("IDirectDrawSurface.Restore");return 0; }
static HRESULT WINAPI draw_unsupported_surface_SetClipper(IDirectDrawSurface *self, LPDIRECTDRAWCLIPPER lpDDClipper) { (void)self;(void)lpDDClipper;spx_wine_unavailable("IDirectDrawSurface.SetClipper");return 0; }
static HRESULT WINAPI draw_unsupported_surface_SetColorKey(IDirectDrawSurface *self, DWORD dwFlags, LPDDCOLORKEY lpDDColorKey) { (void)self;(void)dwFlags;(void)lpDDColorKey;spx_wine_unavailable("IDirectDrawSurface.SetColorKey");return 0; }
static HRESULT WINAPI draw_unsupported_surface_SetOverlayPosition(IDirectDrawSurface *self, LONG lX, LONG lY) { (void)self;(void)lX;(void)lY;spx_wine_unavailable("IDirectDrawSurface.SetOverlayPosition");return 0; }
static HRESULT WINAPI draw_unsupported_surface_SetPalette(IDirectDrawSurface *self, LPDIRECTDRAWPALETTE lpDDPalette) { (void)self;(void)lpDDPalette;spx_wine_unavailable("IDirectDrawSurface.SetPalette");return 0; }
static HRESULT WINAPI draw_unsupported_surface_UpdateOverlay(IDirectDrawSurface *self, LPRECT lpSrcRect, LPDIRECTDRAWSURFACE lpDDDestSurface, LPRECT lpDestRect, DWORD dwFlags, LPDDOVERLAYFX lpDDOverlayFx) { (void)self;(void)lpSrcRect;(void)lpDDDestSurface;(void)lpDestRect;(void)dwFlags;(void)lpDDOverlayFx;spx_wine_unavailable("IDirectDrawSurface.UpdateOverlay");return 0; }
static HRESULT WINAPI draw_unsupported_surface_UpdateOverlayDisplay(IDirectDrawSurface *self, DWORD dwFlags) { (void)self;(void)dwFlags;spx_wine_unavailable("IDirectDrawSurface.UpdateOverlayDisplay");return 0; }
static HRESULT WINAPI draw_unsupported_surface_UpdateOverlayZOrder(IDirectDrawSurface *self, DWORD dwFlags, LPDIRECTDRAWSURFACE lpDDSReference) { (void)self;(void)dwFlags;(void)lpDDSReference;spx_wine_unavailable("IDirectDrawSurface.UpdateOverlayZOrder");return 0; }
static const IDirectDrawSurfaceVtbl draw_surface_vtable={
    .QueryInterface=draw_query_surface,
    .AddRef=draw_addref_surface,
    .Release=draw_release_surface,
    .AddAttachedSurface=draw_unsupported_surface_AddAttachedSurface,
    .AddOverlayDirtyRect=draw_unsupported_surface_AddOverlayDirtyRect,
    .Blt=draw_blt,
    .BltBatch=draw_unsupported_surface_BltBatch,
    .BltFast=draw_unsupported_surface_BltFast,
    .DeleteAttachedSurface=draw_unsupported_surface_DeleteAttachedSurface,
    .EnumAttachedSurfaces=draw_unsupported_surface_EnumAttachedSurfaces,
    .EnumOverlayZOrders=draw_unsupported_surface_EnumOverlayZOrders,
    .Flip=draw_unsupported_surface_Flip,
    .GetAttachedSurface=draw_unsupported_surface_GetAttachedSurface,
    .GetBltStatus=draw_unsupported_surface_GetBltStatus,
    .GetCaps=draw_unsupported_surface_GetCaps,
    .GetClipper=draw_unsupported_surface_GetClipper,
    .GetColorKey=draw_unsupported_surface_GetColorKey,
    .GetDC=draw_unsupported_surface_GetDC,
    .GetFlipStatus=draw_unsupported_surface_GetFlipStatus,
    .GetOverlayPosition=draw_unsupported_surface_GetOverlayPosition,
    .GetPalette=draw_unsupported_surface_GetPalette,
    .GetPixelFormat=draw_unsupported_surface_GetPixelFormat,
    .GetSurfaceDesc=draw_describe,
    .Initialize=draw_unsupported_surface_Initialize,
    .IsLost=draw_unsupported_surface_IsLost,
    .Lock=draw_lock,
    .ReleaseDC=draw_unsupported_surface_ReleaseDC,
    .Restore=draw_unsupported_surface_Restore,
    .SetClipper=draw_unsupported_surface_SetClipper,
    .SetColorKey=draw_unsupported_surface_SetColorKey,
    .SetOverlayPosition=draw_unsupported_surface_SetOverlayPosition,
    .SetPalette=draw_unsupported_surface_SetPalette,
    .Unlock=draw_unlock,
    .UpdateOverlay=draw_unsupported_surface_UpdateOverlay,
    .UpdateOverlayDisplay=draw_unsupported_surface_UpdateOverlayDisplay,
    .UpdateOverlayZOrder=draw_unsupported_surface_UpdateOverlayZOrder
};
void spx_wine_draw_object(spx_wine_object *o) {
    o->vtable=o->kind==SPX_WINE_DD_DEVICE ? (const void *)&draw_device_vtable : (const void *)&draw_surface_vtable;
}

static draw_factory actual_factory(void) {
    static draw_factory actual;
    if(!actual) { HMODULE m=LoadLibraryA("ddraw.dll");require(m!=NULL,"load Wine ddraw.dll");
        actual=(draw_factory)(uintptr_t)GetProcAddress(m,"DirectDrawCreate");require(actual!=NULL,"resolve DirectDrawCreate"); }
    return actual;
}
int spx_wine_install_draw(spx_wine_env *e,const char *module) {
    if(draw_installed || e->draw)return 0;
    draw_hooks *h=calloc(1,sizeof(*h));if(!h)return 0;
    if(!spx_fixture_redirect_import(&h->factory,module,"ddraw.dll","DirectDrawCreate",(void (*)(void))draw_create)) { free(h);return 0; }
    e->draw=h;draw_installed=e;return 1;
}
int spx_wine_uninstall_draw(spx_wine_env *e) {
    draw_hooks *h=e->draw;if(!h)return 1;
    if(draw_installed!=e || !spx_fixture_restore_import(&h->factory))return 0;
    free(h);e->draw=NULL;draw_installed=NULL;return 1;
}
static uint32_t method_call(void *object,spx_wine_call *c) {
    IDirectDraw *device=object;IDirectDrawSurface *surf=object;
    if(c->api==SPX_DD_COOPERATIVE)return (uint32_t)IDirectDraw_SetCooperativeLevel(device,(HWND)c->window,c->arguments[0]);
    if(c->api==SPX_DD_CREATE_SURFACE) {
        DDSURFACEDESC d=to_sdk(c->input);return (uint32_t)IDirectDraw_CreateSurface(device,&d,c->output,NULL);
    }
    if(c->api==SPX_DD_DESCRIBE || c->api==SPX_DD_LOCK) {
        DDSURFACEDESC d=to_sdk(c->output);RECT rect;uint32_t result;
        if(c->input)memcpy(&rect,c->input,16);
        if(c->api==SPX_DD_DESCRIBE)result=(uint32_t)IDirectDrawSurface_GetSurfaceDesc(surf,&d);
        else result=(uint32_t)IDirectDrawSurface_Lock(surf,c->input ? &rect : NULL,&d,c->arguments[0],(HANDLE)c->handle);
        *(spx_wine_surface_desc *)c->output=from_sdk(&d);return result;
    }
    if(c->api==SPX_DD_UNLOCK)return (uint32_t)IDirectDrawSurface_Unlock(surf,c->buffer);
    if(c->api==SPX_DD_BLT) {
        const spx_wine_blt *b=c->input;RECT d,s;DDBLTFX effects={0};
        require(b!=NULL,"portable blit input");if(b->destination)memcpy(&d,b->destination,16);if(b->source_rect)memcpy(&s,b->source_rect,16);
        effects.dwSize=b->effects_size;effects.dwFillColor=b->fill_color;
        return (uint32_t)IDirectDrawSurface_Blt(surf,b->destination ? &d : NULL,(void *)b->source,b->source_rect ? &s : NULL,b->flags,&effects);
    }
    spx_wine_unavailable("DirectDraw binding operation");return 0;
}
uint32_t spx_wine_draw_candidate_call(spx_wine_env *e,spx_wine_call c) {
    if(c.api==SPX_DD_CREATE) {
        require(draw_installed==e,"DirectDraw candidate factory binding");return (uint32_t)draw_create((GUID *)c.input,c.output,NULL);
    }
    require(c.receiver && c.receiver->owner==e,"DirectDraw candidate receiver");return method_call(c.receiver,&c);
}
static uint32_t native(spx_wine_env *e,spx_wine_call *c,spx_wine_event *v) {
    if(c->api==SPX_DD_CREATE || c->api==SPX_DD_CREATE_SURFACE) {
        void *before=spx_wine_initial_output(e,c->output),*made=before;uint32_t result;
        if(c->api==SPX_DD_CREATE)result=(uint32_t)actual_factory()((GUID *)c->input,(IDirectDraw **)&made,NULL);
        else { spx_wine_call with_output=*c;with_output.output=&made;result=method_call(c->receiver->native,&with_output); }
        spx_wine_publish_output(e,c,v,before,made,result,c->api==SPX_DD_CREATE ? SPX_WINE_DD_DEVICE : SPX_WINE_DD_SURFACE);
        return result;
    }
    return method_call(c->receiver->native,c);
}
