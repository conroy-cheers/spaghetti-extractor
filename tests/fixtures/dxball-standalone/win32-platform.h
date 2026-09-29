#ifndef DXBALL_WIN32_PLATFORM_H
#define DXBALL_WIN32_PLATFORM_H
#define COBJMACROS
#include <windows.h>
#include <ddraw.h>
#include <dsound.h>
#include <mmsystem.h>
#include "program-state.h"

/* This first desktop backend implements the original Win32 message ABI. The
 * component sources and owned state remain usable by other platform adapters. */
_Static_assert(sizeof(void *) == 4, "Win32 message transport requires PE32");
struct spx_opaque_display_events_v5 { WNDPROC procedure; };
typedef struct { struct spx_opaque_display_events_v5 events; } dxball_win32;
void dxball_win32_initialize(dxball_program *, dxball_win32 *);
#define DRAW(pointer) ((IDirectDraw *)(void *)(pointer))
#define SURFACE(pointer) ((IDirectDrawSurface *)(void *)(pointer))
#define PALETTE(pointer) ((IDirectDrawPalette *)(void *)(pointer))
#define CLIPPER(pointer) ((IDirectDrawClipper *)(void *)(pointer))
#define SOUND(pointer) ((IDirectSound *)(void *)(pointer))
#define BUFFER(pointer) ((IDirectSoundBuffer *)(void *)(pointer))
#endif
