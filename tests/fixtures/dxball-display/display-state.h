#ifndef DXBALL_DISPLAY_STATE_H
#define DXBALL_DISPLAY_STATE_H
#include "shell-state.h"
#include "damage-state.h"

typedef struct spx_opaque_display_clipper_v5 display_clipper;
typedef struct spx_opaque_display_events_v5 display_events;
typedef struct spx_opaque_display_class_v5 {
    uint32_t style,class_extra,window_extra;
    display_events *events;
    shell_handle *instance,*icon,*cursor,*brush;
    asset_name *menu,*name;
} display_class;
typedef struct spx_opaque_display_caps_v5 {
    uint32_t size,flags,video_memory;
} display_caps;
typedef struct spx_opaque_display_history_v5 {
    uint32_t capability_flags,video_memory;
} display_history;
typedef struct spx_opaque_display_surface_v5 {
    uint32_t size,flags,height,width,backbuffers,caps;
} display_surface;
typedef struct spx_opaque_display_state_v5 {
    shell_state *application;
    damage_state *damage;
    shell_handle *window;
    display_clipper *clipper;
    display_events *events;
} display_state;
#endif
