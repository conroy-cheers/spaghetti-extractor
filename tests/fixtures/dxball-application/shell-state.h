#ifndef DXBALL_SHELL_STATE_H
#define DXBALL_SHELL_STATE_H
#include "scene-state.h"

enum {
    SHELL_CREATE=1, SHELL_DESTROY=2, SHELL_FOCUS_GAIN=7, SHELL_FOCUS_LOSS=8,
    SHELL_ERASE_BACKGROUND=20, SHELL_ACTIVATE=28, SHELL_SET_CURSOR=32,
    SHELL_POWER=72, SHELL_KEY_DOWN=256, SHELL_KEY_UP=257, SHELL_MOUSE_MOVE=512,
    SHELL_LEFT_DOWN=513, SHELL_LEFT_UP=514, SHELL_RIGHT_DOWN=516, SHELL_RIGHT_UP=517,
    SHELL_POWER_BROADCAST=536, SHELL_QUERY_PALETTE=785
};
typedef struct spx_opaque_shell_handle_v5 shell_handle;
typedef struct spx_opaque_shell_device_v5 shell_device;
typedef struct spx_opaque_shell_palette_v5 shell_palette;
typedef struct spx_opaque_shell_point_v5 { uint32_t x,y; } shell_point;
typedef struct spx_opaque_shell_message_v5 {
    shell_handle *window;
    uint32_t kind,wparam,lparam,time,x,y;
} shell_message;
typedef struct spx_opaque_shell_state_v5 {
    scene_state *scene;
    shell_handle *instance_lock;
    shell_device *graphics;
    shell_palette *palette;
    shell_point cursor;
    uint32_t active,control,shift,suspended;
} shell_state;
#endif
