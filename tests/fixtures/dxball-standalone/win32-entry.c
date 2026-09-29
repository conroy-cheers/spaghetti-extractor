#include <stdio.h>
#include <stdlib.h>
#include "win32-platform.h"
#include "file-storage.h"
#include "shell-runtime.h"

static dxball_program program;
static dxball_win32 platform;
extern void dxball_program_observe_entries(FILE *);

static void report(void) {
    const char *path = getenv("DXBALL_PROGRAM_REPORT");
    if (!path) return;
    FILE *output = fopen(path, "wb");
    if (!output) return;
    fprintf(output, "{\"scene\":%u,\"next_scene\":%u,\"first_frame\":%u,\"active\":%u,\"remaining_bricks\":%u,\"entries\":",
        (unsigned)program.flow.scene, (unsigned)program.flow.next_scene, (unsigned)program.flow.first_frame,
        (unsigned)program.application.active, (unsigned)program.play.remaining_bricks);
    dxball_program_observe_entries(output);
    fprintf(output, ",\"paused\":%u,\"score\":%u,\"ball\":", (unsigned)program.play.paused, (unsigned)program.menu.score);
    play_ball *ball=program.play.balls.first;
    if (ball) fprintf(output, "{\"x\":%u,\"y\":%u,\"dx\":%u,\"dy\":%u,\"attached\":%u,\"speed\":%u}",
        (unsigned)ball->x, (unsigned)ball->y, (unsigned)ball->dx, (unsigned)ball->dy, (unsigned)ball->attached, (unsigned)ball->speed);
    else fputs("null", output);
    fputs("}\n", output); fclose(output);
}
int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR command, int show) {
    (void)previous; (void)command;
    dxball_win32_initialize(&program, &platform);
    atexit(report);
    uint32_t result = fixture_shell_run(&program.application, (void *)instance, (uint32_t)show);
    dxball_program_dispose_files(&program);
    dxball_program_dispose_bytes(&program);
    return (int)result;
}
