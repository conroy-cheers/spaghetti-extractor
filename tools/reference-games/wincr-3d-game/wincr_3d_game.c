#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdint.h>

#define GAME_VERSION 1
#define FIXED_SCALE 1024
#define SCREEN_W 320
#define SCREEN_H 200
#define MAX_FRAMES 7200
#define TARGET_COUNT 4

#define INPUT_LEFT 1
#define INPUT_RIGHT 2
#define INPUT_UP 4
#define INPUT_DOWN 8
#define INPUT_THRUST 16
#define INPUT_FIRE 32

typedef struct Target {
    int32_t x;
    int32_t y;
    int32_t z;
    int32_t radius;
    int32_t value;
} Target;

typedef struct GameState {
    int32_t frame;
    int32_t x;
    int32_t y;
    int32_t z;
    int32_t vx;
    int32_t vy;
    int32_t vz;
    int32_t yaw;
    int32_t pitch;
    int32_t energy;
    int32_t health;
    int32_t score;
    int32_t cooldown;
    uint32_t collected_mask;
    uint32_t rng;
} GameState;

typedef struct ProjectedPoint {
    int32_t x;
    int32_t y;
    int32_t visible;
} ProjectedPoint;

typedef struct ArgCursor {
    const char *next;
} ArgCursor;

#ifdef WINCR_WINDOWED
typedef struct TextBuffer {
    char *data;
    int32_t capacity;
    int32_t length;
} TextBuffer;
#endif

static const int32_t SIN_TABLE[32] = {
    0,   200, 392, 569, 724, 851, 946, 1004,
    1024,1004,946, 851, 724, 569, 392, 200,
    0,  -200,-392,-569,-724,-851,-946,-1004,
    -1024,-1004,-946,-851,-724,-569,-392,-200
};

static const int32_t CUBE_VERTS[8][3] = {
    {-256, -256, -256},
    { 256, -256, -256},
    { 256,  256, -256},
    {-256,  256, -256},
    {-256, -256,  256},
    { 256, -256,  256},
    { 256,  256,  256},
    {-256,  256,  256},
};

#ifdef WINCR_WINDOWED
static const int CUBE_EDGES[12][2] = {
    {0, 1}, {1, 2}, {2, 3}, {3, 0},
    {4, 5}, {5, 6}, {6, 7}, {7, 4},
    {0, 4}, {1, 5}, {2, 6}, {3, 7},
};
#endif

#ifdef WINCR_WINDOWED
static GameState g_state;
static Target g_targets[TARGET_COUNT];
static const char *g_scenario = "orbit";
static int32_t g_window_frame_limit = 0;
#endif

static void
zero_bytes(void *target, uint32_t size)
{
    uint8_t *cursor = (uint8_t *)target;
    while (size--)
        *cursor++ = 0;
}

static int32_t
str_len(const char *value)
{
    int32_t length = 0;
    if (value == NULL)
        return 0;
    while (value[length] != '\0')
        ++length;
    return length;
}

static int
str_equal(const char *left, const char *right)
{
    int32_t index = 0;
    if (left == NULL || right == NULL)
        return left == right;
    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index])
            return 0;
        ++index;
    }
    return left[index] == right[index];
}

static void
copy_text(char *destination, int32_t capacity, const char *source)
{
    int32_t index = 0;
    if (capacity <= 0)
        return;
    while (source != NULL && source[index] != '\0' && index < capacity - 1) {
        destination[index] = source[index];
        ++index;
    }
    destination[index] = '\0';
}

static void
write_handle_text(HANDLE handle, const char *text)
{
    DWORD written = 0;
    int32_t length = str_len(text);
    if (length > 0)
        WriteFile(handle, text, (DWORD)length, &written, NULL);
}

static void
write_stdout_text(const char *text)
{
    write_handle_text(GetStdHandle(STD_OUTPUT_HANDLE), text);
}

#ifndef WINCR_WINDOWED
static void
write_stderr_text(const char *text)
{
    write_handle_text(GetStdHandle(STD_ERROR_HANDLE), text);
}
#endif

static void
write_u32(uint32_t value)
{
    char buffer[16];
    int32_t cursor = 0;
    if (value == 0) {
        write_stdout_text("0");
        return;
    }
    while (value > 0 && cursor < (int32_t)sizeof(buffer)) {
        buffer[cursor++] = (char)('0' + (value % 10));
        value /= 10;
    }
    while (cursor > 0) {
        char out[2];
        out[0] = buffer[--cursor];
        out[1] = '\0';
        write_stdout_text(out);
    }
}

static void
write_i32(int32_t value)
{
    if (value < 0) {
        write_stdout_text("-");
        write_u32((uint32_t)(0u - (uint32_t)value));
    } else {
        write_u32((uint32_t)value);
    }
}

#ifdef WINCR_WINDOWED
static void
text_buffer_append(TextBuffer *buffer, const char *text)
{
    int32_t index = 0;
    if (buffer->capacity <= 0)
        return;
    while (text != NULL && text[index] != '\0' && buffer->length < buffer->capacity - 1)
        buffer->data[buffer->length++] = text[index++];
    buffer->data[buffer->length] = '\0';
}

static void
text_buffer_append_u32(TextBuffer *buffer, uint32_t value)
{
    char digits[16];
    int32_t cursor = 0;
    if (value == 0) {
        text_buffer_append(buffer, "0");
        return;
    }
    while (value > 0 && cursor < (int32_t)sizeof(digits)) {
        digits[cursor++] = (char)('0' + (value % 10));
        value /= 10;
    }
    while (cursor > 0) {
        char out[2];
        out[0] = digits[--cursor];
        out[1] = '\0';
        text_buffer_append(buffer, out);
    }
}

static void
text_buffer_append_i32(TextBuffer *buffer, int32_t value)
{
    if (value < 0) {
        text_buffer_append(buffer, "-");
        text_buffer_append_u32(buffer, (uint32_t)(0u - (uint32_t)value));
    } else {
        text_buffer_append_u32(buffer, (uint32_t)value);
    }
}
#endif

static int32_t
abs_i32(int32_t value)
{
    return value < 0 ? -value : value;
}

static int32_t
clamp_i32(int32_t value, int32_t min_value, int32_t max_value)
{
    if (value < min_value)
        return min_value;
    if (value > max_value)
        return max_value;
    return value;
}

static uint32_t
lcg_next(uint32_t *state)
{
    *state = (*state * 1664525u) + 1013904223u;
    return *state;
}

static int32_t
rng_range(uint32_t *state, int32_t min_value, int32_t span)
{
    return min_value + (int32_t)((lcg_next(state) >> 8) % (uint32_t)span);
}

static int32_t
sin_yaw(int32_t yaw)
{
    return SIN_TABLE[yaw & 31];
}

static int32_t
cos_yaw(int32_t yaw)
{
    return SIN_TABLE[(yaw + 8) & 31];
}

static void
init_targets(Target targets[TARGET_COUNT], uint32_t seed)
{
    uint32_t rng = seed ^ 0xa51c3d2fu;
    int index;
    for (index = 0; index < TARGET_COUNT; ++index) {
        targets[index].x = rng_range(&rng, -1400, 2801);
        targets[index].y = rng_range(&rng, -700, 1401);
        targets[index].z = rng_range(&rng, 2600, 3601) + index * 280;
        targets[index].radius = 260 + index * 30;
        targets[index].value = 100 + index * 75;
    }
}

static void
init_state(GameState *state, Target targets[TARGET_COUNT], uint32_t seed)
{
    zero_bytes(state, sizeof(*state));
    state->z = 768;
    state->energy = 1000;
    state->health = 1000;
    state->rng = seed;
    init_targets(targets, seed);
}

static uint32_t
scenario_input(const char *scenario, int32_t frame)
{
    uint32_t input = 0;
    if (str_equal(scenario, "idle"))
        return 0;
    if (str_equal(scenario, "collect")) {
        if (frame < 96)
            input |= INPUT_THRUST;
        if ((frame / 24) % 2 == 0)
            input |= INPUT_RIGHT;
        else
            input |= INPUT_LEFT;
        if (frame >= 20 && frame < 70)
            input |= INPUT_UP;
        if (frame == 34 || frame == 78 || frame == 118)
            input |= INPUT_FIRE;
        return input;
    }
    if (str_equal(scenario, "dive")) {
        if (frame < 8)
            input |= INPUT_LEFT;
        if (frame >= 8 && frame < 120)
            input |= INPUT_THRUST;
        return input;
    }
    if (str_equal(scenario, "burnout")) {
        input |= INPUT_THRUST;
        return input;
    }
    if (str_equal(scenario, "aim_miss")) {
        if (frame == 0)
            input |= INPUT_FIRE;
        return input;
    }
    if (frame < 48)
        input |= INPUT_LEFT;
    if (frame >= 48 && frame < 112)
        input |= INPUT_RIGHT;
    if (frame >= 12 && frame < 120)
        input |= INPUT_THRUST;
    if ((frame % 40) == 16)
        input |= INPUT_FIRE;
    if (frame >= 70 && frame < 118)
        input |= INPUT_DOWN;
    return input;
}

static ProjectedPoint
project_point(const GameState *state, int32_t world_x, int32_t world_y, int32_t world_z)
{
    ProjectedPoint result;
    int32_t rx = world_x - state->x;
    int32_t ry = world_y - state->y;
    int32_t rz = world_z - state->z + 2048;
    int32_t denom = rz <= 96 ? 96 : rz;
    result.x = SCREEN_W / 2 + (rx * 180) / denom;
    result.y = SCREEN_H / 2 - (ry * 180) / denom;
    result.visible = rz > 96 && result.x > -64 && result.x < SCREEN_W + 64 && result.y > -64 && result.y < SCREEN_H + 64;
    return result;
}

static void
mix_u32(uint32_t *hash, uint32_t value)
{
    int i;
    for (i = 0; i < 4; ++i) {
        *hash ^= (value >> (i * 8)) & 0xffu;
        *hash *= 16777619u;
    }
}

static uint32_t
frame_hash(const GameState *state, const Target targets[TARGET_COUNT], uint32_t input)
{
    uint32_t hash = 2166136261u;
    int index;
    mix_u32(&hash, (uint32_t)state->frame);
    mix_u32(&hash, input);
    mix_u32(&hash, (uint32_t)state->x);
    mix_u32(&hash, (uint32_t)state->y);
    mix_u32(&hash, (uint32_t)state->z);
    mix_u32(&hash, (uint32_t)state->vx);
    mix_u32(&hash, (uint32_t)state->vy);
    mix_u32(&hash, (uint32_t)state->vz);
    mix_u32(&hash, (uint32_t)state->yaw);
    mix_u32(&hash, (uint32_t)state->pitch);
    mix_u32(&hash, (uint32_t)state->energy);
    mix_u32(&hash, (uint32_t)state->health);
    mix_u32(&hash, (uint32_t)state->score);
    mix_u32(&hash, state->collected_mask);
    for (index = 0; index < TARGET_COUNT; ++index) {
        ProjectedPoint point = project_point(state, targets[index].x, targets[index].y, targets[index].z);
        mix_u32(&hash, (uint32_t)point.x);
        mix_u32(&hash, (uint32_t)point.y);
        mix_u32(&hash, (uint32_t)point.visible);
    }
    for (index = 0; index < 8; ++index) {
        ProjectedPoint point = project_point(
            state,
            state->x + CUBE_VERTS[index][0],
            state->y + CUBE_VERTS[index][1],
            state->z + 1400 + CUBE_VERTS[index][2]);
        mix_u32(&hash, (uint32_t)point.x);
        mix_u32(&hash, (uint32_t)point.y);
        mix_u32(&hash, (uint32_t)point.visible);
    }
    return hash;
}

static void
step_game(GameState *state, const Target targets[TARGET_COUNT], uint32_t input)
{
    int index;
    if (input & INPUT_LEFT)
        state->yaw = (state->yaw + 31) & 31;
    if (input & INPUT_RIGHT)
        state->yaw = (state->yaw + 1) & 31;
    if (input & INPUT_UP)
        state->pitch = clamp_i32(state->pitch + 16, -384, 384);
    if (input & INPUT_DOWN)
        state->pitch = clamp_i32(state->pitch - 16, -384, 384);
    if (!(input & (INPUT_UP | INPUT_DOWN)))
        state->pitch = (state->pitch * 7) / 8;

    if ((input & INPUT_THRUST) && state->energy > 0) {
        state->vx += cos_yaw(state->yaw) / 24;
        state->vz += sin_yaw(state->yaw) / 24 + 18;
        state->vy += state->pitch / 96;
        state->energy = clamp_i32(state->energy - 3, 0, 1000);
    } else {
        state->energy = clamp_i32(state->energy + 2, 0, 1000);
    }

    state->x += state->vx;
    state->y += state->vy;
    state->z += state->vz;
    state->vx = (state->vx * 31) / 32;
    state->vy = (state->vy * 31) / 32;
    state->vz = (state->vz * 31) / 32;

    if (state->cooldown > 0)
        --state->cooldown;

    for (index = 0; index < TARGET_COUNT; ++index) {
        uint32_t bit = 1u << index;
        int32_t dx;
        int32_t dy;
        int32_t dz;
        if (state->collected_mask & bit)
            continue;
        dx = targets[index].x - state->x;
        dy = targets[index].y - state->y;
        dz = targets[index].z - state->z;
        if (abs_i32(dx) < targets[index].radius &&
            abs_i32(dy) < targets[index].radius &&
            abs_i32(dz) < targets[index].radius) {
            state->collected_mask |= bit;
            state->score += targets[index].value;
            state->energy = clamp_i32(state->energy + 80, 0, 1000);
        } else if ((input & INPUT_FIRE) && state->cooldown == 0) {
            ProjectedPoint point = project_point(state, targets[index].x, targets[index].y, targets[index].z);
            if (point.visible && abs_i32(point.x - SCREEN_W / 2) <= 18 && abs_i32(point.y - SCREEN_H / 2) <= 18) {
                state->score += 25;
                state->cooldown = 12;
            }
        }
    }

    if (state->z < 0) {
        state->z = 0;
        state->vz = 0;
        state->health = clamp_i32(state->health - 5, 0, 1000);
    }
    ++state->frame;
}

static uint32_t
run_transcript(const char *scenario, uint32_t seed, int32_t frames, int emit_json)
{
    GameState state;
    Target targets[TARGET_COUNT];
    uint32_t aggregate = 2166136261u;
    int32_t frame;
    init_state(&state, targets, seed);
    if (emit_json) {
        int index;
        write_stdout_text("{\"format\":\"wincr-3d-game-transcript-v1\",\"game\":\"wincr-3d-reference-game\",");
        write_stdout_text("\"version\":");
        write_i32(GAME_VERSION);
        write_stdout_text(",\"scenario\":\"");
        write_stdout_text(scenario);
        write_stdout_text("\",\"seed\":");
        write_u32(seed);
        write_stdout_text(",\"frames\":");
        write_i32(frames);
        write_stdout_text(",\"constants\":{\"fixed_scale\":");
        write_i32(FIXED_SCALE);
        write_stdout_text(",\"screen_w\":");
        write_i32(SCREEN_W);
        write_stdout_text(",\"screen_h\":");
        write_i32(SCREEN_H);
        write_stdout_text(",\"target_count\":");
        write_i32(TARGET_COUNT);
        write_stdout_text("},\"targets\":[");
        for (index = 0; index < TARGET_COUNT; ++index) {
            if (index)
                write_stdout_text(",");
            write_stdout_text("{\"x\":");
            write_i32(targets[index].x);
            write_stdout_text(",\"y\":");
            write_i32(targets[index].y);
            write_stdout_text(",\"z\":");
            write_i32(targets[index].z);
            write_stdout_text(",\"radius\":");
            write_i32(targets[index].radius);
            write_stdout_text(",\"value\":");
            write_i32(targets[index].value);
            write_stdout_text("}");
        }
        write_stdout_text("],\"samples\":[");
    }
    for (frame = 0; frame < frames; ++frame) {
        uint32_t input = scenario_input(scenario, frame);
        uint32_t hash_before = frame_hash(&state, targets, input);
        if (emit_json && (frame < 16 || frame == frames - 1 || (frame % 30) == 0)) {
            if (!(frame == 0))
                write_stdout_text(",");
            write_stdout_text("{\"frame\":");
            write_i32(state.frame);
            write_stdout_text(",\"input\":");
            write_u32(input);
            write_stdout_text(",\"x\":");
            write_i32(state.x);
            write_stdout_text(",\"y\":");
            write_i32(state.y);
            write_stdout_text(",\"z\":");
            write_i32(state.z);
            write_stdout_text(",\"vx\":");
            write_i32(state.vx);
            write_stdout_text(",\"vy\":");
            write_i32(state.vy);
            write_stdout_text(",\"vz\":");
            write_i32(state.vz);
            write_stdout_text(",\"yaw\":");
            write_i32(state.yaw);
            write_stdout_text(",\"pitch\":");
            write_i32(state.pitch);
            write_stdout_text(",\"energy\":");
            write_i32(state.energy);
            write_stdout_text(",\"health\":");
            write_i32(state.health);
            write_stdout_text(",\"score\":");
            write_i32(state.score);
            write_stdout_text(",\"collected_mask\":");
            write_u32(state.collected_mask);
            write_stdout_text(",\"hash\":");
            write_u32(hash_before);
            write_stdout_text("}");
        }
        mix_u32(&aggregate, hash_before);
        step_game(&state, targets, input);
    }
    mix_u32(&aggregate, frame_hash(&state, targets, 0));
    if (emit_json) {
        write_stdout_text("],\"final\":{\"frame\":");
        write_i32(state.frame);
        write_stdout_text(",\"x\":");
        write_i32(state.x);
        write_stdout_text(",\"y\":");
        write_i32(state.y);
        write_stdout_text(",\"z\":");
        write_i32(state.z);
        write_stdout_text(",\"vx\":");
        write_i32(state.vx);
        write_stdout_text(",\"vy\":");
        write_i32(state.vy);
        write_stdout_text(",\"vz\":");
        write_i32(state.vz);
        write_stdout_text(",\"yaw\":");
        write_i32(state.yaw);
        write_stdout_text(",\"pitch\":");
        write_i32(state.pitch);
        write_stdout_text(",\"energy\":");
        write_i32(state.energy);
        write_stdout_text(",\"health\":");
        write_i32(state.health);
        write_stdout_text(",\"score\":");
        write_i32(state.score);
        write_stdout_text(",\"cooldown\":");
        write_i32(state.cooldown);
        write_stdout_text(",\"collected_mask\":");
        write_u32(state.collected_mask);
        write_stdout_text("},\"aggregate_hash\":");
        write_u32(aggregate);
        write_stdout_text("}\n");
    }
    return aggregate;
}

#ifdef WINCR_WINDOWED
static uint32_t
keyboard_input(void)
{
    uint32_t input = 0;
    if (GetAsyncKeyState(VK_LEFT) & 0x8000)
        input |= INPUT_LEFT;
    if (GetAsyncKeyState(VK_RIGHT) & 0x8000)
        input |= INPUT_RIGHT;
    if (GetAsyncKeyState(VK_UP) & 0x8000)
        input |= INPUT_UP;
    if (GetAsyncKeyState(VK_DOWN) & 0x8000)
        input |= INPUT_DOWN;
    if (GetAsyncKeyState('W') & 0x8000)
        input |= INPUT_THRUST;
    if (GetAsyncKeyState(VK_SPACE) & 0x8000)
        input |= INPUT_FIRE;
    return input;
}

static void
draw_scene(HWND hwnd, HDC dc)
{
    RECT rect;
    HBRUSH background = CreateSolidBrush(RGB(8, 12, 20));
    HPEN grid_pen = CreatePen(PS_SOLID, 1, RGB(36, 48, 64));
    HPEN cube_pen = CreatePen(PS_SOLID, 2, RGB(80, 220, 180));
    HPEN target_pen = CreatePen(PS_SOLID, 1, RGB(240, 190, 70));
    HPEN old_pen;
    int i;
    char hud[160];
    TextBuffer hud_buffer;
    GetClientRect(hwnd, &rect);
    FillRect(dc, &rect, background);
    old_pen = SelectObject(dc, grid_pen);
    for (i = 0; i < SCREEN_W; i += 32) {
        MoveToEx(dc, i, 0, NULL);
        LineTo(dc, i, SCREEN_H);
    }
    for (i = 0; i < SCREEN_H; i += 25) {
        MoveToEx(dc, 0, i, NULL);
        LineTo(dc, SCREEN_W, i);
    }

    SelectObject(dc, target_pen);
    for (i = 0; i < TARGET_COUNT; ++i) {
        ProjectedPoint point;
        if (g_state.collected_mask & (1u << i))
            continue;
        point = project_point(&g_state, g_targets[i].x, g_targets[i].y, g_targets[i].z);
        if (!point.visible)
            continue;
        Rectangle(dc, point.x - 6, point.y - 6, point.x + 6, point.y + 6);
    }

    SelectObject(dc, cube_pen);
    for (i = 0; i < 12; ++i) {
        ProjectedPoint a = project_point(
            &g_state,
            g_state.x + CUBE_VERTS[CUBE_EDGES[i][0]][0],
            g_state.y + CUBE_VERTS[CUBE_EDGES[i][0]][1],
            g_state.z + 1400 + CUBE_VERTS[CUBE_EDGES[i][0]][2]);
        ProjectedPoint b = project_point(
            &g_state,
            g_state.x + CUBE_VERTS[CUBE_EDGES[i][1]][0],
            g_state.y + CUBE_VERTS[CUBE_EDGES[i][1]][1],
            g_state.z + 1400 + CUBE_VERTS[CUBE_EDGES[i][1]][2]);
        if (a.visible || b.visible) {
            MoveToEx(dc, a.x, a.y, NULL);
            LineTo(dc, b.x, b.y);
        }
    }

    SelectObject(dc, old_pen);
    DeleteObject(grid_pen);
    DeleteObject(cube_pen);
    DeleteObject(target_pen);
    DeleteObject(background);
    SetTextColor(dc, RGB(220, 235, 240));
    SetBkMode(dc, TRANSPARENT);
    hud_buffer.data = hud;
    hud_buffer.capacity = (int32_t)sizeof(hud);
    hud_buffer.length = 0;
    hud[0] = '\0';
    text_buffer_append(&hud_buffer, "frame=");
    text_buffer_append_i32(&hud_buffer, g_state.frame);
    text_buffer_append(&hud_buffer, " score=");
    text_buffer_append_i32(&hud_buffer, g_state.score);
    text_buffer_append(&hud_buffer, " energy=");
    text_buffer_append_i32(&hud_buffer, g_state.energy);
    text_buffer_append(&hud_buffer, " hash=");
    text_buffer_append_u32(&hud_buffer, frame_hash(&g_state, g_targets, 0));
    TextOutA(dc, 8, 8, hud, hud_buffer.length);
    MoveToEx(dc, SCREEN_W / 2 - 8, SCREEN_H / 2, NULL);
    LineTo(dc, SCREEN_W / 2 + 8, SCREEN_H / 2);
    MoveToEx(dc, SCREEN_W / 2, SCREEN_H / 2 - 8, NULL);
    LineTo(dc, SCREEN_W / 2, SCREEN_H / 2 + 8);
}

static LRESULT CALLBACK
window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    (void)wparam;
    (void)lparam;
    switch (message) {
    case WM_CREATE:
        SetTimer(hwnd, 1, 16, NULL);
        return 0;
    case WM_TIMER:
        step_game(
            &g_state,
            g_targets,
            g_window_frame_limit > 0 ? scenario_input(g_scenario, g_state.frame) : keyboard_input());
        InvalidateRect(hwnd, NULL, FALSE);
        if (g_window_frame_limit > 0 && g_state.frame >= g_window_frame_limit) {
            UpdateWindow(hwnd);
            DestroyWindow(hwnd);
        }
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        draw_scene(hwnd, dc);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcA(hwnd, message, wparam, lparam);
    }
}

static int
run_windowed(uint32_t seed, const char *scenario, int32_t frame_limit)
{
    WNDCLASSA wc;
    HWND hwnd;
    MSG msg;
    zero_bytes(&wc, sizeof(wc));
    init_state(&g_state, g_targets, seed);
    g_scenario = scenario;
    g_window_frame_limit = frame_limit;
    wc.lpfnWndProc = window_proc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "WinCR3DReferenceGame";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    if (!RegisterClassA(&wc))
        return 2;
    hwnd = CreateWindowExA(
        0,
        wc.lpszClassName,
        "WinCR 3D Reference Game",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        SCREEN_W + 16,
        SCREEN_H + 39,
        NULL,
        NULL,
        wc.hInstance,
        NULL);
    if (!hwnd)
        return 3;
    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);
    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return (int)msg.wParam;
}
#endif

static int
next_arg(ArgCursor *cursor, char *out, int32_t capacity)
{
    const char *input = cursor->next;
    int quoted = 0;
    int32_t length = 0;
    if (capacity <= 0)
        return 0;
    while (*input == ' ' || *input == '\t')
        ++input;
    if (*input == '\0') {
        cursor->next = input;
        out[0] = '\0';
        return 0;
    }
    if (*input == '"') {
        quoted = 1;
        ++input;
    }
    while (*input != '\0') {
        if (quoted) {
            if (*input == '"') {
                ++input;
                break;
            }
        } else if (*input == ' ' || *input == '\t') {
            break;
        }
        if (length < capacity - 1)
            out[length++] = *input;
        ++input;
    }
    out[length] = '\0';
    cursor->next = input;
    return 1;
}

static int
parse_int_arg(const char *value, int fallback)
{
    int sign = 1;
    int parsed = 0;
    int32_t index = 0;
    if (value == NULL || value[0] == '\0')
        return fallback;
    if (value[0] == '-') {
        sign = -1;
        index = 1;
    }
    if (value[index] == '\0')
        return fallback;
    while (value[index] != '\0') {
        if (value[index] < '0' || value[index] > '9')
            return fallback;
        parsed = parsed * 10 + (value[index] - '0');
        ++index;
    }
    return parsed * sign;
}

static void
write_usage(void)
{
    write_stdout_text("usage: wincr-3d-game.exe --json [--scenario idle|orbit|collect|dive|burnout|aim_miss] [--frames N] [--seed N]\n");
    write_stdout_text("       wincr-3d-game-window.exe --window-smoke [--scenario idle|orbit|collect|dive|burnout|aim_miss] [--frames N] [--seed N]\n");
}

static int
game_main(void)
{
    ArgCursor cursor;
    char arg[128];
    char value[128];
    char scenario_storage[32];
    const char *scenario = "orbit";
    int frames = 180;
    uint32_t seed = 7;
    int json = 0;
    int window_smoke = 0;

    scenario_storage[0] = '\0';
    cursor.next = GetCommandLineA();
    next_arg(&cursor, arg, sizeof(arg));
    while (next_arg(&cursor, arg, sizeof(arg))) {
        if (str_equal(arg, "--json")) {
            json = 1;
        } else if (str_equal(arg, "--window-smoke")) {
            window_smoke = 1;
        } else if (str_equal(arg, "--scenario") && next_arg(&cursor, value, sizeof(value))) {
            copy_text(scenario_storage, sizeof(scenario_storage), value);
            scenario = scenario_storage;
        } else if (str_equal(arg, "--frames") && next_arg(&cursor, value, sizeof(value))) {
            frames = parse_int_arg(value, frames);
        } else if (str_equal(arg, "--seed") && next_arg(&cursor, value, sizeof(value))) {
            seed = (uint32_t)parse_int_arg(value, (int)seed);
        } else if (str_equal(arg, "--help")) {
            write_usage();
            return 0;
        }
    }
    frames = clamp_i32(frames, 1, MAX_FRAMES);
    if (json) {
        run_transcript(scenario, seed, frames, 1);
        return 0;
    }
#ifdef WINCR_WINDOWED
    return run_windowed(seed, scenario, window_smoke ? frames : 0);
#else
    if (window_smoke)
        write_stderr_text("window smoke is provided by wincr-3d-game-window.exe\n");
    else
        write_stderr_text("pass --json for deterministic transcript output\n");
    return 4;
#endif
}

void
mainCRTStartup(void)
{
    ExitProcess((UINT)game_main());
}
