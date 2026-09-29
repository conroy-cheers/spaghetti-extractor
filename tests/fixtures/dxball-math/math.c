#include "portable-component-implementation.h"
#include "math-state.h"
#include <math.h>

static int64_t signed_word(uint32_t value) {
    return value < UINT32_C(0x80000000) ? (int64_t)value : (int64_t)value - INT64_C(4294967296);
}
static uint32_t angle_index(uint32_t angle) {
    if (angle < UINT32_C(0x80000000)) return angle % 360;
    return (uint32_t)(360 - signed_word(0u - angle) % 360);
}

void lifted_math_initialize(spx_math_support_context_v5 *context, math_tables *tables) {
    (void)context;
    for (unsigned degree = 0; degree <= 360; ++degree) {
        double radians = (double)degree * 0x1.1df45a50de271p-6;
        tables->cosine[degree] = (int32_t)(cos(radians) * 1024.0);
        tables->sine[degree] = (int32_t)(sin(radians) * 1024.0);
    }
}
uint32_t lifted_math_sine(spx_math_support_context_v5 *context, math_tables *tables, uint32_t angle) {
    (void)context;
    return (uint32_t)tables->sine[angle_index(angle)];
}
uint32_t lifted_math_cosine(spx_math_support_context_v5 *context, math_tables *tables, uint32_t angle) {
    (void)context;
    return (uint32_t)tables->cosine[angle_index(angle)];
}
double lifted_math_sine_value(spx_math_support_context_v5 *context, math_tables *tables, uint32_t angle) {
    (void)context;
    return (double)tables->sine[angle_index(angle)] / 1024.0;
}
double lifted_math_cosine_value(spx_math_support_context_v5 *context, math_tables *tables, uint32_t angle) {
    (void)context;
    return (double)tables->cosine[angle_index(angle)] / 1024.0;
}
uint32_t lifted_math_project_x(spx_math_support_context_v5 *context, math_tables *tables, uint32_t origin, uint32_t angle, uint32_t distance) {
    uint32_t product = lifted_math_cosine(context, tables, angle) * distance;
    return origin + (uint32_t)(signed_word(product) / 1024);
}
uint32_t lifted_math_project_y(spx_math_support_context_v5 *context, math_tables *tables, uint32_t origin, uint32_t angle, uint32_t distance) {
    uint32_t product = lifted_math_sine(context, tables, angle) * distance;
    return origin + (uint32_t)(signed_word(product) / 1024);
}
uint32_t lifted_math_pan(spx_math_support_context_v5 *context, uint32_t position) {
    (void)context;
    return (uint32_t)((signed_word(position) * 25 - 8000) / 16);
}
