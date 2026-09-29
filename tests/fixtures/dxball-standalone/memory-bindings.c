/* Live aliases for the reviewed original-address byte boundary. Wrapped
 * coordinates can cross named owners; they are never clamped to the grid. */
#include <stdio.h>
#include <stdlib.h>
#include "program-state.h"
#include "brick-runtime.h"
#include "play-runtime.h"
#include "warning-runtime.h"

static unsigned char *memory_byte(dxball_program *p, uint32_t base, uint32_t column, uint32_t row) {
    uint32_t address = base + 20 * row + column;
#define REGION(start, field) \
    if (address >= (start) && address-(start) < sizeof(p->field)) \
        return (unsigned char *)&p->field + (address-(start))
    REGION(UINT32_C(0x42ca60), boards.current);
    REGION(UINT32_C(0x42cc10), play.pending_cells);
    REGION(UINT32_C(0x42cdf8), boards.saved);
#undef REGION
    fprintf(stderr, "unmapped original-address byte 0x%08x; this access needs an explicit live storage binding\n", (unsigned)address);
    exit(86); /* Capability gap, not an assertion that the original faults. */
}
uint32_t brick_read_cell(void *u, brick_state *s, uint32_t column, uint32_t row) {
    (void)u; return *memory_byte(DXBALL_OWNER(s, bricks), 0x42ca60, column, row);
}
void brick_write_cell(void *u, brick_state *s, uint32_t column, uint32_t row, uint32_t value) {
    (void)u; *memory_byte(DXBALL_OWNER(s, bricks), 0x42ca60, column, row)=(unsigned char)value;
}
void brick_write_pending(void *u, brick_state *s, uint32_t column, uint32_t row, uint32_t value) {
    (void)u; *memory_byte(DXBALL_OWNER(s, bricks), 0x42cc10, column, row)=(unsigned char)value;
}
uint32_t play_read_pending(void *u, play_state *s, uint32_t column, uint32_t row) {
    (void)u; return *memory_byte(DXBALL_OWNER(s, play), 0x42cc10, column, row);
}
void play_prepare_last_brick(void *u, play_state *s) {
    (void)u; dxball_program *p=DXBALL_OWNER(s, play);
    p->warning.fallback=p->frame_history.words;
    fixture_warning_prepare(&p->warning);
}
