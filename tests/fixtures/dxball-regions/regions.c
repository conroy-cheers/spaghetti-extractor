#include "portable-component-implementation.h"
#include "regions-state.h"

static int64_t signed_word(uint32_t word)
{
    return word < UINT32_C(0x80000000) ? (int64_t)word
        : (int64_t)word - INT64_C(0x100000000);
}

void lifted_regions_reset(spx_hit_regions_context_v5 *context,
                          region_table *table, uint32_t requested)
{
    (void)context;
    uint32_t count = requested + 1;
    *table->count = count;
    if (signed_word(count) < 0)
        return;
    /* The native routine clears the sentinel as well as the active records. */
    for (uint32_t i = 0; i <= count; ++i)
        table->records[i] = (editor_region){0};
}

void lifted_regions_define(spx_hit_regions_context_v5 *context,
                           region_table *table, uint32_t index,
                           uint32_t left, uint32_t top,
                           uint32_t right, uint32_t bottom)
{
    (void)context;
    table->records[index] = (editor_region){left, top, right, bottom, 1};
}

uint32_t lifted_regions_hit(spx_hit_regions_context_v5 *context,
                            region_table *table, uint32_t x, uint32_t y)
{
    (void)context;
    uint32_t hit = 0;
    int64_t count = signed_word(*table->count);
    for (uint32_t i = 1; (int64_t)i < count; ++i) {
        const editor_region *region = &table->records[i];
        if (region->enabled && signed_word(x) >= signed_word(region->left)
            && signed_word(x) <= signed_word(region->right)
            && signed_word(y) >= signed_word(region->top)
            && signed_word(y) <= signed_word(region->bottom))
            hit = i;
    }
    return hit;
}
