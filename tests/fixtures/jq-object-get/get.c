#include "portable-component-implementation.h"
#include "object-view.h"
#include <string.h>

spx_jv_value_v2 lifted_object_get(spx_object_get_context_v5 *boundary,
                                  spx_jv_value_v2 value, spx_jv_value_v2 key) {
    const spx_object_get_services_v5 *services = boundary->services;
    struct spx_opaque_object_table_v5 table;
    services->contents(services->context, value, &table);
    uint32_t hash = services->hash(services->context, key);
    uint32_t bucket = hash & (table.capacity * 2U - 1U);
    int32_t index;
    memcpy(&index, table.buckets + bucket * sizeof(index), sizeof(index));
    spx_jv_value_v2 result;
    while (index != -1) {
        struct jq_object_link slot;
        memcpy(&slot, table.slots + table.stride * (uint32_t)index, sizeof(slot));
        if (slot.hash == hash && services->equal(services->context, key, &table, index)) {
            result = services->copy_value(services->context, &table, index);
            goto done;
        }
        index = slot.next;
    }
    result = services->invalid(services->context);
done:
    services->release(services->context, value);
    services->release(services->context, key);
    return result;
}
