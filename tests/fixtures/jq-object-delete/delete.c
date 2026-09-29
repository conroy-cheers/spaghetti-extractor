#include "portable-component-implementation.h"
#include "object-mutable-view.h"
#include <string.h>

spx_jv_value_v2 lifted_object_delete(spx_object_delete_context_v5 *boundary,
                                     spx_jv_value_v2 value, spx_jv_value_v2 key) {
    const spx_object_delete_services_v5 *services = boundary->services;
    struct spx_opaque_mutable_object_table_v5 table;
    value = services->unshare(services->context, value, &table);
    uint32_t hash = services->hash(services->context, key);
    uint32_t bucket = hash & (table.capacity * 2U - 1U);
    unsigned char *previous = table.buckets + bucket * sizeof(int32_t);
    int32_t index;
    memcpy(&index, previous, sizeof(index));
    while (index != -1) {
        unsigned char *current = table.slots + table.stride * (uint32_t)index;
        struct jq_object_link slot;
        memcpy(&slot, current, sizeof(slot));
        if (slot.hash == hash && services->equal(services->context, key, &table, index)) {
            memcpy(previous, &slot.next, sizeof(slot.next));
            services->erase(services->context, &table, index);
            break;
        }
        previous = current;
        index = slot.next;
    }
    services->release(services->context, key);
    return value;
}
