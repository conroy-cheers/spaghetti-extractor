#include "portable-component-implementation.h"
#include "hash-view.h"
#include <string.h>

static uint32_t rotate(uint32_t value, unsigned count) {
    return (value << count) | (value >> (32U - count));
}

uint32_t lifted_string_hash(spx_string_hash_context_v5 *boundary, spx_jv_value_v2 value) {
    const spx_string_hash_services_v5 *services = boundary->services;
    struct spx_opaque_hash_view_v5 view;
    services->view(services->context, value, &view);
    uint32_t hash = view.hash;
    if (!(view.length_hashed & 1U)) {
        uint32_t length = view.length_hashed >> 1;
        hash = services->seed(services->context);
        uint32_t offset = 0;
        while (length - offset >= 4U) {
            const unsigned char *bytes = view.data + offset;
            uint32_t block = (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
                             ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
            block = rotate(block * UINT32_C(0xcc9e2d51), 15) * UINT32_C(0x1b873593);
            hash = rotate(hash ^ block, 13) * 5U + UINT32_C(0xe6546b64);
            offset += 4U;
        }
        uint32_t tail = 0;
        for (uint32_t i = 0; i < length - offset; ++i)
            tail |= (uint32_t)view.data[offset + i] << (8U * i);
        if (offset != length)
            hash ^= rotate(tail * UINT32_C(0xcc9e2d51), 15) * UINT32_C(0x1b873593);
        hash ^= length;
        hash ^= hash >> 16;
        hash *= UINT32_C(0x85ebca6b);
        hash ^= hash >> 13;
        hash *= UINT32_C(0xc2b2ae35);
        hash ^= hash >> 16;
        uint32_t marked = view.length_hashed | 1U;
        memcpy(view.cache + 4, &marked, sizeof(marked));
        memcpy(view.cache, &hash, sizeof(hash));
    }
    services->release(services->context, value);
    return hash;
}
