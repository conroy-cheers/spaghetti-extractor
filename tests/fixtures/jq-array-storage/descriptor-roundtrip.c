/* Transport checks independent of the array algorithms and native serializer. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include VALUE_LAYOUT_HEADER

static void same_native(jq_native_value before, jq_native_value after) {
    assert(before.kind_flags == after.kind_flags);
    assert(before.pad_ == after.pad_);
    assert(before.offset == after.offset);
    assert(before.size == after.size);
    assert(memcmp(&before.u, &after.u, sizeof(before.u)) == 0);
}

int main(void) {
    const unsigned offsets[] = {0, 1, 32768, 65535};
    const int sizes[] = {INT32_MIN, -1, 0, 1, INT32_MAX};
    /* Includes signed zero, infinities, NaN payloads and ordinary payload bits.
     * No floating operation or pointer access interprets these byte patterns. */
    const uint64_t payloads[] = {0, UINT64_MAX, UINT64_C(0x8000000000000000),
        UINT64_C(0x7ff0000000000000), UINT64_C(0xfff0000000000000),
        UINT64_C(0x7ff800005a170123), UINT64_C(0x7ff0000000000001),
        UINT64_C(0x3ff0000000000000), UINT64_C(0x0123456789abcdef)};
    _Static_assert(sizeof(jq_payload) == sizeof(uint64_t), "payload width");
    unsigned cases = 0;
    for (unsigned tag = 0; tag < 256; ++tag)
        for (unsigned o = 0; o < sizeof(offsets)/sizeof(offsets[0]); ++o)
            for (unsigned s = 0; s < sizeof(sizes)/sizeof(sizes[0]); ++s)
                for (unsigned p = 0; p < sizeof(payloads)/sizeof(payloads[0]); ++p) {
                    jq_native_value original;
                    memset(&original, 0, sizeof(original));
                    original.kind_flags = (unsigned char)tag;
                    original.pad_ = (unsigned char)(255U - tag);
                    original.offset = (unsigned short)offsets[o];
                    original.size = sizes[s];
                    memcpy(&original.u, &payloads[p], sizeof(original.u));
                    jq_value converted = jq_value_load(original);
                    assert(jq_kind(converted) == (tag & 15U));
                    assert(jq_allocated(converted) == ((tag & 128U) != 0));
                    assert(converted.size == sizes[s] && converted.offset == offsets[o]);
                    same_native(original, jq_value_store(converted));
                    ++cases;
                }
    struct jv_refcnt object = {3};
    jq_native_value native = {134, 0x5a, 7, 2, {.ptr = &object}};
    jq_value first = jq_value_load(native), alias = jq_value_load(native);
    assert(first.u.ptr == &object && alias.u.ptr == first.u.ptr);
    first.u.ptr->count = 4;
    assert(alias.u.ptr->count == 4);
    jq_native_value restored = jq_value_store(alias);
    assert(restored.u.ptr == &object && restored.u.ptr->count == 4);
    same_native(native, restored);
    printf("{\"cases\":%u,\"native_size\":%zu,\"private_size\":%zu,"
           "\"native_payload_offset\":%zu,\"private_payload_offset\":%zu,"
           "\"native_elements_offset\":%zu,\"live_alias_preserved\":true}\n",
           cases, sizeof(jq_native_value), sizeof(jq_value),
           offsetof(jq_native_value, u), offsetof(jq_value, u), offsetof(jq_array, elements));
    return 0;
}
