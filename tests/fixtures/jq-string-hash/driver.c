#include <stdio.h>
#include "hash-native.h"
#include "allocation-observer.h"
#include "native-entry.h"

void fixture_hash_seed(uint32_t);
static unsigned calls;
static unsigned long counted_hash(jv value) {
    ++calls;
    return fixture_string_hash(value);
}
static void sample(unsigned length, int retained, int cached, unsigned number) {
    static const unsigned char bytes[] = {'a', 0, 0xff, 'b', 0xc3, 0xa9, 'c', 0x80, 'd', 'e', 'f', 'g', 'h'};
    char placeholder[sizeof(bytes)]; memset(placeholder, 'x', sizeof(placeholder));
    jv value = jv_string_sized(placeholder, (int)length);
    struct spx_opaque_hash_view_v5 view;
    hash_view(value, &view);
    memcpy((unsigned char *)view.data, bytes, length);
    /* Give even an uncached word a defined diagnostic value. A cached word is
     * deliberately independent of the seed: the entry must honor the flag. */
    uint32_t hash = UINT32_C(0x11223344), marked = (length << 1) | (unsigned)cached;
    memcpy(view.cache, &hash, sizeof(hash)); memcpy(view.cache + 4, &marked, sizeof(marked));
    jv keep = retained ? jv_copy(value) : jv_null();
    unsigned long result = jv_string_hash(value);
    printf("%s{\"length\":%u,\"cached\":%s,\"hash\":%lu,\"references\":%d,\"after\":",
           number ? "," : "", length, cached ? "true" : "false", result, jv_get_refcnt(keep));
    if (retained) {
        hash_view(keep, &view);
        /* This fixture initializes the raw word even before the cache is valid. */
        memcpy(&hash, view.cache, sizeof(hash));
        printf("{\"hash\":%lu,\"length_hashed\":%lu,\"bytes\":\"", (unsigned long)hash, (unsigned long)view.length_hashed);
        for (unsigned i = 0; i < length; ++i) printf("%02x", view.data[i]);
        fputs("\"}", stdout);
    } else fputs("null", stdout);
    fputc('}', stdout); jv_free(keep);
}
int main(int argc, char **argv) {
    if (argc != 4 || (strcmp(argv[1], "original") && strcmp(argv[1], "source")) ||
        (strcmp(argv[3], "retained") && strcmp(argv[3], "unique"))) return 2;
    char *end;
    unsigned long seed = strtoul(argv[2], &end, 0); if (*end) return 2;
    fixture_hash_seed((uint32_t)seed);
    int selected = !strcmp(argv[1], "source");
    if (selected && !spx_install_component_entry((void(*)(void))counted_hash)) return 85;
    allocation_observer_begin(); fputs("{\"samples\":[", stdout);
    unsigned number = 0;
    for (unsigned length = 0; length <= 13; ++length)
        for (int cached = 0; cached < 2; ++cached)
            sample(length, !strcmp(argv[3], "retained"), cached, number++);
    fputs("],\"allocation_lifetime\":", stdout); allocation_observer_finish(stdout); fputs("}\n", stdout);
    fprintf(stderr, "authored-string-hash-calls=%u\n", calls);
    return selected && !calls ? 85 : 0;
}
