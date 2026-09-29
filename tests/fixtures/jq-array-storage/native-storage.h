#ifndef SPX_JQ_ARRAY_NATIVE_STORAGE_H
#define SPX_JQ_ARRAY_NATIVE_STORAGE_H
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

/* Storage still shared with unselected native jq readers and destructors.
 * This layout is distinct from the private descriptor held between authored
 * operations. See COPYING.jq and the native-crossing inventory in README.md. */
struct jv_refcnt { int count; };
typedef union { struct jv_refcnt *ptr; double number; } jq_payload;
typedef struct {
    unsigned char kind_flags;
    unsigned char pad_;
    unsigned short offset;
    int size;
    jq_payload u;
} jq_native_value;
typedef struct {
    struct jv_refcnt refcnt;
    int length, alloc_length;
    jq_native_value elements[];
} jq_array;
struct spx_opaque_jq_memory_v5;

_Static_assert(sizeof(int) == 4 && sizeof(unsigned short) == 2 && CHAR_BIT == 8,
               "jq storage requires 32-bit int and 16-bit offsets");
static inline int jq_signed_word(uint32_t bits) {
    return bits <= INT32_MAX ? (int)bits : -1 - (int)(UINT32_MAX - bits);
}
#endif
