#ifndef SPX_JQ_HASH_SOURCE_H
#define SPX_JQ_HASH_SOURCE_H
#include "hash-native.h"

/* Keep the public platform ABI outside the explicitly 32-bit component ABI.
 * unsigned long is 32-bit on Win32 and 64-bit on the exercised source hosts. */
unsigned long jv_string_hash(jv value) {
    return (unsigned long)fixture_string_hash(value);
}
#endif
