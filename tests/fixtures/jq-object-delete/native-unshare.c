#include <windows.h>
#include "object-mutable-native.h"

/* Pinned jvp_object_unshare: result address in EAX, 16-byte value on the stack,
 * caller cleanup. This local ABI was checked at the actual delete call site.
 * The portable backend uses an ordinary C accessor instead. */
jv spx_object_unshare(jv value) {
    unsigned char *base = (unsigned char *)GetModuleHandleA("libjq-1.dll");
    if (!base) abort();
    typedef void (__attribute__((regparm(1))) *unshare_fn)(jv *, jv);
    jv result;
    ((unshare_fn)(base + 0x2a7e3))(&result, value);
    return result;
}
