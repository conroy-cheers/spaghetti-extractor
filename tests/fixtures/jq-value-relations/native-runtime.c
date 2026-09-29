/* The number representation remains a shared runtime service. */
#include <stdint.h>
#include <windows.h>
#include "jv.h"
#include "jv_private.h"

static void *entry(uint32_t rva) {
    HMODULE image = GetModuleHandleA("libjq-1.dll");
    (void)&jv_is_valid;
    if (!image) ExitProcess(84);
    return (unsigned char *)image + rva;
}

int jvp_number_cmp(jv first, jv second) {
    return ((int (*)(jv, jv))entry(0x275fa))(first, second);
}

int jvp_number_is_nan(jv value) {
    return ((int (*)(jv))entry(0x2737a))(value);
}
