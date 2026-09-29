/* Standalone caller of the exported C API; no Wine or comparison adapter. */
#include <stdio.h>
#include "jv.h"
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    jv first = jv_parse(argv[1]), second = jv_parse(argv[2]);
    if (!jv_is_valid(first) || !jv_is_valid(second)) return 3;
    printf("%d\n", jv_cmp(first, second));
    return 0;
}
