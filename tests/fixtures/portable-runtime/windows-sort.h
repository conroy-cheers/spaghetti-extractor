#ifndef SPX_WINDOWS_SORT_H
#define SPX_WINDOWS_SORT_H
#include <stddef.h>

/* Sorting sequence from the pinned Wine 11.0 MSVCRT runtime. The comparator
 * may expose that sequence, including through inconsistent target ordering.
 * The caller owns count * width bytes. Invalid-parameter callbacks, changing
 * the array from the comparator, and other Windows CRT versions are not modeled.
 */
void spx_windows_qsort(void *base, size_t count, size_t width,
    int (*compare)(const void *, const void *));
#endif
