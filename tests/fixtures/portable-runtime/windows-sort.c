/*
 * msvcrt.dll misc functions
 *
 * Copyright 2000 Jon Griffiths
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Adapted 2026-09-27 from Wine 11.0 dlls/msvcrt/misc.c.
 * https://github.com/wine-mirror/wine/blob/wine-11.0/dlls/msvcrt/misc.c
 * Only sorting for valid buffers is exposed. The callback context and Wine
 * platform dependencies are removed; the comparison/swap sequence is retained.
 * This profile pins the tested Wine CRT, not every version of the Windows CRT.
 * See COPYING.LGPL-2.1 distributed with this source and source project.
 */
#include <stdint.h>
#include "windows-sort.h"

static inline void swap(char *l, char *r, size_t size)
{
    char tmp;

    while(size--) {
        tmp = *l;
        *l++ = *r;
        *r++ = tmp;
    }
}

static void small_sort(void *base, size_t nmemb, size_t size,
        int (*compar)(const void *, const void *))
{
    size_t e, i;
    char *max, *p;

    for(e=nmemb; e>1; e--) {
        max = base;
        for(i=1; i<e; i++) {
            p = (char*)base + i*size;
            if(compar(p, max) > 0)
                max = p;
        }

        if(p != max)
            swap(p, max, size);
    }
}

static void quick_sort(void *base, size_t nmemb, size_t size,
        int (*compar)(const void *, const void *))
{
    size_t stack_lo[8*sizeof(size_t)], stack_hi[8*sizeof(size_t)];
    size_t beg, end, lo, hi, med;
    int stack_pos;

    stack_pos = 0;
    stack_lo[stack_pos] = 0;
    stack_hi[stack_pos] = nmemb-1;

#define X(i) ((char*)base+size*(i))
    while(stack_pos >= 0) {
        beg = stack_lo[stack_pos];
        end = stack_hi[stack_pos--];

        if(end-beg < 8) {
            small_sort(X(beg), end-beg+1, size, compar);
            continue;
        }

        lo = beg;
        hi = end;
        med = lo + (hi-lo+1)/2;
        if(compar(X(lo), X(med)) > 0)
            swap(X(lo), X(med), size);
        if(compar(X(lo), X(hi)) > 0)
            swap(X(lo), X(hi), size);
        if(compar(X(med), X(hi)) > 0)
            swap(X(med), X(hi), size);

        lo++;
        hi--;
        while(1) {
            while(lo <= hi) {
                if(lo!=med && compar(X(lo), X(med))>0)
                    break;
                lo++;
            }

            while(med != hi) {
                if(compar(X(hi), X(med)) <= 0)
                    break;
                hi--;
            }

            if(hi < lo)
                break;

            swap(X(lo), X(hi), size);
            if(hi == med)
                med = lo;
            lo++;
            hi--;
        }

        while(hi > beg) {
            if(hi!=med && compar(X(hi), X(med))!=0)
                break;
            hi--;
        }

        if(hi-beg >= end-lo) {
            stack_lo[++stack_pos] = beg;
            stack_hi[stack_pos] = hi;
            stack_lo[++stack_pos] = lo;
            stack_hi[stack_pos] = end;
        }else {
            stack_lo[++stack_pos] = lo;
            stack_hi[stack_pos] = end;
            stack_lo[++stack_pos] = beg;
            stack_hi[stack_pos] = hi;
        }
    }
#undef X
}

void spx_windows_qsort(void *base, size_t count, size_t width,
    int (*compare)(const void *, const void *)) {
    if (!width || !compare || (!base && count) || count > SIZE_MAX / width)
        return;
    if (count >= 2) quick_sort(base, count, width, compare);
}
