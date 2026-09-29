/* Test-only, single-threaded allocation service fault and immediate telemetry.
 * Reporting preserves errno and happens before returning to the application,
 * so later exit/_Exit paths cannot silently discard a reached fault. */
#ifndef SPX_FIXTURE_ALLOCATION_FAULT_H
#define SPX_FIXTURE_ALLOCATION_FAULT_H
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned spx_fault_at, spx_fault_attempts, spx_fault_failures;
static size_t spx_fault_size;
static const char *spx_fault_report;

static void spx_fault_write(void) {
    int saved=errno;
    FILE *file=fopen(spx_fault_report,"wb");
    if (!file) _Exit(125);
    int failed=fprintf(file,"{\"fail_at\":%u,\"attempts\":%u,\"failures\":%u,\"last_size\":%lu}\n",
        spx_fault_at,spx_fault_attempts,spx_fault_failures,(unsigned long)spx_fault_size)<0;
    if (fclose(file)) failed=1;
    if (failed) _Exit(125);
    errno=saved;
}

static void spx_fault_begin(void) {
    int saved=errno;
    const char *value=getenv("SPX_ALLOCATION_FAIL_AT");
    spx_fault_report=getenv("SPX_ALLOCATION_FAULT_REPORT");
    if (!value || !*value || !spx_fault_report || !*spx_fault_report) _Exit(125);
    /* Small explicit ordinals; no ambiguous negative, whitespace or overflow. */
    for (const unsigned char *p=(const unsigned char *)value;*p;++p) {
        if (*p<'0' || *p>'9' || spx_fault_at>1000) _Exit(125);
        spx_fault_at=spx_fault_at*10U+(unsigned)(*p-'0');
    }
    if (spx_fault_at>1000) _Exit(125);
    spx_fault_write();
    errno=saved;
}

static int spx_fault_visit(size_t size) {
    if (spx_fault_attempts==UINT32_MAX || size>UINT32_MAX) _Exit(125);
    ++spx_fault_attempts;
    spx_fault_size=size;
    int failed=spx_fault_at && spx_fault_attempts==spx_fault_at;
    if (failed) ++spx_fault_failures;
    spx_fault_write();
    return failed;
}
#endif
