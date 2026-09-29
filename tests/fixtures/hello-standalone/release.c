#include "services.h"
#include "portable-component-implementation.h"
#include <errno.h>
#include <stdlib.h>

static uint32_t read_error(void *context, spx_ref_v1 base, uint64_t offset, uint32_t width, uint64_t *value) {
    (void)base;
    if (offset || width!=4) return SPX_REF_FAULT;
    *value=(uint32_t)*(int *)context; return SPX_REF_OK;
}
static uint32_t write_error(void *context, spx_ref_v1 base, uint64_t offset, uint32_t width, uint64_t value) {
    (void)base;
    if (offset || width!=4) return SPX_REF_FAULT;
    *(int *)context=(int)(uint32_t)value; return SPX_REF_OK;
}
static spx_view_v5 error_cell(void *context) {
    (void)context;
    return (spx_view_v5){.access_context=&errno, .extent=4, .element_width=1,
        .base={.domain=1, .object=1, .generation=1, .extent=4, .permissions=3},
        .read=read_error, .write=write_error};
}
static void release(void *context, uint32_t token) {
    /* The existing target token is an identity, never a truncated host pointer. */
    if (token!=1) abort();
    ++hello_runtime.releases; free(context);
}
void hello_release(void *block) {
    spx_preserve_errno_free_services_v5 services = {
        .context=block, .errno_cell=error_cell, .release_allocation=release};
    spx_preserve_errno_free_context_v5 context = {.services=&services};
    preserve_errno_free(&context, 1);
}
