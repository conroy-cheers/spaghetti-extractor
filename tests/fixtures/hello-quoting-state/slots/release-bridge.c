/* Test-only bridge to the separately authored, checked real free wrapper.
 * Its token/pointer correspondence is exercised, not a checked adapter rule. */
#include "portable-component-implementation.h"

uint32_t fixture_errno(void *);
uint32_t fixture_load(void *, uint32_t);
void fixture_store(void *, uint32_t, uint32_t);
void fixture_free(void *, uint32_t);

static uint32_t read_cell(void *world, spx_ref_v5 reference, uint64_t offset,
                          uint32_t width, uint64_t *value) {
    if (offset != 0U || width != 4U) return SPX_REF_FAULT;
    *value = fixture_load(world, (uint32_t)reference.object);
    return SPX_REF_OK;
}

static uint32_t write_cell(void *world, spx_ref_v5 reference, uint64_t offset,
                           uint32_t width, uint64_t value) {
    if (offset != 0U || width != 4U) return SPX_REF_FAULT;
    fixture_store(world, (uint32_t)reference.object, (uint32_t)value);
    return SPX_REF_OK;
}

static spx_view_v5 errno_cell(void *world) {
    spx_view_v5 view = {.base = {.object = fixture_errno(world), .extent = 4U, .permissions = 3U},
        .extent = 4U, .element_width = 1U, .access_context = world, .read = read_cell, .write = write_cell};
    return view;
}

void fixture_source_release(void *world, uint32_t token) {
    const spx_preserve_errno_free_services_v5 services = {
        .context = world, .errno_cell = errno_cell, .release_allocation = fixture_free};
    spx_preserve_errno_free_context_v5 context = {.services = &services};
    preserve_errno_free(&context, token);
}
