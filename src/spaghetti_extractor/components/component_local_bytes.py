"""Portable C storage behind a scoped V5 byte view.

The owner and its byte array must remain alive for every use. Logical identity
uses the owner's host pointer opaquely, never as an original machine address.
Closing invalidates borrowed views while the owner is still alive; it cannot
make a pointer to a dead C owner safe. Escaping references need a separate rule.
"""


def _declarations():
    return r'''#ifndef SPX_COMPONENT_LOCAL_BYTES_V5_H
#define SPX_COMPONENT_LOCAL_BYTES_V5_H

_Static_assert(sizeof(uintptr_t) <= sizeof(uint64_t), "local view identity exceeds V5 origin width");

typedef struct spx_local_bytes_v5 {
  uint8_t *bytes;
  uint64_t extent, generation;
  uint32_t permissions, live;
} spx_local_bytes_v5;

static inline uint64_t spx_local_bytes_identity(const spx_local_bytes_v5 *owner) {
  return (uint64_t)(uintptr_t)(const void *)owner;
}

static inline uint32_t spx_local_bytes_access(
    const spx_local_bytes_v5 *owner, spx_ref_v5 reference,
    uint64_t offset, uint32_t width, uint32_t permission, uint64_t *index) {
  if (owner == 0 || owner->live != 1U || reference.generation != owner->generation)
    return 2U;
  if (reference.domain != UINT64_MAX || reference.object != spx_local_bytes_identity(owner) ||
      reference.extent != owner->extent)
    return 3U;
  if ((reference.permissions & owner->permissions) != reference.permissions ||
      (reference.permissions & permission) != permission)
    return 4U;
  if (index == 0 || width == 0U || width > 4U || owner->bytes == 0 ||
      reference.offset > owner->extent || offset > owner->extent - reference.offset ||
      (uint64_t)width > owner->extent - reference.offset - offset)
    return 1U;
  *index = reference.offset + offset;
  return 0U;
}

uint32_t spx_local_bytes_read(void *, spx_ref_v5, uint64_t, uint32_t, uint64_t *);
uint32_t spx_local_bytes_write(void *, spx_ref_v5, uint64_t, uint32_t, uint64_t);

static inline uint32_t spx_local_bytes_view(
    spx_local_bytes_v5 *owner, uint64_t offset, uint64_t extent,
    uint32_t permissions, spx_view_v5 *result) {
  if (owner == 0 || owner->live != 1U) return 2U;
  if (permissions == 0U || permissions > 3U || (permissions & owner->permissions) != permissions)
    return 4U;
  if (result == 0 || offset > owner->extent || extent > owner->extent - offset)
    return 1U;
  *result = (spx_view_v5){.base={UINT64_MAX,spx_local_bytes_identity(owner),owner->generation,
      offset,owner->extent,permissions},.extent=extent,.element_width=1U,.access_context=owner,
      .read=(permissions & 1U) ? spx_local_bytes_read : 0,
      .write=(permissions & 2U) ? spx_local_bytes_write : 0};
  return 0U;
}

/* Initialize each owner with {0}; keep both owner and bytes in the borrow's
 * enclosing C lifetime. Reopening requires close and advances the generation. */
static inline uint32_t spx_local_bytes_open(
    spx_local_bytes_v5 *owner, uint8_t *bytes, uint64_t extent,
    uint32_t permissions, spx_view_v5 *result) {
  if (owner == 0 || result == 0 || owner->live != 0U || owner->generation == UINT64_MAX ||
      bytes == 0 || extent > UINT32_MAX || spx_local_bytes_identity(owner) == 0U)
    return 1U;
  if (permissions == 0U || permissions > 3U) return 4U;
  owner->bytes=bytes; owner->extent=extent; owner->permissions=permissions;
  owner->generation++; owner->live=1U;
  return spx_local_bytes_view(owner,0U,extent,permissions,result);
}

static inline void spx_local_bytes_close(spx_local_bytes_v5 *owner) {
  if (owner != 0) owner->live=0U;
}
#endif
'''


def local_bytes_header():
    return '#include "portable-component.h"\n' + _declarations()


def local_bytes_runtime():
    return _declarations() + r'''
uint32_t spx_local_bytes_read(
    void *opaque, spx_ref_v5 reference, uint64_t offset, uint32_t width, uint64_t *result) {
  const spx_local_bytes_v5 *owner = opaque;
  uint64_t index;
  uint32_t status = spx_local_bytes_access(owner, reference, offset, width, 1U, &index);
  if (status != 0U || result == 0) return status == 0U ? 1U : status;
  uint64_t value = 0U;
  for (uint32_t i = 0U; i < width; ++i) value |= (uint64_t)owner->bytes[index+i] << (8U*i);
  *result = value;
  return 0U;
}

uint32_t spx_local_bytes_write(
    void *opaque, spx_ref_v5 reference, uint64_t offset, uint32_t width, uint64_t value) {
  spx_local_bytes_v5 *owner = opaque;
  uint64_t index;
  uint32_t status = spx_local_bytes_access(owner, reference, offset, width, 2U, &index);
  if (status != 0U) return status;
  for (uint32_t i = 0U; i < width; ++i) owner->bytes[index+i] = (uint8_t)(value >> (8U*i));
  return 0U;
}

'''
