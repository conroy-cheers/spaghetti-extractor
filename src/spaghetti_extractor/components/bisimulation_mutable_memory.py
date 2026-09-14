"""Finite alias-preserving byte storage for the local mutable-view theorem.

This storage is scoped to a source call. It is not an allocation/lifetime model,
nor a substitute for caller entry and post-memory composition obligations.
"""

from __future__ import annotations


MAX_MUTABLE_MODEL_BYTES = (0xffffffff - 4) // 4


def mutable_memory_runtime(capacity: int) -> list[str]:
    """Keep byte contents in a separate object from immutable transport metadata.

    Slots enumerate every view byte, including duplicates at overlapping physical
    addresses. Writes update all matching slots. Read-only aliases therefore see
    writes through a writable view without granting them write permission.
    """
    if (not isinstance(capacity, int) or isinstance(capacity, bool)
            or not 0 < capacity <= MAX_MUTABLE_MODEL_BYTES):
        raise ValueError("mutable address metadata must fit the PE32 object size")
    return f'''
struct spx_mutable_world {{ uint32_t addresses[{capacity}]; uint8_t *values; }};
struct spx_mutable_domain {{
  struct spx_mutable_world *world;
  uint32_t address;
  uint64_t extent;
  uint32_t permissions;
}};
static struct spx_mutable_world *spx_mutable_frame;
uint8_t __CPROVER_uninterpreted_readonly_byte(uint32_t);
static uint32_t spx_mutable_read(void *opaque, uint32_t address,
    uint32_t width, uint32_t *fault) {{
  struct spx_mutable_domain *domain = (struct spx_mutable_domain *)opaque;
  __CPROVER_assert((domain->permissions & 1U) && width >= 1U && width <= 4U &&
      address >= domain->address &&
      (uint64_t)address + width <= (uint64_t)domain->address + domain->extent,
      "spx-mutable-readable-frame");
  uint32_t result = 0U;
  for (uint32_t i=0U; i<width; ++i) {{
    uint8_t byte=0U, found=0U;
    for (uint32_t j=0U; j<{capacity}U; ++j) {{
      if (domain->world->addresses[j] == address+i) {{
        byte = domain->world->values[j];
        found = 1U;
      }}
    }}
    __CPROVER_assert(found, "spx-mutable-readable-byte-present");
    result |= (uint32_t)byte << (8U*i);
  }}
  *fault = 0U;
  return result;
}}
static void spx_mutable_write(void *opaque, uint32_t address,
    uint32_t width, uint32_t value, uint32_t *fault) {{
  struct spx_mutable_domain *domain = (struct spx_mutable_domain *)opaque;
  __CPROVER_assert((domain->permissions & 2U) && width >= 1U && width <= 4U &&
      address >= domain->address &&
      (uint64_t)address + width <= (uint64_t)domain->address + domain->extent,
      "spx-mutable-writable-frame");
  for (uint32_t i=0U; i<width; ++i) {{
    uint8_t found=0U;
    for (uint32_t j=0U; j<{capacity}U; ++j) {{
      if (domain->world->addresses[j] == address+i) {{
        domain->world->values[j] = (uint8_t)(value >> (8U*i));
        found = 1U;
      }}
    }}
    __CPROVER_assert(found, "spx-mutable-writable-byte-present");
  }}
  *fault = 0U;
}}
'''.strip().splitlines()


def sparse_mutable_memory_runtime(capacity: int, *, preserved_spans=()) -> list[str]:
    """Bound writes, not the address space; a probe may observe any physical byte.

    Source stores record their complete width/value. A service range records one
    arbitrary final-byte function indexed by call position and physical address.
    Later events win, including at aliases. No memory contents are reconstructed
    from pointer metadata, and no buffer length is used as an unwinding bound.

    Preserved physical spans retain their incoming bytes for the whole region.
    Every recorded write must prove that frame before reads can bypass history.
    Read-only view permissions alone never establish this storage invariant.
    """
    if not isinstance(capacity, int) or isinstance(capacity, bool) or not 0 < capacity <= 64:
        raise ValueError("sparse mutable event capacity is invalid")
    spans = []
    for span in preserved_spans:
        if (not isinstance(span, (tuple, list)) or len(span) != 2
                or any(type(v) is not int for v in span)
                or not 0 <= span[0] < 2**32 or not 0 < span[1] <= 2**32 - span[0]):
            raise ValueError("preserved physical span is invalid")
        spans.append(tuple(span))
    spans.sort()
    if any(a + n > b for (a, n), (b, _) in zip(spans, spans[1:])):
        raise ValueError("preserved physical spans overlap")
    preserved_reads = ''.join(
        f'  if (address >= {base}U && (uint64_t)address < UINT64_C({base+size})) return result;\n'
        for base, size in spans)
    preserved_writes = ''.join(
        f'  __CPROVER_assert(extent == 0U || (uint64_t)address+extent <= UINT64_C({base}) || '
        f'UINT64_C({base+size}) <= address, "spx-shared-preserved-span-{index}");\n'
        for index, (base, size) in enumerate(spans))
    return f'''
struct spx_mutable_event {{ uint32_t address, value, service, position; uint64_t extent; }};
struct spx_mutable_world {{ uint32_t count; struct spx_mutable_event events[{capacity}]; }};
struct spx_mutable_domain {{ struct spx_mutable_world *world; uint32_t address; uint64_t extent; uint32_t permissions; }};
static struct spx_mutable_world *spx_mutable_frame;
uint8_t __CPROVER_uninterpreted_readonly_byte(uint32_t);
uint8_t __CPROVER_uninterpreted_service_byte(uint32_t, uint32_t);
static uint8_t spx_mutable_byte(const struct spx_mutable_world *world, uint32_t address) {{
  uint8_t result = __CPROVER_uninterpreted_readonly_byte(address);
{preserved_reads}  for (uint32_t j=0; j<{capacity}U; ++j) {{
    if (j < world->count) {{
      const struct spx_mutable_event *event = &world->events[j];
      if (address >= event->address && (uint64_t)address < (uint64_t)event->address + event->extent)
        result = event->service ? __CPROVER_uninterpreted_service_byte(event->position,address)
          : (uint8_t)(event->value >> (8U * (address-event->address)));
    }}
  }}
  return result;
}}
static void spx_mutable_event(struct spx_mutable_world *world, uint32_t address,
    uint64_t extent, uint32_t value, uint32_t service, uint32_t position) {{
  __CPROVER_assert(world->count < {capacity}U, "spx-shared-memory-event-capacity");
  __CPROVER_assume(world->count < {capacity}U);
{preserved_writes}  world->events[world->count++] = (struct spx_mutable_event){{address,value,service,position,extent}};
}}
static uint32_t spx_mutable_read(void *opaque, uint32_t address, uint32_t width, uint32_t *fault) {{
  struct spx_mutable_domain *domain = opaque;
  __CPROVER_assert((domain->permissions & 1U) && width >= 1U && width <= 4U && address >= domain->address &&
    (uint64_t)address+width <= (uint64_t)domain->address+domain->extent, "spx-shared-readable-frame");
  uint32_t result=0;
  for (uint32_t i=0; i<width; ++i) result |= (uint32_t)spx_mutable_byte(domain->world,address+i) << (8U*i);
  *fault=0; return result;
}}
static void spx_mutable_write(void *opaque, uint32_t address, uint32_t width, uint32_t value, uint32_t *fault) {{
  struct spx_mutable_domain *domain = opaque;
  __CPROVER_assert((domain->permissions & 2U) && width >= 1U && width <= 4U && address >= domain->address &&
    (uint64_t)address+width <= (uint64_t)domain->address+domain->extent, "spx-shared-writable-frame");
  spx_mutable_event(domain->world,address,width,value,0U,0U); *fault=0;
}}
'''.strip().splitlines()
