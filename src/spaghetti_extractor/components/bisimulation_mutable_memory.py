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


def sparse_mutable_memory_runtime(capacity: int, *, preserved_spans=(), observed_byte=False,
                                  representation_hooks=False, bulk_operations=False) -> list[str]:
    """Bound writes, not the address space; a probe may observe any physical byte.

    Source stores record their complete width/value. A service range records one
    arbitrary final-byte function indexed by call position and physical address.
    Later events win, including at aliases. No memory contents are reconstructed
    from pointer metadata, and no buffer length is used as an unwinding bound.

    Preserved physical spans frame the recorded byte effects. Every recorded
    write must prove that frame before native reads can bypass history. C record
    fields retain their separately checked frames; bulk reads still consult the
    current field or copy snapshot. Read-only view permissions alone never
    establish either storage invariant.

    An optional observer folds the same write events at one arbitrary address.
    The harness initializes its byte from incoming memory and keeps the address
    fixed. This avoids rebuilding a symbolic history for a final observation;
    reads still use the complete event history. A separate bit observes actual
    non-service writes, preserving the existing initialization-witness rule.

    Optional bulk events fill a span or copy its pre-event contents. Backwards
    lookup follows copies into earlier history, including overlapping copies;
    neither the byte count nor the address space is enumerated. These byte effects
    do not establish access permissions, allocation identity or lifetime. Current
    representation hooks can retain pre-copy field snapshots. A read through a
    copy consults that snapshot before following earlier byte history. Current
    representation values are consulted only at the final observation address.
    Initialization witnesses still need a separate bulk transport rule.
    """
    if not isinstance(capacity, int) or isinstance(capacity, bool) or not 0 < capacity <= 64:
        raise ValueError("sparse mutable event capacity is invalid")
    if type(observed_byte) is not bool:
        raise ValueError("sparse mutable observation mode is invalid")
    if type(bulk_operations) is not bool:
        raise ValueError("sparse mutable bulk mode is invalid")
    if bulk_operations and observed_byte:
        raise ValueError("bulk snapshots need checked initialization-observer transport")
    if type(representation_hooks) is not bool or representation_hooks and (
            observed_byte or preserved_spans and not bulk_operations):
        raise ValueError("record representation needs an unfactored current-byte world")
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
    observation_fields = 'uint32_t observed_address; uint8_t observed_byte, observed_initialized; ' if observed_byte else ''
    representation_fields = ('void *representation; uint8_t (*read_representation)(void *,uint32_t,uint8_t); '
        'void (*write_representation)(void *,const struct spx_mutable_event *); ') if representation_hooks else ''
    if bulk_operations and representation_hooks:
        representation_fields += ('void (*snapshot_representation)(void *,uint32_t); '
            'uint32_t (*read_representation_snapshot)(void *,uint32_t,uint32_t,uint8_t *); ')
    representation_read = ('  if(world->read_representation) result=world->read_representation(world->representation,address,result);\n'
                           if representation_hooks else '')
    representation_write = ('  if(world->write_representation)world->write_representation(world->representation,&world->events[world->count-1U]);\n'
                            if representation_hooks else '')
    observe = '''static uint8_t spx_mutable_apply_event(const struct spx_mutable_event *event,
    uint32_t address, uint8_t previous) {
  if (address >= event->address && (uint64_t)address < (uint64_t)event->address + event->extent)
    return event->service ? __CPROVER_uninterpreted_service_byte(event->position,address)
      : (uint8_t)(event->value >> (8U * (address-event->address)));
  return previous;
}
''' if observed_byte else ''
    read_event = ('      result = spx_mutable_apply_event(event,address,result);' if observed_byte else '''      if (address >= event->address && (uint64_t)address < (uint64_t)event->address + event->extent)
        result = event->service ? __CPROVER_uninterpreted_service_byte(event->position,address)
          : (uint8_t)(event->value >> (8U * (address-event->address)));''')
    observe_write = '''  const struct spx_mutable_event observed={address,value,service,position,extent};
  world->observed_byte=spx_mutable_apply_event(&observed,world->observed_address,world->observed_byte);
  if(!service && world->observed_address>=address && (uint64_t)world->observed_address<(uint64_t)address+extent)
    world->observed_initialized=1U;
''' if observed_byte else ''
    read = f'''static uint8_t spx_mutable_byte(const struct spx_mutable_world *world, uint32_t address) {{
  uint8_t result = __CPROVER_uninterpreted_readonly_byte(address);
{preserved_reads}  for (uint32_t j=0; j<{capacity}U; ++j) {{
    if (j < world->count) {{
      const struct spx_mutable_event *event = &world->events[j];
{read_event}
    }}
  }}
{representation_read}  return result;
}}
'''
    event_checks = bulk = snapshot_write = ''
    if bulk_operations:
        snapshot_read = ('''        uint8_t represented;
        if (world->read_representation_snapshot && world->read_representation_snapshot(
            world->representation,remaining-1U,address,&represented)) return represented;
''' if representation_hooks else '')
        read = f'''static uint8_t spx_mutable_history_byte(const struct spx_mutable_world *world,
    uint32_t address,uint32_t before) {{
  __CPROVER_assert(before <= world->count && world->count <= {capacity}U, "spx-shared-memory-history-capacity");
  __CPROVER_assume(before <= world->count && world->count <= {capacity}U);
  for (uint32_t remaining={capacity}U; remaining>0U; --remaining) {{
    if (remaining>before) continue;
    const struct spx_mutable_event *event=&world->events[remaining-1U];
    if (address >= event->address && (uint64_t)address < (uint64_t)event->address+event->extent) {{
      if (event->service==3U) {{
        /* Read the source snapshot before this copy, never its current bytes. */
        address=event->value+(address-event->address);
{snapshot_read}      }} else if (event->service==2U) return (uint8_t)event->value;
      else if (event->service==1U) return __CPROVER_uninterpreted_service_byte(event->position,address);
      else {{
        uint32_t offset=address-event->address;
        __CPROVER_assert(offset<4U, "spx-shared-memory-word-byte");
        /* Total byte extraction keeps language safety independent of the span
         * theorem; the explicit offset assertion still rejects invalid words. */
        return (uint8_t)(offset==0U ? event->value : offset==1U ? event->value>>8U :
                         offset==2U ? event->value>>16U : event->value>>24U);
      }}
    }}
  }}
  return __CPROVER_uninterpreted_readonly_byte(address);
}}
static uint8_t spx_mutable_byte(const struct spx_mutable_world *world,uint32_t address) {{
  uint8_t result=spx_mutable_history_byte(world,address,world->count);
{representation_read}  return result;
}}
'''
        event_checks = '''  __CPROVER_assert(extent <= UINT64_C(4294967296)-address,
    "spx-shared-memory-destination-range");
  __CPROVER_assert(service <= 3U && (service != 0U || (extent >= 1U && extent <= 4U)),
    "spx-shared-memory-event-kind");
  __CPROVER_assert(service != 3U || extent <= UINT64_C(4294967296)-value,
    "spx-shared-memory-source-range");
'''
        if representation_hooks:
            event_checks += '''  __CPROVER_assert((world->read_representation==0 && world->write_representation==0 &&
    world->snapshot_representation==0 && world->read_representation_snapshot==0) ||
    (world->read_representation!=0 && world->write_representation!=0 &&
     world->snapshot_representation!=0 && world->read_representation_snapshot!=0),
    "spx-shared-memory-representation-snapshot-hooks");
'''
            snapshot_write = '''  if(service==3U && world->snapshot_representation)
    world->snapshot_representation(world->representation,world->count);
'''
        bulk = '''/* A fill uses memset's low byte. A copy has memmove snapshot semantics.
 * Callers separately establish readable/writable live spans and service effects. */
static void spx_mutable_fill(struct spx_mutable_world *world, uint32_t address,
    uint64_t extent, uint32_t value) {
  spx_mutable_event(world,address,extent,value,2U,0U);
}
static void spx_mutable_copy(struct spx_mutable_world *world, uint32_t destination,
    uint32_t source, uint64_t extent) {
  spx_mutable_event(world,destination,extent,source,3U,0U);
}
'''
    append_event = '  world->events[world->count++] = (struct spx_mutable_event){address,value,service,position,extent};\n'
    event_index = 'world->count'
    save_index = ''
    if bulk_operations and representation_hooks:
        # Keep the capacity obligation explicit, but make the storage accesses
        # statically bounded. Repeating a symbolic array bound at each insertion
        # pulled the connected byte/record history into a redundant safety query.
        # Allocation snapshots already use this fixed-slot selection pattern.
        # Select the whole event step, including its pre-copy snapshot. Merging
        # a pointer or snapshot index outside the switch recreates the same
        # expensive bound in callback accesses. Snapshot and write callbacks
        # still see the original pre-event and updated counts respectively.
        event_index = 'event_index'
        save_index = '  const uint32_t event_index=world->count;\n'
        append_event = ('  switch(event_index){\n' + ''.join(
                f'  case {i}U:\n'
                + snapshot_write.replace('world->representation,world->count)', f'world->representation,{i}U)')
                + '    __CPROVER_assert(world->count==event_index,"spx-shared-memory-snapshot-frame");\n'
                '    __CPROVER_assume(world->count==event_index);\n'
                f'    world->events[{i}]=(struct spx_mutable_event){{address,value,service,position,extent}};'
                f'world->count={i+1}U;\n'
                f'    if(world->write_representation)world->write_representation(world->representation,&world->events[{i}]);\n'
                '    return;\n' for i in range(capacity)) +
            '  default:__CPROVER_assume(0);\n  }\n')
        snapshot_write = ''
        representation_write = ''
    return f'''
struct spx_mutable_event {{ uint32_t address, value, service, position; uint64_t extent; }};
struct spx_mutable_world {{ {observation_fields}{representation_fields}uint32_t count; struct spx_mutable_event events[{capacity}]; }};
struct spx_mutable_domain {{ struct spx_mutable_world *world; uint32_t address; uint64_t extent; uint32_t permissions; }};
static struct spx_mutable_world *spx_mutable_frame;
uint8_t __CPROVER_uninterpreted_readonly_byte(uint32_t);
uint8_t __CPROVER_uninterpreted_service_byte(uint32_t, uint32_t);
{observe}{read}static void spx_mutable_event(struct spx_mutable_world *world, uint32_t address,
    uint64_t extent, uint32_t value, uint32_t service, uint32_t position) {{
{save_index}  __CPROVER_assert({event_index} < {capacity}U, "spx-shared-memory-event-capacity");
  __CPROVER_assume({event_index} < {capacity}U);
{event_checks}{preserved_writes}{observe_write}{snapshot_write}{append_event}
{representation_write}
}}
{bulk}static uint32_t spx_mutable_read(void *opaque, uint32_t address, uint32_t width, uint32_t *fault) {{
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
