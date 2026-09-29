"""Live object transport for checked, synchronous paired calls.

The enclosing rule must establish the supplier's read/write frame, normal
outcomes and absence of escaping references. A local backing is actual C
storage, checked live at each invocation; an address alone supplies no bytes.
Local post-state snapshots transport every writable alias to the source side.
Shared sparse storage retains the existing physical post-byte function.
This runtime does not confer native object or lifetime authority.

The observation probe is a view-relative index. Universally checking each view
at that index covers its whole readable span without reconstructing an array
index from a symbolic machine stack address. Physical correspondence and aliases
are checked independently; the program and post-state choices do not depend on
the observation probe.
"""


def paired_object_runtime(capacity, byte_capacity, *, observation_sites=0):
    if type(capacity) is not int or not 1 <= capacity <= 32:
        raise ValueError('paired object capacity must be between 1 and 32')
    if type(byte_capacity) is not int or not 1 <= byte_capacity <= 256:
        raise ValueError('paired local byte capacity must be between 1 and 256')
    if type(observation_sites) is not int or not 0 <= observation_sites <= 64:
        raise ValueError('paired observation sites must be between 0 and 64')
    comparison = ('   __CPROVER_assert(snapshot->byte==spx_paired_object_byte(object,world,probe),'
                  '"spx-paired-object-current-memory");')
    if observation_sites:
        # Trace and object bounds are asserted before comparison. These guards
        # partition every admitted observation; they add no input assumption.
        comparison = '\n'.join(
            f'   if(position=={position}U && i=={index}U) '
            '__CPROVER_assert(snapshot->byte==spx_paired_object_byte(object,world,probe),'
            f'"spx-paired-object-current-memory:{position}:{index}");'
            for position in range(observation_sites) for index in range(capacity))
    position_parameter = ',uint32_t position' if observation_sites else ''
    return f'''
struct spx_paired_object {{
 uint32_t address, permissions, local;
 uint64_t extent;
 uint8_t *bytes;
}};
struct spx_paired_object_snapshot {{
 uint32_t address, permissions, local;
 uint64_t extent;
 uint8_t byte;
 uint8_t post_bytes[{byte_capacity}];
}};
static void spx_paired_objects_check(const struct spx_paired_object *objects,uint32_t count) {{
 __CPROVER_assert(count<={capacity}U,"spx-paired-object-capacity");
 __CPROVER_assume(count<={capacity}U);
 for(uint32_t i=0;i<count;i++){{
  const struct spx_paired_object *a=&objects[i];
  __CPROVER_assert(a->permissions>=1U && a->permissions<=3U && a->local<=1U &&
   a->extent<=UINT64_C(4294967296)-(uint64_t)a->address,"spx-paired-object-domain");
  if(a->local){{
   __CPROVER_assert(a->extent<={byte_capacity}U,"spx-paired-local-object-size");
   __CPROVER_assert(__CPROVER_r_ok(a->bytes,a->extent),"spx-paired-local-object-live");
   if(a->permissions&2U)
    __CPROVER_assert(__CPROVER_w_ok(a->bytes,a->extent),"spx-paired-local-object-writable");
  }}
  for(uint32_t j=0;j<i;j++){{
   const struct spx_paired_object *b=&objects[j];
   if(a->extent && b->extent && (uint64_t)a->address<(uint64_t)b->address+b->extent &&
      (uint64_t)b->address<(uint64_t)a->address+a->extent){{
    __CPROVER_assert(a->local==b->local,"spx-paired-object-storage-alias");
    if(a->local && b->local){{
     if(a->address<=b->address)
      __CPROVER_assert(a->bytes+(b->address-a->address)==b->bytes,"spx-paired-local-object-alias");
     else
      __CPROVER_assert(b->bytes+(a->address-b->address)==a->bytes,"spx-paired-local-object-alias");
    }}
   }}
  }}
 }}
}}
static uint32_t spx_paired_object_contains(const struct spx_paired_object *object,uint32_t probe) {{
 return (uint64_t)probe<object->extent;
}}
static uint8_t spx_paired_object_byte(const struct spx_paired_object *object,
 const struct spx_mutable_world *world,uint32_t probe) {{
 return object->local ? object->bytes[probe] : spx_mutable_byte(world,object->address+probe);
}}
static void spx_paired_objects_record(struct spx_paired_object_snapshot *snapshots,
 const struct spx_paired_object *objects,uint32_t count,const struct spx_mutable_world *world,uint32_t probe) {{
 for(uint32_t i=0;i<count;i++){{
  const struct spx_paired_object *object=&objects[i];
  snapshots[i]=(struct spx_paired_object_snapshot){{object->address,object->permissions,object->local,object->extent,0U}};
  if((object->permissions&1U) && spx_paired_object_contains(object,probe))
   snapshots[i].byte=spx_paired_object_byte(object,world,probe);
 }}
}}
static void spx_paired_objects_compare(const struct spx_paired_object_snapshot *snapshots,
 const struct spx_paired_object *objects,uint32_t count,const struct spx_mutable_world *world,uint32_t probe{position_parameter}) {{
 for(uint32_t i=0;i<count;i++){{
  const struct spx_paired_object *object=&objects[i];
  const struct spx_paired_object_snapshot *snapshot=&snapshots[i];
  __CPROVER_assert(snapshot->address==object->address && snapshot->extent==object->extent &&
   snapshot->permissions==object->permissions && snapshot->local==object->local,"spx-paired-object-correspondence");
  if((object->permissions&1U) && spx_paired_object_contains(object,probe)){{
{comparison}
  }}
 }}
}}
static void spx_paired_objects_update(struct spx_paired_object_snapshot *snapshots,
 struct spx_paired_object *objects,uint32_t count,struct spx_mutable_world *world,uint32_t position,uint32_t side) {{
 for(uint32_t i=0;i<count;i++){{
  struct spx_paired_object *object=&objects[i];
  if(object->permissions&2U){{
   if(object->local){{
    for(uint64_t j=0;j<object->extent;j++){{
     uint8_t arbitrary_byte;
     object->bytes[j]=side==0U ? arbitrary_byte : snapshots[i].post_bytes[j];
    }}
   }}else spx_mutable_event(world,object->address,object->extent,0U,1U,position);
  }}
 }}
 /* Capture only after all original writes, so overlapping mutable views have
  * one coherent post-state. Source aliases were checked against actual storage.
  * This avoids one uninterpreted-function application per local byte. */
 if(side==0U)for(uint32_t i=0;i<count;i++){{
  const struct spx_paired_object *object=&objects[i];
  if(object->local && (object->permissions&2U))
   for(uint64_t j=0;j<object->extent;j++)snapshots[i].post_bytes[j]=object->bytes[j];
 }}
}}
'''.strip().splitlines()
