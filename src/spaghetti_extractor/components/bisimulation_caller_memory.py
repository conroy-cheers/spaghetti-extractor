"""Checked finite native access definitions using existing typed boundary IR.

Definitions constrain actual native execution; they do not implement that execution
or prove admission. Public accesses share sparse physical bytes, including aliases.
Private ABI words require checked separation and initialization before observation.
The enclosing boundary still owns liveness, view admission and continuation proof.
"""

import re

from .bisimulation_call_relations import ScalarBinding, constant, expression, lower_call_relation
from .relation_ir import LogicalPathV1, MachinePlaceV1, RelationExpressionV1, RelationSortV1


U32 = RelationSortV1('bitvector', width=32)
ENTRY_REGISTERS = ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp', 'fs_base')


def entry_register(name):
    if name not in ENTRY_REGISTERS:
        raise ValueError('caller memory: unsupported entry register')
    place = MachinePlaceV1.parse({'kind':'register', 'phase':'entry', 'width':32,
                                 'selector':{'register':name}})
    return RelationExpressionV1.parse({'op':'machine', 'sort':U32.to_payload(),
        'args':[], 'attributes':{'place':place.to_payload()}})


def entry_offset(register, offset):
    if type(offset) is not int or not -(2**32-1) <= offset < 2**32:
        raise ValueError('caller memory: invalid entry offset')
    return expression('sub' if offset < 0 else 'add', U32, entry_register(register), constant(abs(offset)))


def access(identity, address, *, read=False, write=False, storage='public', width=4):
    return {'id':identity, 'address':address.to_payload(), 'width':width,
            'read':read, 'write':write, 'storage':storage}


def private_bytes(identity, address, extent, *, read=True, write=True):
    return {'id':identity, 'address':address.to_payload(), 'extent':extent,
            'read':read, 'write':write, 'storage':'private_bytes'}


def _entry_bindings():
    return {MachinePlaceV1.parse(entry_register(name).attributes['place']).key:
            ScalarBinding(U32, 'initial.'+name) for name in ENTRY_REGISTERS}


def checked_native_memory(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        raise ValueError('caller memory: expected between 1 and 32 access definitions')
    result=[]; ids=set()
    for row in value:
        byte_span=isinstance(row,dict) and row.get('storage')=='private_bytes'
        size='extent' if byte_span else 'width'
        if not isinstance(row, dict) or set(row) != {'id','address',size,'read','write','storage'}:
            raise ValueError('caller memory: access fields differ')
        identity=LogicalPathV1.parse({'root':'state','id':row['id'],'fields':[]}).identity
        if identity in ids:
            raise ValueError('caller memory: duplicate access identity')
        ids.add(identity)
        if (type(row[size]) is not int or not (1<=row[size]<=256 if byte_span else row[size] in {1,2,4})
                or type(row['read']) is not bool or type(row['write']) is not bool
                or not (row['read'] or row['write']) or row['storage'] not in {'public','private','private_bytes'}):
            raise ValueError('caller memory: unsupported width, access or storage')
        address=RelationExpressionV1.parse(row['address'])
        if address.sort != U32:
            raise ValueError('caller memory: address must be a uint32 relation')
        # Exact phase/width/selector binding is required. Unbound memory, logical
        # names, opaque selectors and arbitrary C strings cannot become addresses.
        lower_call_relation(address, parameters={}, machines=_entry_bindings())
        result.append({**row, 'address':address.to_payload()})
    return sorted(result,key=lambda row:row['id'])


def native_memory_initialization(value, *, instance, world, private_low, private_high):
    """Instance/world names are internal checker-owned C bindings."""
    rows=checked_native_memory(value)
    lines=[f'{instance}.world={world};']
    if any(row['storage']=='private_bytes' for row in rows):
        storage='spx_caller_storage_'+re.sub(r'[^A-Za-z0-9_]','_',instance)
        # A distinct C object keeps data writes from syntactically aliasing the
        # checker metadata. Emit in the enclosing entry scope, not a dead block.
        lines.extend([f'spx_caller_private_byte_storage {storage},{storage}_initialized={{0}};',
            f'{instance}.local=(struct spx_caller_private_bytes){{.low=UINT64_C(4294967296),'
            f'.bytes={storage},.initialized={storage}_initialized}};'])
    for index,row in enumerate(rows):
        address=lower_call_relation(row['address'], parameters={}, machines=_entry_bindings())
        lines.append(f'__CPROVER_assert({address.defined},"spx-caller-address-defined");')
        extent=row['extent'] if row['storage']=='private_bytes' else row['width']
        storage={'public':0,'private':1,'private_bytes':2}[row['storage']]
        lines.append(f'{instance}.slots[{index}]=(struct spx_caller_slot){{'
                     f'.address={address.value},.width={extent}U,.readable={int(row["read"])}U,'
                     f'.writable={int(row["write"])}U,.private_storage={storage}U}};')
        if storage==2:
            lines.extend([
                f'if({instance}.slots[{index}].address<{instance}.local.low)'
                f'{instance}.local.low={instance}.slots[{index}].address;',
                f'if((uint64_t){instance}.slots[{index}].address+{extent}U>{instance}.local.high)'
                f'{instance}.local.high=(uint64_t){instance}.slots[{index}].address+{extent}U;'])
    lines.append(f'spx_caller_memory_check(&{instance},{private_low},{private_high});')
    return '\n'.join(lines)+'\n'


def native_memory_runtime(capacity, *, private_byte_capacity=0):
    if type(capacity) is not int or not 1 <= capacity <= 32:
        raise ValueError('caller memory: invalid runtime capacity')
    if type(private_byte_capacity) is not int or not 0<=private_byte_capacity<=4096:
        raise ValueError('caller memory: invalid private byte capacity')
    source=f'''
struct spx_caller_slot {{ uint32_t address,width,readable,writable,private_storage,value,initialized; }};
struct spx_caller_memory {{ struct spx_mutable_world *world; uint32_t private_writes; struct spx_caller_slot slots[{capacity}]; }};
static void spx_caller_memory_check(const struct spx_caller_memory *memory,uint64_t private_low,uint64_t private_high) {{
 __CPROVER_assert(private_low<=private_high && private_high<=UINT64_C(4294967296),"spx-caller-private-frame-range");
 for(uint32_t i=0;i<{capacity}U;i++){{
  const struct spx_caller_slot *a=&memory->slots[i];
  __CPROVER_assert((a->width==1U || a->width==2U || a->width==4U) &&
   (uint64_t)a->address+a->width<=UINT64_C(4294967296),"spx-caller-nonwrapping-slot");
  __CPROVER_assert(!a->private_storage || ((uint64_t)a->address>=private_low &&
   (uint64_t)a->address+a->width<=private_high),"spx-caller-private-slot-in-frame");
  for(uint32_t j=0;j<i;j++){{
   const struct spx_caller_slot *b=&memory->slots[j];
   __CPROVER_assert(!(a->private_storage || b->private_storage) ||
    (uint64_t)a->address+a->width<=b->address || (uint64_t)b->address+b->width<=a->address,
    "spx-caller-private-slot-separation");
  }}
 }}
}}
static void spx_caller_public_span(const struct spx_caller_memory *memory,uint32_t address,uint64_t extent) {{
 __CPROVER_assert(extent<=UINT64_C(4294967296)-(uint64_t)address,"spx-caller-public-span-nonwrapping");
 for(uint32_t i=0;i<{capacity}U;i++){{
  const struct spx_caller_slot *slot=&memory->slots[i];
  __CPROVER_assert(!slot->private_storage || extent==0U ||
   (uint64_t)address+extent<=slot->address || (uint64_t)slot->address+slot->width<=address,
   "spx-caller-private-view-separation");
 }}
}}
static uint32_t spx_caller_read(struct spx_caller_memory *memory,uint32_t address,uint32_t width,uint32_t *fault) {{
 uint32_t public_read=0U;
 for(uint32_t i=0;i<{capacity}U;i++){{
  const struct spx_caller_slot *slot=&memory->slots[i];
  if(slot->address==address && slot->width==width && slot->readable){{
   *fault=0U;
   if(slot->private_storage){{__CPROVER_assert(slot->initialized,"spx-caller-private-read-initialized");return slot->value;}}
   public_read=1U;
  }}
 }}
 __CPROVER_assert(public_read,"spx-caller-readable-frame");
 if(!public_read){{*fault=1U;return 0U;}}
 uint32_t value=0U;
 for(uint32_t byte=0;byte<width;byte++)value|=(uint32_t)spx_mutable_byte(memory->world,address+byte)<<(8U*byte);
 *fault=0U;return value;
}}
static void spx_caller_write(struct spx_caller_memory *memory,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault) {{
 uint32_t public_write=0U;
 for(uint32_t i=0;i<{capacity}U;i++){{
  struct spx_caller_slot *slot=&memory->slots[i];
  if(slot->address==address && slot->width==width && slot->writable){{
   if(slot->private_storage){{
    slot->value=value & (uint32_t)((UINT64_C(1)<<(8U*width))-1U);
    slot->initialized=1U;memory->private_writes++;*fault=0U;return;
   }}else public_write=1U;
  }}
 }}
 __CPROVER_assert(public_write,"spx-caller-writable-frame");
 if(!public_write){{*fault=1U;return;}}
 spx_mutable_event(memory->world,address,width,value,0U,0U);*fault=0U;
}}
static uint32_t spx_caller_private_value(const struct spx_caller_memory *memory,uint32_t address,uint32_t width) {{
 for(uint32_t i=0;i<{capacity}U;i++){{
  const struct spx_caller_slot *slot=&memory->slots[i];
  if(slot->address==address && slot->width==width && slot->private_storage){{
   __CPROVER_assert(slot->initialized,"spx-caller-private-transport-initialized");return slot->value;
  }}
 }}
 __CPROVER_assert(0U,"spx-caller-private-transport-present");return 0U;
}}
'''.strip()
    if private_byte_capacity:
        from .bisimulation_caller_private_bytes import extend_private_bytes_runtime
        source=extend_private_bytes_runtime(source,capacity,private_byte_capacity)
    return source.splitlines()
