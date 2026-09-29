"""Transport ordinary C local records through synchronous paired calls.

Native byte offsets are independent of the C layout. The adapter reads the
actual live C fields, checks them through the existing local-object rule, then
writes the paired result back before authored C continues. Packing is not a
lifetime or escape proof. Partial overlaps need a separate representation rule.
"""
from dataclasses import dataclass

from .bisimulation_call_relations import constant
from .bisimulation_caller_records import _path, _type, checked_record_specification
from .component_c_v5 import _c
from .relation_ir import RelationExpressionV1, RelationSortV1

U32 = RelationSortV1('bitvector', width=32)


def require(condition, message):
    if not condition:
        raise ValueError('caller local records: ' + message)


def local_record_definitions(boundary, bundle):
    rows = boundary.get('local_records', [])
    require(isinstance(rows, list) and len(rows) <= 32, 'invalid inventory')
    if not rows:
        return []
    specification = checked_record_specification(boundary, bundle)
    require(specification is not None, 'a bound record layout is required')
    layouts = {row['id']: row for row in specification['types']}
    seen = {row['id'] for row in boundary.get('local_views', [])}
    result = []
    for row in rows:
        require(isinstance(row, dict) and set(row) == {'id', 'type_id', 'address', 'permissions'},
                'definition fields differ')
        require(isinstance(row['id'], str) and row['id'] and row['id'] not in seen,
                'duplicate local identity')
        seen.add(row['id'])
        layout = layouts.get(row['type_id'])
        require(layout is not None and layout['fields'], 'a typed record layout is required')
        require(type(row['permissions']) is int and row['permissions'] in {1, 2, 3}
                and RelationExpressionV1.parse(row['address']).sort == U32,
                'invalid address or permissions')
        covered = {i for field in layout['fields']
                   for i in range(field['offset'], field['offset'] + (1 if field['kind'] == 'byte' else 4))}
        require(covered == set(range(layout['extent'])), 'native padding needs an explicit contents relation')
        require(row['permissions'] != 2 or all(field['writable'] for field in layout['fields']),
                'write-only records cannot frame unread incoming fields')
        result.append({**row, 'layout': layout, 'extent': constant(layout['extent']).to_payload()})
    return result


@dataclass(frozen=True)
class LocalRecordBinding:
    type_id: str
    address: str
    extent: str
    permissions: int
    layout: dict


def local_record_runtime(bindings):
    layouts = {binding.type_id: binding.layout for binding in bindings.values()}
    lines = []
    for identity, layout in sorted(layouts.items()):
        tag = _c(identity)
        lines.extend([
            f'static void spx_local_record_pack_{tag}({_type(identity)} *object,uint8_t *bytes){{',
            '__CPROVER_assert(__CPROVER_r_ok(object,sizeof(*object)),"spx-local-record-readable");',
        ])
        for index, field in enumerate(layout['fields']):
            member = 'object->' + _path(field['path'])[1:]
            if field['kind'] == 'reference':
                if not field['nullable']:
                    lines.append(f'__CPROVER_assert({member}!=0,"spx-local-record-reference-nonnull");')
                value = f'spx_record_encode_{_c(field["type_id"])}({member})'
            else:
                value = member
            lines.append(f'uint32_t field_{index}={value};')
            width = 1 if field['kind'] == 'byte' else 4
            for byte in range(width):
                lines.append(f'bytes[{field["offset"]+byte}U]=(uint8_t)(field_{index}>>{byte*8}U);')
        lines.extend(['}', f'static void spx_local_record_unpack_{tag}({_type(identity)} *object,const uint8_t *bytes){{',
                      '__CPROVER_assert(__CPROVER_w_ok(object,sizeof(*object)),"spx-local-record-writable");'])
        for index, field in enumerate(layout['fields']):
            width = 1 if field['kind'] == 'byte' else 4
            value = '|'.join(f'((uint32_t)bytes[{field["offset"]+byte}U]<<{byte*8}U)' for byte in range(width))
            lines.append(f'uint32_t field_{index}={value};')
            member = 'object->' + _path(field['path'])[1:]
            if field['kind'] == 'reference':
                if not field['nullable']:
                    lines.append(f'__CPROVER_assert(field_{index}!=0U,"spx-local-record-reference-nonnull");')
                value = f'spx_record_decode_{_c(field["type_id"])}(field_{index})'
            else:
                value = f'field_{index}'
            if field['writable']:
                lines.append(f'{member}={value};')
            else:
                lines.append(f'__CPROVER_assert({member}==({value}),"spx-local-record-field-frame");')
        lines.append('}')
    return lines


def pack_local_records(parameters, indices):
    """One byte backing per distinct actual local object; preserve exact aliases."""
    lines = []
    for position, (index, _, binding) in enumerate(parameters):
        extent = binding.layout['extent']
        lines.extend([
            f'__CPROVER_assert(__CPROVER_r_ok(p{index},sizeof(*p{index})),"spx-local-record-live");',
            f'__CPROVER_assert(!spx_record_incoming_object(p{index}),"spx-local-record-incoming-alias");',
            f'uint8_t local_record_storage_{index}[{extent}];',
            f'uint8_t *local_record_bytes_{index}=local_record_storage_{index};',
        ])
        if binding.permissions & 2:
            lines.append(f'__CPROVER_assert(__CPROVER_w_ok(p{index},sizeof(*p{index})),"spx-local-record-writable");')
        for other, _, earlier in parameters[:position]:
            equal_type = int(binding.type_id == earlier.type_id)
            lines.extend([
                f'__CPROVER_assert(!__CPROVER_same_object(p{index},p{other}) ||',
                f' (uint64_t)__CPROVER_POINTER_OFFSET(p{index})+sizeof(*p{index})<=__CPROVER_POINTER_OFFSET(p{other}) ||',
                f' (uint64_t)__CPROVER_POINTER_OFFSET(p{other})+sizeof(*p{other})<=__CPROVER_POINTER_OFFSET(p{index}) ||',
                f' ((void *)p{index}==(void *)p{other} && {equal_type}U),"spx-local-record-source-overlap");',
                f'__CPROVER_assert(((void *)p{index}==(void *)p{other})==({binding.address}=={earlier.address}),',
                ' "spx-local-record-exact-alias");',
                f'if((void *)p{index}==(void *)p{other})local_record_bytes_{index}=local_record_bytes_{other};',
            ])
        if binding.permissions & 1:
            lines.append(f'spx_local_record_pack_{_c(binding.type_id)}(p{index},local_record_bytes_{index});')
        lines.append(f'local_objects[{indices[index]}]=(struct spx_paired_object){{{binding.address},'
                     f'{binding.permissions}U,1U,{binding.extent},local_record_bytes_{index}}};')
    return lines


def unpack_local_records(parameters):
    return [f'spx_local_record_unpack_{_c(binding.type_id)}(p{index},local_record_bytes_{index});'
            for index, _, binding in parameters if binding.permissions & 2]
