"""Borrowed typed records over the caller's existing physical byte world.

The relation names actual C fields and a finite incoming object inventory. It
checks their C types, contents, canonical pointer identities and frames. Objects
must remain live for the operation; allocation, release and moving that inventory
require a separate lifetime rule. No record declaration establishes that premise.

Native offsets describe the original representation, not host sizeof/offsetof.
Ordinary authored structs therefore retain their natural host layout. Logical
state projections can gather globals without inventing a contiguous native object.
Identity representations transport addresses only, including null and aliases.
Their zero-size checker objects grant no readable bytes or native lifetime.
Service results may introduce further address identities, bounded by the checked
call inventory. They do not introduce storage objects or allocation generations.
"""
from dataclasses import dataclass
import json
from pathlib import Path
import re

from .component_c_v5 import _c
from .relation_ir import RelationSortV1

U32 = RelationSortV1('bitvector', width=32)


def require(value, message):
    if not value:
        raise ValueError('caller records: '+message)


def _path(parts):
    require(isinstance(parts, list) and parts and isinstance(parts[0], str), 'field path is empty')
    result = ''
    for part in parts:
        if type(part) is int:
            require(0 <= part <= 255, 'field index is outside the supported record shape')
            result += f'[{part}]'
        else:
            require(isinstance(part, str) and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', part),
                    'field path must contain C member names and constant indices')
            result += '.'+part
    return result


def _type(identity):
    return 'struct spx_opaque_'+_c(identity)+'_v5'


def _identity_results(spec, bundle):
    types = {row['id'] for row in spec['types'] if row.get('representation') == 'identity'}
    results = {}
    for service in bundle.interface.services:
        signature = bundle.intent.schema.signature_index[service.signature_id]
        if len(signature.results) == 1:
            result = signature.results[0]
            if result.interpretation == 'value' and result.type_id in types:
                require(result.access == 'none' and result.extent['kind'] == 'none'
                        and result.provider_domain is None and result.resource_kind is None,
                        'an identity result cannot grant contents, access or lifetime')
                results[service.identity] = result.type_id
    return results


def checked_record_specification(definition, bundle):
    spec = definition.get('records')
    if spec is None:
        return None
    require(isinstance(spec, dict) and set(spec) == {'header', 'lifetime', 'types', 'objects', 'projections', 'state'},
            'record relation fields differ')
    header = Path(spec['header'])
    require(isinstance(spec['header'], str) and str(header) == spec['header'] and not header.is_absolute()
            and '..' not in header.parts and header.suffix == '.h'
            and re.fullmatch(r'[A-Za-z_0-9./-]+', spec['header']), 'record header path is invalid')
    require(spec['lifetime'] == 'operation', 'record lifetime needs a checked transition rule')
    types = bundle.intent.schema.type_index
    require(isinstance(spec['types'], list) and 1 <= len(spec['types']) <= 32, 'invalid record type inventory')
    layouts = {}
    for row in spec['types']:
        require(isinstance(row, dict) and set(row)-{'representation'} == {'id', 'extent', 'fields', 'subobjects'}, 'record type fields differ')
        identity = row['id']
        require(identity in types and types[identity].kind == 'opaque' and identity not in layouts,
                'record type must name a distinct declared opaque C type')
        identity_only = row.get('representation') == 'identity'
        require('representation' not in row or identity_only, 'unsupported record representation')
        require(type(row['extent']) is int and
                (row['extent'] == 0 if identity_only else 1 <= row['extent'] <= 256), 'invalid native record extent')
        require(isinstance(row['fields'], list) and len(row['fields']) <= 64, 'invalid record field inventory')
        require(isinstance(row['subobjects'], list) and len(row['subobjects']) <= 32, 'invalid subobject inventory')
        require(not identity_only or not row['fields'] and not row['subobjects'],
                'an identity representation cannot grant fields or subobjects')
        layouts[identity] = row
    def field(row, *, projection=False):
        common = {'path', 'kind', 'writable'}
        if row.get('kind') == 'reference':
            common |= {'type_id', 'nullable'}
            require(row['type_id'] in layouts
                    and type(row['nullable']) is bool, 'invalid record reference type or nullability')
        else:
            require(row.get('kind') in {'word', 'byte'}, 'unsupported record field kind')
        placement = ({'address'} if 'address' in row else {'value'}) if projection else {'offset'}
        require(set(row) == common | placement and type(row['writable']) is bool, 'record field binding differs')
        _path(row['path'])
        if 'value' in placement:
            require(not row['writable'], 'a computed state value must be framed')
    for row in spec['types']:
        occupied = set(); paths = set()
        for member in row['fields']:
            require(isinstance(member, dict), 'invalid field')
            field(member)
            offset = member['offset']; path = _path(member['path'])
            width = 1 if member['kind'] == 'byte' else 4
            require(type(offset) is int and 0 <= offset <= row['extent']-width and path not in paths
                    and not occupied & set(range(offset, offset+width)), 'native record fields overlap or escape their extent')
            occupied.update(range(offset, offset+width)); paths.add(path)
        for member in row['subobjects']:
            require(isinstance(member, dict) and set(member) == {'path', 'type_id', 'offset'}
                    and member['type_id'] in layouts, 'invalid typed subobject')
            require(layouts[member['type_id']].get('representation') != 'identity',
                    'an identity representation cannot name embedded storage')
            _path(member['path'])
            require(type(member['offset']) is int and 0 <= member['offset']
                    and member['offset']+layouts[member['type_id']]['extent'] <= row['extent'],
                    'native subobject escapes its parent')
            # Subobject pointers must describe the same fields, not an unrelated
            # address alias with a compatible C tag.
            for nested in layouts[member['type_id']]['fields']:
                expected = {**nested, 'path': member['path']+nested['path'],
                            'offset': member['offset']+nested['offset']}
                require(expected in row['fields'], 'subobject fields do not preserve the parent relation')
    require(isinstance(spec['objects'], list) and len(spec['objects']) <= 32
            and isinstance(spec['projections'], list) and len(spec['projections']) <= 32,
            'invalid object inventory')
    objects = {}
    for row in spec['objects']:
        require(isinstance(row, dict) and set(row) == {'id', 'type_id', 'address', 'count'}, 'object fields differ')
        require(row['type_id'] in layouts and type(row['count']) is int and 1 <= row['count'] <= 32,
                'object needs a known type and fixed incoming count')
        require(layouts[row['type_id']].get('representation') != 'identity' or row['count'] == 1,
                'identity representations do not define array strides')
        require(isinstance(row['id'], str) and row['id'] and row['id'] not in objects, 'duplicate object identity')
        objects[row['id']] = row
    for row in spec['projections']:
        require(isinstance(row, dict) and set(row) == {'id', 'type_id', 'fields'}
                and row['type_id'] in types and types[row['type_id']].kind == 'opaque', 'invalid state projection')
        require(layouts.get(row['type_id'], {}).get('representation') != 'identity',
                'an identity representation cannot project storage fields')
        require(isinstance(row['id'], str) and row['id'] and row['id'] not in objects, 'duplicate object identity')
        require(isinstance(row['fields'], list) and 1 <= len(row['fields']) <= 64, 'invalid projected fields')
        paths = set()
        for member in row['fields']:
            require(isinstance(member, dict), 'invalid projected field')
            field(member, projection=True)
            path = _path(member['path'])
            require(path not in paths, 'duplicate projected field')
            paths.add(path)
        objects[row['id']] = row
    require(objects or definition.get('local_records') or _identity_results(spec, bundle), 'record relation has no objects')
    states = {s.value.identity: s for s in bundle.interface.state if types[s.value.type_id].kind == 'opaque'}
    require(isinstance(spec['state'], dict) and set(spec['state']) == set(states), 'record state coverage differs')
    for name, identity in spec['state'].items():
        state = states[name]
        require(identity in objects and state.initial is None and state.value.interpretation == 'value'
                and state.value.type_id == objects[identity]['type_id'], 'record state binding differs')
    return spec


def record_type_ids(definition, bundle):
    spec = checked_record_specification(definition, bundle)
    return set() if spec is None else {row['id'] for row in spec['types']} | {row['type_id'] for row in spec['projections']}


def record_type_check_source(definition, bundle):
    """C11 nominal checks, separate from the Windows-mode execution model.

    goto-cc's Windows parser does not accept _Generic. Its GCC C11 parser checks
    these unevaluated type expressions using the same bound header and uint32_t
    definitions. No operation executes in that compiler mode. The actual paired
    program continues to use the existing PE32 compiler policy.
    """
    spec=checked_record_specification(definition,bundle)
    require(spec is not None, 'type check needs a record relation')
    lines=['#include "portable-component-implementation.h"','#include '+json.dumps(spec['header'])]
    for row in [*spec['types'],*spec['projections']]:
        identity=row.get('type_id',row.get('id'))
        for member in row['fields']:
            source='&((('+_type(identity)+' *)0)->'+_path(member['path'])[1:]+')'
            ctype=(_type(member['type_id'])+' *' if member['kind']=='reference' else
                   'uint8_t' if member['kind']=='byte' else 'uint32_t')
            lines.append(f'_Static_assert(_Generic(({source}),{ctype} *:1,default:0),"record field type");')
        for member in row.get('subobjects',[]):
            source='&((('+_type(identity)+' *)0)->'+_path(member['path'])[1:]+')'
            lines.append(f'_Static_assert(_Generic(({source}),{_type(member["type_id"])} *:1,default:0),"record subobject type");')
    return '\n'.join([*lines,'void spx_check_record_types(void){}'])+'\n'


@dataclass
class RecordTransport:
    declarations: list[str]
    runtime: list[str]
    initializers: list[str]
    spans: list[str]
    state: dict[str, str]
    types: set[str]
    identity_results: dict[str, str]

    def decode(self, type_id, address):
        require(type_id in self.types, 'opaque input has no checked record type')
        return f'spx_record_decode_{_c(type_id)}({address})'

    def encode(self, type_id, pointer):
        require(type_id in self.types, 'opaque output has no checked record type')
        return f'spx_record_encode_{_c(type_id)}({pointer})'


def render_record_transport(definition, bundle, lower, *, bulk_operations=False):
    spec = checked_record_specification(definition, bundle)
    if spec is None:
        return None
    require(type(bulk_operations) is bool, 'invalid bulk record transport mode')
    layouts = {row['id']: row for row in spec['types']}
    identity_types = {name for name, row in layouts.items() if row.get('representation') == 'identity'}
    identity_results = _identity_results(spec, bundle)
    declarations = ['#include '+json.dumps(spec['header'])]
    initialization = []; spans = []; fields = []; identities = []; state_objects = {}; incoming_objects = []
    def scalar(raw):
        lowered = lower(raw)
        require(lowered.sort == U32, 'record address/value must be an unsigned word')
        initialization.append(f'__CPROVER_assert({lowered.defined},"spx-record-binding-defined");')
        return lowered.value
    def add_field(member, source, address, constant=None, *, raw=False):
        expression = source if raw else source+_path(member['path'])
        index = len(fields)
        initialization.append(f'spx_record_cells[{index}].address={address or "0U"};')
        initialization.append(f'spx_record_cells[{index}].mapped={int(address is not None)}U;')
        initialization.append(f'spx_record_cells[{index}].writable={int(member["writable"])}U;')
        width = 1 if member['kind']=='byte' else 4
        initialization.append(f'spx_record_cells[{index}].width={width}U;')
        if constant is not None:
            initialization.append(f'spx_record_cells[{index}].bits={constant};')
        if address is not None:
            spans.append(f'spx_caller_public_span(&m.memory,spx_record_cells[{index}].address,{width}U);')
        fields.append((member, expression, address is not None))
    for i, row in enumerate(spec['objects']):
        layout = layouts[row['type_id']]; name = f'spx_record_object_{i}'
        incoming_objects.append('&'+name)
        if row['type_id'] in identity_types:
            # A zero-size checker object permits equality/passing but rejects
            # source dereferences. It is never mapped to native storage. Equal
            # physical addresses decode to the first token, preserving aliases
            # without assuming pairwise-distinct incoming pointer values.
            declarations += [f'static uint8_t {name}[0];', f'static uint32_t {name}_address;']
            initialization.append(f'{name}_address={scalar(row["address"])};')
            pointer = f'({_type(row["type_id"])} *){name}'
            identities.append((row['type_id'], pointer, name+'_address'))
            state_objects[row['id']] = f'spx_record_decode_{_c(row["type_id"])}({name}_address)'
            continue
        if not layout['fields']:
            require(not layout['subobjects'], 'raw byte storage has no typed subobjects')
            extent = row['count']*layout['extent']
            require(extent<=256,'raw byte object budget exceeded')
            declarations += [f'static uint8_t {name}[{extent}];', f'static uint32_t {name}_address;']
            initialization.append(f'{name}_address={scalar(row["address"])};')
            initialization.append(f'__CPROVER_assert({name}_address!=0U && (uint64_t){name}_address+{extent}U<=UINT64_C(4294967296),"spx-record-object-domain");')
            state_objects[row['id']] = f'({_type(row["type_id"])} *)&{name}[0]'
            for j in range(extent):
                source=f'{name}[{j}]'; address=f'({name}_address+{j}U)'
                identities.append((row['type_id'],f'({_type(row["type_id"])} *)&{source}',address))
                add_field({'kind':'byte','writable':True},source,address,raw=True)
            continue
        declarations += [f'static {_type(row["type_id"])} {name}[{row["count"]}];', f'static uint32_t {name}_address;']
        initialization += [f'{_type(row["type_id"])} arbitrary_record_{i}[{row["count"]}];',
                           *[f'{name}[{j}]=arbitrary_record_{i}[{j}];' for j in range(row['count'])]]
        initialization.append(f'{name}_address={scalar(row["address"])};')
        initialization.append(f'__CPROVER_assert({name}_address!=0U && (uint64_t){name}_address+{row["count"]*layout["extent"]}U<=UINT64_C(4294967296),"spx-record-object-domain");')
        state_objects[row['id']] = f'&{name}[0]'
        for j in range(row['count']):
            source = f'{name}[{j}]'; address = f'({name}_address+{j*layout["extent"]}U)'
            identities.append((row['type_id'], '&'+source, address))
            for member in layout['fields']:
                add_field(member, source, f'({address}+{member["offset"]}U)')
            for member in layout['subobjects']:
                pointer = '&'+source+_path(member['path'])
                identities.append((member['type_id'], pointer, f'({address}+{member["offset"]}U)'))
    for i, row in enumerate(spec['projections']):
        name = f'spx_record_projection_{i}'
        incoming_objects.append('&'+name)
        declarations.append(f'static {_type(row["type_id"])} {name};')
        initialization += [f'{_type(row["type_id"])} arbitrary_projection_{i};', f'{name}=arbitrary_projection_{i};']
        state_objects[row['id']] = '&'+name
        for member in row['fields']:
            add_field(member, name, scalar(member['address']) if 'address' in member else None,
                      scalar(member['value']) if 'value' in member else None)
    require(len(fields) <= 256 and (fields or definition.get('local_records') or identity_types), 'record cell budget exceeded')
    declarations += ['struct spx_record_cell {uint32_t address,mapped,writable,width,bits,incoming;};',
                     f'static struct spx_record_cell spx_record_cells[{max(1,len(fields))}];',
                     'static uint32_t spx_record_service_active;']
    if bulk_operations:
        snapshot_capacity = definition['event_capacity']
        require(type(snapshot_capacity) is int and 1 <= snapshot_capacity <= 64, 'invalid record snapshot capacity')
        declarations += [f'static uint32_t spx_record_snapshots[{snapshot_capacity}][{max(1,len(fields))}];',
                         f'static uint32_t spx_record_snapshot_present[{snapshot_capacity}];',
                         'static const void *spx_record_snapshot_owner;']
    types = record_type_ids(definition, bundle)
    returned = {}
    for type_id in sorted(set(identity_results.values())):
        capacity = sum(row['maximum_calls'] for row in definition['services']
                       if identity_results.get(row['id']) == type_id)
        require(1 <= capacity <= 64, 'identity result capacity exceeds the checked call inventory')
        tokens = []
        for i in range(capacity):
            name = f'spx_record_returned_{_c(type_id)}_{i}'
            declarations += [f'static uint8_t {name}[0];', f'static uint32_t {name}_address,{name}_present;']
            tokens.append((f'({_type(type_id)} *){name}', name+'_address', name+'_present'))
            incoming_objects.append('&'+name)
        returned[type_id] = tokens
    runtime = ['static uint32_t spx_record_incoming_object(const void *pointer){(void)pointer;return '+
               (' || '.join(f'__CPROVER_same_object(pointer,{name})' for name in incoming_objects) or '0U')+';}']
    for type_id in sorted(types):
        selected = [(p, a) for t, p, a in identities if t == type_id]
        introduced = returned.get(type_id, [])
        ctype = _type(type_id)+' *'
        runtime += [f'static {ctype} spx_record_decode_{_c(type_id)}(uint32_t address){{', 'if(!address)return 0;',
                    *[f'if(address=={a})return {p};' for p, a in selected],
                    *[f'if({present} && address=={a})return {p};' for p, a, present in introduced],
                    '__CPROVER_assert(0U,"spx-record-reference-related");__CPROVER_assume(0);return 0;}',
                    f'static uint32_t spx_record_encode_{_c(type_id)}({ctype} pointer){{', 'if(!pointer)return 0U;',
                    *[f'if(pointer=={p})return {a};' for p, a in selected],
                    *[f'if({present} && pointer=={p})return {a};' for p, a, present in introduced],
                    '__CPROVER_assert(0U,"spx-record-pointer-related");__CPROVER_assume(0);return 0U;}']
        if introduced:
            runtime += [f'static void spx_record_return_{_c(type_id)}(uint32_t address){{', 'if(!address)return;',
                        *[f'if(address=={a})return;' for _, a in selected],
                        *[f'if({present} && address=={a})return;' for _, a, present in introduced],
                        *[f'if(!{present}){{{a}=address;{present}=1U;return;}}' for _, a, present in introduced],
                        '__CPROVER_assert(0U,"spx-record-return-identity-capacity");__CPROVER_assume(0);}']
        # Equal physical references must name the same actual C object, including
        # embedded subobjects. Different layouts may not counterfeit aliasing.
        for i, (p, a) in enumerate(selected):
            for q, b in selected[:i]:
                if type_id not in identity_types:
                    initialization.append(f'__CPROVER_assert(({a}=={b})==({p}=={q}),"spx-record-reference-alias");')
    runtime += ['static uint32_t spx_record_get(uint32_t cell){', 'switch(cell){']
    for i, (member, source, _) in enumerate(fields):
        expression = f'spx_record_encode_{_c(member["type_id"])}({source})' if member['kind'] == 'reference' else source
        nonnull = f'__CPROVER_assert({source}!=0,"spx-record-reference-nonnull");' if member['kind'] == 'reference' and not member['nullable'] else ''
        runtime.append(f'case {i}U:{nonnull}return {expression};')
    runtime += ['default:__CPROVER_assert(0U,"spx-record-cell-index");return 0U;}}',
                'static void spx_record_set(uint32_t cell,uint32_t bits){switch(cell){']
    for i, (member, source, _) in enumerate(fields):
        expression = f'spx_record_decode_{_c(member["type_id"])}(bits)' if member['kind'] == 'reference' else ('(uint8_t)bits' if member['kind']=='byte' else 'bits')
        nonnull = '__CPROVER_assert(bits!=0U,"spx-record-reference-nonnull");' if member['kind'] == 'reference' and not member['nullable'] else ''
        runtime.append(f'case {i}U:{nonnull}{source}={expression};break;')
    runtime += ['default:__CPROVER_assert(0U,"spx-record-cell-index");}}',
                'static uint32_t spx_record_current(uint32_t cell){',
                f'__CPROVER_assert(cell<{len(fields)}U,"spx-record-current-cell");',
                'return spx_record_service_active?spx_record_cells[cell].bits:spx_record_get(cell);}',
                # Keep the offset theorem explicit while making extraction
                # total, as in the existing sparse-history word-byte reader.
                # Rechecking a variable shift through the entire memory history
                # otherwise duplicates the field-range obligation at each read.
                'static uint8_t spx_record_byte(uint32_t bits,uint32_t offset){',
                '__CPROVER_assert(offset<4U,"spx-record-byte-index");',
                'return (uint8_t)(offset==0U?bits:offset==1U?bits>>8U:offset==2U?bits>>16U:bits>>24U);}',
                'static uint8_t spx_record_read(void *opaque,uint32_t address,uint8_t stored){(void)opaque;',
                f'for(uint32_t i=0;i<{len(fields)}U;i++){{const struct spx_record_cell *cell=&spx_record_cells[i];',
                'if(cell->mapped && address>=cell->address && (uint64_t)address<(uint64_t)cell->address+cell->width)',
                'return spx_record_byte(spx_record_current(i),address-cell->address);}return stored;}']
    if bulk_operations:
        runtime += ['static void spx_record_snapshot(void *opaque,uint32_t index){',
                    f'__CPROVER_assert(index<{snapshot_capacity}U,"spx-record-snapshot-index");',
                    '__CPROVER_assert(!spx_record_snapshot_owner || spx_record_snapshot_owner==opaque,"spx-record-snapshot-owner");',
                    'spx_record_snapshot_owner=opaque;',
                    '__CPROVER_assert(!spx_record_snapshot_present[index],"spx-record-snapshot-fresh");',
                    f'for(uint32_t i=0;i<{len(fields)}U;i++)spx_record_snapshots[index][i]=spx_record_current(i);',
                    'spx_record_snapshot_present[index]=1U;}',
                    'static uint32_t spx_record_snapshot_read(void *opaque,uint32_t index,uint32_t address,uint8_t *result){',
                    f'__CPROVER_assert(index<{snapshot_capacity}U,"spx-record-snapshot-index");',
                    '__CPROVER_assert(spx_record_snapshot_owner==opaque && spx_record_snapshot_present[index],"spx-record-snapshot-present");',
                    f'for(uint32_t i=0;i<{len(fields)}U;i++){{const struct spx_record_cell *cell=&spx_record_cells[i];',
                    'if(cell->mapped && address>=cell->address && (uint64_t)address<(uint64_t)cell->address+cell->width){',
                    '*result=spx_record_byte(spx_record_snapshots[index][i],address-cell->address);return 1U;}}return 0U;}']
    effect_byte = ('spx_mutable_history_byte((const struct spx_mutable_world *)opaque,address,'
                   '((const struct spx_mutable_world *)opaque)->count)' if bulk_operations else
                   'event->service?__CPROVER_uninterpreted_service_byte(event->position,address):'
                   '(uint8_t)(event->value>>(8U*(address-event->address)))')
    runtime += [
                'static void spx_record_apply(void *opaque,const struct spx_mutable_event *event){(void)opaque;',
                f'for(uint32_t i=0;i<{len(fields)}U;i++){{struct spx_record_cell *cell=&spx_record_cells[i];',
                'if(!cell->mapped)continue;',
                # A readonly field has no writeback. Check its whole frame once
                # before taking that branch, rather than reconstructing every
                # byte and pointer through unrelated memory-history effects.
                '__CPROVER_assert(cell->writable || event->extent==0U ||',
                '(uint64_t)event->address+event->extent<=cell->address ||',
                '(uint64_t)cell->address+cell->width<=event->address,"spx-record-service-frame");',
                'if(!cell->writable)continue;',
                'uint32_t bits=spx_record_service_active?cell->bits:spx_record_get(i);',
                'for(uint32_t j=0;j<cell->width;j++){uint32_t address=cell->address+j;',
                'if(address>=event->address && (uint64_t)address<(uint64_t)event->address+event->extent){',
                f'uint32_t byte={effect_byte};',
                'bits=(bits&~(255U<<(8U*j)))|(byte<<(8U*j));}}',
                'if(spx_record_service_active)cell->bits=bits;else spx_record_set(i,bits);}}',
                'static void spx_record_begin_service(void){',
                '__CPROVER_assert(!spx_record_service_active,"spx-record-synchronous-service");',
                f'for(uint32_t i=0;i<{len(fields)}U;i++)spx_record_cells[i].bits=spx_record_get(i);',
                'spx_record_service_active=1U;}',
                'static void spx_record_end_service(void){',
                f'for(uint32_t i=0;i<{len(fields)}U;i++)spx_record_set(i,spx_record_cells[i].bits);',
                'spx_record_service_active=0U;}',
                'static void spx_record_frame(void){',
                '__CPROVER_assert(!spx_record_service_active,"spx-record-no-active-service");',
                f'for(uint32_t i=0;i<{len(fields)}U;i++){{const struct spx_record_cell *cell=&spx_record_cells[i];',
                'uint32_t bits=spx_record_get(i);if(!cell->writable)',
                '__CPROVER_assert(bits==cell->incoming,"spx-record-field-frame");}}',
                'static uint32_t spx_record_native_access(uint32_t address,uint32_t width,uint32_t permission){',
                'if(width!=1U && width!=2U && width!=4U)return 0U;',
                'if((uint64_t)address+width>UINT64_C(4294967296))return 0U;',
                'for(uint32_t j=0;j<width;j++){uint32_t covered=0U;',
                f'for(uint32_t i=0;i<{len(fields)}U;i++){{const struct spx_record_cell *cell=&spx_record_cells[i];',
                'if(cell->mapped && (permission==1U || cell->writable) && address+j>=cell->address &&',
                '(uint64_t)address+j<(uint64_t)cell->address+cell->width)covered=1U;}if(!covered)return 0U;}return 1U;}',
                'static void spx_record_initialize(void){',
                f'for(uint32_t i=0;i<{len(fields)}U;i++){{struct spx_record_cell *a=&spx_record_cells[i];',
                'if(a->mapped){__CPROVER_assert((uint64_t)a->address+a->width<=UINT64_C(4294967296),"spx-record-nonwrapping-cell");',
                'for(uint32_t j=0;j<i;j++){const struct spx_record_cell *b=&spx_record_cells[j];',
                '__CPROVER_assert(!b->mapped || (uint64_t)a->address+a->width<=b->address ||',
                '(uint64_t)b->address+b->width<=a->address,"spx-record-physical-field-alias");}',
                'a->bits=0U;for(uint32_t j=0;j<a->width;j++)a->bits|=(uint32_t)__CPROVER_uninterpreted_readonly_byte(a->address+j)<<(8U*j);}',
                'a->incoming=a->bits;spx_record_set(i,a->bits);}',
                f'for(uint32_t i=0;i<{len(fields)}U;i++)__CPROVER_assert(spx_record_get(i)==spx_record_cells[i].incoming,"spx-record-incoming-contents");}}']
    initialization.append('spx_record_initialize();')
    return RecordTransport(declarations, runtime, initialization, spans,
                           {name: state_objects[identity] for name, identity in spec['state'].items()}, types, identity_results)
