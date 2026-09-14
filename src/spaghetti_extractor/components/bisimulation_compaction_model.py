"""Render the checked local byte-compaction domain around ordinary source cuts."""
import re

from .bisimulation_compaction_contract import require
from .bisimulation_compaction_template import TEMPLATE
from .bisimulation_compaction_domain import compaction_public_domain
from .bisimulation_harness import _architectural_state_equalities
from .bisimulation_mutable_memory import sparse_mutable_memory_runtime
from .machine_overlay_v5 import _view_runtime_helpers
from .capabilities import spx_portable_reference_runtime_v5_source


def _insert(text, insertions):
    positions = []
    for anchor, code in insertions:
        require(text.count(anchor['text']) == 1, 'source anchor is absent or ambiguous')
        index = text.index(anchor['text'])
        require(index == 0 or text[index-1] == '\n', 'source anchor is not at a line boundary')
        if anchor['position'] == 'after':
            index += len(anchor['text'])
        positions.append((index, code))
    require(len({i for i, _ in positions}) == len(positions), 'source model anchors overlap')
    for index, code in sorted(positions, reverse=True):
        text = text[:index] + code + text[index:]
    return text


def render_compaction_source(text, boundary, contract):
    locals_ = contract['source_locals']
    restores = ''.join(f'{locals_[role]}=spx_cut.{role};' for role in ('input','output','removed','scratch'))
    arguments = ','.join(locals_[k] for k in ('input','output','removed')) + ',&' + locals_['scratch']
    anchors = {'entry': boundary['entry'], **boundary['exits']}
    insertions = [(contract['begin'], '  goto spx_region_entry;\n')]
    for name, rva in [(contract['entry_cut'], contract['entry_rva']), (contract['exit_cut'], contract['exit_rva'])]:
        restore = 'spx_region_entry: '+restores+'__CPROVER_assert(1,"source-cut-invariant");' if name == contract['entry_cut'] else ''
        code = f'  do {{ __CPROVER_assert(1,"source-cut-invariant:{name}");observe_loop({rva}U,{arguments});return {rva}U;{restore} }} while(0);\n'
        insertions.append((anchors[name], code))
    return _insert(text, insertions)


def render_compaction_model(contract, *, source_function, original_function, parameters):
    registers, cells = contract['registers'], contract['private_cells']
    refined = contract.get('runtime_revision', 2) == 3
    pending = lambda index, byte: tuple(byte('text_address+'+index+suffix) for suffix in ('', '+1U'))
    incoming = compaction_public_domain(
        text_nul_byte='__CPROVER_uninterpreted_readonly_byte(text_address+scratch_extent-1U)',
        scratch_probe_byte='__CPROVER_uninterpreted_readonly_byte(probe)',
        pending_bytes=pending('input', lambda a: '__CPROVER_uninterpreted_readonly_byte('+a+')') if refined else None)
    outgoing = compaction_public_domain(
        text_nul_byte='spx_mutable_byte(&right,text_address+scratch_extent-1U)',
        scratch_probe_byte='spx_mutable_byte(&right,probe)',
        input_value='state.'+registers['input'], output_value='state.'+registers['output'],
        removed_value='memory.private_removed',
        pending_bytes=pending('state.'+registers['input'], lambda a: 'spx_mutable_byte(&right,'+a+')')) if refined else {}
    lines = ['static struct {uint32_t input,output,removed;spx_view_v5 scratch;} spx_cut;',
             'static spx_machine_state observed_state;', 'static spx_step_result observed_step;',
             'static uint32_t observed_removed,observed_extent;',
             'static void observe_loop(uint32_t cut,uint32_t input,uint32_t output,uint32_t removed,const spx_view_v5 *scratch){']
    predicates = {'cut': 'cut==observed_step.target_rva', 'input': f'input==observed_state.{registers["input"]}',
        'output': f'output==observed_state.{registers["output"]}', 'count': 'removed==observed_removed',
        'cursor-order': 'output<=input', 'count-invariant': 'removed==input-output',
        'progress': f'(cut!={contract["entry_rva"]}U) | ((input>spx_cut.input) & (input<observed_extent))'}
    fields = ['base.' + k for k in ['domain','object','generation','offset','extent','permissions']]
    fields += ['extent','element_width','context','access_context','read_u8','write_u8','read','write']
    predicates.update({'view-'+f: f'scratch->{f}==spx_cut.scratch.{f}' for f in fields})
    lines += [f' __CPROVER_assert({predicate},"loop-observer-{name}");' for name,predicate in predicates.items()]
    lines += ['}']
    declarations, reads, writes, initializers = [], [], [], []
    for cell in cells:
        field = 'private_' + cell['name']; width, offset = cell['width'], cell['offset']
        declarations.append(f'uint{8*width}_t {field};')
        reads.append(f' if(address==m->stack+{offset}U && width=={width}U)return m->{field};')
        writes.append(f' if(address==m->stack+{offset}U && width=={width}U){{m->{field}=(uint{8*width}_t)value;return;}}')
        if cell['name'] == 'removed':
            initializers.append(f' memory.{field}=removed;')
        else:
            initializers.append(f' uint{8*width}_t {field}; memory.{field}={field};')
    offsets = contract['stack_offsets']
    low = max(0, *(-v for v in offsets.values()))
    high = max(contract['private_extent'], *(v+1 for v in offsets.values()))
    expression = lambda v: f'stack-{abs(v)}U' if v < 0 else f'stack+{v}U'
    initial = [' spx_machine_state initial,state;', *(f'initial.{k}={expression(v)};' for k,v in offsets.items())]
    initial += [f'initial.{registers[k]}={k}_address;' for k in ('text','scratch')]
    initial += [f'initial.{registers[k]}={k};' for k in ('input','output')]
    initial += ['state=initial;']
    frame = [v for v in _architectural_state_equalities('state','initial')
             if re.match(r'state\.(\w+)', v)[1] not in contract['clobbers']]
    arguments = ['&text' if k == contract['text_parameter'] else '0' for k in parameters]
    values = {'MEMORY_RUNTIME': '\n'.join(sparse_mutable_memory_runtime(1)),
        'PUBLIC_DOMAIN': '\n'.join(f' __CPROVER_assume({predicate});' for predicate in incoming.values()),
        'OUTGOING_DOMAIN': '\n'.join(f'  __CPROVER_assert({predicate},"loop-all-exits-{name}");' for name,predicate in outgoing.items()),
        'TEXT_PERMISSIONS': '3' if refined else '1',
        'TEXT_RUNTIME_WRITE': ',.write=spx_mutable_write' if refined else '',
        'TEXT_VIEW_WRITE': ',.write_u8=spx_component_view_write,.write=spx_component_view_write_span' if refined else '',
        'VIEW_RUNTIME': '\n'.join(_view_runtime_helpers(need_read=True,need_write=True)),
        'REFERENCE_RUNTIME': spx_portable_reference_runtime_v5_source(), 'OBSERVER': '\n'.join(lines),
        'PRIVATE_DECLARATIONS': ''.join(declarations), 'PRIVATE_READS': '\n'.join(reads),
        'PRIVATE_WRITES': '\n'.join(writes), 'PRIVATE_INITIALIZERS': '\n'.join(initializers),
        'PRIVATE_EXTENT': str(contract['private_extent']),
        'STACK_DOMAIN': f'stack>={low}U && (uint64_t)stack+{high}U<=UINT64_C(4294967296)',
        'INITIAL_STATE': ''.join(initial), 'IMAGE_BASE': str(contract['image_base']),
        'ORIGINAL_FUNCTION': original_function, 'ENTRY_RVA': str(contract['entry_rva']),
        'SOURCE_CALL': source_function+'('+','.join(arguments)+')',
        'INPUT_REGISTER': registers['input'], 'OUTPUT_REGISTER': registers['output'], 'FRAME': ' && '.join(frame)}
    source = TEMPLATE.replace('memory.removed','memory.private_removed')
    for key, value in values.items():
        source = source.replace('@'+key+'@', value)
    require(not re.search(r'@[A-Z_]+@', source), 'unexpanded model token')
    return source
