"""Render a checked entry body and all outgoing local-memory guarantees."""
import re

from .bisimulation_compaction_model import _insert
from .bisimulation_compaction_domain import compaction_public_domain
from .bisimulation_fresh_buffer_contract import require
from .bisimulation_fresh_buffer_template import TEMPLATE
from .bisimulation_harness import _architectural_state_equalities
from .bisimulation_mutable_memory import sparse_mutable_memory_runtime
from .capabilities import spx_portable_reference_runtime_v5_source
from .machine_overlay_v5 import _view_runtime_helpers


def render_fresh_buffer_source(data):
    contract, boundary = data['contract'], data['boundary']
    anchors = {'entry': boundary['entry'], **boundary['exits']}
    names = contract['source_locals']
    arguments = ','.join(names[k] for k in ['input', 'output', 'removed']) + ',&' + names['scratch']
    return _insert(data['text'], [
        (anchors[contract['entry_cut']], '  __CPROVER_assert(1,"source-cut-invariant");\n'),
        (anchors[contract['exit_cut']], f'  __CPROVER_assert(1,"source-cut-invariant:{contract["exit_cut"]}");\n'
         f'  observe_entry({contract["exit_rva"]}U,{arguments});return {contract["exit_rva"]}U;\n')])


def render_fresh_buffer_model(data):
    contract = data['contract']
    runtime = '\n'.join(sparse_mutable_memory_runtime(2)).replace(
        'uint8_t result = __CPROVER_uninterpreted_readonly_byte(address);', 'uint8_t result = fresh_zero_byte(address);')
    clobbers = {'eax', 'ebx', 'ecx', 'edx', 'esi', 'esp', 'ebp', 'cf', 'zf', 'sf', 'of', 'pf', 'eflags'}
    frame = [v for v in _architectural_state_equalities('state', 'initial')
             if re.match(r'state\.(\w+)', v)[1] not in clobbers]
    admission = compaction_public_domain(text_nul_byte='spx_mutable_byte(&right,text_address+scratch_extent-1U)',
        scratch_probe_byte='spx_mutable_byte(&right,probe)', input_value='state.esi', output_value='state.ecx',
        removed_value='memory.word_7', pending_bytes=('spx_mutable_byte(&right,text_address+state.esi)',
                                                   'spx_mutable_byte(&right,text_address+state.esi+1U)'))
    roles = {name: role for role, name in contract['parameter_roles'].items()}
    arguments = [{'context': '&context', 'text': '&text'}.get(roles[name], '0') for name in data['parameters']]
    values = {'LOOP_ADMISSION': '\n'.join(f'  __CPROVER_assert({p},"entry-consumer-{n}");' for n, p in admission.items()),
        'MEMORY_RUNTIME': runtime, 'VIEW_RUNTIME': '\n'.join(_view_runtime_helpers(need_read=True, need_write=True)),
        'REFERENCE_RUNTIME': spx_portable_reference_runtime_v5_source(),
        'PRESERVED_FRAME': ('uint32_t continuation_slot,continuation_byte;\n'
            ' __CPROVER_assume(continuation_slot<8U && continuation_byte<10U);\n'
            ' __CPROVER_assert(' + ' && '.join(frame) + ',"entry-preserved-machine-frame");'),
        'ORIGINAL_FUNCTION': data['original_function'], 'SOURCE_CALL': data['source_function']+'('+','.join(arguments)+')',
        **{k.upper(): str(contract[k]) for k in ['entry_rva', 'exit_rva', 'image_base', 'length_pointer']}}
    for name, site in contract['calls'].items():
        values.update({name.upper()+'_'+k.upper(): str(v) for k, v in site.items()})
    source = TEMPLATE.replace('(@LENGTH_POINTER@U+4U)', 'UINT64_C('+str(contract['length_pointer']+4)+')')
    for key, value in values.items():
        source = source.replace('@'+key+'@', value)
    require(not re.search(r'@[A-Z_]+@', source), 'unexpanded entry model token')
    return source
