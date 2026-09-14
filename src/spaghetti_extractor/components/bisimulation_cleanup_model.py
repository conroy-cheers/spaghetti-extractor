"""Render the admitted terminal region against complete dependency contracts."""
import re

from .bisimulation_cleanup_contract import require
from .bisimulation_cleanup_template import TEMPLATE
from .bisimulation_compaction_model import _insert
from .bisimulation_compaction_domain import compaction_public_domain
from .bisimulation_mutable_memory import sparse_mutable_memory_runtime
from .machine_overlay_v5 import _view_runtime_helpers
from .capabilities import spx_portable_reference_runtime_v5_source


def render_cleanup_source(data):
    contract = data['contract']
    restores = ''.join(f'{contract["source_locals"][role]}=spx_cut.{role};' for role in ['input', 'output', 'removed', 'scratch'])
    anchors = {'entry': data['boundary']['entry'], **data['boundary']['exits']}
    return _insert(data['text'], [(contract['begin'], '  goto spx_tail;\n'),
        (anchors[contract['entry_cut']], '  spx_tail: '+restores+'\n  __CPROVER_assert(1,"source-cut-invariant");\n')])


def render_cleanup_model(data):
    contract, domain = data['contract'], data['domain']
    views = contract['views']; spans = [(domain['views']['module'][2], 4)]
    spans += [(views[n]['address'], views[n]['extent']) for n in ['notice', 'window', 'edit']]
    merged = []
    for start, size in sorted(spans):
        if merged and start < merged[-1][0]+merged[-1][1]:
            low, old_size = merged[-1]; merged[-1] = (low, max(low+old_size, start+size)-low)
        else:
            merged.append((start, size))
    memory = '\n'.join(sparse_mutable_memory_runtime(4, preserved_spans=merged)).replace(
        'uint8_t result = __CPROVER_uninterpreted_readonly_byte(address);', 'uint8_t result = current_byte(address);')
    values = {'MEMORY_RUNTIME': memory, 'VIEW_RUNTIME': '\n'.join(_view_runtime_helpers(need_read=True, need_write=True)),
        'REFERENCE_RUNTIME': spx_portable_reference_runtime_v5_source(), 'IMAGE_BASE': str(contract['image_base']),
        'IMAGE_SIZE': str(contract['image_size']), 'IMAGE_END': str(contract['image_base']+contract['image_size']),
        'RESOURCE': str(domain['result_address']), 'RESOURCE_EXTENT': str(domain['result_extent']),
        'CAPTION_EXTENT': str(views['caption']['extent']), 'ENTRY_RVA': str(contract['entry_rva']),
        'ORIGINAL_FUNCTION': data['original_function'], 'SUPPLIER_ENTRY': str(domain['callee']),
        'RESULT_REFERENCE': ','.join(f'UINT64_C({domain["result_reference"][n]})' for n in ['domain', 'object', 'generation', 'offset', 'extent', 'permissions']),
        'SUPPLIER_CLOBBERS': '\n'.join(f'  {{uint32_t value; output->{name}=value;}}' for name in domain['clobbers'])}
    values.update({macro: str(views[role]['address']) for macro, role in [('CAPTION', 'caption'), ('WINDOW', 'window'), ('EDIT', 'edit'), ('SUPPRESS', 'notice')]})
    for name, site in contract['calls'].items():
        values.update({name.upper()+'_'+field.upper(): str(value) for field, value in site.items()})
    live = []
    for word in domain['stack_words']:
        if word['exit']['kind'] == 'constant':
            offset = word['offset']-16
            address = f'm->stack-{abs(offset)}U' if offset < 0 else f'm->stack+{offset}U'
            live.append(f'  __CPROVER_assert(machine_read(m,{address},4U,&fault)=={word["exit"]["value"]}U && !fault,"tail-supplier-live-word");')
    values['SUPPLIER_LIVE_WORDS'] = '\n'.join(live)
    roles = {name: role for role, name in contract['parameter_roles'].items()}
    args = {'context': '&context', 'text': '&text', 'suppress_notice': '&notice', 'main_window': '&window', 'edit_window': '&edit', 'caption': '&caption'}
    values['SOURCE_CALL'] = data['source_function']+'('+','.join(args[roles[name]] for name in data['parameters'])+')'
    predicates = compaction_public_domain(text_nul_byte='current_byte(text_address+scratch_extent-1U)',
        scratch_probe_byte='current_byte(probe)', pending_bytes=('current_byte(text_address+input)', 'current_byte(text_address+input+1U)'))
    values['PUBLIC_DOMAIN'] = '\n'.join(' __CPROVER_assume('+v+');' for v in predicates.values())
    result = TEMPLATE
    for key, value in values.items():
        result = result.replace('@'+key+'@', value)
    require(not re.search('@[A-Z_]+@', result), 'unexpanded model token')
    return result
