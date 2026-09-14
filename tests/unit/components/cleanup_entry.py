"""Real cleanup entry, prepared through public source graphs and compiled locally."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import time

from spaghetti_extractor.components.bisimulation_call_evidence import checker_options
from spaghetti_extractor.components.bisimulation_compaction_inputs import read_inventory, coarsen_inert_cuts
from spaghetti_extractor.components.bisimulation_compaction_domain import compaction_public_domain
from spaghetti_extractor.components.bisimulation_compilation import workspace_compile_command
from .fresh_buffer_frame import check_fresh_buffer_entry_frame
from spaghetti_extractor.components.bisimulation_harness import _architectural_state_equalities
from spaghetti_extractor.components.bisimulation_mutable_memory import sparse_mutable_memory_runtime
from spaghetti_extractor.components.bisimulation_query_evidence import CbmcQueryEvidence
from spaghetti_extractor.components.bisimulation_region_observer import check_marked_region_observer_transport
from spaghetti_extractor.components.bisimulation_source_call_check import checked_source_region_graphs
from spaghetti_extractor.components.bisimulation_source_edit_check import _marked_source
from spaghetti_extractor.components.capabilities import spx_portable_reference_runtime_v5_source
from spaghetti_extractor.components.cbmc_backend import bind_smt_solver, run_cbmc_properties
from spaghetti_extractor.components.machine_overlay_v5 import _view_runtime_helpers
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.util import sha256_file
from ..operator.test_source_call_regions import check as prepare, FIXTURE as SOURCE

FIXTURE = Path(__file__).parents[2] / 'fixtures/metapad-cleanup-entry'


def prepare_entry(root, *, body=None):
    root = Path(root); root.mkdir()
    body = (SOURCE/'cleanup.c').read_text() if body is None else body
    boundary = json.loads((FIXTURE/'boundary.json').read_text())
    preparation = root/'preparation'; preparation.mkdir()
    tick = time.monotonic()
    status, feedback, timings = prepare(preparation, body, boundary=boundary, graph=True)
    if status['status'] != 'complete':
        raise ValueError(str(feedback))
    output = preparation/'feedback'
    prepared = feedback['source_region_graphs']
    graph, = checked_source_region_graphs(prepared, artifacts=output/'source-region-graph-models')
    marked = read_inventory(output/'source-region-graph-models/0000-marked')
    # Both sides of an internal loop-header edge belong to this merged prefix.
    # Only external entries from outside the selected union would be a hole.
    selected = {i for node in graph['regions'] for i in node['instruction_indices']}
    selected_cuts = {graph['cut_sites'][node['entry']] for node in graph['regions']}
    if graph['cut_sites']['entry'] != 0 or any(
            edge['source_instruction'] not in selected | selected_cuts
            for node in graph['regions'] for edge in node['external_interior_entries']):
        raise ValueError('entry prefix has an unproved predecessor')
    identities = {}
    for name in ['input', 'output', 'removed', 'scratch']:
        matches = [key for key, value in marked['symbols'].items()
                   if value.get('baseName') == name and value.get('location', {}).get('function') == 'cleanup'
                   and not value.get('isAuxiliary')]
        if len(matches) != 1:
            raise ValueError('ambiguous outgoing local')
        identities[name] = matches[0]
    footprint = check_fresh_buffer_entry_frame(**marked, function='cleanup', instruction_indices=selected,
        context_parameter='cleanup::context', text_parameter='cleanup::text', scratch_local=identities['scratch'])
    _, markers = _marked_source(body, boundary)
    merged = coarsen_inert_cuts(marked, function='cleanup', markers=markers, keep={'entry', 'loop'})
    source = body.replace(boundary['entry']['text'],
        '  __CPROVER_assert(1,"source-cut-invariant");\n' + boundary['entry']['text'])
    source = source.replace(boundary['exits']['loop']['text'],
        '  __CPROVER_assert(1,"source-cut-invariant:loop");\n'
        '  observe_entry(0x5606U,input,output,removed,&scratch);return 0x5606U;\n'
        + boundary['exits']['loop']['text'])
    (root/'authored.c').write_text(source)
    include = output/'source-region-graph-models/0000-ordinary/include'
    for path in include.iterdir():
        shutil.copyfile(path, root/path.name)
    manifest = json.loads((FIXTURE/'component-exact-c-slice-v1.json').read_text())
    if manifest['slice_sha256'] != canonical_sha256_v3({k:v for k,v in manifest.items() if k != 'slice_sha256'}):
        raise ValueError('original slice receipt changed')
    for row in manifest['files']:
        if sha256_file(FIXTURE/row['path']) != row['sha256']:
            raise ValueError('retained original entry bytes changed')
        if row['path'] != 'behavioral-dispatch.c':
            shutil.copyfile(FIXTURE/row['path'], root/row['path'])
    runtime = '\n'.join(sparse_mutable_memory_runtime(2)).replace(
        'uint8_t result = __CPROVER_uninterpreted_readonly_byte(address);', 'uint8_t result = fresh_zero_byte(address);')
    clobbers = {'eax','ebx','ecx','edx','esi','esp','ebp','cf','zf','sf','of','pf','eflags'}
    frame = [v for v in _architectural_state_equalities('state','initial')
             if re.match(r'state\.(\w+)', v)[1] not in clobbers]
    frame_text = ('uint32_t continuation_slot,continuation_byte;\n'
        ' __CPROVER_assume(continuation_slot<8U && continuation_byte<10U);\n'
        ' __CPROVER_assert(' + ' && '.join(frame) + ',"entry-preserved-machine-frame");')
    admission = compaction_public_domain(text_nul_byte='spx_mutable_byte(&right,text_address+scratch_extent-1U)',
        scratch_probe_byte='spx_mutable_byte(&right,probe)', input_value='state.esi', output_value='state.ecx', removed_value='memory.word_7')
    values = {'LOOP_ADMISSION': '\n'.join(f'  __CPROVER_assert({predicate},"entry-consumer-{name}");' for name,predicate in admission.items()),
              'MEMORY_RUNTIME': runtime, 'VIEW_RUNTIME': '\n'.join(_view_runtime_helpers(need_read=True,need_write=True)),
              'REFERENCE_RUNTIME': spx_portable_reference_runtime_v5_source(), 'PRESERVED_FRAME': frame_text}
    model = (FIXTURE/'pair.c.in').read_text()
    for key, value in values.items():
        model = model.replace('@'+key+'@', value)
    (root/'pair.c').write_text(model)
    return {'marked': merged, 'markers': {k:v for k,v in markers.items() if k in {'entry','loop'}},
            'identities': identities, 'footprint': footprint, 'graph': graph,
            'preparation_seconds': time.monotonic()-tick, 'source_preparation_timings': timings}


def compile_entry(root):
    root = Path(root)
    command = [shutil.which('goto-cc'),'--i386-win32','-nostdinc','-I','.',
        'pair.c','behavioral-fn-000055b7.c','behavioral-support.c','--function','check_entry','-o','model.goto']
    tick = time.monotonic()
    process = subprocess.run(workspace_compile_command(command,root), capture_output=True,text=True,timeout=30)
    if process.returncode:
        raise ValueError(process.stderr)
    seconds = time.monotonic()-tick
    for name, flag in [('functions','--show-goto-functions'),('symbols','--show-symbol-table')]:
        process = subprocess.run(workspace_compile_command([shutil.which('goto-instrument'),flag,'--json-ui','model.goto'],root),
                                 capture_output=True,text=True,check=True,timeout=30)
        (root/(name+'.stdout')).write_text(process.stdout)
    return read_inventory(root), seconds


def checked_entry_transport(data, local):
    marked = data['marked']; identities = data['identities']
    result = check_marked_region_observer_transport(marked_functions=marked['functions'], marked_symbols=marked['symbols'],
        local_functions=local['functions'], local_symbols=local['symbols'], function='cleanup', entry_sync='entry',
        markers=data['markers'], restored_locals={}, cut_results={'loop':0x5606}, observer='observe_entry',
        observer_arguments=[(identities[k],k=='scratch') for k in identities], captured_locals=list(identities.values()),
        control_graph=True)
    for name in ('spx_view_read_u8', 'spx_view_write_u8'):
        # Public preparation binds declarations. The comparison links the
        # existing reference-runtime implementation as an explicit premise.
        if marked['functions'][name]['isBodyAvailable'] or not local['functions'][name]['isBodyAvailable']:
            raise ValueError('byte helper is not an external source dependency')
    return result


def check_entry_properties(root):
    root = Path(root)
    solver = bind_smt_solver(Path(shutil.which('z3')))
    evidence = CbmcQueryEvidence(model=root/'model.goto',checker=Path(shutil.which('cbmc')),
        compiler=Path(shutil.which('goto-cc')),output=root/'query-evidence',smt_solver=solver)
    return run_cbmc_properties(command=[shutil.which('cbmc'),'model.goto','--function','check_entry',
        *checker_options(16,solver)],cwd=root,timeout_seconds=60,query_evidence=evidence,output_prefix=root/'query')
