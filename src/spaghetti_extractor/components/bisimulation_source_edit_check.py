"""Check a configured ordinary-C edit without importing its baseline's proofs."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file, write_json
from .bisimulation_compilation import workspace_compile_command
from .bisimulation_query_evidence import CbmcQueryEvidence
from .bisimulation_source_inventory import compile_source_inventory
from .bisimulation_region_context import check_inert_region_markers
from .bisimulation_source_edit import prepare_pure_region_comparison
from .cbmc_backend import run_cbmc_properties
from .component_c_v5 import render_component_c_headers_v5
from .inductive_refinement import _write_cbmc_stdint
from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from .source import load_component_source_package, component_operation_symbols
from .source_profile import check_component_source_profile


POLICY = 'configured-source-edit-check-v1'
OPTIONS = ['--function', 'compare_regions', '--json-ui', '--trace', '--bounds-check',
           '--pointer-check', '--signed-overflow-check', '--undefined-shift-check',
           '--div-by-zero-check', '--unwinding-assertions']


def _require(condition, message):
    if not condition:
        raise ValueError('source edit: ' + message)


def checked_edit_boundary(value, source, *, minimum_exits=2):
    """Exact manual anchors locate proof marks; compiled erasure validates them."""
    _require(isinstance(value, dict) and set(value) == {'operation_id', 'source', 'entry', 'exits'},
             'boundary fields differ')
    _require(value['operation_id'] in component_operation_symbols(source), 'unknown operation')
    _require(value['source'] in {v['path'] for v in source['files'] if v['path'].endswith('.c')},
             'boundary source is not an authored C file')
    exits = value['exits']
    _require(isinstance(exits, dict) and len(exits) >= minimum_exits and 'entry' not in exits and all(
        isinstance(k, str) and re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', k) for k in exits), 'invalid exit ports')
    for anchor in [value['entry'], *exits.values()]:
        _require(isinstance(anchor, dict) and set(anchor) == {'position', 'text'}
                 and anchor['position'] in {'before', 'after'} and isinstance(anchor['text'], str)
                 and anchor['text'].endswith('\n') and anchor['text'].strip(), 'invalid line anchor')
    return {**value, 'exits': dict(sorted(exits.items()))}


def _marked_source(text, boundary):
    markers = {'entry': 'spx_edit_region_entry', **{
        name: 'spx_edit_region_exit_' + str(i) for i, name in enumerate(sorted(boundary['exits']))}}
    insertions = []
    for name, anchor in [('entry', boundary['entry']), *boundary['exits'].items()]:
        _require(text.count(anchor['text']) == 1, 'anchor must occur exactly once: ' + name)
        index = text.index(anchor['text'])
        _require(index == 0 or text[index - 1] == '\n', 'anchor does not start on a complete line')
        if anchor['position'] == 'after':
            index += len(anchor['text'])
        insertions.append((index, '  ' + markers[name] + '();\n'))
    _require(len({v[0] for v in insertions}) == len(insertions), 'overlapping marker positions')
    for index, call in sorted(insertions, reverse=True):
        text = text[:index] + call + text[index:]
    return ''.join('void ' + name + '(void) {}\n' for name in markers.values()) + text, markers


def check_source_edit(*, component_id, interface_package, baseline_interface_package,
                      source_package, baseline_source_package, boundary, workspace,
                      goto_cc, goto_instrument, cbmc, timeout_seconds=30,
                      previous=None, timings=None, baseline_evidence=None, baseline_obligation=None, baseline_query_transport=False):
    """Compile both complete source packages and prove their selected pure edit.

    A successful source comparison may transport separately scoped bounded query
    results. A changed interface or unsupported region stays incomplete; neither
    step supplies a complete baseline application theorem.
    """
    started = time.monotonic()
    workspace = Path(workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=False)
    result = {'policy': POLICY, 'component_id': component_id, 'authorizing': False,
              'activation_authorized': False, 'baseline_proof_imported': False,
              'status': 'incomplete', 'checks': [], 'inputs': {}, 'models': {},
              'query_reuse': {'executed_queries': 0, 'reused_queries': 0}}
    _require(type(baseline_query_transport) is bool and (not baseline_query_transport or baseline_evidence is not None),
             'query transport requires retained baseline evidence')
    if baseline_query_transport:
        result['baseline_query_transport'] = True
    if baseline_evidence is not None:
        result['baseline_obligation'] = baseline_obligation

    def measured(phase, step, function):
        tick = time.monotonic()
        try:
            return function()
        finally:
            if timings is not None:
                timings.append({'phase': phase, 'step': step, 'seconds': time.monotonic() - tick})

    def run(command, root, name, phase='compiler'):
        process = measured(phase, name, lambda: subprocess.run(workspace_compile_command(command, root),
            capture_output=True, text=True, timeout=timeout_seconds, check=False))
        (root / (name + '.stdout')).write_text(process.stdout)
        (root / (name + '.stderr')).write_text(process.stderr)
        _require(process.returncode == 0, name + ': ' + process.stderr[-2000:])
        return process.stdout

    def compile_package(package, source, headers, side, marked):
        root = workspace / (side + ('-marked' if marked else '-ordinary'))
        inventory, command = compile_source_inventory(package=package, source=source, headers=headers,
            root=root, function=function, goto_cc=goto_cc, goto_instrument=goto_instrument, run=run,
            transform=(lambda path, text: _marked_source(text, boundary)[0]
                       if path == boundary['source'] else text) if marked else None)
        result['models'][root.name] = {'goto_model_sha256': sha256_file(root / 'model.goto'), 'compile_command': command}
        return inventory

    try:
        sources = {side: load_component_source_package(package) for side, package in [
            ('original', baseline_source_package), ('edited', source_package)]}
        interfaces = {side: ComponentInterfaceIntentV1.parse(json.loads((package / 'component-interface-intent-v1.json').read_text()))
                      for side, package in [('original', baseline_interface_package), ('edited', interface_package)]}
        result['inputs'] = {'source_packages': sources,
            'interface_intents': {k: v.to_payload() for k, v in interfaces.items()}, 'boundary': boundary}
        _require(all(v['lift_unit_id'] == component_id for v in sources.values())
                 and all(v.component_id == component_id for v in interfaces.values()), 'component identity differs')
        _require(interfaces['original'].to_payload() == interfaces['edited'].to_payload(),
                 'interface contract changed; a compatibility proof is required')
        symbols = component_operation_symbols(sources['original'])
        _require(symbols == component_operation_symbols(sources['edited']), 'operation bindings changed')
        boundary = checked_edit_boundary(boundary, sources['original'])
        checked_edit_boundary(boundary, sources['edited'])
        function = symbols[boundary['operation_id']]
        result['inputs']['boundary'] = boundary
        for package in [baseline_source_package, source_package]:
            profile = check_component_source_profile(package=package)
            _require(profile['status'] == 'satisfied', 'ordinary source profile rejected: ' + json.dumps(profile['issues']))
        bundle = compile_component_interface_v5(interfaces['original'])
        headers = render_component_c_headers_v5(bundle, symbols)
        result['headers_sha256'] = {name: hashlib.sha256(text.encode()).hexdigest() for name, text in headers.items()}
        result['tools'] = {name: sha256_file(Path(path)) for name, path in [('goto_cc', goto_cc), ('goto_instrument', goto_instrument), ('cbmc', cbmc)]}
        marked = {}
        _, markers = _marked_source((baseline_source_package / 'sources' / boundary['source']).read_bytes().decode('utf-8'), boundary)
        result['marker_erasure'] = {}
        for side, package in [('original', baseline_source_package), ('edited', source_package)]:
            ordinary = compile_package(package, sources[side], headers, side, False)
            marked[side] = compile_package(package, sources[side], headers, side, True)
            result['marker_erasure'][side] = measured('model', side + '-marker-erasure', lambda: check_inert_region_markers(
                original_functions=ordinary['functions'], original_symbols=ordinary['symbols'],
                marked_functions=marked[side]['functions'], marked_symbols=marked[side]['symbols'],
                function=function, markers=list(markers.values())))
        candidate = measured('model', 'edit-comparison', lambda: prepare_pure_region_comparison(
            original_functions=marked['original']['functions'], original_symbols=marked['original']['symbols'],
            edited_functions=marked['edited']['functions'], edited_symbols=marked['edited']['symbols'],
            function=function, entry=markers['entry'], exits={k: v for k, v in markers.items() if k != 'entry'}))
        result['comparison'] = {k: v for k, v in candidate.items() if k != 'source'}
        root = workspace / 'comparison'
        root.mkdir()
        (root / 'comparison.c').write_text(candidate['source'])
        _write_cbmc_stdint(root / 'stdint.h')
        run([str(goto_cc), '--i386-win32', '-nostdinc', '-I', '.', 'comparison.c', '-o', 'model.goto'], root, 'compile-comparison')
        previous_query = None
        if previous is not None:
            old = json.loads((previous / 'source-edit-evidence.json').read_text())
            _require(old.get('policy') == POLICY and old.get('authorizing') is False
                     and old.get('receipt_sha256') == canonical_sha256_v3({k: v for k, v in old.items() if k != 'receipt_sha256'}),
                     'previous source-edit evidence is stale')
            if 'query' in old:
                previous_query = {'directory': previous / 'source-edit-models/comparison/query-evidence',
                    'outputs': {old['query']['output_sha256']}, 'goto_model_sha256': old['comparison_goto_sha256'],
                    'assurance': None, 'checker': {'goto_cc_sha256': old['tools']['goto_cc'], 'cbmc_sha256': old['tools']['cbmc']}}
        model = root / 'model.goto'
        cache = CbmcQueryEvidence(model=model, checker=cbmc, compiler=goto_cc, output=root / 'query-evidence', previous=previous_query)
        result['comparison_goto_sha256'] = sha256_file(model)
        result['checker_options'] = OPTIONS
        query = measured('solver', 'source-edit', lambda: run_cbmc_properties(
            command=[str(cbmc), str(model), *OPTIONS], timeout_seconds=timeout_seconds,
            query_evidence=cache, output_prefix=root / 'query'))
        result.update(status=query['status'], query=query,
            query_reuse={'executed_queries': cache.executed, 'reused_queries': cache.reused})
        result['checks'].append({'status': query['status'], 'code': query['code'], 'detail': query.get('detail')})
        if baseline_evidence is not None and query['status'] == 'satisfied':
            from .bisimulation_source_edit_context import check_baseline_edit_context
            result['baseline_context'] = check_baseline_edit_context(evidence=baseline_evidence,
                obligation_id=baseline_obligation, local=result, source_package=source_package,
                baseline_source_package=baseline_source_package, workspace=workspace / 'baseline-context',
                goto_cc=goto_cc, goto_instrument=goto_instrument, mark_source=_marked_source,
                timeout_seconds=timeout_seconds, timings=timings, transport_queries=baseline_query_transport, previous=previous)
            result['checks'].append({'status': 'satisfied', 'code': 'source_edit_baseline_context_matched', 'detail': None})
    except (ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired) as error:
        if result['status'] != 'violated':
            result['status'] = 'incomplete'
        result['checks'].append({'status': 'incomplete', 'code': 'source_edit_unsupported', 'detail': str(error)})
    result['inputs_sha256'] = canonical_sha256_v3(result['inputs'])
    result['artifacts'] = [{'path': str(path.relative_to(workspace)), 'sha256': sha256_file(path)}
                           for path in sorted(workspace.rglob('*')) if path.is_file()]
    result['receipt_sha256'] = canonical_sha256_v3(result)
    write_json(workspace / 'source-edit-evidence.json', result)
    if timings is not None:
        timings.append({'phase': 'total', 'step': 'source-edit-check', 'seconds': time.monotonic() - started})
    return result
