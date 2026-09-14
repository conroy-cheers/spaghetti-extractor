"""Bind a checked local edit to a retained conditional application's context.

The old model must reproduce exactly before its ordinary and edited contexts
can be compared. Optional bounded-query transport adds a processed-model relation
and retains the original query scope; neither step discharges a baseline theorem.
"""

import json
from pathlib import Path
import re
import shutil
import subprocess
import time

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file
from .bisimulation_compilation import workspace_compile_command
from .bisimulation_region_context import check_inert_region_markers
from .bisimulation_source_edit import prepare_pure_region_comparison
from .bisimulation_edit_prefix import comparison_effects_preserved
from .conditional_check_result import checked_conditional_packet
from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from .interface_ir import ProofKernelComponentInterface
from .refinement_v5 import _logical_projection


POLICY = 'exact-conditional-source-edit-context-v1'


def _require(condition, message):
    if not condition:
        raise ValueError('baseline edit context: ' + message)


def baseline_interface_bindings(packet, baseline, local):
    """Keep the public V5 and lowered proof-interface digest namespaces distinct."""
    intent = ComponentInterfaceIntentV1.parse(local['inputs']['interface_intents']['original'])
    bundle = compile_component_interface_v5(intent)
    interface = bundle.interface.interface_sha256
    logical = ProofKernelComponentInterface.parse(_logical_projection(bundle)).sha256
    _require(packet['inputs'].get('interface_sha256') == interface
             and baseline['bindings'].get('interface_sha256') == logical,
             'baseline packet binds a different or unspecified interface contract')
    return {'interface_sha256': interface, 'logical_interface_sha256': logical}


def check_baseline_edit_context(*, evidence, obligation_id, local, source_package,
                                baseline_source_package, workspace, goto_cc, goto_instrument,
                                mark_source, timeout_seconds, timings=None, transport_queries=False, previous=None):
    """Reproduce the old model and check the local query in its exact environment.

    The full retained evidence directory is required. A diagnostic compilation
    manifest alone intentionally omits recursively included C dependencies.
    """
    started = time.monotonic()
    evidence, workspace = Path(evidence), Path(workspace)
    workspace.mkdir(parents=True, exist_ok=False)
    _require(local['status'] == 'satisfied', 'local edit must be checked first')
    packet_path = evidence / 'conditional-engine-result.json'
    packet = json.loads(packet_path.read_text())
    baseline, assurance = checked_conditional_packet(packet, local['component_id'])
    interfaces = baseline_interface_bindings(packet, baseline, local)
    sources, boundary = local['inputs']['source_packages'], local['inputs']['boundary']
    _require(baseline['bindings']['implementation_sha256'] == sources['original']['implementation_sha256'],
             'baseline source implementation differs')
    selected = [row for row in baseline['checks'] if row['operation_id'] == boundary['operation_id']
                and row['obligation_id'] == obligation_id]
    _require(len(selected) == 1 and selected[0].get('goto_model_sha256') is not None,
             'selected baseline obligation is absent or uncompiled')
    check = selected[0]
    _require(baseline['checker'].get('goto_cc_sha256') == sha256_file(goto_cc) == local['tools']['goto_cc']
             and baseline['checker'].get('cbmc_sha256') == local['tools']['cbmc']
             and sha256_file(goto_instrument) == local['tools']['goto_instrument'], 'compiler/checker binding differs')
    prior = evidence / 'proof-diagnostics'
    manifests = []
    for path in prior.glob('operation-*-obligation-*/compile-inputs.json'):
        value = json.loads(path.read_text())
        if (value.get('operation_id'), value.get('obligation_id')) == (boundary['operation_id'], obligation_id):
            manifests.append((path, value))
    _require(len(manifests) == 1, 'retained compile manifest is absent or ambiguous')
    manifest_path, manifest = manifests[0]
    relative = manifest_path.parent.relative_to(prior)
    command = manifest['command']
    _require(command[0] == str(goto_cc) and command[1] == '--i386-win32'
             and manifest.get('compiler_workspace') == '/tmp/spx-proof'
             and manifest.get('compiler_workspace_host') == '$PROOF_ROOT', 'unsupported compiler recipe')
    allowed_defines = {'-DSPX_CONDITIONAL_RUNTIME_CONTRACT_' + row['contract_sha256'] for row in assurance['contracts']}
    seen_defines, outputs = set(), []
    i = 2
    while i < len(command):
        argument = command[i]
        if argument in {'-I', '-o'}:
            _require(i + 1 < len(command), 'truncated compiler argument')
            value = command[i + 1]
            _require(value == '$PROOF_ROOT' or value.startswith(('$PROOF_ROOT/', '/nix/store/')), 'external compiler path is not retained')
            if argument == '-o':
                outputs.append(value)
            i += 2
        else:
            _require(argument in allowed_defines or (argument.startswith(('$PROOF_ROOT/', '/nix/store/'))
                     and argument.endswith('.c')), 'unsupported compiler option')
            if argument in allowed_defines:
                seen_defines.add(argument)
            i += 1
    expected_output = '$PROOF_ROOT/' + str(relative / 'model.goto')
    _require(outputs == [expected_output] and seen_defines == allowed_defines, 'compiled output or assurance recipe differs')
    for row in manifest['files']:
        path = Path(row['path'].removeprefix('$PROOF_ROOT/'))
        _require(not path.is_absolute() and '..' not in path.parts and sha256_file(prior / path) == row['sha256'],
                 'retained generated source differs')
    original_file = baseline_source_package / 'sources' / boundary['source']
    edited_file = source_package / 'sources' / boundary['source']
    for side, path in [('original', original_file), ('edited', edited_file)]:
        rows = [row for row in sources[side]['files'] if row['path'] == boundary['source']]
        _require(len(rows) == 1 and sha256_file(path) == rows[0]['sha256'], 'authored edit bytes changed')
    wrappers = []
    for argument in command:
        if argument.startswith('$PROOF_ROOT/') and re.fullmatch(r'source-\d{4}\.c', Path(argument).name):
            path = Path(argument.removeprefix('$PROOF_ROOT/'))
            match = re.fullmatch('#include "component-bisimulation.h"\n#include "([^"\n]+)"\n', (prior / path).read_text())
            if match and match[1].endswith('/' + boundary['source']):
                original_path = Path(match[1])
                _require(original_path.is_relative_to('/nix/store')
                         and sha256_file(original_path) == sha256_file(original_file), 'authored baseline source differs')
                wrappers.append((path, match[1]))
    _require(len(wrappers) == 1, 'authored wrapper is absent or ambiguous')
    wrapper, included = wrappers[0]
    _, markers = mark_source(original_file.read_bytes().decode(), boundary)
    measurements = []

    def run(name, arguments, root, phase):
        tick = time.monotonic()
        result = subprocess.run(workspace_compile_command(arguments, root), capture_output=True,
                                text=True, timeout=timeout_seconds, check=False)
        measurements.append({'phase': phase, 'step': name, 'seconds': time.monotonic() - tick})
        (root / (name + '.stdout')).write_text(result.stdout)
        (root / (name + '.stderr')).write_text(result.stderr)
        _require(result.returncode == 0, name + ': ' + result.stderr[-2000:])
        return result.stdout

    def compile_variant(name, source=None, marked=False):
        root = workspace / name
        root.mkdir()
        for path in prior.rglob('*'):
            if path.is_file() and path.suffix in {'.c', '.h'}:
                _require(path.resolve().is_relative_to(prior.resolve()), 'generated source escapes retained evidence')
                destination = root / path.relative_to(prior)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
        if source is not None:
            text = source.read_bytes().decode()
            target = root / wrapper.parent / 'source-edit-input.c'
            target.write_text(mark_source(text, boundary)[0] if marked else text)
            old = (root / wrapper).read_text()
            _require(old.count(included) == 1, 'authored wrapper include changed')
            (root / wrapper).write_text(old.replace(included, target.name))
        arguments = [v.replace('$PROOF_ROOT', str(root.resolve())) for v in command]
        run(name + '-compile', arguments, root, 'compiler')
        model = root / relative / 'model.goto'
        result = {'model_sha256': sha256_file(model)}
        if name == 'baseline':
            _require(result['model_sha256'] == check['goto_model_sha256'], 'original model does not reproduce exactly')
        for key, flag, field in [('functions', '--show-goto-functions', 'functions'), ('symbols', '--show-symbol-table', 'symbolTable')]:
            data = json.loads(run(name + '-' + key, [str(goto_instrument), flag, '--json-ui', str(model.resolve())], root, 'model'))
            values = [v[field] for v in data if field in v]
            _require(len(values) == 1, 'ambiguous compiler inventory')
            result[key] = {v['name']: v for v in values[0]} if key == 'functions' else values[0]
        return result

    try:
        ordinary = compile_variant('baseline')
        marked = compile_variant('baseline-marked', original_file, True)
        edited = compile_variant('edited', edited_file)
        edited_marked = compile_variant('edited-marked', edited_file, True)
        function = sources['original']['operation_symbols'][boundary['operation_id']]
        erasures = {}
        tick = time.monotonic()
        for name, before, after in [('baseline', ordinary, marked), ('edited', edited, edited_marked)]:
            erasures[name] = check_inert_region_markers(original_functions=before['functions'], original_symbols=before['symbols'],
                marked_functions=after['functions'], marked_symbols=after['symbols'], function=function, markers=list(markers.values()))
        candidate = prepare_pure_region_comparison(original_functions=marked['functions'], original_symbols=marked['symbols'],
            edited_functions=edited_marked['functions'], edited_symbols=edited_marked['symbols'], function=function,
            entry=markers['entry'], exits={k:v for k,v in markers.items() if k != 'entry'})
        _require(candidate['source'] == (workspace.parent / 'comparison/comparison.c').read_text(),
                 'local query differs in the baseline proof environment')
        measurements.append({'phase': 'model', 'step': 'baseline-context-correspondence', 'seconds': time.monotonic() - tick})
        context = {'policy': POLICY, 'status': 'matched', 'authorizing': False,
            'baseline_packet_sha256': sha256_file(packet_path), 'assurance': assurance,
            'operation_id': boundary['operation_id'], 'obligation_id': obligation_id,
            'baseline_obligation_status': check['status'], 'interface_bindings': interfaces,
            'models': {name: value['model_sha256'] for name, value in [('baseline', ordinary), ('baseline-marked', marked),
                ('edited', edited), ('edited-marked', edited_marked)]}, 'marker_erasure': erasures,
            'local_query_output_sha256': local['query']['output_sha256'],
            'local_comparison_goto_sha256': local['comparison_goto_sha256'],
            'proof_environment_comparison': {k:v for k,v in candidate.items() if k != 'source'},
            'local_query_binding_sha256': canonical_sha256_v3(local['comparison']),
            'baseline_queries_imported': False, 'activation_authorized': False}
        if transport_queries:
            from .bisimulation_source_edit_queries import transport_baseline_queries
            context['query_transport'] = transport_baseline_queries(evidence=evidence, context=context, local=local,
                models={name: workspace / name / relative / 'model.goto' for name in context['models']},
                symbols={'baseline-marked': marked['symbols'], 'edited-marked': edited_marked['symbols']},
                function=function, markers=markers, workspace=workspace / 'query-transport',
                cbmc=Path(goto_cc).with_name('cbmc'), goto_cc=goto_cc, timeout_seconds=timeout_seconds, timings=measurements, previous=previous)
            context['baseline_queries_imported'] = True
        return context
    finally:
        if timings is not None:
            timings.extend(measurements)
            timings.append({'phase': 'total', 'step': 'baseline-edit-context', 'seconds': time.monotonic() - started})


def validate_baseline_edit_context(context, *, packet, packet_sha256, local):
    """Cross-bind embedding evidence; optional query transport is validated separately."""
    _require(isinstance(context, dict) and context.get('policy') == POLICY
             and context.get('status') == 'matched' and context.get('authorizing') is False
             and context.get('baseline_queries_imported') is ('query_transport' in context)
             and ('query_transport' in context) is local.get('baseline_query_transport', False)
             and context.get('activation_authorized') is False,
             'context policy, status or authority differs')
    _require(set(context.get('models', {})) == {'baseline', 'baseline-marked', 'edited', 'edited-marked'}
             and set(context.get('marker_erasure', {})) == {'baseline', 'edited'}
             and all(row.get('status') == 'matched-inert-region-markers' for row in context['marker_erasure'].values()),
             'context model or marker-erasure coverage differs')
    baseline, assurance = checked_conditional_packet(packet, local['component_id'])
    expected = baseline_interface_bindings(packet, baseline, local)
    candidates = [row for row in baseline['checks'] if row['operation_id'] == context.get('operation_id')
                  and row['obligation_id'] == context.get('obligation_id')]
    _require(len(candidates) == 1 and context.get('obligation_id') == local.get('baseline_obligation')
             and context.get('operation_id') == local['inputs']['boundary']['operation_id'], 'context obligation differs')
    _require(context.get('baseline_packet_sha256') == packet_sha256 and context.get('assurance') == assurance
             and context.get('interface_bindings') == expected
             and context.get('baseline_obligation_status') == candidates[0]['status']
             and context.get('models', {}).get('baseline') == candidates[0].get('goto_model_sha256')
             and context.get('local_query_output_sha256') == local.get('query', {}).get('output_sha256')
             and context.get('local_comparison_goto_sha256') == local.get('comparison_goto_sha256')
             and context.get('local_query_binding_sha256') == canonical_sha256_v3(local['comparison']),
             'context evidence or local query binding differs')
    compared = context.get('proof_environment_comparison', {})
    _require(compared.get('binding_sha256') == canonical_sha256_v3(compared.get('binding'))
             and compared.get('binding', {}).get('source_sha256') == local['comparison']['binding']['source_sha256']
             and comparison_effects_preserved(compared) and compared.get('parent_evidence_imported') is False
             and local['query']['status'] == 'satisfied', 'context does not bind the checked local comparison')
    for name, digest in context['models'].items():
        matches = [row['sha256'] for row in local['artifacts']
                   if row['path'].startswith('baseline-context/' + name + '/') and row['path'].endswith('/model.goto')]
        _require(matches == [digest], 'context model artifact differs')
