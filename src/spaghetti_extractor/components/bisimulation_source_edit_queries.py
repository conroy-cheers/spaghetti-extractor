"""Transport completed bounded property checks through a checked pure edit.

The original process output remains evidence about the original model. The
separate processed-context relation supplies the edit substitution premise; no
cache key is rewritten to pretend that CBMC ran on the edited model. Neither
partial checks nor their transport discharge an application obligation.
"""

import json
from pathlib import Path
import shutil
import subprocess
import time
from types import SimpleNamespace

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file
from .bisimulation_query_evidence import CbmcQueryEvidence, previous_proof_queries
from .bisimulation_source_edit_query_context import (
    compare_processed_query_context, summarize_processed_query_context,
)
from .cbmc_backend import run_cbmc_properties

POLICY = 'pure-edit-bounded-query-transport-v1'
_FLAGS = {'--json-ui', '--trace', '--stop-on-fail', '--no-unwinding-assertions', '--no-assertions',
          '--no-standard-checks', '--symex-cache-dereferences', '--no-self-loops-to-assumptions',
          '--reachability-slice-fb', '--slice-formula'}
_VALUES = {'--function', '--object-bits', '--sat-solver', '--unwind', '--unwindset'}


def _require(condition, message):
    if not condition:
        raise ValueError('source edit query transport: ' + message)


def checked_bounded_query_scope(arguments):
    """Preserve loop bounds; reject depth/path/resource shortcuts and unknown flags."""
    _require(isinstance(arguments, list) and arguments and arguments[0] == '$GOTO_MODEL', 'invalid model argument')
    common, properties, values, seen = [], [], {}, set()
    position = 1
    while position < len(arguments):
        flag = arguments[position]
        position += 1
        _require(flag == '--property' or flag in _FLAGS | _VALUES, 'unsupported query option: ' + str(flag))
        _require(flag == '--property' or flag not in seen, 'duplicate query option')
        seen.add(flag)
        if flag in _VALUES or flag == '--property':
            _require(position < len(arguments) and isinstance(arguments[position], str)
                     and arguments[position] and not arguments[position].startswith('--'), 'missing query option value')
            value = arguments[position]
            position += 1
            if flag == '--property':
                properties.append(value)
            else:
                values[flag] = value
                common.extend([flag, value])
        else:
            common.append(flag)
    _require(properties and len(properties) == len(set(properties)), 'missing or duplicate property selection')
    _require({'--json-ui', '--no-unwinding-assertions', '--no-self-loops-to-assumptions', '--function', '--unwind'} <= seen,
             'unsupported progress or entry policy')
    _require(values['--unwind'].isdigit() and int(values['--unwind']) > 0, 'invalid unwind bound')
    _require(values.get('--sat-solver', 'cadical') == 'cadical', 'unsupported solver')
    _require(values.get('--object-bits', '8').isdigit() and 1 <= int(values.get('--object-bits', '8')) <= 32,
             'invalid object encoding')
    bounds = {}
    for item in values.get('--unwindset', '').split(','):
        if not item:
            _require(not values.get('--unwindset'), 'empty unwindset entry')
            continue
        fields = item.split(':')
        _require(len(fields) == 2 and fields[0] and fields[0] not in bounds
                 and fields[1].isdigit() and int(fields[1]) > 0, 'invalid or thread-specific unwindset')
        bounds[fields[0]] = int(fields[1])
    return {'kind': 'bounded-property-checks', 'common_arguments': common, 'property_ids': properties,
            'entry_function': values['--function'], 'unwind': int(values['--unwind']), 'unwindset': bounds,
            'unwinding_assertions': False, 'termination_proved': False}


def retained_bounded_queries(*, evidence, operation_id, obligation_id, assurance, model, cbmc, goto_cc, out):
    """Reparse only complete processes whose bytes are bound by the old packet."""
    previous = previous_proof_queries(evidence, runtime_assurance=assurance)[operation_id, obligation_id]
    _require(not previous.get('coverage_only'), 'baseline has no published property partitions')
    cache = CbmcQueryEvidence(model=model, checker=cbmc, compiler=goto_cc, output=out,
                             previous=previous, assurance=assurance)
    rows = []
    for path in sorted(Path(previous['directory']).glob('*/query.json')):
        record = json.loads(path.read_text())
        binding = record['binding']
        if ('--property' not in binding.get('arguments', [])
                or set(binding['arguments']) & {'--cover', '--show-properties', '--show-loops'}):
            continue
        scope = checked_bounded_query_scope(binding['arguments'])
        _require(set(binding) == {'policy', 'authorizing', 'tools', 'goto_model_sha256', 'arguments', 'assurance', 'cwd'}
                 and isinstance(binding['cwd'], str) and Path(binding['cwd']).is_absolute()
                 and path.parent.name == canonical_sha256_v3(binding) and cache._compatible_previous(binding)
                 and binding.get('policy') == 'exact-compiled-cbmc-query-evidence-v1'
                 and binding.get('authorizing') is False and binding.get('assurance') == assurance
                 and binding.get('tools') == cache.tools and binding.get('goto_model_sha256') == sha256_file(model),
                 'original query model, tools or assurance differs')
        process = cache._read(path.parent, binding, allowed_outputs=previous['outputs'])
        parsed = run_cbmc_properties(command=[], timeout_seconds=1,
            query_evidence=SimpleNamespace(run=lambda *args, **kwargs: process))
        _require(parsed.get('status') == 'satisfied'
                 and set(parsed.get('property_ids', [])) == set(scope['property_ids']),
                 'retained query is not a complete satisfied property selection')
        destination = Path(out) / path.parent.name
        shutil.copytree(path.parent, destination)
        rows.append({'query_sha256': path.parent.name, 'binding': binding, 'scope': scope,
                     'result': parsed, 'source_receipt_sha256': previous['proof_receipt_sha256']})
    _require(rows, 'no completed bounded property query is available')
    return rows


def transport_baseline_queries(*, evidence, context, local, models, symbols, function, markers,
                               workspace, cbmc, goto_cc, timeout_seconds, timings, previous=None):
    """Compare processed models once per query policy, then transport its results."""
    workspace = Path(workspace)
    workspace.mkdir(exist_ok=False)
    rows = retained_bounded_queries(evidence=evidence, operation_id=context['operation_id'],
        obligation_id=context['obligation_id'], assurance=context['assurance'], model=models['baseline'],
        cbmc=cbmc, goto_cc=goto_cc, out=workspace / 'query-evidence')
    groups, reused = {}, 0
    prior_transport = None
    if previous is not None:
        tick = time.monotonic()
        prior = json.loads((Path(previous) / 'source-edit-evidence.json').read_text())
        candidate = prior.get('baseline_context', {}).get('query_transport')
        if (candidate is not None and candidate.get('models') == context['models']
                and candidate.get('baseline_packet_sha256') == context['baseline_packet_sha256']
                and prior.get('tools') == local['tools']
                and prior['comparison']['binding']['source_sha256'] == local['comparison']['binding']['source_sha256']
                and prior.get('checker_options') == local.get('checker_options')):
            _require(prior.get('receipt_sha256') == canonical_sha256_v3({k:v for k,v in prior.items() if k != 'receipt_sha256'}),
                     'previous source-edit receipt differs')
            for artifact in prior['artifacts']:
                path = Path(artifact['path'])
                _require(not path.is_absolute() and '..' not in path.parts
                         and sha256_file(Path(previous) / 'source-edit-models' / path) == artifact['sha256'],
                         'previous source-edit artifact differs')
            validate_transported_queries(candidate, context=prior['baseline_context'], local=prior,
                packet=json.loads((Path(evidence) / 'conditional-engine-result.json').read_text()),
                root=Path(previous) / 'source-edit-models')
            prior_transport = candidate
        timings.append({'phase': 'evidence-reuse', 'step': 'query-context-previous-check', 'seconds': time.monotonic() - tick})
    for row in rows:
        common = row['scope']['common_arguments']
        identity = canonical_sha256_v3(common)
        if identity in groups:
            continue
        root = workspace / identity
        if prior_transport is not None and identity in prior_transport['groups']:
            tick = time.monotonic()
            groups[identity] = prior_transport['groups'][identity]
            shutil.copytree(Path(previous) / 'source-edit-models/baseline-context/query-transport' / identity, root)
            reused += 1
            timings.append({'phase': 'evidence-reuse', 'step': 'query-context-copy', 'seconds': time.monotonic() - tick})
            continue
        root.mkdir()
        summaries = {}
        for side, model in models.items():
            values = {}
            for flag, field in [('--show-goto-functions', 'functions'), ('--show-loops', 'loops')]:
                tick = time.monotonic()
                output = root / (side + '-' + field + '.json')
                with output.open('w') as stream:
                    process = subprocess.run([str(cbmc), str(model), *common, flag], stdout=stream,
                        stderr=subprocess.PIPE, text=True, timeout=timeout_seconds, check=False)
                _require(process.returncode == 0, 'processed inventory failed: ' + process.stderr[-2000:])
                data = json.loads(output.read_text())
                found = [v[field] for v in data if field in v]
                _require(len(found) == 1, 'ambiguous processed inventory')
                values[field] = found[0]
                # Exact model, command and tool inputs are retained. Record the
                # bulky deterministic inventory digest, then retain its checked
                # compact summary instead of copying ~600 MB per variant.
                values[field + '_sha256'] = sha256_file(output)
                output.unlink()
                timings.append({'phase': 'model', 'step': 'query-context-' + side + '-' + field,
                                'seconds': time.monotonic() - tick})
            tick = time.monotonic()
            summaries[side] = summarize_processed_query_context(values['functions'], values['loops'],
                function=function, markers=markers)
            (root / (side + '.json')).write_text(json.dumps(summaries[side]) + '\n')
            (root / (side + '-inventory.json')).write_text(json.dumps({k:v for k,v in values.items() if k.endswith('_sha256')}) + '\n')
            timings.append({'phase': 'model', 'step': 'query-context-' + side + '-correspondence',
                            'seconds': time.monotonic() - tick})
        tick = time.monotonic()
        checked = compare_processed_query_context(summaries, symbols, function=function, markers=markers,
            checked_source=(workspace.parent.parent / 'comparison/comparison.c').read_text())
        groups[identity] = {'common_arguments': common, 'context': checked}
        timings.append({'phase': 'model', 'step': 'query-context-compare', 'seconds': time.monotonic() - tick})
    for row in rows:
        row['context_id'] = canonical_sha256_v3(row['scope']['common_arguments'])
        checked = groups[row['context_id']]['context']
        row['inactive_unwindset'] = {k:v for k,v in row['scope']['unwindset'].items() if k not in checked['loop_ids']}
        _require(set(row['scope']['property_ids']) <= set(checked['property_ids']),
                 'selected query property has no preserved site')
    result = {'policy': POLICY, 'status': 'transported-bounded-property-results', 'authorizing': False,
        'activation_authorized': False, 'application_obligation_discharged': False,
        'baseline_packet_sha256': context['baseline_packet_sha256'], 'assurance': context['assurance'],
        'operation_id': context['operation_id'], 'obligation_id': context['obligation_id'],
        'baseline_obligation_status': context['baseline_obligation_status'], 'models': context['models'],
        'local_query_output_sha256': local['query']['output_sha256'],
        'groups': groups, 'queries': rows, 'executed_application_queries': 0,
        'processed_contexts_reused': reused, 'processed_contexts_executed': len(groups) - reused,
        'transported_queries': len(rows), 'transported_properties': len(set().union(*(set(v['result']['property_ids']) for v in rows)))}
    result['receipt_sha256'] = canonical_sha256_v3(result)
    return result


def validate_transported_queries(transport, *, context, local, packet, root):
    """Recheck retained outputs and the processed relation before public display."""
    from .bisimulation_query_evidence import _output_digests

    root = Path(root)
    _require(transport.get('policy') == POLICY and transport.get('status') == 'transported-bounded-property-results'
             and transport.get('authorizing') is False and transport.get('activation_authorized') is False
             and transport.get('application_obligation_discharged') is False
             and transport.get('executed_application_queries') == 0
             and transport.get('receipt_sha256') == canonical_sha256_v3({k:v for k,v in transport.items() if k != 'receipt_sha256'}),
             'transport status, receipt or authority differs')
    for key in ('baseline_packet_sha256', 'assurance', 'operation_id', 'obligation_id', 'baseline_obligation_status', 'models'):
        _require(transport.get(key) == context[key], 'transport baseline binding differs: ' + key)
    _require(local.get('baseline_query_transport') is True and local['query']['status'] == 'satisfied'
             and transport.get('local_query_output_sha256') == local['query']['output_sha256'], 'transport local premise differs')
    previous = packet['result']
    selected = [row for row in previous['checks'] if (row['operation_id'], row['obligation_id'])
                == (context['operation_id'], context['obligation_id'])]
    _require(len(selected) == 1, 'baseline obligation is ambiguous')
    allowed = _output_digests(selected[0])
    _require(all(type(transport.get(k)) is int and transport[k] >= 0
                 for k in ('processed_contexts_reused', 'processed_contexts_executed'))
             and transport['processed_contexts_reused'] + transport['processed_contexts_executed'] == len(transport['groups']),
             'processed context execution counts differ')
    queries = transport.get('queries', [])
    _require(queries and transport.get('transported_queries') == len(queries)
             and len({row['query_sha256'] for row in queries}) == len(queries), 'query inventory differs')
    properties, used_groups = set(), set()
    for row in queries:
        binding, scope = row['binding'], checked_bounded_query_scope(row['binding']['arguments'])
        key = canonical_sha256_v3(binding)
        _require(row['query_sha256'] == key and row['scope'] == scope
                 and row['source_receipt_sha256'] == previous['receipt_sha256']
                 and set(binding) == {'policy', 'authorizing', 'tools', 'goto_model_sha256', 'arguments', 'assurance', 'cwd'}
                 and binding['policy'] == 'exact-compiled-cbmc-query-evidence-v1' and binding['authorizing'] is False
                 and binding['assurance'] == context['assurance'] and binding['goto_model_sha256'] == context['models']['baseline']
                 and binding['tools']['checker_sha256'] == previous['checker']['cbmc_sha256'] == local['tools']['cbmc']
                 and binding['tools']['compiler_sha256'] == previous['checker']['goto_cc_sha256'] == local['tools']['goto_cc'],
                 'transport original query binding differs')
        process = CbmcQueryEvidence._read(root / 'baseline-context/query-transport/query-evidence' / key,
                                         binding, allowed_outputs=allowed)
        _require(process is not None, 'transport lacks retained query bytes')
        parsed = run_cbmc_properties(command=[], timeout_seconds=1,
            query_evidence=SimpleNamespace(run=lambda *args, **kwargs: process))
        _require(parsed == row['result'] and parsed['status'] == 'satisfied'
                 and set(parsed['property_ids']) == set(scope['property_ids']), 'transported property result differs')
        group = row['context_id']
        _require(group == canonical_sha256_v3(scope['common_arguments']), 'processed query arguments differ')
        used_groups.add(group)
        properties.update(parsed['property_ids'])
    _require(set(transport['groups']) == used_groups and transport['transported_properties'] == len(properties),
             'transport processed context or property coverage differs')
    symbols = {}
    for side in ('baseline-marked', 'edited-marked'):
        data = json.loads((root / 'baseline-context' / side / (side + '-symbols.stdout')).read_text())
        symbols[side] = next(v['symbolTable'] for v in data if 'symbolTable' in v)
    boundary = local['inputs']['boundary']
    markers = {'entry': 'spx_edit_region_entry', **{name: 'spx_edit_region_exit_' + str(i)
               for i, name in enumerate(boundary['exits'])}}
    function = local['inputs']['source_packages']['original']['operation_symbols'][boundary['operation_id']]
    for key, group in transport['groups'].items():
        directory = root / 'baseline-context/query-transport' / key
        models = {side: json.loads((directory / (side + '.json')).read_text()) for side in context['models']}
        checked = compare_processed_query_context(models, symbols, function=function, markers=markers,
            checked_source=(root / 'comparison/comparison.c').read_text())
        _require(key == canonical_sha256_v3(group['common_arguments'])
                 and canonical_sha256_v3(checked) == canonical_sha256_v3(group['context']), 'processed relation differs')
        for row in queries:
            if row['context_id'] == key:
                _require(set(row['scope']['property_ids']) <= set(checked['property_ids'])
                         and row.get('inactive_unwindset') == {k:v for k,v in row['scope']['unwindset'].items()
                                                               if k not in checked['loop_ids']}, 'query scope lacks preserved sites')
