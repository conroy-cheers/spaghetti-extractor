"""Public composition checks consume regional contracts without their bodies.

Spatial requirements and private-byte transport are checked separately. The
operation remains incomplete until complete state transport and concrete
admission hold; selecting requirements does not establish caller compatibility.
"""
from pathlib import Path
import json
import shutil
import subprocess
import time

from ..artifacts.artifact_set import canonical_sha256_v3
from ..components.bisimulation_call_evidence import read_json, producer_binding, checker_options
from ..components.bisimulation_cleanup_admission import (
    cleanup_admission_domain, render_cleanup_admission, check_cleanup_admission_transport,
)
from ..components.bisimulation_private_transport import (
    cleanup_private_transport_domain, private_transport_header, check_private_transport_header,
)
from ..components.bisimulation_private_transport_template import TEMPLATE as PRIVATE_TEMPLATE
from ..components.bisimulation_public_transport import (
    cleanup_public_transport_domain, render_public_transport, check_public_transport,
)
from ..components.bisimulation_descriptor_transport import (
    cleanup_descriptor_transport_domain, cleanup_source_grant_protocol, descriptor_files, check_descriptor_files,
    HEADERS as DESCRIPTOR_HEADERS, TEMPLATE as DESCRIPTOR_TEMPLATE,
)
from ..components.bisimulation_cleanup_source_use import cleanup_source_representation_use
from ..components.bisimulation_runtime_view_transport import (
    runtime_view_recipe, runtime_view_files, check_runtime_view_files, TEMPLATE as RUNTIME_VIEW_TEMPLATE,
)
from ..components.bisimulation_cleanup_composition import cleanup_control_domain, TEMPLATE as CONTROL_TEMPLATE
from ..components.bisimulation_cleanup_observations import cleanup_observation_domain, TEMPLATE as OBSERVATION_TEMPLATE
from ..components.bisimulation_cleanup_summary import cleanup_operation_domain, conditional_cleanup_summary
from ..components.bisimulation_source_call_check import checked_source_region_graphs
from ..components.bisimulation_compaction_contract import require
from ..components.bisimulation_compilation import workspace_compile_command
from ..components.bisimulation_query_evidence import CbmcQueryEvidence
from ..components.cbmc_backend import run_cbmc_properties, _property_statuses, _output_sha256
from ..util import sha256_file, write_json
from .source_region_check import validate_component_source_region_feedback
from .work_status import build_operator_work_status_v2, build_operator_blocker_detail_v1

POLICY = 'conditional-cleanup-composition-v9'
NAMES = ('entry', 'loop', 'tail')
CASES = ('existing', 'proposed', 'nonempty', 'private_transport', 'public_transport', 'descriptor_transport',
         'runtime_view_transport', 'control_transport', 'observations')
REMAINING = ['Establish the proposed caller and allocator requirements in real contexts.',
    'Establish physical private-frame compatibility and the named persistent-context, grant and lifetime requirements.',
    'Complete state/trace composition and establish concrete service compatibility.']


def _inputs(regions, target_id, component_id, exact_operation=None):
    require(isinstance(regions, dict) and set(regions) == set(NAMES), 'composition needs three checked regions')
    results, models, dependencies, headers = {}, {}, {}, {}
    for name in NAMES:
        root = Path(regions[name])
        status = read_json(root/'source-check.json')
        require(status['status'] == 'complete' and status['target_id'] == target_id
            and status['scope'] == 'component-source' and len(status['subjects']) == 1
            and status['subjects'][0]['subject'] == 'component:' + component_id,
            'regional component identity differs or proof is incomplete')
        local = read_json(root/'compiler-checks.json')['local_contract']
        validate_component_source_region_feedback(root, local, 'complete')
        results[name] = result = read_json(root/'region-comparison/result.json')
        models[name] = (root/'region-comparison/proof/pair.c').read_text()
        headers[name] = {n: (root/'region-comparison/proof'/n).read_text() for n in DESCRIPTOR_HEADERS}
        dependencies[name] = {'path': str(root), 'receipt_sha256': result['receipt_sha256'],
            'model_sha256': result['proof_files']['model.goto']}
    require(len({r['inputs']['preparation'] for r in results.values()}) == 1,
        'regional source preparations differ')
    contracts = {n: results[n]['inputs']['contract'] for n in NAMES}
    domain = cleanup_admission_domain(contracts, models)
    domain['private_transport'] = cleanup_private_transport_domain(models)
    domain['public_transport'] = cleanup_public_transport_domain(models)
    require(all(h == headers['entry'] for h in headers.values()), 'regional descriptor ABI headers differ')
    domain['descriptor_transport'] = cleanup_descriptor_transport_domain(models, headers['entry'])
    domain['descriptor_transport']['grant_protocol'] = cleanup_source_grant_protocol(
        results['entry']['inputs']['preparation'], contracts)
    domain['source_representation_use'] = cleanup_source_representation_use(
        results['entry']['inputs']['preparation'], contracts, domain['descriptor_transport']['grant_protocol'])
    domain['runtime_view_transport'] = runtime_view_recipe()
    preparation = Path(results['entry']['inputs']['preparation'])
    graphs = checked_source_region_graphs(read_json(preparation/'compiler-checks.json')['source_region_graphs'],
                                         artifacts=preparation/'source-region-graph-models')
    require(len(graphs) == 1, 'cleanup control needs the shared source graph')
    domain['control_transport'] = cleanup_control_domain(models, contracts, graphs[0], domain['private_transport'])
    domain['observations'] = cleanup_observation_domain(models, domain['control_transport'])
    if exact_operation is not None:
        domain['operation'] = cleanup_operation_domain(domain, models, results, exact_operation, component_id)
    return domain, dependencies, results['entry']['inputs']['preparation']


def _key(domain, goto_cc, cbmc):
    return {'domain': domain, 'options': checker_options(20, None),
        'tools': {n: {'path': str(p), 'sha256': sha256_file(Path(p))}
                  for n, p in [('compiler', goto_cc), ('checker', cbmc)]},
        'producers': producer_binding({__name__})}


def _queries(root, key, timeout_seconds, timings):
    cases = {n: tuple(key['domain']['additional_requirements']) if n in {'proposed', 'nonempty'} else () for n in CASES}
    results = {}
    for name, requirements in cases.items():
        proof = root/name; proof.mkdir()
        start = time.monotonic()
        (proof/'admission.c').write_text(_model(key['domain'], name, requirements))
        if name == 'private_transport':
            (proof/'private-layout.h').write_text(private_transport_header(key['domain']['private_transport']))
        if name in {'descriptor_transport', 'runtime_view_transport'}:
            for filename, content in descriptor_files(key['domain']['descriptor_transport']).items():
                (proof/filename).write_text(content)
        if name == 'runtime_view_transport':
            for filename, content in runtime_view_files().items():
                (proof/filename).write_text(content)
        timings.append({'phase': 'model', 'case': name, 'seconds': time.monotonic()-start})
        compiler, checker = (key['tools'][n]['path'] for n in ['compiler', 'checker'])
        command = [compiler, '--i386-win32', '-nostdinc', '-I', '.', 'admission.c', '--function', 'check_admission', '-o', 'model.goto']
        start = time.monotonic()
        process = subprocess.run(workspace_compile_command(command, proof), cwd=proof, capture_output=True,
                                 text=True, timeout=timeout_seconds)
        timings.append({'phase': 'compiler', 'case': name, 'seconds': time.monotonic()-start})
        write_json(proof/'compiler.json', {'command': command, 'returncode': process.returncode,
            'inputs': {p.name: sha256_file(p) for p in sorted(proof.iterdir()) if p.suffix in {'.c', '.h'}},
            'stdout': process.stdout, 'stderr': process.stderr})
        require(process.returncode == 0, 'admission compilation failed: ' + process.stderr[-2000:])
        evidence = CbmcQueryEvidence(model=proof/'model.goto', checker=Path(checker), compiler=Path(compiler),
                                    output=proof/'query-evidence')
        start = time.monotonic()
        query = run_cbmc_properties(command=[checker, 'model.goto', '--function', 'check_admission', *key['options']],
            cwd=proof, timeout_seconds=timeout_seconds, query_evidence=evidence, output_prefix=proof/'query')
        timings.append({'phase': 'solver', 'case': name, 'seconds': time.monotonic()-start})
        results[name] = {'query': query, 'additional_requirements': list(requirements),
            'files': {str(p.relative_to(proof)): sha256_file(p) for p in sorted(proof.rglob('*')) if p.is_file()}}
    return results


def _model(domain, name, requirements):
    if name == 'observations':
        return OBSERVATION_TEMPLATE
    if name == 'control_transport':
        return CONTROL_TEMPLATE
    if name == 'runtime_view_transport':
        return RUNTIME_VIEW_TEMPLATE
    if name == 'descriptor_transport':
        return DESCRIPTOR_TEMPLATE
    if name == 'public_transport':
        return render_public_transport()
    if name == 'private_transport':
        return PRIVATE_TEMPLATE
    source = render_cleanup_admission(domain, additional_requirements=requirements)
    if name == 'nonempty':
        source = source.removesuffix('}\n') + ' __CPROVER_assert(0,"admission-domain-nonempty");\n}\n'
    return source


def _validate_queries(result, root):
    key = result['proof_key']
    require(set(result['queries']) == set(CASES), 'missing admission comparison or nonvacuity check')
    for name, row in result['queries'].items():
        proof = root/name
        expected = list(key['domain']['additional_requirements']) if name in {'proposed', 'nonempty'} else []
        # JSON sorts object keys; order is immaterial for a conjunction.
        require(set(row['additional_requirements']) == set(expected)
            and len(row['additional_requirements']) == len(expected), 'admission requirements differ')
        for path, digest in row['files'].items():
            file = proof/path
            require(file.resolve().is_relative_to(proof.resolve()) and sha256_file(file) == digest, 'changed admission evidence')
        if name == 'observations':
            require((proof/'admission.c').read_text() == OBSERVATION_TEMPLATE, 'cleanup observation recipe changed')
        elif name == 'control_transport':
            require((proof/'admission.c').read_text() == CONTROL_TEMPLATE, 'cleanup control recipe changed')
        elif name == 'private_transport':
            require((proof/'admission.c').read_text() == PRIVATE_TEMPLATE, 'private transport recipe changed')
            check_private_transport_header((proof/'private-layout.h').read_text(), key['domain']['private_transport'])
        elif name == 'public_transport':
            check_public_transport((proof/'admission.c').read_text())
        elif name in {'descriptor_transport', 'runtime_view_transport'}:
            template = DESCRIPTOR_TEMPLATE if name == 'descriptor_transport' else RUNTIME_VIEW_TEMPLATE
            require((proof/'admission.c').read_text() == template, 'descriptor/runtime transport recipe changed')
            check_descriptor_files(proof, key['domain']['descriptor_transport'])
            if name == 'runtime_view_transport':
                check_runtime_view_files(proof, key['domain']['runtime_view_transport'])
        else:
            check_cleanup_admission_transport((proof/'admission.c').read_text(), key['domain'],
                row['additional_requirements'], nonempty=name == 'nonempty')
        compiler = read_json(proof/'compiler.json')
        inputs = ['admission.c', 'private-layout.h'] if name == 'private_transport' else ['admission.c']
        if name in {'descriptor_transport', 'runtime_view_transport'}:
            inputs += [*DESCRIPTOR_HEADERS, 'descriptor-accessors.h']
        if name == 'runtime_view_transport':
            inputs.append('runtime-accessors.h')
        require(compiler['returncode'] == 0 and compiler['inputs'] == {n: row['files'][n] for n in inputs}
            and compiler['command'] == [key['tools']['compiler']['path'], '--i386-win32', '-nostdinc', '-I', '.',
                'admission.c', '--function', 'check_admission', '-o', 'model.goto'], 'admission compiler binding differs')
        files = list((proof/'query-evidence').glob('*/query.json'))
        require(len(files) == 1, 'admission needs one complete query')
        record = read_json(files[0]); binding = record['binding']; directory = files[0].parent
        require(directory.name == canonical_sha256_v3(binding)
            and binding['goto_model_sha256'] == row['files']['model.goto']
            and binding['arguments'] == ['$GOTO_MODEL', '--function', 'check_admission', *key['options']],
            'admission query binding differs')
        for role in ['compiler', 'checker']:
            require(binding['tools'][role] == key['tools'][role]['path']
                and binding['tools'][role+'_sha256'] == key['tools'][role]['sha256'], 'admission tool binding differs')
        stdout, stderr = (directory/'stdout').read_text(), (directory/'stderr').read_text()
        require(sha256_file(directory/'stdout') == record['stdout_sha256']
            and sha256_file(directory/'stderr') == record['stderr_sha256'], 'admission query output changed')
        statuses = _property_statuses(json.loads(stdout))
        query = row['query']; status = query['status']
        require(status in {'satisfied', 'violated'} and statuses
            and set(statuses.values()) <= {'SUCCESS', 'FAILURE'}
            and (status == 'satisfied') == (set(statuses.values()) == {'SUCCESS'})
            and record['returncode'] == (0 if status == 'satisfied' else 10)
            and query['property_ids'] == sorted(statuses) and query['properties'] == len(statuses)
            and query['output_sha256'] == _output_sha256(stdout, stderr), 'incomplete admission query')
        if name == 'nonempty':
            failed = [r['description'] for event in json.loads(stdout) for r in event.get('result', [])
                      if r['status'] == 'FAILURE']
            require(failed == ['admission-domain-nonempty'], 'proposed admission lacks a valid nonempty witness')


def write_component_source_composition_check(*, target_id, component_id, regions, out, workspace,
                                             goto_cc, cbmc, previous=None, timeout_seconds=60, timings=None, exact_operation=None,
                                             summary_export=None):
    out, root = Path(out), Path(workspace).resolve()
    require(not root.is_relative_to(out.resolve()), 'composition workspace must be outside output')
    root.mkdir(parents=True, exist_ok=False)
    timings = [] if timings is None else timings
    start = time.monotonic()
    domain, dependencies, preparation = _inputs(regions, target_id, component_id, exact_operation)
    timings.append({'phase': 'evidence-import', 'seconds': time.monotonic()-start})
    key = _key(domain, goto_cc, cbmc)
    result = {'policy': POLICY, 'status': 'incomplete', 'authorizing': False, 'activation_authorized': False,
        'whole_component_complete': False, 'state_composition_checked': False, 'runtime_compatibility': 'unverified',
        'target_id': target_id, 'component_id': component_id, 'dependencies': dependencies,
        'summary_export': summary_export,
        'exact_operation': None if exact_operation is None else str(Path(exact_operation).resolve()),
        'proof_key': key, 'proof_key_sha256': canonical_sha256_v3(key),
        'reuse': {'model_generation': 0, 'compiler_runs': 0, 'solver_runs': 0, 'status': 'not-requested'},
        'remaining': REMAINING}
    old = read_json(Path(previous)/'region-composition/result.json') if previous is not None else None
    if old is not None and old['proof_key'] == key:
        _validate_result(old, Path(previous)/'region-composition')
        for name in CASES:
            shutil.copytree(Path(previous)/'region-composition'/name, root/name)
        result['queries'] = old['queries']; result['reuse']['status'] = 'reused'
    else:
        result['queries'] = _queries(root, key, timeout_seconds, timings)
        result['reuse'].update(model_generation=len(CASES), compiler_runs=len(CASES), solver_runs=len(CASES),
            status='not-requested' if previous is None else 'requires-recheck')
    result['conditional_operation_summary'] = conditional_cleanup_summary(result)
    result['receipt_sha256'] = canonical_sha256_v3(result)
    write_json(root/'result.json', result)
    _validate_result(result, root)
    out.mkdir(parents=True, exist_ok=True)
    shutil.copytree(root, out/'region-composition')
    baseline = read_json(Path(preparation)/'source-check.json')
    blockers = [{'family': 'source-region-composition', 'status': 'incomplete', 'code': 'cleanup_composition_unqualified',
        'diagnostic': 'Spatial admission, private-byte and current-memory transport checked separately; ' + ' '.join(result['remaining'])}]
    for name in ['proposed', 'private_transport', 'public_transport', 'descriptor_transport', 'runtime_view_transport', 'control_transport', 'observations']:
        query = result['queries'][name]['query']
        if query['status'] != 'satisfied':
            blockers.append({'family': 'source-region-composition', 'status': query['status'],
                'code': 'cleanup_' + name + '_unproved', 'diagnostic': query.get('detail') or query['code']})
    status = build_operator_work_status_v2(target_id=target_id, scope='component-source', subjects=[{
        'subject': 'component:'+component_id, 'kind': 'component', 'state': 'incomplete', 'authority': 'not-applicable',
        'stage': 'source-compile-profile-and-local-contract', 'sources': baseline['subjects'][0]['sources'],
        'blockers': [{'family': b['family'], 'code': b['code'], 'location': None} for b in blockers],
        'next_action': 'Establish the named caller/allocator requirements and checked state composition.'}])
    write_json(out/'source-check.json', status)
    write_json(out/'source-check-details.json', build_operator_blocker_detail_v1(target_id=target_id,
        subject='component:'+component_id, source_format=status['format'], source_sha256=sha256_file(out/'source-check.json'),
        blockers=blockers, family=None, code=None, limit=None))
    write_json(out/'compiler-checks.json', {'local_contract': _feedback(result)})
    return status


def _feedback(result):
    return {'status': 'incomplete', 'authorizing': False, 'qualified_connected_summary': False,
        'receipt_sha256': result['receipt_sha256'], 'path': 'region-composition/result.json',
        'region_composition': {'spatial_admission': {n: result['queries'][n]['query']['status'] for n in ['existing', 'proposed']},
            'proposed_admission_nonempty': result['queries']['nonempty']['query']['status'] == 'violated',
            'private_transport': {'status': result['queries']['private_transport']['query']['status'],
                'contract': result['proof_key']['domain']['private_transport']},
            'public_transport': {'status': result['queries']['public_transport']['query']['status'],
                'contract': result['proof_key']['domain']['public_transport']},
            'descriptor_transport': {'status': result['queries']['descriptor_transport']['query']['status'],
                'requires': result['proof_key']['domain']['descriptor_transport']['requires'],
                'runtime_requirements': result['proof_key']['domain']['descriptor_transport']['runtime_requirements'],
                'grant_protocol': result['proof_key']['domain']['descriptor_transport']['grant_protocol']},
            'runtime_view_transport': {'status': result['queries']['runtime_view_transport']['query']['status'],
                'requires': result['proof_key']['domain']['runtime_view_transport']['requires'],
                'scope': result['proof_key']['domain']['runtime_view_transport']['scope'],
                'source_use': result['proof_key']['domain']['source_representation_use']},
            'control_transport': {'status': result['queries']['control_transport']['query']['status'],
                'contract': result['proof_key']['domain']['control_transport']},
            'observations': {'status': result['queries']['observations']['query']['status'],
                'contract': result['proof_key']['domain']['observations']},
            'conditional_operation_summary': result['conditional_operation_summary'],
            'additional_requirements': result['proof_key']['domain']['additional_requirements'],
            'dependencies': result['dependencies'], 'reuse': result['reuse'], 'remaining': result['remaining'],
            'state_composition_checked': False, 'runtime_compatibility': 'unverified'}}


def _validate_result(result, root):
    require(result['policy'] == POLICY and result['status'] == 'incomplete'
        and result['authorizing'] is False and result['activation_authorized'] is False
        and result['whole_component_complete'] is False and result['state_composition_checked'] is False
        and result['runtime_compatibility'] == 'unverified'
        and result['remaining'] == REMAINING
        and result['receipt_sha256'] == canonical_sha256_v3({k: v for k, v in result.items() if k != 'receipt_sha256'})
        and result['proof_key_sha256'] == canonical_sha256_v3(result['proof_key']), 'invalid composition envelope')
    key = result['proof_key']
    require(key == _key(key['domain'], key['tools']['compiler']['path'], key['tools']['checker']['path']),
        'composition options, tools or producers changed')
    _validate_queries(result, root)
    require(result['conditional_operation_summary'] == conditional_cleanup_summary(result),
            'cleanup operation summary differs from its complete evidence')


def validate_component_source_composition_feedback(root, local, status):
    root = Path(root); result = read_json(root/'region-composition/result.json')
    public = read_json(root/'source-check.json')
    require(public['target_id'] == result['target_id'] and len(public['subjects']) == 1
        and public['subjects'][0]['subject'] == 'component:' + result['component_id'], 'composition identity differs')
    _validate_result(result, root/'region-composition')
    require(status == 'incomplete' and local == _feedback(result), 'composition feedback differs')
    domain, dependencies, _ = _inputs({n: d['path'] for n, d in result['dependencies'].items()},
                                      result['target_id'], result['component_id'], result['exact_operation'])
    require(domain == result['proof_key']['domain'] and dependencies == result['dependencies'],
            'composition dependencies changed')


def checked_component_operation_summary(root):
    """Import a conditional paired-call summary without executing either body."""
    root = Path(root); local = read_json(root/'compiler-checks.json')['local_contract']
    validate_component_source_composition_feedback(root, local, 'incomplete')
    summary = read_json(root/'region-composition/result.json')['conditional_operation_summary']
    require(summary['status'] == 'satisfied', 'component lacks a complete conditional operation contract')
    return summary
