"""Public source-edit feedback, with baseline proof eligibility kept separate."""

import json
from pathlib import Path
import shutil

from ..artifacts.artifact_set import canonical_sha256_v3
from ..components.bisimulation_source_edit_check import POLICY, check_source_edit
from ..components.bisimulation_source_edit_context import baseline_interface_bindings, validate_baseline_edit_context
from ..components.conditional_check_result import checked_conditional_packet
from ..util import sha256_file, write_json
from .formats import OPERATOR_WORK_STATUS_FORMAT
from .source_check import write_component_source_check
from .work_status import build_operator_work_status_v2


def _baseline(packet_path, component_id, result):
    if packet_path is None:
        return {'status': 'unavailable', 'proof_imported': False,
                'detail': 'No conditional baseline packet is configured; source comparison alone does not assure the binary lifting.'}
    feedback = {'packet_sha256': sha256_file(packet_path), 'proof_imported': False}
    try:
        packet = json.loads(packet_path.read_text())
        baseline, assurance = checked_conditional_packet(packet, component_id)
        source = result['inputs']['source_packages']['original']
        if baseline['bindings']['implementation_sha256'] != source['implementation_sha256']:
            raise ValueError('baseline packet binds a different source implementation')
        interfaces = baseline_interface_bindings(packet, baseline, result)
        obligations = [{key: row.get(key) for key in ('operation_id', 'obligation_id', 'status', 'code')}
                       for row in baseline['checks']]
        return {**feedback, 'status': 'available-unimported', 'assurance': assurance,
                **interfaces, 'baseline_packet_status': packet['status'],
                'baseline_obligation_status': baseline['status'],
                'obligations': obligations, 'selected_obligations': baseline.get('selected_obligations'),
                'boundary_requirements': baseline.get('boundary_requirements', []),
                'detail': 'Baseline source and interface match; its original obligation status and assumptions remain unchanged. '
                          'Source-to-source evidence is not yet a public application-proof import rule.'}
    except (ValueError, KeyError, TypeError) as error:
        return {**feedback, 'status': 'unsupported', 'detail': str(error)}


def write_component_source_edit(*, target_id, component_id, interface_package, baseline_interface_package,
                                source_package, baseline_source_package, boundary, workspace,
                                host_compiler, pe32_compiler, cbmc, out, previous=None,
                                baseline_conditional_packet=None, timeout_seconds=30, timings=None,
                                baseline_conditional_evidence=None, baseline_obligation=None, baseline_query_transport=False):
    """Run ordinary portability checks and an explicitly configured source comparison."""
    out = Path(out)
    if baseline_conditional_evidence is not None:
        if baseline_conditional_packet is not None or not isinstance(baseline_obligation, str) or not baseline_obligation:
            raise ValueError('baseline proof context requires its evidence directory and one obligation, without a separate packet')
        baseline_conditional_packet = Path(baseline_conditional_evidence) / 'conditional-engine-result.json'
    elif baseline_obligation is not None:
        raise ValueError('baseline obligation requires its full conditional evidence directory')
    if Path(workspace).resolve().is_relative_to(out.resolve()):
        raise ValueError('source-edit workspace must be outside its artifact output')
    out.mkdir(parents=True, exist_ok=True)
    source_status = write_component_source_check(target_id=target_id, component_id=component_id,
        interface_package=interface_package, source_package=source_package, host_compiler=host_compiler,
        pe32_compiler=pe32_compiler, out=out / 'source-check', timings=timings)
    result = check_source_edit(component_id=component_id, interface_package=interface_package,
        baseline_interface_package=baseline_interface_package, source_package=source_package,
        baseline_source_package=baseline_source_package, boundary=boundary, workspace=workspace,
        goto_cc=cbmc.with_name('goto-cc'), goto_instrument=cbmc.with_name('goto-instrument'), cbmc=cbmc,
        timeout_seconds=timeout_seconds, previous=previous, timings=timings,
        baseline_evidence=baseline_conditional_evidence, baseline_obligation=baseline_obligation,
        baseline_query_transport=baseline_query_transport)
    shutil.copytree(workspace, out / 'source-edit-models')
    write_json(out / 'source-edit-evidence.json', result)
    state = {'satisfied': 'complete', 'violated': 'violated', 'incomplete': 'incomplete'}[result['status']]
    if source_status['status'] != 'complete':
        state = 'violated' if source_status['status'] == 'violated' or state == 'violated' else 'incomplete'
    checks = [row for row in result['checks'] if row['status'] != 'satisfied']
    blockers = [{'family': 'source-edit', 'code': row['code'], 'location': None} for row in checks]
    if source_status['status'] != 'complete':
        blockers.append({'family': 'source-compile', 'code': 'source_edit_portability_check_failed', 'location': None})
    status = build_operator_work_status_v2(target_id=target_id, scope='component-source-edit', subjects=[{
        'subject': 'component:' + component_id, 'kind': 'component', 'state': state,
        'authority': 'not-applicable', 'stage': 'source-edit-comparison', 'sources': [], 'blockers': blockers,
        'next_action': ('Review baseline proof eligibility and wider contract obligations before reusing application proofs.'
                        if state == 'complete' else 'Inspect the failed comparison or unsupported boundary and refine the source or contract.'),
    }])
    write_json(out / 'source-edit-check.json', status)
    if baseline_conditional_packet is not None:
        shutil.copyfile(baseline_conditional_packet, out / 'baseline-conditional-engine-result.json')
    details = {'target_id': target_id, 'component_id': component_id,
        'status_sha256': sha256_file(out / 'source-edit-check.json'),
        'evidence_sha256': sha256_file(out / 'source-edit-evidence.json'),
        'source_check_sha256': sha256_file(out / 'source-check/source-check.json'),
        'baseline': _baseline(baseline_conditional_packet, component_id, result),
        'activation_authorized': False, 'application_proofs_reused': False}
    write_json(out / 'source-edit-details.json', details)
    return status


def render_component_source_edit(*, path, payload, target_id, component_id, as_json):
    root = path.parent
    details = json.loads((root / 'source-edit-details.json').read_text())
    result = json.loads((root / 'source-edit-evidence.json').read_text())
    subjects = payload.get('subjects', [])
    if (payload.get('format') != OPERATOR_WORK_STATUS_FORMAT or payload.get('target_id') != target_id
            or payload.get('scope') != 'component-source-edit' or len(subjects) != 1
            or subjects[0].get('subject') != 'component:' + component_id
            or subjects[0].get('stage') != 'source-edit-comparison' or subjects[0].get('authority') != 'not-applicable'
            or details.get('target_id') != target_id or details.get('component_id') != component_id
            or details.get('status_sha256') != sha256_file(path)
            or details.get('evidence_sha256') != sha256_file(root / 'source-edit-evidence.json')
            or details.get('source_check_sha256') != sha256_file(root / 'source-check/source-check.json')
            or details.get('activation_authorized') is not False or details.get('application_proofs_reused') is not False
            or result.get('policy') != POLICY or result.get('component_id') != component_id
            or result.get('authorizing') is not False or result.get('baseline_proof_imported') is not False
            or result.get('activation_authorized') is not False
            or result.get('receipt_sha256') != canonical_sha256_v3({k: v for k, v in result.items() if k != 'receipt_sha256'})):
        raise ValueError('source-edit feedback has stale identity, evidence or authority')
    for row in result['artifacts']:
        artifact = root / 'source-edit-models' / row['path']
        if not artifact.resolve().is_relative_to((root / 'source-edit-models').resolve()) or sha256_file(artifact) != row['sha256']:
            raise ValueError('source-edit model artifact is stale')
    baseline_packet = root / 'baseline-conditional-engine-result.json'
    if details.get('baseline') != _baseline(baseline_packet if baseline_packet.exists() else None, component_id, result):
        raise ValueError('source-edit baseline feedback differs from its checked packet')
    if 'baseline_context' in result:
        validate_baseline_edit_context(result['baseline_context'], packet=json.loads(baseline_packet.read_text()),
                                      packet_sha256=sha256_file(baseline_packet), local=result)
        if 'query_transport' in result['baseline_context']:
            from ..components.bisimulation_source_edit_queries import validate_transported_queries
            validate_transported_queries(result['baseline_context']['query_transport'], context=result['baseline_context'],
                local=result, packet=json.loads(baseline_packet.read_text()), root=root / 'source-edit-models')
    elif result.get('baseline_obligation') is not None and result['status'] == 'satisfied':
        raise ValueError('source edit lacks its requested baseline context')
    source_status = json.loads((root / 'source-check/source-check.json').read_text())['status']
    expected = {'satisfied': 'complete', 'violated': 'violated', 'incomplete': 'incomplete'}[result['status']]
    if source_status != 'complete':
        expected = 'violated' if source_status == 'violated' or expected == 'violated' else 'incomplete'
    if payload.get('status') != expected or subjects[0].get('state') != expected:
        raise ValueError('source-edit aggregate status differs')
    if as_json:
        print(json.dumps({'status': payload, 'details': details, 'source_edit': result,
                          'activation_authorized': False}, indent=2, sort_keys=True))
    else:
        print(f"{component_id}: source edit={result['status']}; source compilation/profile={source_status}")
        for row in result['checks']:
            if row['status'] != 'satisfied':
                print('  ' + (row.get('detail') or row['code']))
        reuse = result['query_reuse']
        print(f"  local queries executed={reuse['executed_queries']}; reused={reuse['reused_queries']}")
        print('  baseline evidence: ' + details['baseline']['status'] + '; application proofs reused=false')
        if 'baseline_packet_status' in details['baseline']:
            baseline = details['baseline']
            satisfied = sum(row['status'] == 'satisfied' for row in baseline['obligations'])
            print(f"  baseline packet={baseline['baseline_packet_status']}; satisfied obligations={satisfied}/{len(baseline['obligations'])}")
        print('  ' + details['baseline']['detail'])
        if 'baseline_context' in result:
            context = result['baseline_context']
            print(f"  baseline proof context={context['status']}; baseline obligation={context['baseline_obligation_status']}; baseline queries imported={context['baseline_queries_imported']}")
            if 'query_transport' in context:
                transported = context['query_transport']
                print(f"  transported bounded queries={transported['transported_queries']}; properties={transported['transported_properties']}; application obligation discharged=false")
        print('next: ' + subjects[0]['next_action'])
    return 0 if expected == 'complete' else 2
