"""Public feedback for contextual checks conditional on named runtime contracts.

This is a diagnostic view of engine output, never a supplier-proof importer.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..components.conditional_check_result import checked_conditional_packet as _checked_packet, conditional_packet_status
from ..util import sha256_file, write_json
from .formats import OPERATOR_WORK_STATUS_FORMAT, OPERATOR_BLOCKER_DETAIL_FORMAT
from .work_status import build_operator_work_status_v2, build_operator_blocker_detail_v1


def _composition_facts(result):
    return [{"operation_id": row["operation_id"], "obligation_id": row["obligation_id"],
             "fact": name, "status": certificate["result"]["status"],
             "code": certificate["result"].get("code"), "detail": certificate["result"].get("detail")}
            for row in result["checks"] for name, certificate in sorted(row.items())
            if isinstance(certificate, dict) and "receipt_sha256" in certificate
            and isinstance(certificate.get("result"), dict)]


def _region_feedback(result):
    deferred = [row for row in result['checks'] if row.get('code') == 'conditional_region_deferred']
    statuses = {row['status'] for row in result['checks'] if row.get('code') != 'conditional_region_deferred'}
    return {'selected_obligations': result.get('selected_obligations'),
            'deferred_obligations': [{key: row[key] for key in ('operation_id', 'obligation_id')} for row in deferred],
            'selected_obligation_status': ('violated' if 'violated' in statuses else
                                          'satisfied' if statuses == {'satisfied'} else 'incomplete'),
            'supplier_export_blocked_by_focus': result.get('selected_obligations') is not None}


def _entry_models(result):
    from ..components.bisimulation_entry_queries import entry_query_summary
    entries = []
    for row in result['checks']:
        if 'source_entry_model' not in row:
            continue
        entry = dict(row['source_entry_model'])
        if 'entry_check' in entry:
            entry['entry_check'] = entry_query_summary(entry['entry_check'])
        entries.append({'operation_id': row['operation_id'], 'obligation_id': row['obligation_id'], **entry})
    return entries


def write_component_conditional_feedback(*, target_id, component_id, packet_path: Path):
    packet = json.loads(packet_path.read_text())
    result, assurance = _checked_packet(packet, component_id)
    out = packet_path.parent
    state = {'satisfied': 'complete', 'incomplete': 'incomplete', 'violated': 'violated'}[conditional_packet_status(result)]
    requirements = result.get('boundary_requirements', [])
    blockers = [{'family': 'conditional-proof', 'code': row.get('code', 'conditional_obligation_unresolved'),
                 'location': row.get('shard_id')} for row in result['checks'] if row['status'] != 'satisfied']
    blockers += [{'family': 'boundary-requirement', 'code': row['code'],
                  'location': row.get('operation_id')} for row in requirements]
    status = build_operator_work_status_v2(target_id=target_id, scope='component-conditional-contextual', subjects=[{
        'subject': f'component:{component_id}', 'kind': 'component', 'state': state,
        'authority': 'not-applicable', 'stage': 'contextual-proof-under-runtime-contracts',
        'sources': [], 'blockers': blockers,
        'next_action': ('review contract validation and caller admission before qualification' if state == 'complete'
                        else 'discharge pending boundary requirements and unresolved obligations, then rerun the conditional check'),
    }])
    write_json(out/'conditional-check.json', status)
    details = build_operator_blocker_detail_v1(target_id=target_id, subject=f'component:{component_id}',
        source_format=status['format'], source_sha256=sha256_file(out/'conditional-check.json'),
        blockers=([{**row, 'family': 'conditional-proof'} for row in result['checks'] if row['status'] != 'satisfied']
                  + [{**row, 'family': 'boundary-requirement', 'status': 'incomplete'} for row in requirements]),
        family=None, code=None, limit=None)
    details['conditional_result'] = {'path': packet_path.name, 'sha256': sha256_file(packet_path)}
    details['runtime_contracts'] = assurance['contracts']
    details['obligations'] = [{'operation_id': row['operation_id'], 'obligation_id': row['obligation_id'],
        'status': row['status'], 'code': row.get('code'), 'detail': row.get('detail')} for row in result['checks']]
    details['admission_issues'] = result.get('issues', [])
    details['composition_facts'] = _composition_facts(result)
    details['entry_models'] = _entry_models(result)
    details['boundary_requirements'] = requirements
    details['local_obligation_status'] = result['status']
    details['supplier_export_blocked_by_boundary'] = bool(requirements)
    details.update(_region_feedback(result))
    write_json(out/'conditional-check-details.json', details)
    return status


def render_component_conditional_check(*, path: Path, payload: dict, target_id, component_id, as_json):
    subjects = payload.get('subjects', [])
    if (payload.get('format') != OPERATOR_WORK_STATUS_FORMAT or payload.get('target_id') != target_id
            or payload.get('scope') != 'component-conditional-contextual' or len(subjects) != 1
            or subjects[0].get('subject') != f'component:{component_id}'
            or subjects[0].get('authority') != 'not-applicable'
            or subjects[0].get('stage') != 'contextual-proof-under-runtime-contracts'):
        raise ValueError('conditional feedback has stale subject or authority')
    details = json.loads((path.parent/'conditional-check-details.json').read_text())
    evidence = details.get('conditional_result', {})
    packet_path = path.parent/'conditional-engine-result.json'
    if (details.get('format') != OPERATOR_BLOCKER_DETAIL_FORMAT
            or details.get('target_id') != target_id or details.get('subject') != subjects[0]['subject']
            or details.get('source') != {'format': payload['format'], 'sha256': sha256_file(path)}
            or evidence != {'path': packet_path.name, 'sha256': sha256_file(packet_path)}):
        raise ValueError('conditional feedback evidence is stale')
    result, assurance = _checked_packet(json.loads(packet_path.read_text()), component_id)
    expected = {'satisfied': 'complete', 'incomplete': 'incomplete', 'violated': 'violated'}[conditional_packet_status(result)]
    if payload.get('status') != expected or subjects[0].get('state') != expected or details.get('runtime_contracts') != assurance['contracts']:
        raise ValueError('conditional feedback status or dependencies disagree')
    composition_facts = _composition_facts(result)
    region_feedback = _region_feedback(result)
    if (details.get('selected_obligations') != region_feedback['selected_obligations']
            or details.get('deferred_obligations', []) != region_feedback['deferred_obligations']):
        raise ValueError('conditional feedback selected or deferred regions disagree')
    details.update(region_feedback)
    requirements = result.get('boundary_requirements', [])
    if details.get('boundary_requirements', []) != requirements:
        raise ValueError('conditional feedback boundary requirements disagree')
    details['local_obligation_status'] = result['status']
    details['supplier_export_blocked_by_boundary'] = bool(requirements)
    if 'composition_facts' in details and details['composition_facts'] != composition_facts:
        raise ValueError('conditional feedback composition facts disagree')
    # Older feedback can acquire this view from its bound engine packet without
    # rebuilding the proof or silently trusting a stale declared fact.
    details['composition_facts'] = composition_facts
    entry_models = _entry_models(result)
    if 'entry_models' in details and details['entry_models'] != entry_models:
        raise ValueError('conditional feedback entry preparation differs from its engine packet')
    details['entry_models'] = entry_models
    if as_json:
        print(json.dumps({'status': payload, 'details': details, 'assurance': assurance,
                          'activation_authorized': False}, indent=2, sort_keys=True))
    else:
        print(f"{component_id}: conditional contextual check={conditional_packet_status(result)} (no activation authority)")
        if result.get('selected_obligations') is not None:
            print(f"  focused regions: {len(result['selected_obligations'])} of {len(result['checks'])}; "
                  f"selected status={region_feedback['selected_obligation_status']}; supplier export withheld")
        if requirements:
            print(f"  local obligations: {result['status']}; supplier theorem unavailable")
        for row in requirements:
            print(f"  pending boundary requirement: {row['code']}")
        for row in assurance['contracts']:
            print(f"  runtime contract: {row['id']}:{row['revision']} ({row['contract_sha256']})")
        for row in result['checks']:
            if row['status'] != 'satisfied':
                print(f"  {row['operation_id']}/{row['obligation_id']}: {row.get('detail') or row.get('code') or row['status']}")
        for row in details['composition_facts']:
            if row['status'] != 'satisfied':
                print(f"  composition fact unavailable: {row['operation_id']}/{row['fact']} "
                      f"({row['status']}: {row['detail'] or row['code']})")
        for row in entry_models:
            qualification = ('entry qualified conditional on runtime contracts' if row['entry_obligations_checked']
                             else 'entry qualification incomplete')
            print(f"  entry preparation {row['operation_id']}/{row['obligation_id']}: {row['status']}; "
                  + qualification)
            if row.get('detail'):
                print(f"    {row['detail']}")
            if 'prefix_correspondence' in row:
                prefix = row['prefix_correspondence']
                print(f"    compiled prefix: {prefix['status']}")
                if prefix.get('detail'):
                    print(f"    {prefix['detail']}")
            if 'entry_check' in row:
                checked = row['entry_check']
                print(f"    entry properties: {checked['property_status']}; nonvacuity: {checked['nonvacuity_status']}; "
                      f"queries reused: {checked['reused_queries']}; executed: {checked['executed_queries']}")
        print(f"next: {subjects[0]['next_action']}")
    return 0 if expected == 'complete' else 2
