"""Discharge selected allocation premises against the materialized runtime.

This check consumes existing provider, object-manifest and runtime-package
bindings. Its report is diagnostic; the normal strong dispatch/link gate remains
the execution authority and must only run after these prerequisites pass.
"""

from pathlib import Path

from ..artifacts.artifact_set import canonical_sha256_v3
from ..candidate.build_model import CandidateNativeBuildError
from ..candidate.build_values import _read_json_object
from ..candidate.runtime_model import NATIVE_RUNTIME_MANIFEST_FILENAME
from ..candidate.formats import SHARED_MODULE_RUNTIME_PACKAGE_FORMAT
from ..components.bisimulation_allocation_classes import checked_allocation_requirements, require_allocation_class
from ..components.bisimulation_allocation_producers import allocation_producer_correspondence
from ..components.bisimulation_lifetime_namespace import checked_lifetime_call
from ..semantic_objects.object_authority import MachineObjectAuthorityV2
from ..util import sha256_file


def check_allocation_manifest_binding(*, qualification, manifest, manifest_sha256):
    """Reconstruct the existing object-binding facet before consuming metadata."""
    if not {'qualification_input_sha256', 'implementation_sha256', 'proof_classification'} <= set(manifest):
        raise CandidateNativeBuildError('portable allocation manifest omits its qualification binding')
    provenance = {}
    for dependency in qualification.payload['dependencies']:
        if dependency.startswith('provider-provenance:'):
            identity, separator, digest = dependency.removeprefix('provider-provenance:').rpartition(':')
            if not separator or not identity or len(digest) != 64 or identity in provenance:
                raise CandidateNativeBuildError('portable allocation provenance is ambiguous')
            provenance[identity] = digest
    expected = canonical_sha256_v3({
        'qualification_input': manifest['qualification_input_sha256'],
        'source_package': manifest['implementation_sha256'], 'object_manifest': manifest_sha256,
        'proof_classification': manifest['proof_classification'], 'provenance_artifact_sha256s': provenance,
        'facet': 'object_binding', 'status': 'checked',
    })
    facets = [row for row in qualification.payload['facets'] if row['name'] == 'object_binding']
    if len(facets) != 1 or facets[0]['status'] != 'checked' or facets[0]['receipt_sha256'] != expected:
        raise CandidateNativeBuildError('portable allocation overlay manifest is not bound to its qualification')


def check_portable_allocation_contexts(*, portable_inputs, object_manifest_path, selection, qualifications):
    """Check only consumed classes, using the runtime selected for this link."""
    required = [row for row in portable_inputs if row.get('allocation_context') is not None]
    if not required:
        return None
    try:
        if selection.payload['status'] != 'complete':
            raise ValueError('allocation implementation selection is incomplete')
        root = Path(object_manifest_path).parent
        manifest = _read_json_object(Path(object_manifest_path), 'allocation runtime object manifest')
        manifest_core = {k: v for k, v in manifest.items() if k != 'receipt_sha256'}
        if manifest.get('receipt_sha256') != canonical_sha256_v3(manifest_core):
            raise ValueError('allocation runtime object manifest is stale')
        runtime_path = root / NATIVE_RUNTIME_MANIFEST_FILENAME
        runtime = _read_json_object(runtime_path, 'allocation runtime package')
        runtime_sha256 = sha256_file(runtime_path)
        if (manifest.get('source_runtime_package_sha256') != runtime_sha256 or
                runtime.get('format') != SHARED_MODULE_RUNTIME_PACKAGE_FORMAT or
                runtime.get('status') != 'ready' or runtime.get('blockers') != []):
            raise ValueError('allocation runtime package is missing, stale or incomplete')
        object_hashes = sorted({row['object_sha256'] for row in manifest['objects']})
        artifact = canonical_sha256_v3({
            'runtime_package_sha256': runtime_sha256,
            'ingress_plan_sha256': sha256_file(root / 'native-ingress-plan.json'),
            'object_manifest_receipt_sha256': manifest['receipt_sha256'], 'object_sha256s': object_hashes,
        })
        choices = [*selection.payload['definition_selections'], *selection.payload['obligation_selections']]
        selected = {(row['provider_id'], row['qualification_sha256']) for row in choices}
        runtime_providers = [item for item in qualifications
            if item.provider_kind == 'qualified_runtime' and (item.provider_id, item.identity) in selected and
            item.payload['status'] == 'complete' and item.payload['provider_artifact_sha256'] == artifact and
            any(facet['name'] == 'runtime_qualification' and facet['status'] == 'checked' and
                facet['receipt_sha256'] == runtime_sha256 for facet in item.payload['facets'])]
        if len(runtime_providers) != 1:
            raise ValueError('allocation runtime objects and package lack one exact selected qualification')
        inputs = runtime['inputs']
        native_authority = inputs['canonical_inputs']['machine_object_authority']
        relative = native_authority['path']
        if not isinstance(relative, str) or Path(relative).name != relative:
            raise ValueError('allocation runtime authority path is not a package member')
        authority_path = root / relative
        authority = MachineObjectAuthorityV2.parse(_read_json_object(authority_path, 'allocation runtime authority'))
        if sha256_file(authority_path) != native_authority['sha256'] or authority.authority_sha256 != native_authority['authority_sha256']:
            raise ValueError('allocation runtime authority is stale')
        inventory = {'object_rules': native_authority['rules'], 'external_range_rules': inputs['external_range_contracts']['rules']}
        entries = []
        for item in required:
            if (item['provider_id'], item['qualification_sha256']) not in selected:
                raise ValueError('allocation component is no longer selected')
            context = item['allocation_context']
            proof_authority = MachineObjectAuthorityV2.parse(context['reference_authority'])
            original = proof_authority.bindings.get('original_pe_sha256')
            if (not isinstance(original, str) or len(original) != 64 or
                    original != authority.bindings.get('original_pe_sha256')):
                raise ValueError('allocation proof and runtime bind different original modules')
            requirements = checked_allocation_requirements(proof_authority, context['requirements'])
            identities = {row['authority']['id'] for row in requirements}
            subset = MachineObjectAuthorityV2(machine_backend=authority.machine_backend,
                bindings=authority.bindings,
                rules=[row for row in authority.to_payload()['rules'] if row['id'] in identities])
            correspondence = [row for row in allocation_producer_correspondence(subset, inventory) if row is not None]
            actual = {row['class_requirement']['authority']['id']: row for row in correspondence}
            for requirement in requirements:
                require_allocation_class(requirement, actual[requirement['authority']['id']]['class_requirement'])
            for spec in context['call_specs']:
                checked_lifetime_call(spec, inventory=inventory)
                if spec['instruction_rva'] not in inputs['external_dispatch']['authorized_instruction_rvas']:
                    raise ValueError('allocation call site is not authorized by the selected runtime')
            entries.append({'provider_id': item['provider_id'], 'qualification_sha256': item['qualification_sha256'],
                'contextual_proof_sha256': item['contextual_proof_sha256'], 'operation_id': item['overlay']['operation_id'],
                'requirements_sha256': canonical_sha256_v3(requirements), 'correspondence': correspondence})
        return {'authority': False, 'runtime_package_sha256': runtime_sha256,
            'runtime_qualification_sha256': runtime_providers[0].identity,
            'runtime_object_manifest_receipt_sha256': manifest['receipt_sha256'], 'entries': entries}
    except (ValueError, KeyError, TypeError, OSError) as exc:
        raise CandidateNativeBuildError(f'portable allocation correspondence failed: {exc}') from exc
