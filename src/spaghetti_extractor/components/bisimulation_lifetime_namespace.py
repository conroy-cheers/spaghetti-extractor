"""Check call frames and lower lifetime requirements in the chosen proof namespace.

Local classes are conditional proof inputs. Native correspondence is checked only
when a native inventory is supplied; neither path establishes incoming ownership.
"""

from collections.abc import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..external.contracts import CheckedExternalSiteContractError, parse_checked_external_site_contract
from ..external.lifetime_effects import LifetimeEffectError, checked_lifetime_effect
from .bisimulation_allocation_classes import allocation_class_requirement, checked_allocation_requirements, require_allocation_class
from .bisimulation_allocation_namespace import allocation_namespace_producers
from .bisimulation_allocation_producers import allocation_producer_correspondence
from .bisimulation_support import BisimulationRefinementError


def lifetime_namespace(authority, *, inventory, requirements):
    if authority is None or (inventory is None and requirements is None):
        raise BisimulationRefinementError('proof lifetime calls require allocation class correspondence')
    namespace = allocation_namespace_producers(authority, inventory=inventory, requirements=requirements)
    if inventory is None:
        classes = {row['authority']['id']: row for row in checked_allocation_requirements(authority, requirements)}
    else:
        classes = {row['class_requirement']['authority']['id']: row['class_requirement']
                   for row in allocation_producer_correspondence(authority, inventory) if row is not None}
    producers = [{**row, 'object': rule.object_id, 'class_requirement': classes[rule.identity]}
                 for rule, row in zip(authority.rules, namespace) if row is not None]
    families = {row['class_requirement']['effect']['ownership']['family']: row['proof_family'] for row in producers}
    return producers, families


def checked_lifetime_transitions(specs, *, authority, inventory=None, requirements=None):
    """Validate the same class, site and argument premises for adapters and oracle."""
    lifetime_specs = [spec for spec in specs if isinstance(spec.get('external_effect_contract'), Mapping)
                      and spec['external_effect_contract'].get('world_effect') in {'dynamicRanges', 'dynamicRangeRelease'}]
    if not lifetime_specs:
        return []
    producers, families = lifetime_namespace(authority, inventory=inventory, requirements=requirements)
    transitions = []
    for spec in lifetime_specs:
        effect = checked_lifetime_call(spec, inventory=inventory)
        if spec['raw_indices'] != list(range(len(spec['offsets']))) or spec['outputs'] or spec['cell_inputs']:
            raise BisimulationRefinementError('proof lifetime call needs its full scalar physical argument frame')
        family = families.get(effect['ownership']['family'])
        if family is None:
            raise BisimulationRefinementError('proof release family has no represented owned allocation class')
        producer = None
        if effect['action'] == 'add_result_range':
            selected = [row for row in producers if
                        row['class_requirement']['contract_identity_sha256'] == spec['external_contract_identity_sha256']]
            if len(selected) != 1:
                raise BisimulationRefinementError('proof allocation call lacks a unique producer authority')
            producer = selected[0]
            rule = next(rule for rule in authority.rules
                        if rule.identity == producer['class_requirement']['authority']['id'])
            require_allocation_class(allocation_class_requirement(rule,
                contract_identity_sha256=spec['external_contract_identity_sha256'],
                effect=effect, argument_words=len(spec['offsets'])), producer['class_requirement'])
        transitions.append({'spec': spec, 'effect': effect, 'family': family, 'producer': producer})
    return transitions


def checked_lifetime_call(spec, *, inventory):
    """Consume the canonical import frame, including the selected call outcome.

    The overlay derives this site from replayed transfers and the resolved
    environment. Parsing a supplied site alone is not provenance or activation.
    """
    try:
        payload = spec.get('checked_external_contract')
        if not isinstance(payload, Mapping):
            raise ValueError('lifetime call lacks its checked external site contract')
        site = parse_checked_external_site_contract(payload, context='proof lifetime call')
        if canonical_sha256_v3(site.payload()) != canonical_sha256_v3(payload):
            raise ValueError('lifetime call site contract is not canonical')
        if (spec['event_kind'] != 'SPX_CALL_EXTERNAL_IMPORT' or site.identity.kind != 'import' or
                site.transfer_kind != 'call' or site.disposition != 'returns_here' or site.argument_base_offset != 0):
            raise ValueError('proof lifetime transition requires a checked direct CALL frame')
        if (site.profile_disposition != 'returns' or site.arity_kind != 'fixed' or
                site.callback_effect != 'none' or site.external_service_protocol is not None):
            raise ValueError('lifetime call outcome or protocol is unsupported')
        if site.identity_sha256() != spec['external_contract_identity_sha256']:
            raise ValueError('lifetime call site disagrees with its selected behavior identity')
        if (site.argument_words != len(spec['offsets']) or
                [argument.offset for argument in site.stack_arguments] != spec['offsets'] or
                spec['callee_cleanup'] != (4 * site.argument_words if site.abi_template == 'pe32-stdcall-v1' else 0)):
            raise ValueError('lifetime call site disagrees with its proof argument frame')
        effect = checked_lifetime_effect(spec['external_effect_contract'], argument_words=site.argument_words)
        expected = checked_lifetime_effect(site.profile_effect_payload(), argument_words=site.argument_words)
        if canonical_sha256_v3(effect) != canonical_sha256_v3(expected):
            raise ValueError('lifetime call effect disagrees with its checked site')
        if inventory is not None:
            matches = [row for row in inventory['external_range_rules']
                       if row.get('contract_identity_sha256') == site.identity_sha256() and
                       row.get('instruction_rva') == spec['instruction_rva'] and row.get('action') == effect['action']]
            if len(matches) != 1:
                raise ValueError('proof lifetime site has missing or ambiguous native evidence')
            native = matches[0]
            if (type(native.get('argument_base_offset')) is not int or native['argument_base_offset'] != 0 or
                    type(native.get('argument_count')) is not int or native['argument_count'] != site.argument_words or
                    canonical_sha256_v3({key: native.get(key) for key in effect}) != canonical_sha256_v3(effect)):
                raise ValueError('proof lifetime effect disagrees with its native range rule')
        return effect
    except (CheckedExternalSiteContractError, LifetimeEffectError, ValueError, KeyError, TypeError) as exc:
        raise BisimulationRefinementError(str(exc)) from exc
