"""Proof adapters retain the exact behavior identity used by native range rules."""

import copy
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.candidate.runtime_canonical_common import _checked_contract
from spaghetti_extractor.candidate.runtime_external_range_validation import _external_range_rules
from spaghetti_extractor.external.contracts import (
    CheckedExternalSiteContractError, parse_checked_external_site_contract,
)
from spaghetti_extractor.external.machine_import_profiles import load_machine_import_profile_set
from spaghetti_extractor.external.resolved_contract import resolved_import_contract_behavior
from .test_runtime_allocation_sites import checked_site, native_inventory

TESTKIT = {"fixtures": (), "resources": ("profiles/pe32-kernel32-runtime-v1.json",)}
ROOT = Path(__file__).resolve().parents[3]


def selected_row(symbol="GlobalAlloc"):
    profiles = load_machine_import_profile_set([ROOT / TESTKIT["resources"][0]])
    selected = next(value for identity, value in profiles.by_identity().items() if identity.value == symbol)
    return {"identity": {**selected.contract["import"], "ordinal": None}, "boundary": {},
            "contract": {"payload": copy.deepcopy(selected.contract),
                "profile_id": selected.profile_id, "profile_sha256": selected.profile_sha256,
                "entry_key": selected.entry_key, "entry_index": selected.entry_index}}


class NativeContractIdentityTests(unittest.TestCase):
    def test_real_allocation_and_release_profiles_match_native_inventory_identity(self):
        for index, symbol in enumerate(("GlobalAlloc", "GlobalFree")):
            row = selected_row(symbol)
            behavior = resolved_import_contract_behavior(row)
            template = checked_site(index)
            call = SimpleNamespace(argument_nodes=(), instruction_rva=template.instruction_rva)
            checked = _checked_contract(row=row, call=call, escape_index={})
            tail = _checked_contract(row=row, call=call, escape_index={}, tail_jump=True)
            self.assertNotEqual(checked.stack_arguments, tail.stack_arguments)
            self.assertEqual(behavior.identity_sha256(), checked.identity_sha256())
            self.assertEqual(checked.identity_sha256(), tail.identity_sha256())
            # Preserve the established native digest and exact serialized site.
            self.assertEqual(checked.identity_sha256(), canonical_sha256_v3({
                "identity": checked.identity.payload(), "profile_binding": checked.profile_binding,
                "abi_template": checked.abi_template, "arity": checked.arity_payload(),
                "profile_disposition": checked.profile_disposition,
                "effect_contract": checked.profile_effect_payload(),
            }))
            self.assertEqual(parse_checked_external_site_contract(checked.payload()).payload(), checked.payload())
            site = replace(template, dll="kernel32.dll", symbol=symbol,
                checked_external_contract=checked, abi_metadata_sha256=canonical_sha256_v3(checked.profile_effect_payload()),
                target_resolution_evidence={"kind": "resolved-external-environment-v1", "sha256": "d" * 64,
                    "identity": ["kernel32.dll", "symbol", symbol]})
            rules, _, blockers = _external_range_rules(native_inventory([site]), None,
                                                      resolved_environment_sha256="d" * 64)
            self.assertFalse(blockers)
            self.assertTrue(rules)
            self.assertEqual({r.contract_identity_sha256 for r in rules}, {behavior.identity_sha256()})

    def test_same_effects_with_different_selected_profiles_have_distinct_identities(self):
        row = selected_row()
        original = resolved_import_contract_behavior(row)
        mutations = [
            ("profile_id", "other-profile"), ("profile_sha256", "e" * 64),
            ("entry_key", "other-contracts"), ("entry_index", 999),
        ]
        for key, value in mutations:
            altered = copy.deepcopy(row)
            altered["contract"][key] = value
            behavior = resolved_import_contract_behavior(altered)
            with self.subTest(field=key):
                self.assertEqual(original.profile_effect_payload(), behavior.profile_effect_payload())
                self.assertNotEqual(original.identity_sha256(), behavior.identity_sha256())

    def test_import_abi_disposition_ownership_and_initialization_remain_bound(self):
        original = selected_row()
        digest = resolved_import_contract_behavior(original).identity_sha256()
        paths = [
            (("identity", "symbol"), "AnotherAllocator"),
            (("contract", "payload", "abi_template"), "pe32-cdecl-v1"),
            (("contract", "payload", "disposition"), "terminates"),
            (("contract", "payload", "result_register_relations", 0, "ownership", "family"), "another.heap"),
            (("contract", "payload", "result_register_relations", 0, "nullable"), False),
            (("contract", "payload", "result_register_relations", 0, "allocation", "initialization"), {"kind": "zero"}),
        ]
        for path, value in paths:
            altered = copy.deepcopy(original)
            target = altered
            for part in path[:-1]: target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path):
                self.assertNotEqual(digest, resolved_import_contract_behavior(altered).identity_sha256())
        case_only = copy.deepcopy(original)
        case_only["identity"]["dll"] = "KERNEL32.DLL"
        self.assertEqual(digest, resolved_import_contract_behavior(case_only).identity_sha256())

    def test_metadata_spelling_normalizes_and_collisions_fail_closed(self):
        original = selected_row()
        original["contract"]["payload"]["memory_footprints"] = [{"bytes": 4}]
        normalized = copy.deepcopy(original)
        normalized["contract"]["payload"]["memory_footprints"] = [{"byte_count": 4}]
        self.assertEqual(resolved_import_contract_behavior(original).identity_sha256(),
                         resolved_import_contract_behavior(normalized).identity_sha256())
        original["contract"]["payload"]["memory_footprints"][0]["byte_count"] = 8
        with self.assertRaisesRegex(CheckedExternalSiteContractError, "collides"):
            resolved_import_contract_behavior(original)
        for field in ("identity", "contract", "boundary"):
            row = selected_row()
            del row[field]
            with self.subTest(field=field), self.assertRaisesRegex(CheckedExternalSiteContractError, "incomplete"):
                resolved_import_contract_behavior(row)
