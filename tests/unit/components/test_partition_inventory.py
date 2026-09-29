"""Manual ownership cannot erase code, dynamic routes or deployment premises."""
from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from spaghetti_extractor.cli import main
from spaghetti_extractor.components.formats import COMPONENT_PARTITION_INTENT_V1_FORMAT
from spaghetti_extractor.components.partition_inventory import inventory_partition, parse_partition

TESTKIT = {"commands": ("boundary inventory",)}


def fixture():
    def symbol(uid):
        return f"original:function:{uid}"
    units = [{"unit_id": uid, "rva_start": rva, "rva_end": rva + 4}
             for uid, rva in (("caller", 16), ("leaf", 32), ("cold", 48))]
    plan = {"bindings": {"pe_sha256": "1" * 64}, "unit_inventory": units,
            "transfers": [{"identity": row["unit_id"], "terminator": {"op": "outcome_return"}}
                          for row in units]}
    module = SimpleNamespace(identity="2" * 64, semantic_object=SimpleNamespace(transfer_plan=plan), payload={
        "status": "incomplete",
        "roots": [{"root_id": "process", "target_symbol": symbol("caller")}],
        "active_symbols": [{"symbol_id": symbol(row["unit_id"]), "domain_ids": ["callback-domain"]} for row in units],
        "active_relocations": [
            {"source_symbol": symbol("caller"), "target_symbols": [symbol("leaf")],
             "kind": "internal_call", "relocation_id": "call", "status": "resolved"},
            {"source_symbol": symbol("leaf"), "target_symbols": [symbol("cold")],
             "kind": "direct_control", "relocation_id": "cold-edge", "status": "resolved"},
            {"source_symbol": "image", "target_symbols": [symbol("leaf")],
             "kind": "code_pointer", "relocation_id": "callback", "status": "resolved"},
            {"source_symbol": symbol("leaf"), "target_symbols": ["image"],
             "kind": "data", "relocation_id": "memory", "status": "resolved"},
            {"source_symbol": symbol("caller"), "target_symbols": [],
             "kind": "indirect_call", "relocation_id": "dynamic", "status": "runtime_obligation"},
            {"source_symbol": symbol("cold"), "target_symbols": [],
             "kind": "direct_control", "relocation_id": "noreturn", "status": "checked_infeasible"},
        ],
        "definitions": [{"definition_id": "d-" + row["unit_id"], "symbol_id": symbol(row["unit_id"])} for row in units]
                       + [{"definition_id": "d-image", "symbol_id": "image"}],
        "definition_requirements": [],
        "residual_obligations": [{"obligation_id": "dispatch", "class": "internal_code_dispatch"}],
        "semantic_holes": [{"subject": "unavailable"}], "analysis_frontiers": [{"subject": "unresolved"}],
    })
    partition = {"format": COMPONENT_PARTITION_INTENT_V1_FORMAT, "target": "fixture", "pe_sha256": "1" * 64,
                 "units": [{"id": "caller", "description": "Caller", "rva_ranges": [[16, 20]]},
                           {"id": "leaf", "description": "Leaf including cold tail", "rva_ranges": [[32, 36], [48, 52]]}]}
    return module, partition


class PartitionInventoryTests(unittest.TestCase):
    def setUp(self):
        self.module, self.partition = fixture()

    def audit(self, **kwargs):
        return inventory_partition(module=self.module, partition=self.partition, **kwargs)

    def test_full_coverage_keeps_runtime_storage_and_semantic_blockers(self):
        result = self.audit()
        self.assertEqual(result["coverage_status"], "complete")
        self.assertEqual(result["counts"]["assigned_machine_units"], 3)
        self.assertEqual(result["liftability_status"], "unverified")
        self.assertFalse(result["activation_authorized"])
        self.assertEqual(result["non_code_definitions"], [{"definition_id": "d-image", "symbol_id": "image"}])
        for key in ("roots", "semantic_holes", "analysis_frontiers", "residual_obligations"):
            self.assertEqual(result[key], self.module.payload[key])
        self.assertEqual([r["relocation_id"] for r in result["relocations_without_targets"]], ["dynamic", "noreturn"])

    def test_crossings_include_callback_and_memory_but_keep_cold_tail_internal(self):
        result = self.audit()
        caller, leaf = result["units"]
        self.assertEqual(caller["dependencies"], [{"subject": "leaf", "kinds": ["internal_call"]}])
        self.assertEqual(leaf["dependencies"], [{"subject": "image", "kinds": ["data"]}])
        self.assertEqual(leaf["incoming_owners"], ["caller", "image"])
        self.assertEqual(leaf["entries"], ["leaf"])
        self.assertNotIn("cold-edge", leaf["crossing_relocation_ids"])
        self.assertEqual(leaf["admitted_domain_ids"], ["callback-domain"])

    def test_omission_remains_uncovered_even_when_no_root_names_it(self):
        self.partition["units"][1]["rva_ranges"].pop()
        result = self.audit()
        self.assertEqual(result["coverage_status"], "incomplete")
        self.assertEqual(result["unassigned_unit_ids"], ["cold"])
        self.assertIn("original:function:cold", [r["subject"] for r in result["units"][1]["dependencies"]])

    def test_overlap_mid_instruction_empty_and_foreign_image_reject(self):
        for mutation, message in (
            (lambda p: p["units"][1]["rva_ranges"].append([18, 20]), "overlapping"),
            (lambda p: p["units"][0].update(rva_ranges=[[16, 19]]), "cuts through"),
            (lambda p: p["units"][0].update(rva_ranges=[[17, 20]]), "cuts through"),
            (lambda p: p["units"][0].update(rva_ranges=[[80, 84]]), "no machine transfers"),
            (lambda p: p.update(pe_sha256="9" * 64), "different original"),
        ):
            with self.subTest(message=message):
                plan = copy.deepcopy(self.partition)
                mutation(plan)
                with self.assertRaisesRegex(ValueError, message):
                    inventory_partition(module=self.module, partition=plan)

    def test_unknown_fields_duplicate_names_and_boolean_rvas_reject(self):
        for mutation in (
            lambda p: p.update(authority=True),
            lambda p: p["units"].append(copy.deepcopy(p["units"][0])),
            lambda p: p["units"][0].update(rva_ranges=[[True, 20]]),
        ):
            plan = copy.deepcopy(self.partition)
            mutation(plan)
            with self.assertRaises(ValueError):
                parse_partition(plan)

    def test_split_and_merge_recompute_boundaries_without_synthetic_apis(self):
        self.partition["units"][1]["rva_ranges"].pop()
        self.partition["units"].append({"id": "tail", "description": "Manual subregion", "rva_ranges": [[48, 52]]})
        split = self.audit()
        leaf = next(r for r in split["units"] if r["id"] == "leaf")
        self.assertIn({"subject": "tail", "kinds": ["direct_control"]}, leaf["dependencies"])
        self.assertEqual(split["coverage_status"], "complete")
        self.assertIn("partition_is_not_a_checked_boundary_contract", leaf["blockers"])
        self.partition["units"][1]["rva_ranges"].append([48, 52])
        self.partition["units"].pop()
        self.assertEqual(self.audit()["counts"]["partition_units"], 2)

    def test_machine_context_is_visible_even_inside_same_planned_routine(self):
        semantics = SimpleNamespace(unit_ids=("leaf",), proof_context_transfer_ids=("leaf", "cold"))
        binding = SimpleNamespace(operations=[SimpleNamespace(semantics=semantics)], intent_sha256="3" * 64, status="complete")
        result = self.audit(bindings={"small-leaf": binding})
        row = result["component_bindings"][0]
        self.assertEqual(row["unowned_proof_context_unit_ids"], ["cold"])
        self.assertEqual(row["unowned_proof_context_owners"], ["leaf"])
        self.assertFalse(row["activation_authorized"])

    def test_public_command_uses_retained_inputs_and_returns_failure_for_omissions(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "partition.json"
            output = root / "inventory.json"
            for complete in (True, False):
                if not complete:
                    self.partition["units"][1]["rva_ranges"].pop()
                plan.write_text(json.dumps(self.partition))
                with patch("spaghetti_extractor.semantic_link.module_v2.LinkedSemanticModuleV2.load", return_value=self.module), contextlib.redirect_stdout(io.StringIO()):
                    result = main(["boundary", "inventory", "fixture", "--partition", str(plan),
                                   "--semantic-module", str(root / "module.json"), "--output", str(output)])
                self.assertEqual(result, 0 if complete else 1)
                self.assertFalse(json.loads(output.read_text())["authority"])

    def test_qualification_coverage_and_exact_context_are_separate(self):
        owned = {"definitions": [{"definition_id": "d-leaf", "symbol_id": "original:function:leaf"}], "obligations": []}
        context = {"definitions": [{"definition_id": "d-cold", "symbol_id": "original:function:cold"}], "semantic_slice_sha256": "5" * 64}
        qualification = SimpleNamespace(identity="6" * 64,
            semantic_slice=SimpleNamespace(payload=owned, identity="4" * 64),
            payload={"status": "complete", "provider_kind": "qualified_portable_c", "exact_context": context})
        with patch("spaghetti_extractor.components.partition_inventory.build_semantic_slice_v2",
                   side_effect=[{"semantic_slice_sha256": "4" * 64}, {"semantic_slice_sha256": "5" * 64}]):
            result = self.audit(qualifications=(qualification,))
        leaf = result["units"][1]
        self.assertEqual(leaf["observed_portable_definition_ids"], ["d-leaf"])
        self.assertEqual(leaf["machine_definition_ids_without_portable_qualification"], ["d-cold"])
        self.assertIn("qualification_requires_exact_machine_neighbors", leaf["blockers"])
        self.assertFalse(result["activation_authorized"])
        for hashes in (("0" * 64,), ("4" * 64, "0" * 64)):
            with patch("spaghetti_extractor.components.partition_inventory.build_semantic_slice_v2",
                       side_effect=[{"semantic_slice_sha256": h} for h in hashes]):
                with self.assertRaisesRegex(ValueError, "stale"):
                    self.audit(qualifications=(qualification,))

    def test_runtime_obligations_are_attributed_without_dropping_global_ones(self):
        local = {"obligation_id": "local-dispatch", "subjects": ["leaf:call:0"]}
        self.module.payload["residual_obligations"].append(local)
        result = self.audit()
        self.assertEqual(result["units"][1]["residual_obligation_ids"], ["local-dispatch"])
        self.assertEqual(len(result["residual_obligations"]), 2)
