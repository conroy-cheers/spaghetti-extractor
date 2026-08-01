from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.gnu_hello_original_combined_declarations import (
    GnuHelloOriginalCombinedDeclarationsError,
    REACHABILITY_EXPORT_FIELD,
    VALUE_FLOW_EXPORT_FIELD,
    write_gnu_hello_original_combined_declarations,
)
from spaghetti_extractor.relational.lean.original_combined_inventory import (
    ORIGINAL_COMBINED_CALL_FRAME_DECLARATIONS_FORMAT,
    ORIGINAL_COMBINED_REACHABILITY_DECLARATIONS_FORMAT,
    ORIGINAL_COMBINED_VALUE_FLOW_DECLARATIONS_FORMAT,
)
from spaghetti_extractor.util import sha256_file


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    return path


def _ref(module: str, namespace: str, symbol: str) -> dict[str, str]:
    return {"module": module, "namespace": namespace, "symbol": symbol}


class _Fixture:
    original = "1" * 64
    state_machine = "2" * 64
    reach_module = "StageA.GeneratedReachabilityExports"
    reach_namespace = "StageA.Generated.ReachabilityExports"
    value_module = "StageA.GeneratedValueFlowExports"
    value_namespace = "StageA.Generated.ValueFlowExports"
    combined_module = "StageA.GeneratedStackCombined"
    combined_namespace = "StageA.Generated.StackCombined"
    direct_module = "StageA.GeneratedDirectCall"
    direct_namespace = "StageA.Generated.DirectCall"

    def __init__(self, root: Path) -> None:
        self.root = root
        self.documents: dict[str, object] = {}
        self.paths: dict[str, Path] = {}
        self._build()

    def _put(self, name: str, value: object) -> Path:
        self.documents[name] = value
        path = _write(self.root / f"{name}.json", value)
        self.paths[name] = path
        return path

    def _build(self) -> None:
        declarations = {
            name: _ref(
                self.reach_module,
                self.reach_namespace,
                {
                    "program": "generatedProgram",
                    "original_context": "generatedOriginalContext",
                    "target_ids": "generatedTargetIds",
                    "target_ids_exact": "generatedTargetIdsExact",
                    "target_ids_unique": "generatedTargetIdsUnique",
                    "target_round_trips": "generatedTargetRoundTrips",
                }[name],
            )
            for name in (
                "program",
                "original_context",
                "target_ids",
                "target_ids_exact",
                "target_ids_unique",
                "target_round_trips",
            )
        }
        plan = {
            "format": "stage-a-interpreter-mixed-original-v1",
            "state_machine_sha256": self.state_machine,
            "reachable_target_ids": [0, 1, 2],
            "counts": {"regions": 3},
            REACHABILITY_EXPORT_FIELD: declarations,
        }
        plan_path = self._put("mixed_plan", plan)

        mixed_manifest = {
            "format": "stage-a-relational-phase-v1",
            "phase": "mixed-original-final-lean",
            "proof_authority": False,
            "inputs": {
                "original_pe": {"sha256": self.original},
                "state_machine": {"sha256": self.state_machine},
            },
            "counts": {"regions": 3},
            "modules": ["GeneratedMixedOriginal", "GeneratedReachabilityExports"],
        }
        mixed_path = self._put("mixed_manifest", mixed_manifest)

        static_theorem = (
            "StageA.Generated.StaticReachability."
            "generatedExactOriginalDecodedStaticReachability"
        )
        static_plan = {
            "format": "stage-a-interpreter-mixed-original-static-reachability-v1",
            "inputs": {
                "mixed_original_plan": {"sha256": sha256_file(plan_path)},
                "state_machine_sha256": self.state_machine,
            },
            "counts": {"reachable_targets": 3},
            "result": {"theorem": static_theorem},
        }
        self._put("static_plan", static_plan)
        static_manifest = {
            "format": "stage-a-relational-phase-v1",
            "phase": "mixed-original-static-reachability",
            "proof_authority": False,
            "inputs": {
                "mixed_original_plan": {"sha256": sha256_file(plan_path)}
            },
            "theorem": static_theorem,
            "modules": ["GeneratedStaticReachability"],
        }
        self._put("static_manifest", static_manifest)

        carrier_binding = (
            "StageA.Generated.CarrierBinding."
            "generatedOriginalExactMixedProgramBinding"
        )
        carrier = {
            "format": "stage-a-relational-phase-v1",
            "phase": "mixed-original-carrier-binding-lean",
            "proof_authority": False,
            "inputs": {
                "mixed_original_manifest": {"sha256": sha256_file(mixed_path)}
            },
            "exact_mixed_binding": carrier_binding,
            "modules": ["GeneratedCarrierBinding"],
        }
        self._put("carrier", carrier)

        direct_term = _ref(
            self.direct_module,
            self.direct_namespace,
            "generatedCallerFrameContract",
        )
        direct = {
            "format": "stage-a-mixed-original-direct-call-authority-bindings-v2",
            "inputs": {
                "original_sha256": self.original,
                "state_machine_sha256": self.state_machine,
            },
            "contracts": [
                {
                    "source_rva": 0x2033,
                    "callsite_rva": 0x203C,
                    "continuation_target_id": 293,
                    "origin": "checked_finite_origin_call_caller_frame_word_summary",
                    "preserved_caller_frame_word_offsets": [32],
                    "authorizing_lean_term": direct_term,
                    "caller_frame_word_authorizing_lean_term": direct_term,
                }
            ],
        }
        direct_path = self._put("direct", direct)

        stack = {
            "format": "stage-a-original-stack-dynamic-control-closure-v1",
            "inputs": {
                "original_pe_sha256": self.original,
                "state_machine_sha256": self.state_machine,
            },
            "sites": [
                {
                    "source_rva": 0x2033,
                    "instruction_rva": 0x203C,
                    "source_target_id": 292,
                    "closure_mode": "finite_stack_target",
                }
            ],
        }
        self._put("stack", stack)

        value_ir = {
            "format": "stage-a-runtime-value-carry-ir-v1",
            "inputs": {
                "original_pe_sha256": self.original,
                "state_machine_sha256": self.state_machine,
                "direct_call_authority_sha256": sha256_file(direct_path),
            },
            "routes": [
                {
                    "stable_id": "gnu.original.callback-stack-slot",
                    "origin": {
                        "kind": "static_code_target",
                        "target_id": 17,
                        "offset": 0,
                    },
                    "locations": [
                        {
                            "location_id": 0,
                            "kind": "register",
                            "register": "ebx",
                            "offset": 0,
                        },
                        {
                            "location_id": 1,
                            "kind": "frame_word",
                            "register": "esp",
                            "offset": 32,
                        },
                    ],
                    "facts": [
                        {"target_id": 291, "location_id": 0},
                        {"target_id": 292, "location_id": 0},
                        {"target_id": 293, "location_id": 1},
                    ],
                    "target_fact": {"target_id": 293, "location_id": 1},
                    "transfers": [
                        {
                            "transfer_id": 0,
                            "kind": "call_frame_word_preserve",
                            "source_target_id": 292,
                            "target_target_id": 293,
                            "authority_lean_term": direct_term,
                        }
                    ],
                }
            ],
        }
        value_ir_path = self._put("value_ir", value_ir)

        value_report = {
            "format": "stage-a-runtime-value-carry-lean-v1",
            "proof_authority": False,
            "modules": ["GeneratedValueFlowExports"],
            "routes": [
                {
                    "stable_id": "gnu.original.callback-stack-slot",
                    "semantic_authority": [{"transfer_id": 0}],
                }
            ],
            VALUE_FLOW_EXPORT_FIELD: {
                "inventory": _ref(
                    self.value_module,
                    self.value_namespace,
                    "generatedInventory",
                ),
                "facts_exact": _ref(
                    self.value_module,
                    self.value_namespace,
                    "generatedFactsExact",
                ),
                "facts": [
                    {
                        "route_stable_id": "gnu.original.callback-stack-slot",
                        "fact_stable_id": (
                            "gnu.original.callback-stack-slot:location:0"
                        ),
                        "location_id": 0,
                        "target_ids": [291, 292],
                        "id": 0,
                        "term": _ref(
                            self.value_module,
                            self.value_namespace,
                            "generatedFact0",
                        ),
                        "id_exact": _ref(
                            self.value_module,
                            self.value_namespace,
                            "generatedFact0IdExact",
                        ),
                    },
                    {
                        "route_stable_id": "gnu.original.callback-stack-slot",
                        "fact_stable_id": (
                            "gnu.original.callback-stack-slot:location:1"
                        ),
                        "location_id": 1,
                        "target_ids": [293],
                        "id": 1,
                        "term": _ref(
                            self.value_module,
                            self.value_namespace,
                            "generatedFact1",
                        ),
                        "id_exact": _ref(
                            self.value_module,
                            self.value_namespace,
                            "generatedFact1IdExact",
                        ),
                    }
                ],
            },
        }
        value_report_path = self._put("value_report", value_report)

        stack_manifest = {
            "format": "stage-a-relational-phase-v1",
            "phase": "mixed-original-stack-dynamic-authority-lean",
            "proof_authority": False,
            "inputs": {
                "original_pe": {"sha256": self.original},
                "state_machine": {"sha256": self.state_machine},
                "direct_call_authority": {"sha256": sha256_file(direct_path)},
                "runtime_value_carry": {"sha256": sha256_file(value_ir_path)},
                "runtime_value_carry_lean_report": {
                    "sha256": sha256_file(value_report_path)
                },
            },
            "modules": ["GeneratedStackCombined"],
        }
        self._put("stack_manifest", stack_manifest)

        combined = {
            "format": "stage-a-gnu-hello-stack-dynamic-combined-evidence-v1",
            "proof_authority": False,
            "kernel_check": {
                "term": _ref(
                    self.combined_module,
                    self.combined_namespace,
                    "generatedCombinedEvidenceChecked",
                )
            },
            "sites": [
                {
                    "instruction_rva": 0x203C,
                    "source_target_id": 292,
                    "checked_dependencies": [
                        f"{self.combined_namespace}.generatedStackCallEntryCertificate",
                        f"{self.combined_namespace}.generatedStackCallFrameTransferAuthority",
                    ],
                }
            ],
        }
        self._put("combined", combined)

    def rewrite(self, name: str) -> None:
        _write(self.paths[name], self.documents[name])
        if name == "direct":
            direct_hash = sha256_file(self.paths[name])
            self.documents["value_ir"]["inputs"][
                "direct_call_authority_sha256"
            ] = direct_hash
            self.rewrite("value_ir")
            self.documents["stack_manifest"]["inputs"][
                "direct_call_authority"
            ]["sha256"] = direct_hash
        if name == "value_ir":
            self.documents["stack_manifest"]["inputs"]["runtime_value_carry"][
                "sha256"
            ] = sha256_file(self.paths[name])
        if name == "value_report":
            self.documents["stack_manifest"]["inputs"][
                "runtime_value_carry_lean_report"
            ]["sha256"] = sha256_file(self.paths[name])
        if name in {"direct", "value_ir", "value_report"}:
            _write(self.paths["stack_manifest"], self.documents["stack_manifest"])

    def generate(self, out: Path):
        return write_gnu_hello_original_combined_declarations(
            mixed_original_plan=self.paths["mixed_plan"],
            mixed_original_manifest=self.paths["mixed_manifest"],
            static_reachability_plan=self.paths["static_plan"],
            static_reachability_manifest=self.paths["static_manifest"],
            carrier_binding_manifest=self.paths["carrier"],
            direct_call_authority_report=self.paths["direct"],
            stack_dynamic_authority_report=self.paths["stack"],
            stack_dynamic_authority_manifest=self.paths["stack_manifest"],
            stack_combined_evidence_report=self.paths["combined"],
            value_provenance_ir=self.paths["value_ir"],
            value_provenance_report=self.paths["value_report"],
            out=out,
        )


class StageAGnuHelloOriginalCombinedDeclarationTests(unittest.TestCase):
    def test_emits_exact_deterministic_consumer_documents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            first = fixture.generate(fixture.root / "first")
            second = fixture.generate(fixture.root / "second")

            self.assertEqual(first.reachability.read_bytes(), second.reachability.read_bytes())
            self.assertEqual(first.call_frames.read_bytes(), second.call_frames.read_bytes())
            self.assertEqual(first.value_flows.read_bytes(), second.value_flows.read_bytes())

            reachability = json.loads(first.reachability.read_text(encoding="ascii"))
            frames = json.loads(first.call_frames.read_text(encoding="ascii"))
            flows = json.loads(first.value_flows.read_text(encoding="ascii"))
            self.assertEqual(
                reachability["format"],
                ORIGINAL_COMBINED_REACHABILITY_DECLARATIONS_FORMAT,
            )
            self.assertEqual(
                frames["format"], ORIGINAL_COMBINED_CALL_FRAME_DECLARATIONS_FORMAT
            )
            self.assertEqual(
                flows["format"], ORIGINAL_COMBINED_VALUE_FLOW_DECLARATIONS_FORMAT
            )
            self.assertEqual(len(frames["declarations"]["facts"]), 2)
            self.assertEqual(
                [row["id"] for row in flows["declarations"]["facts"]],
                [0, 1],
            )
            self.assertEqual(
                reachability["inputs"], frames["inputs"] | flows["inputs"]
            )

    def test_rejects_cross_artifact_original_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            fixture.documents["direct"]["inputs"]["original_sha256"] = "9" * 64
            fixture.rewrite("direct")
            with self.assertRaisesRegex(
                GnuHelloOriginalCombinedDeclarationsError,
                "direct-call report original_sha256 SHA-256 does not match",
            ):
                fixture.generate(fixture.root / "out")

    def test_rejects_missing_typed_reachability_exports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            del fixture.documents["mixed_plan"][REACHABILITY_EXPORT_FIELD]
            fixture.rewrite("mixed_plan")
            plan_hash = sha256_file(fixture.paths["mixed_plan"])
            fixture.documents["static_plan"]["inputs"]["mixed_original_plan"][
                "sha256"
            ] = plan_hash
            fixture.rewrite("static_plan")
            fixture.documents["static_manifest"]["inputs"][
                "mixed_original_plan"
            ]["sha256"] = plan_hash
            fixture.rewrite("static_manifest")
            with self.assertRaisesRegex(
                GnuHelloOriginalCombinedDeclarationsError,
                REACHABILITY_EXPORT_FIELD,
            ):
                fixture.generate(fixture.root / "out")

    def test_rejects_legacy_value_report_without_typed_value_flows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            del fixture.documents["value_report"][VALUE_FLOW_EXPORT_FIELD]
            fixture.rewrite("value_report")
            with self.assertRaisesRegex(
                GnuHelloOriginalCombinedDeclarationsError,
                "aggregate_invariant_constructor is not a typed",
            ):
                fixture.generate(fixture.root / "out")

    def test_rejects_value_flow_authority_that_disagrees_with_direct_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            fixture.documents["value_ir"]["routes"][0]["transfers"][0][
                "authority_lean_term"
            ] = _ref(
                "StageA.GeneratedOther",
                "StageA.Generated.Other",
                "otherAuthority",
            )
            fixture.rewrite("value_ir")
            with self.assertRaisesRegex(
                GnuHelloOriginalCombinedDeclarationsError,
                "value-provenance authority disagrees",
            ):
                fixture.generate(fixture.root / "out")

    def test_rejects_missing_typed_location_fact_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            fixture.documents["value_report"][VALUE_FLOW_EXPORT_FIELD]["facts"].pop()
            fixture.rewrite("value_report")
            with self.assertRaisesRegex(
                GnuHelloOriginalCombinedDeclarationsError,
                "do not cover the exact value-provenance route inventory",
            ):
                fixture.generate(fixture.root / "out")

    def test_rejects_duplicate_typed_value_flow_fact_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            facts = fixture.documents["value_report"][VALUE_FLOW_EXPORT_FIELD][
                "facts"
            ]
            facts[1]["id"] = 0
            fixture.rewrite("value_report")
            with self.assertRaisesRegex(
                GnuHelloOriginalCombinedDeclarationsError,
                "fact IDs must be nonempty, dense, and unique",
            ):
                fixture.generate(fixture.root / "out")

    def test_rejects_noncanonical_typed_value_flow_fact_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            facts = fixture.documents["value_report"][VALUE_FLOW_EXPORT_FIELD][
                "facts"
            ]
            facts.reverse()
            fixture.rewrite("value_report")
            with self.assertRaisesRegex(
                GnuHelloOriginalCombinedDeclarationsError,
                "canonical route/location order",
            ):
                fixture.generate(fixture.root / "out")


if __name__ == "__main__":
    unittest.main()
