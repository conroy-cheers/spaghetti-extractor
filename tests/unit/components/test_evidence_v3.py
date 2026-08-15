"""Candidate-only component evidence and qualification tests."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.evidence import (
    _MachineMemory,
    _UnsupportedSemantics,
    _eval_expr,
    produce_component_evidence,
)
from spaghetti_extractor.components.formats import (
    COMPONENT_ADAPTER_PLAN_V1_FORMAT,
    COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
)
from spaghetti_extractor.components.logical_abi import (
    LOGICAL_C_V1,
    LOGICAL_OBJECT_C_V1,
    READ_ONLY_BYTES_V1,
    logical_abi_header,
    logical_c_type,
    logical_type_kind,
)
from spaghetti_extractor.components.qualification import qualify_lift_unit
from spaghetti_extractor.components.source import (
    build_component_source_package,
    load_component_source_package,
)
from spaghetti_extractor.reconstruction.ir import MACHINE_IR_FORMAT


class ComponentEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.machine = self.root / "machine"
        self.machine.mkdir()
        self.contract = self.root / "contract"
        self.contract.mkdir()
        self.source_file = self.root / "component.c"
        self._write_scalar_machine()
        self._write_scalar_contract()
        self.verification = {
            "producer": "exhaustive-finite-domain-v1",
            "parameter_domains": [
                {
                    "parameter_id": "value",
                    "kind": "integer-range",
                    "minimum": 0,
                    "maximum": 255,
                }
            ],
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_exhaustive_evidence_qualifies_exact_scalar_logical_c(self) -> None:
        package = self._source(
            "uint32_t identity(uint32_t value) { return value; }\n"
        )
        adapter = self._adapter(package)
        evidence = self._evidence(
            package, adapter, self.verification, "evidence.json"
        )
        self.assertEqual(evidence["status"], "satisfied")
        self.assertEqual(evidence["coverage"]["cases"], 256)
        self.assertEqual(
            evidence["bindings"]["adapter_plan_sha256"],
            _read(adapter / "adapter-plan.json")["adapter_plan_sha256"],
        )
        qualification = qualify_lift_unit(
            contract=self.contract / "contract.json",
            implementation=package,
            evidence=evidence,
            adapter_plan=adapter,
            machine_ir=self.machine,
            verification=self.verification,
            out=self.root / "qualification.json",
        )
        self.assertEqual(qualification["status"], "qualified")
        self.assertTrue(qualification["activation"]["authorized"])

    def test_counterexample_is_violated_and_source_mapped(self) -> None:
        package = self._source(
            "uint32_t identity(uint32_t value) { return value + 1U; }\n"
        )
        adapter = self._adapter(package)
        evidence = self._evidence(
            package, adapter, self.verification, "violated.json"
        )
        self.assertEqual(evidence["status"], "violated")
        counterexample = evidence["coverage"]["first_counterexample"]
        self.assertEqual(counterexample["arguments"], {"value": 0})
        self.assertEqual(counterexample["expected"], 0)
        self.assertEqual(counterexample["observed"], 1)

    def test_scalar_control_evidence_compares_exact_branch_condition(self) -> None:
        self._write_control_machine()
        self._write_control_contract()
        verification = {
            "producer": "exhaustive-finite-domain-v1",
            "parameter_domains": [
                {
                    "parameter_id": "value",
                    "kind": "integer-range",
                    "minimum": 0,
                    "maximum": 15,
                }
            ],
        }
        package = self._source(
            "uint32_t identity(uint32_t value) { return value != 7U; }\n"
        )
        adapter = self._adapter(package)

        evidence = self._evidence(
            package, adapter, verification, "control-evidence.json"
        )

        self.assertEqual(evidence["status"], "satisfied")
        self.assertEqual(evidence["coverage"]["cases"], 16)

    def test_candidate_only_functional_vectors_qualify(self) -> None:
        self._write_scalar_contract(profile="validation-backed-v1")
        verification = {
            "producer": "candidate-only-functional-suite-v1",
            "cases": [
                {"id": "zero", "arguments": {"value": 0}, "expected": 0},
                {"id": "high", "arguments": {"value": 255}, "expected": 255},
            ],
        }
        package = self._source(
            "uint32_t identity(uint32_t value) { return value; }\n"
        )
        adapter = self._adapter(package)
        evidence = self._evidence(
            package, adapter, verification, "functional-evidence.json"
        )
        self.assertEqual(evidence["status"], "satisfied")
        self.assertEqual(
            evidence["method"]["kind"], "candidate_only_functional_suite_v1"
        )
        qualification = qualify_lift_unit(
            contract=self.contract / "contract.json",
            implementation=package,
            evidence=evidence,
            adapter_plan=adapter,
            machine_ir=self.machine,
            verification=verification,
            out=self.root / "functional-qualification.json",
        )
        self.assertEqual(qualification["status"], "qualified")

    def test_object_view_reads_declared_byte_buffer(self) -> None:
        self._use_object_fixture()
        package = self._object_source(
            """
uint32_t identity(const spx_ro_bytes_v1 *value, uint32_t length) {
  uint8_t byte = 0U;
  if (length == 0U) return 0U;
  return value->read_u8(value->context, 0U, &byte) == 0U ? byte : 0U;
}
"""
        )
        adapter = self._adapter(package)
        evidence = self._evidence(
            package,
            adapter,
            self._object_verification([[0], [1], [255]], extent=1),
            "object-evidence.json",
        )
        self.assertEqual(evidence["status"], "satisfied")
        self.assertEqual(evidence["coverage"]["cases"], 3)

    def test_out_of_view_access_is_a_located_protocol_violation(self) -> None:
        self._use_object_fixture()
        package = self._object_source(
            """
uint32_t identity(const spx_ro_bytes_v1 *value, uint32_t length) {
  uint8_t byte = 0U;
  (void)length;
  (void)value->read_u8(value->context, value->extent, &byte);
  return byte;
}
"""
        )
        adapter = self._adapter(package)
        evidence = self._evidence(
            package,
            adapter,
            self._object_verification([[7]], extent=1),
            "object-violation.json",
        )
        self.assertEqual(evidence["status"], "violated")
        issue = _issue(evidence, "component_checked_view_protocol_violation")
        self.assertEqual(
            issue["case_location"], {"case_index": 0, "case_id": "domain-0"}
        )
        self.assertEqual(
            issue["violation"],
            {
                "kind": "out_of_view_read",
                "parameter_id": "value",
                "offset": 1,
                "extent": 1,
            },
        )

    def test_malformed_extent_is_rejected_before_source_runs(self) -> None:
        self._use_object_fixture()
        package = self._object_source(
            """
uint32_t identity(const spx_ro_bytes_v1 *value, uint32_t length) {
  (void)value;
  (void)length;
  __builtin_trap();
}
"""
        )
        adapter = self._adapter(package)
        evidence = self._evidence(
            package,
            adapter,
            self._object_verification([[]], extent=1),
            "malformed-extent.json",
        )
        self.assertEqual(evidence["status"], "incomplete")
        issue = _issue(evidence, "component_evidence_semantics_unsupported")
        self.assertIn("declared bytes but extent 1", issue["detail"])

    def test_candidate_crash_is_incomplete(self) -> None:
        self._use_object_fixture()
        package = self._object_source(
            """
uint32_t identity(const spx_ro_bytes_v1 *value, uint32_t length) {
  (void)value;
  (void)length;
  __builtin_trap();
}
"""
        )
        adapter = self._adapter(package)
        evidence = self._evidence(
            package,
            adapter,
            self._object_verification([[7]], extent=1),
            "candidate-crash.json",
        )
        self.assertEqual(evidence["status"], "incomplete")
        _issue(evidence, "component_candidate_process_crashed")

    def test_candidate_timeout_is_incomplete(self) -> None:
        self._use_object_fixture()
        package = self._object_source(
            """
uint32_t identity(const spx_ro_bytes_v1 *value, uint32_t length) {
  (void)value;
  (void)length;
  for (;;) {}
}
"""
        )
        adapter = self._adapter(package)
        evidence = self._evidence(
            package,
            adapter,
            self._object_verification([[7]], extent=1),
            "candidate-timeout.json",
        )
        self.assertEqual(evidence["status"], "incomplete")
        _issue(evidence, "component_candidate_process_timed_out")

    def test_object_completion_mismatch_is_source_mapped(self) -> None:
        self._use_object_fixture()
        package = self._object_source(
            """
uint32_t identity(const spx_ro_bytes_v1 *value, uint32_t length) {
  uint8_t byte = 0U;
  (void)length;
  return value->read_u8(value->context, 0U, &byte) == 0U ? byte : 0U;
}
"""
        )
        adapter = self._adapter(package)
        payload = _read(adapter / "adapter-plan.json")
        payload["lowering"]["completion"]["state"]["ebx"] = {
            "op": "const",
            "value": 1,
            "width": 32,
        }
        _rewrite_hashed(adapter / "adapter-plan.json", payload, "adapter_plan_sha256")
        evidence = self._evidence(
            package,
            adapter,
            self._object_verification([[7]], extent=1),
            "completion-mismatch.json",
        )
        self.assertEqual(evidence["status"], "violated")
        counterexample = evidence["coverage"]["first_counterexample"]
        self.assertEqual(counterexample["case_id"], "domain-0")
        self.assertEqual(counterexample["kind"], "adapter_completion_mismatch")
        self.assertEqual(
            counterexample["boundary_mismatches"],
            [{"location": "state.ebx", "expected": 0, "observed": 1}],
        )

    def test_object_completion_memory_mismatch_is_source_mapped(self) -> None:
        self._use_object_fixture()
        package = self._object_source(
            """
uint32_t identity(const spx_ro_bytes_v1 *value, uint32_t length) {
  uint8_t byte = 0U;
  (void)length;
  return value->read_u8(value->context, 0U, &byte) == 0U ? byte : 0U;
}
"""
        )
        adapter = self._adapter(package)
        payload = _read(adapter / "adapter-plan.json")
        payload["lowering"]["completion"]["memory_writes"] = [
            {
                "address": {
                    "op": "sub32",
                    "args": [
                        {"op": "entry", "name": "esp"},
                        {"op": "const", "value": 4, "width": 32},
                    ],
                },
                "width": 1,
                "value": {"op": "const", "value": 0xA5, "width": 32},
            }
        ]
        _rewrite_hashed(adapter / "adapter-plan.json", payload, "adapter_plan_sha256")
        evidence = self._evidence(
            package,
            adapter,
            self._object_verification([[7]], extent=1),
            "completion-memory-mismatch.json",
        )
        self.assertEqual(evidence["status"], "violated")
        counterexample = evidence["coverage"]["first_counterexample"]
        self.assertEqual(counterexample["kind"], "adapter_completion_mismatch")
        self.assertEqual(
            counterexample["boundary_mismatches"],
            [
                {
                    "location": "memory[0x000ffffc]",
                    "expected": None,
                    "observed": 0xA5,
                }
            ],
        )

    def test_unsupported_object_completion_is_incomplete(self) -> None:
        self._use_object_fixture()
        package = self._object_source(
            """
uint32_t identity(const spx_ro_bytes_v1 *value, uint32_t length) {
  uint8_t byte = 0U;
  (void)length;
  return value->read_u8(value->context, 0U, &byte) == 0U ? byte : 0U;
}
"""
        )
        adapter = self._adapter(package)
        payload = _read(adapter / "adapter-plan.json")
        payload["lowering"]["completion"]["state"]["ebx"] = {
            "op": "unsupported-completion-op"
        }
        _rewrite_hashed(adapter / "adapter-plan.json", payload, "adapter_plan_sha256")
        evidence = self._evidence(
            package,
            adapter,
            self._object_verification([[7]], extent=1),
            "unsupported-completion.json",
        )
        self.assertEqual(evidence["status"], "incomplete")
        issue = _issue(evidence, "component_evidence_semantics_unsupported")
        self.assertIn("unsupported-completion-op", issue["detail"])

    def test_machine_ite_does_not_evaluate_unselected_read(self) -> None:
        memory = _MachineMemory()
        expression = {
            "op": "ite",
            "args": [
                {"op": "true"},
                {"op": "const", "value": 17, "width": 32},
                {
                    "op": "load",
                    "width": 1,
                    "address": {"op": "const", "value": 0x400000, "width": 32},
                },
            ],
        }
        self.assertEqual(_eval_expr(expression, {}, memory), 17)
        expression["args"][0] = {"op": "false"}
        with self.assertRaisesRegex(_UnsupportedSemantics, "outside declared"):
            _eval_expr(expression, {}, memory)

    def test_logical_object_c_type_is_a_borrowed_view_pointer(self) -> None:
        self.assertIsNone(
            logical_type_kind(READ_ONLY_BYTES_V1, source_abi=LOGICAL_C_V1)
        )
        self.assertEqual(
            logical_type_kind(
                READ_ONLY_BYTES_V1, source_abi=LOGICAL_OBJECT_C_V1
            ),
            "read_only_bytes",
        )
        self.assertEqual(
            logical_c_type(
                READ_ONLY_BYTES_V1, source_abi=LOGICAL_OBJECT_C_V1
            ),
            "const spx_ro_bytes_v1 *",
        )
        logical_abi_header().encode("ascii")

    def _evidence(
        self,
        package: Path,
        adapter: Path,
        verification: dict[str, object],
        name: str,
    ) -> dict[str, object]:
        return produce_component_evidence(
            contract=self.contract,
            implementation=package,
            adapter_plan=adapter,
            machine_ir=self.machine,
            verification=verification,
            compiler=shutil.which("cc") or "cc",
            out=self.root / name,
        )

    def _source(self, text: str, *, abi: str = "logical-c-v1") -> Path:
        self.source_file.write_text("#include <stdint.h>\n" + text, encoding="ascii")
        digest = hashlib.sha256((abi + "\0" + text).encode()).hexdigest()[:8]
        package = self.root / f"source-{digest}"
        build_component_source_package(
            lift_unit_id="identity",
            files={"component.c": self.source_file},
            shared_inputs={},
            entry={"abi": abi, "symbol": "identity"},
            out_dir=package,
        )
        return package

    def _object_source(self, text: str) -> Path:
        return self._source(
            '#include "spaghetti-component-abi.h"\n' + text,
            abi="logical-object-c-v1",
        )

    def _adapter(self, package: Path) -> Path:
        source = load_component_source_package(package)
        contract = _read(self.contract / "contract.json")
        output = self.root / f"adapter-{source['implementation_sha256'][:8]}"
        output.mkdir(exist_ok=True)
        header = output / "spaghetti-component-abi.h"
        header.write_text(logical_abi_header(), encoding="ascii")
        machine_ir = self.machine / "machine-ir.jsonl"
        machine_manifest = self.machine / "machine-ir-manifest.json"
        core = {
            "format": COMPONENT_ADAPTER_PLAN_V1_FORMAT,
            "status": "checked",
            "lift_unit_id": "identity",
            "executes_original_binary": False,
            "bindings": {
                "contract_sha256": contract["contract_sha256"],
                "implementation_sha256": source["implementation_sha256"],
                "machine_ir_sha256": _file_hash(machine_ir),
                "machine_ir_manifest_sha256": _file_hash(machine_manifest),
                "source_entry": source["entry"],
            },
            "entry_unit_ids": ["unit:identity"],
            "lowering": (
                {
                    "kind": "checked-object-view-v1",
                    "member_unit_ids": ["unit:identity"],
                    "completion": _read(
                        self.contract / "reviewed-interface.json"
                    )["completion"],
                }
                if source["entry"]["abi"] == "logical-object-c-v1"
                else {"kind": "test-fixture-v1"}
            ),
            "artifacts": {
                "logical_abi_header": {
                    "path": header.name,
                    "sha256": _file_hash(header),
                }
            },
            "policy": {
                "portable_source_called_once": True,
                "machine_ir_fallback_used": False,
                "runtime_completion": "explicit-reviewed-completion-v1",
                "raw_machine_addresses_exposed": False,
                "fallback_on_unimplemented": False,
            },
            "issues": [],
        }
        _write(
            output / "adapter-plan.json",
            {**core, "adapter_plan_sha256": _canonical_hash(core)},
        )
        return output

    def _use_object_fixture(self) -> None:
        self._write_object_machine()
        self._write_object_contract()

    @staticmethod
    def _object_verification(
        buffers: list[list[int]], *, extent: int
    ) -> dict[str, object]:
        return {
            "producer": "exhaustive-finite-domain-v1",
            "parameter_domains": [
                {
                    "parameter_id": "value",
                    "kind": "byte-buffer-set",
                    "values": buffers,
                },
                {
                    "parameter_id": "length",
                    "kind": "integer-range",
                    "minimum": extent,
                    "maximum": extent,
                },
            ],
        }

    def _write_c_string_machine(self) -> None:
        pointer = _stack_load(4, 4)
        result = {
            "op": "add32",
            "args": [pointer, {"op": "const", "value": 1, "width": 32}],
        }
        unit = _unit(
            register_writes=[
                {"register": "eax", "value": result},
                {"register": "esp", "value": _stack_address(4)},
            ],
            memory_events=[{"kind": "read", "width": 1, "address": pointer}],
        )
        self._write_machine(unit)

    def _write_c_string_contract(self) -> None:
        unit = _read(self.machine / "machine-ir.jsonl")
        pointer = unit["semantics"]["register_writes"][0]["value"]["args"][0]
        result = unit["semantics"]["register_writes"][0]["value"]
        event_ref = {
            "family": "memory_event",
            "unit_id": "unit:identity",
            "index": 0,
        }
        interface = {
            "source_abi": "logical-object-c-v1",
            "parameters": [
                {
                    "id": "value",
                    "type": "nul-terminated-bytes-v1",
                    "memory_view": {
                        "kind": "nul-terminated-read-view-v1",
                        "element_width": 1,
                        "event_refs": [event_ref],
                        "access_witness": {
                            "kind": "finite-domain-machine-replay-v1"
                        },
                    },
                    "machine_source": _machine_source(
                        pointer,
                        "/semantics/register_writes/0/value/args/0",
                    ),
                }
            ],
            "results": [
                {
                    **_result(result, "/semantics/register_writes/0/value"),
                    "value_relation": {
                        "kind": "offset-into-view-v1",
                        "parameter_id": "value",
                    },
                }
            ],
            "objects": [],
            "services": [],
            "adapter_effects": [],
            "claims": [],
            "policy": {},
            "completion": _c_string_completion(),
        }
        self._write_contract(interface)

    def _write_scalar_machine(self) -> None:
        load_argument = _stack_load(4, 4)
        unit = _unit(
            register_writes=[
                {"register": "eax", "value": load_argument},
                {"register": "esp", "value": _stack_address(4)},
            ],
            memory_events=[
                {"kind": "read", "width": 4, "address": load_argument["address"]}
            ],
        )
        self._write_machine(unit)

    def _write_scalar_contract(
        self, *, profile: str = "bounded-equivalence-v1"
    ) -> None:
        expression = _read(self.machine / "machine-ir.jsonl")["semantics"][
            "register_writes"
        ][0]["value"]
        interface = {
            "parameters": [
                {
                    "id": "value",
                    "type": "uint32_t",
                    "machine_source": _machine_source(
                        expression, "/semantics/register_writes/0/value"
                    ),
                }
            ],
            "results": [_result(expression, "/semantics/register_writes/0/value")],
            "objects": [],
            "services": [],
            "adapter_effects": [],
            "claims": [],
            "policy": {},
        }
        self._write_contract(interface, profile=profile)

    def _write_object_machine(self) -> None:
        pointer = _stack_load(4, 4)
        length = _stack_load(8, 4)
        first = {"op": "load", "width": 1, "address": pointer}
        unit = _unit(
            register_writes=[
                {"register": "eax", "value": first},
                {"register": "ecx", "value": length},
                {"register": "esp", "value": _stack_address(4)},
            ],
            memory_events=[
                {"kind": "read", "width": 1, "address": pointer},
                {"kind": "read", "width": 4, "address": length["address"]},
            ],
        )
        self._write_machine(unit)

    def _write_control_machine(self) -> None:
        condition = {
            "op": "not",
            "args": [
                {
                    "op": "eq",
                    "args": [
                        {"op": "reg", "name": "ecx", "width": 32},
                        {"op": "const", "value": 7, "width": 32},
                    ],
                }
            ],
        }
        unit = _unit(register_writes=[], memory_events=[])
        unit["semantics"]["outcome"] = {
            "kind": "branch",
            "condition": condition,
            "true_target_rva": 0x2000,
            "false_target_rva": 0x3000,
        }
        self._write_machine(unit)

    def _write_control_contract(self) -> None:
        condition = _read(self.machine / "machine-ir.jsonl")["semantics"][
            "outcome"
        ]["condition"]
        interface = {
            "parameters": [
                {
                    "id": "value",
                    "type": "uint32_t",
                    "machine_source": {
                        "kind": "register",
                        "name": "ecx",
                        "width": 32,
                        "evidence": {
                            "unit_id": "unit:identity",
                            "json_pointer": "/semantics/outcome/condition/args/0/args/0",
                        },
                    },
                }
            ],
            "results": [
                {
                    "id": "route",
                    "kind": "value",
                    "type": "uint32_t",
                    "machine_source": _machine_source(
                        condition, "/semantics/outcome/condition"
                    ),
                    "effect_refs": [],
                },
                {
                    "id": "control",
                    "kind": "control",
                    "control": {
                        "unit_id": "unit:identity",
                        "outcome_kind": "branch",
                        "condition": condition,
                        "routes": [
                            {"target_rva": 0x2000, "when": True},
                            {"target_rva": 0x3000, "when": False},
                        ],
                    },
                },
            ],
            "objects": [],
            "services": [],
            "adapter_effects": [],
            "claims": [],
            "policy": {},
        }
        self._write_contract(interface)

    def _write_object_contract(self) -> None:
        unit = _read(self.machine / "machine-ir.jsonl")
        pointer = unit["semantics"]["register_writes"][0]["value"]["address"]
        length = unit["semantics"]["register_writes"][1]["value"]
        result = unit["semantics"]["register_writes"][0]["value"]
        event_ref = {
            "family": "memory_event",
            "unit_id": "unit:identity",
            "index": 0,
        }
        interface = {
            "source_abi": "logical-object-c-v1",
            "parameters": [
                {
                    "id": "value",
                    "type": "read-only-bytes-v1",
                    "memory_view": {
                        "kind": "indexed-read-view-v1",
                        "extent_parameter_id": "length",
                        "element_width": 1,
                        "event_refs": [event_ref],
                        "access_witness": {
                            "kind": "checked-memory-event-v1",
                            "event_ref": event_ref,
                        },
                    },
                    "machine_source": _machine_source(
                        pointer,
                        "/semantics/register_writes/0/value/address",
                    ),
                },
                {
                    "id": "length",
                    "type": "uint32_t",
                    "machine_source": _machine_source(
                        length, "/semantics/register_writes/1/value"
                    ),
                },
            ],
            "results": [_result(result, "/semantics/register_writes/0/value")],
            "objects": [],
            "services": [],
            "adapter_effects": [],
            "claims": [],
            "policy": {},
            "completion": _object_completion(),
        }
        self._write_contract(interface)

    def _write_machine(self, unit: dict[str, object]) -> None:
        ir = self.machine / "machine-ir.jsonl"
        ir.write_text(json.dumps(unit, sort_keys=True) + "\n", encoding="ascii")
        manifest = {
            "format": MACHINE_IR_FORMAT,
            "artifacts": {"machine_ir": {"path": ir.name, "sha256": _file_hash(ir)}},
            "binary": {"sha256": "3" * 64},
        }
        _write(self.machine / "machine-ir-manifest.json", manifest)

    def _write_contract(
        self, interface: dict[str, object], *, profile: str = "bounded-equivalence-v1"
    ) -> None:
        _write(self.contract / "reviewed-interface.json", interface)
        core = {
            "format": COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
            "status": "checked",
            "lift_unit": {
                "kind": "component",
                "id": "identity",
                "label": "Identity",
                "unit_ids": ["unit:identity"],
                "evidence_profile": profile,
            },
            "bindings": {},
            "authority": {},
            "review": {},
            "artifacts": {},
            "blockers": [],
        }
        _write(
            self.contract / "contract.json",
            {**core, "contract_sha256": _canonical_hash(core)},
        )


def _unit(
    *, register_writes: list[dict[str, object]], memory_events: list[dict[str, object]]
) -> dict[str, object]:
    return {
        "format": MACHINE_IR_FORMAT,
        "record_kind": "unit",
        "id": "unit:identity",
        "source": {
            "contract_sha256": "1" * 64,
            "instruction_bytes_sha256": "2" * 64,
            "original": {"rva_start": 0x1000, "rva_end": 0x1008},
        },
        "semantics": {
            "register_writes": register_writes,
            "flag_writes": [],
            "memory_events": memory_events,
            "external_events": [],
            "faults": [],
            "outcome": {
                "kind": "return",
                "value": _stack_load(0, 4),
            },
        },
    }


def _stack_address(offset: int) -> dict[str, object]:
    return {
        "op": "add32",
        "args": [
            {"op": "const", "value": offset, "width": 32},
            {"op": "reg", "name": "esp", "width": 32},
        ],
    }


def _stack_load(offset: int, width: int) -> dict[str, object]:
    return {"op": "load", "width": width, "address": _stack_address(offset)}


def _machine_source(expression: object, pointer: str) -> dict[str, object]:
    return {
        "kind": "expression",
        "expression": expression,
        "evidence": {"unit_id": "unit:identity", "json_pointer": pointer},
    }


def _result(expression: object, pointer: str) -> dict[str, object]:
    return {
        "id": "result",
        "kind": "return",
        "type": "uint32_t",
        "machine_source": _machine_source(expression, pointer),
        "effect_refs": [
            {"family": "register_write", "unit_id": "unit:identity", "index": 0}
        ],
    }


def _object_completion() -> dict[str, object]:
    state = {name: {"op": "entry", "name": name} for name in _state_fields()}
    state["eax"] = {"op": "logical_result", "result_id": "result"}
    state["ecx"] = {
        "op": "load",
        "width": 4,
        "address": {
            "op": "add32",
            "args": [
                {"op": "entry", "name": "esp"},
                {"op": "const", "value": 8, "width": 32},
            ],
        },
    }
    state["esp"] = {
        "op": "add32",
        "args": [
            {"op": "entry", "name": "esp"},
            {"op": "const", "value": 4, "width": 32},
        ],
    }
    return {
        "kind": "explicit-machine-state-v1",
        "state": state,
        "memory_writes": [],
        "return_target": {
            "op": "load",
            "width": 4,
            "address": {"op": "entry", "name": "esp"},
        },
    }


def _c_string_completion() -> dict[str, object]:
    state = {name: {"op": "entry", "name": name} for name in _state_fields()}
    state["eax"] = {
        "op": "add32",
        "args": [
            {
                "op": "load",
                "width": 4,
                "address": {
                    "op": "add32",
                    "args": [
                        {"op": "entry", "name": "esp"},
                        {"op": "const", "value": 4, "width": 32},
                    ],
                },
            },
            {"op": "logical_result", "result_id": "result"},
        ],
    }
    state["esp"] = {
        "op": "add32",
        "args": [
            {"op": "entry", "name": "esp"},
            {"op": "const", "value": 4, "width": 32},
        ],
    }
    return {
        "kind": "explicit-machine-state-v1",
        "state": state,
        "memory_writes": [],
        "return_target": {
            "op": "load",
            "width": 4,
            "address": {"op": "entry", "name": "esp"},
        },
    }


def _state_fields() -> tuple[str, ...]:
    return (
        "eax",
        "ebx",
        "ecx",
        "edx",
        "esi",
        "edi",
        "ebp",
        "esp",
        "cf",
        "zf",
        "sf",
        "of",
        "pf",
        "df",
    )


def _issue(evidence: dict[str, object], code: str) -> dict[str, object]:
    matches = [row for row in evidence["issues"] if row["code"] == code]
    if len(matches) != 1:
        raise AssertionError(f"expected one {code} issue, observed {matches!r}")
    return matches[0]


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")


def _read(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="ascii"))


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _rewrite_hashed(path: Path, payload: dict[str, object], field: str) -> None:
    core = dict(payload)
    core.pop(field, None)
    _write(path, {**core, field: _canonical_hash(core)})


if __name__ == "__main__":
    unittest.main()
