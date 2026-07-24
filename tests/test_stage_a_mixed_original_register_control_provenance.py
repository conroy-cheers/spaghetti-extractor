from __future__ import annotations

import dataclasses
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from pe_fixtures import pe32_import_image
from test_stage_a_relational_interpreter_mixed_original import (
    _pe32_register_code_pointer_image,
    _record,
    _spec,
    _write_jsonl,
)

from spaghetti_extractor.relational.lean.interpreter_mixed_original import (
    InterpreterMixedOriginalSpec,
    OriginalIATImport,
    OriginalImportIdentity,
    OriginalModuleBindings,
    OriginalPERecoveryInput,
    OriginalRegisterControlCallContractProposal,
    OriginalRegisterImportBinding,
    QualifiedLeanSymbol,
    interpreter_mixed_original_register_control_lean_adapter,
    load_original_iat_import_proposals,
    load_original_pe_recovery_input,
    load_original_register_control_call_contract_proposals,
    plan_interpreter_mixed_original,
)


def _loop_rows() -> list[dict[str, object]]:
    target = {"op": "reg", "name": "ebx", "width": 32}
    return [
        {
            **_record(
                0x1000,
                {"kind": "jump", "target_rva": 0x1010},
                edges=[0x1010],
                instructions=[
                    {"rva": 0x1000, "size": 5, "mnemonic": "mov"},
                    {"rva": 0x1005, "size": 5, "mnemonic": "jmp"},
                ],
            ),
            "original": {"rva_start": 0x1000, "rva_end": 0x100A, "size": 10},
        },
        {
            **_record(
                0x1010,
                {
                    "kind": "branch",
                    "true_target_rva": 0x1010,
                    "false_target_rva": 0x1014,
                },
                edges=[0x1010, 0x1014],
                instructions=[
                    {"rva": 0x1010, "size": 2, "mnemonic": "test"},
                    {"rva": 0x1012, "size": 2, "mnemonic": "jne"},
                ],
            ),
            "original": {"rva_start": 0x1010, "rva_end": 0x1014, "size": 4},
        },
        {
            **_record(
                0x1014,
                {"kind": "jump", "target_rva": 0x1020},
                edges=[0x1020],
                instructions=[{"rva": 0x1014, "size": 2, "mnemonic": "jmp"}],
            ),
            "original": {"rva_start": 0x1014, "rva_end": 0x1016, "size": 2},
        },
        {
            **_record(
                0x1020,
                {"kind": "fallthrough", "target_rva": 0x1022},
                edges=[0x1022],
                ordered=[{
                    "kind": "indirect_call",
                    "instruction_rva": 0x1020,
                    "return_rva": 0x1022,
                    "target": target,
                }],
                instructions=[{"rva": 0x1020, "size": 2, "mnemonic": "call"}],
            ),
            "original": {"rva_start": 0x1020, "rva_end": 0x1022, "size": 2},
        },
        _record(0x1022, {"kind": "return"}),
        _record(0x1030, {"kind": "return"}),
    ]


def _loop_image() -> bytes:
    image = bytearray(_pe32_register_code_pointer_image())
    image[0x210:0x214] = b"\x85\xc0\x75\xfc"
    image[0x214:0x216] = b"\xeb\x0a"
    return bytes(image)


def _import_crossing_image() -> bytes:
    iat_va = 0x402040
    code = bytearray(b"\x90" * 0x0B)
    code[0:8] = b"\x8b\x1d" + iat_va.to_bytes(4, "little") + b"\xff\xd3"
    code[8:10] = b"\xff\xd3"
    code[10] = 0xC3
    return pe32_import_image(bytes(code), symbol="TestImport")


def _import_crossing_rows() -> list[dict[str, object]]:
    loaded = {
        "op": "load",
        "width": 4,
        "address": {"op": "const", "value": 0x402040, "width": 32},
    }
    register = {"op": "reg", "name": "ebx", "width": 32}
    return [
        {
            **_record(
                0x1000,
                {"kind": "fallthrough", "target_rva": 0x1008},
                edges=[0x1008],
                ordered=[{
                    "kind": "indirect_call",
                    "instruction_rva": 0x1006,
                    "return_rva": 0x1008,
                    "target": loaded,
                }],
                instructions=[
                    {"rva": 0x1000, "size": 6, "mnemonic": "mov"},
                    {"rva": 0x1006, "size": 2, "mnemonic": "call"},
                ],
            ),
            "original": {"rva_start": 0x1000, "rva_end": 0x1008, "size": 8},
        },
        {
            **_record(
                0x1008,
                {"kind": "fallthrough", "target_rva": 0x100A},
                edges=[0x100A],
                ordered=[{
                    "kind": "indirect_call",
                    "instruction_rva": 0x1008,
                    "return_rva": 0x100A,
                    "target": register,
                }],
                instructions=[{"rva": 0x1008, "size": 2, "mnemonic": "call"}],
            ),
            "original": {"rva_start": 0x1008, "rva_end": 0x100A, "size": 2},
        },
        _record(0x100A, {"kind": "return"}),
    ]


def _repeated_import_crossing_image() -> bytes:
    iat_va = 0x402040
    code = bytearray(b"\x90" * 0x0D)
    code[0:8] = b"\x8b\x1d" + iat_va.to_bytes(4, "little") + b"\xff\xd3"
    code[8:10] = b"\xff\xd3"
    code[10:12] = b"\xff\xd3"
    code[12] = 0xC3
    return pe32_import_image(bytes(code), symbol="TestImport")


def _repeated_import_crossing_rows() -> list[dict[str, object]]:
    rows = _import_crossing_rows()
    rows[1] = {
        **rows[1],
        "outcome": {"kind": "fallthrough", "target_rva": 0x100A},
    }
    rows[-1] = {
        **_record(
            0x100A,
            {"kind": "fallthrough", "target_rva": 0x100C},
            edges=[0x100C],
            ordered=[{
                "kind": "indirect_call",
                "instruction_rva": 0x100A,
                "return_rva": 0x100C,
                "target": {"op": "reg", "name": "ebx", "width": 32},
            }],
            instructions=[{"rva": 0x100A, "size": 2, "mnemonic": "call"}],
        ),
        "original": {"rva_start": 0x100A, "rva_end": 0x100C, "size": 2},
    }
    rows.append(_record(0x100C, {"kind": "return"}))
    return rows


def _machine_contract_symbol() -> QualifiedLeanSymbol:
    return QualifiedLeanSymbol(
        module="StageA.GeneratedTinyMachineContracts",
        namespace="StageA.GeneratedRelational.TinyMachineContracts",
        symbol="contracts",
    )


class StageAMixedOriginalRegisterControlProvenanceTests(unittest.TestCase):
    def test_exact_loop_yields_scc_witness_without_closing_site(self) -> None:
        image = _loop_image()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(state_machine, _loop_rows())
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(recovery_pe=OriginalPERecoveryInput(
                    pe, hashlib.sha256(image).hexdigest()
                )),
            )

        unresolved = [
            blocker for blocker in plan.blockers
            if blocker.reason_code == "unresolved_indirect_control"
        ]
        self.assertEqual(len(unresolved), 1)
        self.assertIsNone(plan.regions[3].indirect_sites[0].static_binding)
        proposal = plan.to_json()["register_control_provenance"]
        use = next(item for item in proposal["uses"] if item["source_rva"] == 0x1020)
        self.assertEqual(use["witness"]["status"], "resolved")
        self.assertEqual(use["witness"]["atoms"][0]["target_id"], 5)
        self.assertTrue(any(
            row["cyclic"] and 1 in row["region_indices"]
            for row in proposal["witness"]["sccs"]
        ))
        self.assertEqual(proposal["checked_static_bindings_added"], 0)
        self.assertEqual(
            proposal["unresolved_indirect_control_blockers_removed"], 0
        )
        adapter = interpreter_mixed_original_register_control_lean_adapter(plan)
        self.assertFalse(adapter["acceptance_authority"])
        self.assertIsNone(adapter["authorizing_term"])
        self.assertEqual(
            adapter,
            interpreter_mixed_original_register_control_lean_adapter(plan),
        )

    def test_checked_call_contract_selects_import_crossing_for_lean_replay(self) -> None:
        image = _import_crossing_image()
        identity = OriginalImportIdentity("KERNEL32.dll", "TestImport")
        imported = OriginalIATImport(0x402040, 0x2040, identity)
        contract = OriginalRegisterControlCallContractProposal(
            contract_id=7,
            # The separately checked import-boundary span may begin in a
            # preceding decoded region; the exact call/return site is the
            # authoritative edge key for register preservation.
            source_rva=0x0FF0,
            instruction_rva=0x1006,
            continuation_rva=0x1008,
            preserved_registers=("ebx", "esi", "edi", "ebp"),
            import_identity=identity,
            return_register="eax",
            machine_contract_id=7,
            arity_kind="fixed",
            argument_words=0,
        )
        bindings = dataclasses.replace(
            _spec().bindings,
            machine_import_call_contracts=_machine_contract_symbol(),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(state_machine, _import_crossing_rows())
            common = _spec(
                bindings=bindings,
                iat_imports=(imported,),
                recovery_pe=OriginalPERecoveryInput(
                    pe, hashlib.sha256(image).hexdigest()
                ),
            )
            baseline = plan_interpreter_mixed_original(state_machine, common)
            proposed = plan_interpreter_mixed_original(
                state_machine,
                dataclasses.replace(
                    common, register_control_call_contracts=(contract,)
                ),
            )

        self.assertEqual(len(baseline.blockers), 1)
        self.assertEqual(proposed.blockers, ())
        self.assertIsInstance(
            proposed.regions[1].indirect_sites[0].static_binding,
            OriginalRegisterImportBinding,
        )
        payload = proposed.to_json()["register_control_provenance"]
        self.assertEqual(payload["checked_static_bindings_added"], 1)
        self.assertEqual(payload["unresolved_indirect_control_blockers_removed"], 1)
        self.assertEqual(payload["call_contract_matches"][0]["contract_id"], 7)
        flow = payload["import_address_flows"][0]
        self.assertEqual(flow["use_instruction_rva"], 0x1008)
        self.assertEqual(flow["preserving_contract_ids"], [7])
        self.assertEqual(flow["status"], "selected_for_generated_lean_replay")
        self.assertIn("import-address atom", flow["next_action"])
        use = next(item for item in payload["uses"] if item["source_rva"] == 0x1008)
        self.assertEqual(use["witness"]["status"], "incomplete")
        self.assertTrue(use["existing_static_binding"])
        self.assertFalse(use["existing_unresolved_blocker_retained"])

    def test_checked_import_call_contract_closes_repeated_calls_to_fixed_point(
        self,
    ) -> None:
        image = _repeated_import_crossing_image()
        identity = OriginalImportIdentity("KERNEL32.dll", "TestImport")
        imported = OriginalIATImport(0x402040, 0x2040, identity)
        first_call = OriginalRegisterControlCallContractProposal(
            contract_id=7,
            source_rva=0x1000,
            instruction_rva=0x1006,
            continuation_rva=0x1008,
            preserved_registers=("ebx", "esi", "edi", "ebp"),
            import_identity=identity,
            return_register="eax",
            machine_contract_id=7,
            arity_kind="fixed",
            argument_words=0,
        )
        bindings = dataclasses.replace(
            _spec().bindings,
            machine_import_call_contracts=_machine_contract_symbol(),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(state_machine, _repeated_import_crossing_rows())
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    bindings=bindings,
                    iat_imports=(imported,),
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    ),
                    register_control_call_contracts=(first_call,),
                ),
            )

        self.assertTrue(plan.complete, plan.blockers)
        self.assertIsInstance(
            plan.regions[1].indirect_sites[0].static_binding,
            OriginalRegisterImportBinding,
        )
        self.assertIsInstance(
            plan.regions[2].indirect_sites[0].static_binding,
            OriginalRegisterImportBinding,
        )
        propagated = [
            proposal
            for proposal in plan.spec.register_control_call_contracts
            if proposal.origin == "propagated_machine_import"
        ]
        self.assertEqual(
            {proposal.instruction_rva for proposal in propagated},
            {0x1008, 0x100A},
        )
        self.assertTrue(all(
            proposal.machine_authority_id == 7
            and proposal.contract_id != 7
            for proposal in propagated
        ))
        third_binding = plan.regions[2].indirect_sites[0].static_binding
        assert isinstance(third_binding, OriginalRegisterImportBinding)
        second_contract = next(
            proposal for proposal in propagated
            if proposal.instruction_rva == 0x1008
        )
        self.assertIn(
            second_contract.contract_id,
            third_binding.call_contract_ids,
        )

    def test_machine_import_report_loader_is_hash_bound(self) -> None:
        report = {
            "format": "stage-a-static-machine-import-contracts-v1",
            "inputs": {
                "original_sha256": "a" * 64,
                "state_machine_sha256": "b" * 64,
            },
            "signatures": [{
                "id": 2,
                "abi": "cdecl",
                "disposition": "returns",
                "arity": {"kind": "fixed", "words": 0},
                "import": {"dll": "KERNEL32.dll", "symbol": "TestImport"},
            }],
            "boundaries": [{
                "id": 9,
                "signature_id": 2,
                "source_rva": 0x1000,
                "instruction_rva": 0x1006,
                "continuation_rva": 0x1008,
                "import": {"dll": "KERNEL32.dll", "symbol": "TestImport"},
            }],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            proposals = load_original_register_control_call_contract_proposals(
                path,
                original_sha256="a" * 64,
                state_machine_sha256="b" * 64,
            )
            with self.assertRaisesRegex(Exception, "does not match"):
                load_original_register_control_call_contract_proposals(
                    path, original_sha256="c" * 64
                )

        self.assertEqual(len(proposals), 1)
        self.assertEqual(proposals[0].preserved_registers, (
            "ebx", "esi", "edi", "ebp"
        ))
        self.assertEqual(proposals[0].return_register, "eax")

    def test_exact_gnu_import_crossings_are_selected_for_lean_replay(self) -> None:
        root = Path(__file__).parents[1]
        state_machine = (
            root
            / "build/stage-b-gnu-hello-roundtrip/stage-a-static-export-v3/state-machine.jsonl"
        )
        reference = (
            root
            / "build/stage-b-gnu-hello-roundtrip/stage-a-static-export-v3/reference-contract.json"
        )
        reports = sorted(Path("/nix/store").glob(
            "*stage-a-gnu-hello-roundtrip-static-machine-import-contracts-lean/"
            "machine-import-contract-report.json"
        ))
        if not state_machine.is_file() or not reference.is_file() or not reports:
            self.skipTest("exact GNU mixed-original inputs are absent")
        recovery = load_original_pe_recovery_input(reference)
        report = next((
            path for path in reports
            if all(
                "continuation_rva" in row
                for row in json.loads(path.read_text(encoding="utf-8"))["boundaries"]
            )
        ), None)
        if report is None:
            self.skipTest("exact boundary-indexed GNU import report is absent")
        contracts = load_original_register_control_call_contract_proposals(
            report, original_sha256=recovery.sha256
        )
        bindings = OriginalModuleBindings(
            module="StageA.GeneratedGnuHelloOriginalPE",
            namespace="StageA.GeneratedRelational.GnuHelloOriginalPE",
            machine_import_call_contracts=_machine_contract_symbol(),
        )
        common = InterpreterMixedOriginalSpec(
            bindings=bindings,
            entry_rva=0x1420,
            tls_callback_rvas=(0xA2F0, 0xA2A0),
            iat_imports=load_original_iat_import_proposals(reference),
            recovery_pe=recovery,
        )
        baseline = plan_interpreter_mixed_original(state_machine, common)
        proposed = plan_interpreter_mixed_original(
            state_machine,
            dataclasses.replace(
                common, register_control_call_contracts=contracts
            ),
        )

        baseline_blockers = set(baseline.blockers)
        proposed_blockers = set(proposed.blockers)
        self.assertFalse(proposed_blockers - baseline_blockers)
        promoted_rvas = {
            0x1B41, 0x1B49, 0x1B63, 0x1B65,
            0x296E, 0x2978, 0xAB77,
        }
        self.assertTrue(
            promoted_rvas.issubset({
                blocker.rva
                for blocker in baseline_blockers - proposed_blockers
                if blocker.reason_code == "unresolved_indirect_control"
            })
        )
        payload = proposed.to_json()["register_control_provenance"]
        flows = {
            (row["import"].get("symbol"), row["register"], row["use_instruction_rva"]): row
            for row in payload["import_address_flows"]
        }
        self.assertTrue(flows[("_errno", "ebx", 0x1B47)][
            "preserving_contract_ids"
        ])
        self.assertEqual(
            flows[("_errno", "ebx", 0x1B47)]["status"],
            "selected_for_generated_lean_replay",
        )
        self.assertTrue(flows[("__p___argv", "ebx", 0x296E)][
            "preserving_contract_ids"
        ])
        self.assertEqual(
            flows[("__p___argv", "ebx", 0x296E)]["status"],
            "selected_for_generated_lean_replay",
        )
        for source_rva in (0x1B41, 0x296E):
            region = next(item for item in proposed.regions if item.rva == source_rva)
            self.assertIsInstance(
                region.indirect_sites[0].static_binding,
                OriginalRegisterImportBinding,
            )
        self.assertGreaterEqual(payload["checked_static_bindings_added"], 2)
        self.assertGreaterEqual(
            payload["unresolved_indirect_control_blockers_removed"],
            len(promoted_rvas),
        )


if __name__ == "__main__":
    unittest.main()
