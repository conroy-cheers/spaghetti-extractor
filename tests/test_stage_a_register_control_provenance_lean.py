from __future__ import annotations

import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.analyses.registers import (
    REGISTER_CONTROL_AMBIGUOUS_WRITABLE_LOAD,
    RegisterControlBlockedOutput,
    RegisterControlCallContract,
    RegisterControlCopy,
    RegisterControlEdge,
    RegisterControlImportResult,
    RegisterControlProvenanceAtom,
    RegisterControlRegionTransfer,
    RegisterControlRegisterPair,
    RegisterControlUse,
    build_register_control_provenance_witness,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.register_control_provenance import (
    REGISTER_CONTROL_PROVENANCE_LEAN_FILENAME,
    register_control_provenance_source,
)


EAX = RegisterControlRegisterPair("eax", "eax")
EBX = RegisterControlRegisterPair("ebx", "ebx")


def _code_atom(
    region: int,
    pair: RegisterControlRegisterPair,
    target: int,
    *,
    static: bool = False,
) -> RegisterControlProvenanceAtom:
    return RegisterControlProvenanceAtom(
        kind="static_code_pointer" if static else "exact_code_pointer",
        producer_region_index=region,
        register_pair=pair,
        target_id=target,
        claim_kind="immutable_static_word" if static else "exact_constant",
    )


def _direct_witness():
    return build_register_control_provenance_witness(
        region_count=2,
        register_pairs=(EAX,),
        entry_region_indices=(0,),
        transfers=(
            RegisterControlRegionTransfer(
                0, producers=(_code_atom(0, EAX, 11),)
            ),
            RegisterControlRegionTransfer(1, preserve_unmentioned=True),
        ),
        edges=(RegisterControlEdge(0, 1),),
        uses=(RegisterControlUse(1, EAX, "indirect_control"),),
    )


def _stable_edge_id_witness():
    return build_register_control_provenance_witness(
        region_count=2,
        register_pairs=(EAX,),
        entry_region_indices=(0,),
        transfers=(
            RegisterControlRegionTransfer(
                0, producers=(_code_atom(0, EAX, 11),)
            ),
            RegisterControlRegionTransfer(1, preserve_unmentioned=True),
        ),
        edges=(RegisterControlEdge(0, 1, edge_id=0xF00DBAAD),),
        uses=(RegisterControlUse(1, EAX, "indirect_control"),),
    )


def _import_preservation_witness():
    identity = ("KERNEL32.dll", "symbol", "GetLastError")
    return build_register_control_provenance_witness(
        region_count=3,
        register_pairs=(EAX, EBX),
        entry_region_indices=(0,),
        transfers=(
            RegisterControlRegionTransfer(0, preserve_unmentioned=True),
            RegisterControlRegionTransfer(
                1,
                copies=(RegisterControlCopy(output=EBX, source=EAX),),
                preserve_unmentioned=True,
            ),
            RegisterControlRegionTransfer(2, preserve_unmentioned=True),
        ),
        edges=(
            RegisterControlEdge(0, 1, "call_return", 7),
            RegisterControlEdge(1, 2, "call_return", 8),
        ),
        call_contracts=(
            RegisterControlCallContract(
                7,
                import_results=(RegisterControlImportResult(EAX, identity),),
            ),
            RegisterControlCallContract(8, preserved_registers=(EBX,)),
        ),
        uses=(RegisterControlUse(2, EBX, "register_state"),),
    )


def _loop_witness():
    return build_register_control_provenance_witness(
        region_count=2,
        register_pairs=(EAX,),
        entry_region_indices=(0,),
        transfers=(
            RegisterControlRegionTransfer(
                0, producers=(_code_atom(0, EAX, 23, static=True),)
            ),
            RegisterControlRegionTransfer(1, preserve_unmentioned=True),
        ),
        edges=(RegisterControlEdge(0, 1), RegisterControlEdge(1, 1)),
        uses=(RegisterControlUse(1, EAX, "indirect_control"),),
    )


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageARegisterControlProvenanceLeanTests(unittest.TestCase):
    source_root = (
        Path(__file__).parents[1]
        / "src/spaghetti_extractor/lean/StageA"
    )

    def _compile(self, witness, expectation: str = "accepted") -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            shutil.copyfile(
                self.source_root / "RelationalRegisterControlProvenance.lean",
                stage_a / "RelationalRegisterControlProvenance.lean",
            )
            (stage_a / REGISTER_CONTROL_PROVENANCE_LEAN_FILENAME).write_text(
                register_control_provenance_source(
                    witness, expectation=expectation
                ),
                encoding="utf-8",
            )
            return _run_lean_relational(
                root, bundle="GeneratedRelationalRegisterControlProvenance"
            )

    def test_reviewed_kernel_has_semantic_soundness_and_no_escape_hatches(self):
        source = (
            self.source_root / "RelationalRegisterControlProvenance.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "native_decide", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        self.assertIn("structure Certificate.SemanticallyValid", source)
        self.assertIn("theorem Certificate.checked_sound", source)
        self.assertIn("Certificate.checked_region_replay", source)
        self.assertIn("Certificate.checked_scc_replay", source)
        self.assertIn("Certificate.checked_indirect_use_classified", source)

    def test_direct_import_preservation_and_loop_scc_compile(self):
        for label, witness in (
            ("direct", _direct_witness()),
            ("stable-edge-id", _stable_edge_id_witness()),
            ("import-preserved", _import_preservation_witness()),
            ("loop-scc", _loop_witness()),
        ):
            with self.subTest(label=label):
                result = self._compile(witness)
                self.assertEqual(result["status"], "checked", result)
                self.assertNotIn("sorryAx", result["stdout"])

    def test_generated_acceptance_ignores_python_status_and_hashes(self):
        payload = _direct_witness().to_payload()
        payload["status"] = "incomplete"
        payload["acceptance_authority"] = True
        payload["witness_sha256"] = "0" * 64
        for atom in payload["transfers"][0]["producers"]:
            atom["atom_id"] = "1" * 64
        source = register_control_provenance_source(payload)
        self.assertNotIn("incomplete", source)
        self.assertNotIn("acceptance_authority", source)
        self.assertNotIn("witness_sha256", source)
        self.assertNotIn("atom_id", source)
        self.assertIn("generatedRegisterControlProvenanceSemanticallyValid", source)
        self.assertEqual(self._compile(payload)["status"], "checked")

    def test_fail_closed_cases_are_kernel_checked_rejections(self):
        identity = ("KERNEL32.dll", "symbol", "GetLastError")
        rejected = {}
        rejected["unknown-call"] = build_register_control_provenance_witness(
            region_count=2,
            register_pairs=(EAX,),
            entry_region_indices=(0,),
            transfers=(
                RegisterControlRegionTransfer(
                    0, producers=(_code_atom(0, EAX, 1),)
                ),
                RegisterControlRegionTransfer(1, preserve_unmentioned=True),
            ),
            edges=(RegisterControlEdge(0, 1, "call_return"),),
            uses=(RegisterControlUse(1, EAX, "indirect_control"),),
        )
        rejected["writable-ambiguity"] = (
            build_register_control_provenance_witness(
                region_count=1,
                register_pairs=(EAX,),
                entry_region_indices=(0,),
                transfers=(RegisterControlRegionTransfer(
                    0,
                    blocked_outputs=(RegisterControlBlockedOutput(
                        EAX, REGISTER_CONTROL_AMBIGUOUS_WRITABLE_LOAD
                    ),),
                ),),
                edges=(),
                uses=(RegisterControlUse(0, EAX, "indirect_control"),),
            )
        )
        rejected["budget-overflow"] = build_register_control_provenance_witness(
            region_count=3,
            register_pairs=(EAX,),
            entry_region_indices=(0, 1),
            transfers=(
                RegisterControlRegionTransfer(
                    0, producers=(_code_atom(0, EAX, 1),)
                ),
                RegisterControlRegionTransfer(
                    1, producers=(_code_atom(1, EAX, 2),)
                ),
                RegisterControlRegionTransfer(2, preserve_unmentioned=True),
            ),
            edges=(RegisterControlEdge(0, 2), RegisterControlEdge(1, 2)),
            uses=(RegisterControlUse(2, EAX, "indirect_control"),),
            finite_disjunction_budget=1,
        )
        rejected["import-return-control"] = (
            build_register_control_provenance_witness(
                region_count=2,
                register_pairs=(EAX,),
                entry_region_indices=(0,),
                transfers=(
                    RegisterControlRegionTransfer(0, preserve_unmentioned=True),
                    RegisterControlRegionTransfer(1, preserve_unmentioned=True),
                ),
                edges=(RegisterControlEdge(0, 1, "call_return", 4),),
                call_contracts=(RegisterControlCallContract(
                    4,
                    import_results=(RegisterControlImportResult(EAX, identity),),
                ),),
                uses=(RegisterControlUse(1, EAX, "indirect_control"),),
            )
        )
        nonconverged = _direct_witness().to_payload()
        nonconverged["fixed_point"]["converged"] = False
        nonconverged["status"] = "proposal_requires_generated_lean_replay"
        nonconverged["blockers"] = []
        rejected["nonconvergence"] = nonconverged

        for label, witness in rejected.items():
            with self.subTest(label=label):
                result = self._compile(witness, expectation="rejected")
                self.assertEqual(result["status"], "checked", result)

    def test_mutated_fixed_point_evidence_is_rejected(self):
        payload = json.loads(json.dumps(_direct_witness().to_payload()))
        payload["regions"][1]["inputs"][0]["atoms"][0]["target_id"] = 99
        result = self._compile(payload, expectation="rejected")
        self.assertEqual(result["status"], "checked", result)


if __name__ == "__main__":
    unittest.main()
