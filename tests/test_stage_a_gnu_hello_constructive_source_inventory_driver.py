from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DRIVER_PATH = ROOT / "nix" / "gnu-hello-constructive-source-inventory.py"
DRIVER_SPEC = importlib.util.spec_from_file_location(
    "gnu_hello_constructive_source_inventory_driver",
    DRIVER_PATH,
)
assert DRIVER_SPEC is not None
assert DRIVER_SPEC.loader is not None
DRIVER = importlib.util.module_from_spec(DRIVER_SPEC)
sys.modules[DRIVER_SPEC.name] = DRIVER
DRIVER_SPEC.loader.exec_module(DRIVER)


STATE_MACHINE_SHA256 = "11" * 32
CANDIDATE_SHA256 = "22" * 32
OPERATION_ENTRIES = {
    "programLookup": 307753,
    "interpreterStep": 307914,
    "runFunction": 310608,
    "invokeCall": 310949,
}


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class _ArtifactFixture:
    def __init__(
        self,
        root: Path,
        *,
        target_ids: tuple[int, ...] = (0, 1, 2, 3, 4),
        record_count: int = 5,
        source_rva_for_target: dict[int, int] | None = None,
    ) -> None:
        self.root = root
        self.target_ids = target_ids
        self.record_count = record_count
        self.source_rva_for_target = source_rva_for_target or {
            target_id: 4096 + target_id * 16 for target_id in target_ids
        }
        self.record_source_rvas = tuple(
            4096 + index * 16 for index in range(record_count)
        )
        self.mixed_plan = root / "interpreter-mixed-original-plan.json"
        self.static_plan = (
            root / "interpreter-mixed-original-static-reachability.json"
        )
        self.kernel_data = root / "module-inventory.json"
        self.compiled_kernel = root / "interpreter-kernel-plan.json"
        self.kernel_abi = root / "interpreter-kernel-abi-plan.json"
        self.bindings = root / "constructive-source-bindings.json"

        (root / "StageA").mkdir(parents=True)
        self._write_artifacts()

    def _write_artifacts(self) -> None:
        launch_target_id = 72 if 72 in self.target_ids else self.target_ids[0]
        launch_rva = self.source_rva_for_target[launch_target_id]
        _write_json(
            self.mixed_plan,
            {
                "format": DRIVER.MIXED_PLAN_FORMAT,
                "state_machine_sha256": STATE_MACHINE_SHA256,
                "entry_rva": launch_rva,
                "reachable_target_ids": list(self.target_ids),
                "counts": {"reachable_targets": len(self.target_ids)},
                "status": "non-authoritative-diagnostic-only",
            },
        )
        _write_json(
            self.static_plan,
            {
                "format": DRIVER.STATIC_REACHABILITY_FORMAT,
                "acceptance_authority": False,
                "inputs": {
                    "mixed_original_plan": {
                        "path": self.mixed_plan.name,
                        "sha256": _sha256(self.mixed_plan),
                    },
                    "state_machine_sha256": STATE_MACHINE_SHA256,
                },
                "counts": {"reachable_targets": len(self.target_ids)},
                "result": {
                    "theorem": (
                        "StageA.GeneratedRelational."
                        "InterpreterMixedOriginalStaticReachability."
                        "generatedExactOriginalDecodedStaticReachability"
                    )
                },
                "failure_mode": "diagnostic-only",
            },
        )

        pack_size = 8
        pack_count = (self.record_count + pack_size - 1) // pack_size
        _write_json(
            self.kernel_data,
            {
                "format": DRIVER.KERNEL_DATA_FORMAT,
                "acceptance_authority": False,
                "candidate_sha256": CANDIDATE_SHA256,
                "state_machine_sha256": STATE_MACHINE_SHA256,
                "counts": {
                    "records": self.record_count,
                    "certificate_packs": pack_count,
                },
            },
        )
        _write_json(
            self.compiled_kernel,
            {
                "format": DRIVER.COMPILED_KERNEL_FORMAT,
                "acceptance_authority": False,
                "candidate": {"pe_sha256": CANDIDATE_SHA256},
                "program": {"transfer_count": self.record_count},
                "kernel_functions": [
                    {"role": role, "rva_start": entry_rva}
                    for role, entry_rva in OPERATION_ENTRIES.items()
                ],
                "status": "non-authoritative-diagnostic-only",
            },
        )
        _write_json(
            self.kernel_abi,
            {
                "format": DRIVER.KERNEL_ABI_FORMAT,
                "acceptance_authority": False,
                "candidate_pe_sha256": CANDIDATE_SHA256,
                "program_records": self.record_count,
                "inputs": {
                    "data_inventory": {
                        "path": self.kernel_data.name,
                        "sha256": _sha256(self.kernel_data),
                    },
                    "kernel_plan": {
                        "path": self.compiled_kernel.name,
                        "sha256": _sha256(self.compiled_kernel),
                    },
                },
                "operations": [
                    {"role": role, "image_offset": entry_rva}
                    for role, entry_rva in OPERATION_ENTRIES.items()
                ],
                "failure_mode": "diagnostic-only",
            },
        )

        target_rows = "\n".join(
            "  { id := "
            f"{target_id}, regionIndex := {target_id}, "
            f"rva := {self.source_rva_for_target[target_id]}, aliases := [] }}"
            for target_id in self.target_ids
        )
        (
            self.root
            / "StageA"
            / "GeneratedRelationalInterpreterMixedOriginalFinalShard0000.lean"
        ).write_text(
            "def generatedOriginalTargetIndexFinalShard0000 := [\n"
            f"{target_rows}\n"
            "]\n",
            encoding="utf-8",
        )

        pack_defs: list[str] = []
        for pack in range(pack_count):
            values = self.record_source_rvas[
                pack * pack_size : (pack + 1) * pack_size
            ]
            body = ", ".join(str(value) for value in values)
            pack_defs.append(
                "def generatedInterpreterKernelDataCertificatePack"
                f"{pack:04d}SourceRvas : List Nat := [{body}]"
            )
        (
            self.root
            / "StageA"
            / "GeneratedInterpreterKernelDataAuthorityPack0000.lean"
        ).write_text("\n\n".join(pack_defs) + "\n", encoding="utf-8")
        (
            self.root
            / "StageA"
            / "GeneratedInterpreterKernelDataBase.lean"
        ).write_text(
            "def generatedInterpreterKernelCandidatePe : PE32 :=\n"
            "  { bytes := candidateBytes, entrypointRva := 9000 }\n",
            encoding="utf-8",
        )

    def write_complete_bindings(self) -> None:
        terms = {
            field: f"requirements.{field}"
            for field in DRIVER.ConstructiveClassifierTerms.__dataclass_fields__
        }
        source_rows = []
        source_fields: list[str] = []
        for target_id in self.target_ids:
            prefix = f"source_{target_id}"
            source_rows.append(
                {
                    "target_id": target_id,
                    "source_term": f"requirements.{prefix}",
                    "target_id_exact": (
                        f"requirements.{prefix}_target_id_exact"
                    ),
                    "source_rva_exact": (
                        f"requirements.{prefix}_source_rva_exact"
                    ),
                    "record_at_index_exact": (
                        f"requirements.{prefix}_record_at_index_exact"
                    ),
                }
            )
            source_fields.extend(
                (
                    prefix,
                    f"{prefix}_target_id_exact",
                    f"{prefix}_source_rva_exact",
                    f"{prefix}_record_at_index_exact",
                )
            )

        entry_fields = [
            f"{operation}_entry_exact" for operation in OPERATION_ENTRIES
        ]
        all_fields = [*terms, *source_fields, *entry_fields]
        structure = "\n".join(f"  {field} : Nat" for field in all_fields)
        (
            self.root / "StageA" / "GnuHelloConstructiveBindings.lean"
        ).write_text(
            "namespace StageA.GnuHelloConstructiveBindings\n\n"
            "structure Requirements where\n"
            f"{structure}\n\n"
            "end StageA.GnuHelloConstructiveBindings\n",
            encoding="utf-8",
        )

        launch_target_id = 72 if 72 in self.target_ids else self.target_ids[0]
        non_launch_targets = [
            target_id
            for target_id in self.target_ids
            if target_id != launch_target_id
        ]
        rules = [{"target_id": launch_target_id, "kind": "launch"}]
        rules.extend(
            {
                "target_id": target_id,
                "kind": "semantic_transfer",
                "operation": operation,
            }
            for target_id, operation in zip(
                non_launch_targets,
                OPERATION_ENTRIES,
                strict=True,
            )
        )
        _write_json(
            self.bindings,
            {
                "format": DRIVER.BINDINGS_FORMAT,
                "binding_module": (
                    "StageA.GnuHelloConstructiveBindings"
                ),
                "parameter_name": "requirements",
                "parameter_type": (
                    "StageA.GnuHelloConstructiveBindings.Requirements"
                ),
                "namespace": (
                    "StageA.GeneratedRelational."
                    "GnuHelloConstructiveSourceInventory"
                ),
                "terms": terms,
                "candidate_root_rva": 9000,
                "sources": source_rows,
                "operation_entry_equalities": {
                    operation: f"requirements.{operation}_entry_exact"
                    for operation in OPERATION_ENTRIES
                },
                "rules": rules,
            },
        )

    def plan(self, *, with_bindings: bool) -> object:
        return DRIVER.plan_gnu_hello_constructive_source_inventory(
            mixed_original_plan_path=self.mixed_plan,
            static_reachability_plan_path=self.static_plan,
            kernel_data_inventory_path=self.kernel_data,
            compiled_kernel_plan_path=self.compiled_kernel,
            kernel_abi_plan_path=self.kernel_abi,
            mixed_original_source_root=self.root,
            kernel_data_source_root=self.root,
            binding_inventory_path=self.bindings if with_bindings else None,
            additional_source_roots=(self.root,),
        )


class GnuHelloConstructiveSourceInventoryDriverTests(unittest.TestCase):
    def test_complete_spec_derives_bindings_entries_and_rules(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _ArtifactFixture(Path(temporary))
            fixture.write_complete_bindings()

            plan = fixture.plan(with_bindings=True)

            self.assertEqual(plan.blockers, ())
            self.assertIsNotNone(plan.spec)
            assert plan.spec is not None
            self.assertEqual(plan.spec.expected_target_ids, (0, 1, 2, 3, 4))
            self.assertEqual(
                tuple(source.record_index for source in plan.spec.sources),
                (0, 1, 2, 3, 4),
            )
            self.assertEqual(
                tuple(entry.operation for entry in plan.spec.entries),
                tuple(OPERATION_ENTRIES),
            )
            self.assertEqual(len(plan.spec.rules), 5)

    def test_cli_emits_complete_generic_bundle_without_lean_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _ArtifactFixture(root)
            fixture.write_complete_bindings()
            out = root / "out"

            result = DRIVER.main(
                [
                    "--mixed-original-plan",
                    str(fixture.mixed_plan),
                    "--static-reachability-plan",
                    str(fixture.static_plan),
                    "--kernel-data-inventory",
                    str(fixture.kernel_data),
                    "--compiled-kernel-plan",
                    str(fixture.compiled_kernel),
                    "--kernel-abi-plan",
                    str(fixture.kernel_abi),
                    "--mixed-original-source-root",
                    str(root),
                    "--kernel-data-source-root",
                    str(root),
                    "--additional-source-root",
                    str(root),
                    "--binding-inventory",
                    str(fixture.bindings),
                    "--out",
                    str(out),
                ]
            )

            self.assertEqual(result, 0)
            report = json.loads(
                (
                    out
                    / "gnu-hello-constructive-source-inventory-driver.json"
                ).read_text(encoding="utf-8")
            )
            self.assertTrue(report["generator_spec_emitted"])
            self.assertEqual(report["typed_blockers"], [])
            generated = (
                out
                / "GeneratedRelationalInterpreterMixedConstructiveSourceInventory.lean"
            )
            source = generated.read_text(encoding="utf-8")
            self.assertIn("generatedSourceSource00000000", source)
            self.assertIn("requirements.programLookup_entry_exact", source)

    def test_pinned_gnu_shape_allows_unreachable_candidate_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target_ids = tuple(range(3063))
            fixture = _ArtifactFixture(
                Path(temporary),
                target_ids=target_ids,
                record_count=5326,
            )

            plan = fixture.plan(with_bindings=False)

            self.assertIsNone(plan.spec)
            self.assertEqual(len(plan.derived.reachable_target_ids), 3063)
            self.assertEqual(plan.derived.candidate_record_count, 5326)
            self.assertEqual(plan.derived.launch_root_target_id, 72)
            self.assertEqual(plan.derived.candidate_root_rva, 9000)
            self.assertEqual(
                dict(plan.derived.operation_entries),
                OPERATION_ENTRIES,
            )
            blockers = {blocker.code: blocker for blocker in plan.blockers}
            self.assertNotIn(
                "candidate_record_reachability_cardinality_mismatch",
                blockers,
            )
            self.assertEqual(
                blockers[
                    "programLookup_function_entry_equality_missing"
                ].required_type,
                "generatedCompiledKernelProgram.functionEntry? "
                "KernelOperation.programLookup.role = some 307753",
            )

    def test_duplicate_target_mapping_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _ArtifactFixture(root)
            shard = (
                root
                / "StageA"
                / "GeneratedRelationalInterpreterMixedOriginalFinalShard0000.lean"
            )
            shard.write_text(
                shard.read_text(encoding="utf-8")
                + "{ id := 0, regionIndex := 0, rva := 9999, aliases := [] }\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                DRIVER.GnuHelloConstructiveSourceInventoryError,
                "duplicate target-to-RVA mapping",
            ):
                fixture.plan(with_bindings=False)

    def test_ambiguous_target_rva_mapping_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _ArtifactFixture(root)
            shard = (
                root
                / "StageA"
                / "GeneratedRelationalInterpreterMixedOriginalFinalShard0000.lean"
            )
            shard.write_text(
                shard.read_text(encoding="utf-8")
                + "{ id := 99, regionIndex := 99, rva := 4096, aliases := [] }\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                DRIVER.GnuHelloConstructiveSourceInventoryError,
                "ambiguous target-to-RVA mapping",
            ):
                fixture.plan(with_bindings=False)

    def test_missing_candidate_record_mapping_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _ArtifactFixture(root)
            authority = (
                root
                / "StageA"
                / "GeneratedInterpreterKernelDataAuthorityPack0000.lean"
            )
            authority.write_text(
                authority.read_text(encoding="utf-8").replace("4096,", "9999,"),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                DRIVER.GnuHelloConstructiveSourceInventoryError,
                "sources have no unique kernel-data semantic record",
            ):
                fixture.plan(with_bindings=False)

    def test_compiled_kernel_abi_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _ArtifactFixture(Path(temporary))
            abi = json.loads(fixture.kernel_abi.read_text(encoding="utf-8"))
            abi["operations"][0]["image_offset"] += 1
            _write_json(fixture.kernel_abi, abi)

            with self.assertRaisesRegex(
                DRIVER.GnuHelloConstructiveSourceInventoryError,
                "compiled-kernel/ABI entry mismatch",
            ):
                fixture.plan(with_bindings=False)

    def test_undeclared_named_witness_blocks_spec(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _ArtifactFixture(Path(temporary))
            fixture.write_complete_bindings()
            bindings = json.loads(fixture.bindings.read_text(encoding="utf-8"))
            bindings["sources"][2][
                "record_at_index_exact"
            ] = "requirements.not_generated"
            _write_json(fixture.bindings, bindings)

            plan = fixture.plan(with_bindings=True)

            self.assertIsNone(plan.spec)
            blockers = {blocker.code: blocker for blocker in plan.blockers}
            self.assertIn(
                "named_source_or_entry_witnesses_missing",
                blockers,
            )
            self.assertIn(
                "requirements.not_generated",
                blockers["named_source_or_entry_witnesses_missing"].detail,
            )

    def test_duplicate_rule_mapping_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _ArtifactFixture(Path(temporary))
            fixture.write_complete_bindings()
            bindings = json.loads(fixture.bindings.read_text(encoding="utf-8"))
            bindings["rules"].append(dict(bindings["rules"][0]))
            _write_json(fixture.bindings, bindings)

            with self.assertRaisesRegex(
                DRIVER.GnuHelloConstructiveSourceInventoryError,
                "duplicate deterministic rule",
            ):
                fixture.plan(with_bindings=True)


if __name__ == "__main__":
    unittest.main()
