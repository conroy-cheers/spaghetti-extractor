from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.stage_b_fallback_coverage import (
    FALLBACK_COVERAGE_RECEIPT_FORMAT,
    FallbackCoverageReceiptError,
    validate_stage_b_fallback_coverage_receipt,
    write_stage_b_fallback_coverage_receipt,
)
from spaghetti_extractor.util import sha256_bytes, sha256_file


ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _unit(identity: str, rva: int, marker: str) -> dict:
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": identity,
        "status": "qualified",
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 1, "size": 1},
            "contract_sha256": sha256_bytes(f"contract:{marker}".encode("ascii")),
            "instruction_bytes_sha256": sha256_bytes(
                f"source-span:{marker}".encode("ascii")
            ),
        },
    }


class _CoverageFixture:
    def __init__(self, root: Path) -> None:
        root.mkdir(parents=True)
        self.root = root
        self.units = [
            _unit("unit:entry", 0x1000, "entry"),
            _unit("unit:reachable", 0x1010, "reachable"),
            _unit("unit:unreachable", 0x2000, "unreachable"),
        ]
        self.machine_ir = root / "machine-ir.jsonl"
        self._write_machine_ir()
        self.manifest = root / "machine-ir-manifest.json"
        self._write_manifest()

        self.interpreter = root / "interpreter"
        self.interpreter.mkdir()
        source = self.interpreter / "state-machine-program.c"
        source.write_text("/* selected semantic lowering */\n", encoding="ascii")
        self.adapted_semantics = (
            self.interpreter / "machine-ir-adapted-semantics.jsonl"
        )
        self.adapted_semantics.write_text(
            "".join(
                json.dumps({"id": unit["id"]}, sort_keys=True) + "\n"
                for unit in self.units
            ),
            encoding="ascii",
        )
        self.program = self.interpreter / "state-machine-interpreter-program.json"
        self.package = self.interpreter / "state-machine-interpreter-package.json"
        self._write_lowering(self._transfers())

        self.coverage_receipt = root / "fallback-coverage-receipt.json"

    def _write_machine_ir(self) -> None:
        self.machine_ir.write_text(
            "".join(json.dumps(unit, sort_keys=True) + "\n" for unit in self.units),
            encoding="utf-8",
        )

    def _write_manifest(self) -> None:
        _write_json(self.manifest, {
            "format": "stage-a-machine-ir-v2",
            "counts": {"units": len(self.units)},
            "artifacts": {
                "machine_ir": {
                    "format": "stage-a-machine-ir-v2",
                    "path": self.machine_ir.name,
                    "sha256": sha256_file(self.machine_ir),
                }
            },
            "control": {
                "reachability": {
                    "status": "complete",
                    "roots": ["unit:entry"],
                    "reachable_units": ["unit:entry", "unit:reachable"],
                    "potential_units": [],
                    "confirmed_unreachable_units": ["unit:unreachable"],
                    "frontiers": [],
                }
            },
        })

    def _transfers(self) -> list[dict]:
        return [
            {
                "id": unit["id"],
                "rva_start": unit["source"]["original"]["rva_start"],
                "contract_sha256": unit["source"]["contract_sha256"],
                "source_span_sha256": unit["source"][
                    "instruction_bytes_sha256"
                ],
                "counts": {
                    "word_nodes": 0,
                    "x87_nodes": 0,
                    "actions": 0,
                    "calls": 0,
                    "x87_operations": 0,
                },
                "x87_operations": [],
            }
            for unit in self.units
        ]

    def _write_lowering(self, transfers: list[dict]) -> None:
        counts = {
            "input_transfers": len(self.units),
            "transfers": len(transfers),
            "blocked_transfers": 0,
            "deferred_transfers": 0,
        }
        _write_json(self.program, {
            "format": "stage-b-semantic-interpreter-program-v1",
            "status": "ready",
            "state_machine_sha256": sha256_file(self.machine_ir),
            "counts": counts,
            "blockers": [],
            "semantic_coverage": {
                "status": "complete",
                "deferred_transfers": 0,
                "acceptance_authority": False,
            },
            "execution_policy": "complete_transfer_inventory_v1",
            "transfers": transfers,
        })
        source = self.interpreter / "state-machine-program.c"
        _write_json(self.package, {
            "format": "stage-b-semantic-interpreter-package-v1",
            "status": "ready",
            "machine_ir": {
                "path": self.machine_ir.name,
                "sha256": sha256_file(self.machine_ir),
            },
            "input_mode": "sanitized_machine_ir_v2",
            "program": {
                "path": self.program.name,
                "sha256": sha256_file(self.program),
            },
            "sources": [{
                "role": "program_source",
                "path": source.name,
                "sha256": sha256_file(source),
            }],
            "adapted_semantics": {
                "role": "byte_free_definedness_analysis_input",
                "path": self.adapted_semantics.name,
                "sha256": sha256_file(self.adapted_semantics),
            },
            "counts": counts,
            "blockers": [],
            "semantic_coverage": {
                "status": "complete",
                "deferred_transfers": 0,
                "acceptance_authority": False,
            },
            "execution_policy": "complete_transfer_inventory_v1",
        })

    def write_coverage(
        self, replacements: list[dict] | Path | None = None
    ) -> dict:
        return write_stage_b_fallback_coverage_receipt(
            machine_ir=self.machine_ir,
            machine_ir_manifest=self.manifest,
            interpreter_package=self.interpreter,
            portable_replacements=replacements,
            out=self.coverage_receipt,
        )

    def validate_coverage(
        self, replacements: list[dict] | Path | None = None
    ):
        return validate_stage_b_fallback_coverage_receipt(
            receipt=self.coverage_receipt,
            machine_ir=self.machine_ir,
            machine_ir_manifest=self.manifest,
            interpreter_package=self.interpreter,
            portable_replacements=replacements,
        )


class StageBFallbackCoverageTests(unittest.TestCase):
    def test_receipt_binds_exact_inputs_and_assigns_each_structural_unit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _CoverageFixture(Path(temporary) / "fixture")
            payload = fixture.write_coverage()
            receipt = fixture.validate_coverage()

            self.assertEqual(payload["format"], FALLBACK_COVERAGE_RECEIPT_FORMAT)
            self.assertEqual(payload["status"], "complete")
            self.assertEqual(
                [entry["implementation_kind"] for entry in payload["entries"]],
                [
                    "machine_ir_fallback",
                    "machine_ir_fallback",
                    "machine_ir_fallback",
                ],
            )
            self.assertNotIn("reachability", payload)
            self.assertEqual(payload["counts"]["structural_units"], 3)
            self.assertEqual(payload["counts"]["implementation_entries"], 3)
            self.assertEqual(
                receipt.machine_ir_sha256, sha256_file(fixture.machine_ir)
            )
            self.assertEqual(
                receipt.interpreter_program_sha256, sha256_file(fixture.program)
            )
            self.assertEqual(
                {entry["unit_contract_sha256"] for entry in payload["entries"]},
                {
                    fixture.units[0]["source"]["contract_sha256"],
                    fixture.units[1]["source"]["contract_sha256"],
                    fixture.units[2]["source"]["contract_sha256"],
                },
            )

    def test_rejects_a_structural_unit_missing_from_lowering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _CoverageFixture(Path(temporary) / "fixture")
            transfers = [
                row
                for row in fixture._transfers()
                if row["id"] != "unit:unreachable"
            ]
            fixture._write_lowering(transfers)

            with self.assertRaisesRegex(
                FallbackCoverageReceiptError,
                "structural machine-IR unit cannot be lowered: unit:unreachable",
            ):
                fixture.write_coverage()

    def test_rejects_lowering_bound_to_a_different_unit_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _CoverageFixture(Path(temporary) / "fixture")
            transfers = fixture._transfers()
            transfers[1]["contract_sha256"] = "f" * 64
            fixture._write_lowering(transfers)

            with self.assertRaisesRegex(
                FallbackCoverageReceiptError, "different unit contract"
            ):
                fixture.write_coverage()

    def test_explicit_portable_replacement_selects_one_nonfallback_kind(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _CoverageFixture(Path(temporary) / "fixture")
            replacement = {
                "unit_id": "unit:reachable",
                "rva": 0x1010,
                "replacement_id": "portable-reachable-v1",
                "cluster_id": "cluster-reachable-v1",
                "component_manifest_sha256": "c" * 64,
                "fallback_on_unimplemented": False,
            }
            selection = fixture.root / "portable-replacements.json"
            _write_json(selection, {
                "format": "stage-b-portable-replacement-selection-v1",
                "replacements": [replacement],
            })
            payload = fixture.write_coverage(selection)

            by_id = {entry["unit_id"]: entry for entry in payload["entries"]}
            self.assertEqual(
                by_id["unit:entry"]["implementation_kind"],
                "machine_ir_fallback",
            )
            self.assertEqual(
                by_id["unit:reachable"]["implementation_kind"],
                "portable_replacement",
            )
            self.assertEqual(payload["counts"]["portable_replacement"], 1)
            self.assertEqual(
                payload["inputs"]["portable_replacements"]["artifact"]["sha256"],
                sha256_file(selection),
            )
            self.assertIsNone(by_id["unit:entry"]["portable_replacement"])
            self.assertFalse(
                by_id["unit:reachable"]["portable_replacement"][
                    "fallback_on_unimplemented"
                ]
            )

            with self.assertRaisesRegex(
                FallbackCoverageReceiptError, "duplicate dispatch assignments"
            ):
                fixture.write_coverage([replacement, replacement])
            permissive = dict(replacement)
            permissive["fallback_on_unimplemented"] = True
            with self.assertRaisesRegex(
                FallbackCoverageReceiptError, "must disable machine-IR fallback"
            ):
                fixture.write_coverage([permissive])

    def test_receipt_validation_rejects_stale_bound_artifacts(self) -> None:
        mutations = {
            "machine IR": lambda fixture: fixture.machine_ir.write_text(
                fixture.machine_ir.read_text(encoding="utf-8") + "\n",
                encoding="utf-8",
            ),
            "manifest": lambda fixture: fixture.manifest.write_text(
                fixture.manifest.read_text(encoding="utf-8") + "\n",
                encoding="utf-8",
            ),
            "program": lambda fixture: fixture.program.write_text(
                fixture.program.read_text(encoding="utf-8") + "\n",
                encoding="utf-8",
            ),
            "package": lambda fixture: fixture.package.write_text(
                fixture.package.read_text(encoding="utf-8") + "\n",
                encoding="utf-8",
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                fixture = _CoverageFixture(Path(temporary) / "fixture")
                fixture.write_coverage()
                mutate(fixture)
                with self.assertRaises(FallbackCoverageReceiptError):
                    fixture.validate_coverage()

    def test_generic_nix_dag_requires_final_authorization_before_generation(self) -> None:
        module = (ROOT / "nix" / "stage-b-hybrid-candidate.nix").read_text(
            encoding="utf-8"
        )
        coverage_module = (
            ROOT / "nix" / "stage-b-fallback-coverage-receipt.nix"
        ).read_text(encoding="utf-8")
        self.assertNotIn("dxball", module.lower())
        for name in (
            "fallbackCoverageReceipt",
            "candidateAuthorityReport",
            "candidateAuthorityGate",
            "build_stage_b_candidate_authority_v3",
            "require_stage_b_candidate_authority_v3",
        ):
            self.assertIn(name, module)
        self.assertIn(
            "import ./stage-b-fallback-coverage-receipt.nix", module
        )
        self.assertNotIn("write_stage_b_fallback_coverage_receipt", module)
        self.assertIn("write_stage_b_fallback_coverage_receipt", coverage_module)
        authorization_reference = (
            "${candidateAuthorityGate}/candidate-authority.json"
        )
        native_start = module.index('nativeEngine = pkgs.runCommand')
        native_end = module.index('nativeRuntime = pkgs.runCommand', native_start)
        candidate_start = module.index('candidate = pkgs.runCommand')
        self.assertIn(
            authorization_reference, module[native_start:native_end]
        )
        self.assertIn(authorization_reference, module[candidate_start:])
        self.assertLess(
            module.index(authorization_reference, native_start),
            module.index("write_stage_b_native_engine_package", native_start),
        )
        self.assertLess(
            module.index(authorization_reference, candidate_start),
            module.index("build_stage_b_interpreter_native_candidate", candidate_start),
        )


if __name__ == "__main__":
    unittest.main()
