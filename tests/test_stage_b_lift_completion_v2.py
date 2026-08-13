from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetWriterV3,
)
from spaghetti_extractor.authority_bindings_v2 import BinaryBinding, UnitBinding
from spaghetti_extractor.implementation_ledger_v2 import (
    ArtifactIdentityV2,
    CompletionProfileV2,
    ImplementationLedgerV2,
    ImplementationOwnerKindV2,
    ImplementationOwnerV2,
    UnitOwnershipRecordV2,
)
from spaghetti_extractor.stage_b_lift_completion_v2 import (
    build_lift_completion_receipt_v2,
)


PE_SHA = "a" * 64
UNIVERSE_SHA = "b" * 64
BINDING = ArtifactBindingV3("binary", "pe32", "fixture.exe", PE_SHA)


def _write_artifact(
    path: Path, kind: str, records: tuple[ArtifactRecordV3, ...]
) -> Path:
    ArtifactSetWriterV3(artifact_kind=kind, bindings=(BINDING,)).write(
        path, records
    )
    return path


def _write_json(path: Path, value: object) -> Path:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    return path


class StageBLiftCompletionAdapterTests(unittest.TestCase):
    def test_rederives_incomplete_status_from_exact_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            final = _write_artifact(
                root / "final",
                "final-authority-v3",
                (
                    ArtifactRecordV3.create(
                        "final",
                        {
                            "status": "incomplete",
                            "authorizing": False,
                            "binary": {
                                "pe_sha256": PE_SHA,
                                "exact_universe_sha256": UNIVERSE_SHA,
                            },
                        },
                    ),
                ),
            )
            fallback = _write_artifact(
                root / "fallback",
                "fallback-coverage-v3",
                (
                    ArtifactRecordV3.create(
                        "unit:one",
                        {"status": "incomplete", "authorizing": False},
                    ),
                ),
            )
            unit = UnitBinding(
                binary=BinaryBinding(PE_SHA, UNIVERSE_SHA),
                unit_id="unit:one",
                rva_start=0x1000,
                rva_end=0x1010,
                unit_sha256="c" * 64,
                instruction_bytes_sha256="d" * 64,
            )
            ledger = ImplementationLedgerV2.create(
                profile=CompletionProfileV2.PORTABLE_APPLICATION,
                binary=unit.binary,
                structural_units=(unit,),
                ownership_records=(
                    UnitOwnershipRecordV2.create(
                        owner=ImplementationOwnerV2(
                            ImplementationOwnerKindV2.UNASSIGNED, None, None
                        ),
                        units=(unit,),
                    ),
                ),
            )
            ledger_dir = root / "ledger"
            ledger_dir.mkdir()
            (ledger_dir / "implementation-ledger-v2.json").write_text(
                ledger.to_json(), encoding="ascii"
            )
            runtime_dir = root / "runtime"
            runtime_dir.mkdir()
            runtime_file = _write_json(
                runtime_dir / "runtime-lock-v1.json",
                {
                    "format": "spaghetti-extractor-runtime-lock-v1",
                    "schema_version": 1,
                    "lock_id": "runtime-lock-v1:test",
                    "status": "complete",
                    "dependencies": [],
                },
            )
            runtime_sha = hashlib.sha256(runtime_file.read_bytes()).hexdigest()
            source_binding = {
                "format": "stage-b-source-project-binding-v1",
            }
            source_binding["binding_sha256"] = hashlib.sha256(
                json.dumps(
                    source_binding, sort_keys=True, separators=(",", ":")
                ).encode("ascii")
            ).hexdigest()

            def candidate(
                name: str,
                platform: str,
                architecture: str,
                triple: str,
                contents: bytes,
            ) -> Path:
                directory = root / name
                (directory / "bin").mkdir(parents=True)
                share = directory / "share/spaghetti-extractor"
                share.mkdir(parents=True)
                binary = directory / "bin/program"
                binary.write_bytes(contents)
                digest = hashlib.sha256(contents).hexdigest()
                binding_file = _write_json(
                    share / "source-project-binding.json", source_binding
                )
                source_sha = hashlib.sha256(binding_file.read_bytes()).hexdigest()
                (share / "runtime-lock-v1.json").write_bytes(
                    runtime_file.read_bytes()
                )
                _write_json(
                    directory / "portable-c-candidate-v1.json",
                    {
                        "format": "spaghetti-extractor-portable-c-candidate-v1",
                        "schema_version": 1,
                        "status": "candidate-generated",
                        "platform": platform,
                        "architecture": architecture,
                        "target_triple": triple,
                        "executes_original_binary": False,
                        "source_project_sha256": source_sha,
                        "source_project_binding_sha256": source_binding[
                            "binding_sha256"
                        ],
                        "source_project_specification_sha256": "2" * 64,
                        "runtime_lock_sha256": runtime_sha,
                        "output": {
                            "path": "bin/program",
                            "sha256": digest,
                            "bytes": len(contents),
                        },
                        "linker_map": None,
                    },
                )
                return directory

            receipt = build_lift_completion_receipt_v2(
                profile=CompletionProfileV2.PORTABLE_APPLICATION,
                final_authority=final,
                fallback_coverage=fallback,
                implementation_ledger=ledger_dir,
                runtime_lock=runtime_dir,
                pe32_candidate=candidate(
                    "pe32", "pe32", "i686", "i686-w64-mingw32", b"p"
                ),
                non_x86_candidate=candidate(
                    "arm", "non_x86", "aarch64", "aarch64-linux-gnu", b"a"
                ),
            )

        self.assertEqual(receipt.status.value, "incomplete")
        self.assertFalse(receipt.authorizing)
        codes = {issue.code for issue in receipt.issues}
        self.assertIn("final_authority_incomplete", codes)
        self.assertIn("bound_evidence_incomplete", codes)
        self.assertIn("implementation_ledger_incomplete", codes)


if __name__ == "__main__":
    unittest.main()
