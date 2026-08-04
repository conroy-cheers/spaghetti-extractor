from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spaghetti_extractor_target_gnu_hello.gnu_hello_native_source_environment_family import (
    write_gnu_hello_native_source_environment_family,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_native_source_environment_family_inputs import (
    GNU_HELLO_ENVIRONMENT_FAMILY_INPUTS_MODULE,
    GNU_HELLO_ENVIRONMENT_FAMILY_INPUTS_REPORT_FORMAT,
    GnuHelloEnvironmentFamilyInputProducerError,
    write_gnu_hello_native_source_environment_family_inputs,
)


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    return path


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class _Fixture:
    candidate_sha256 = "a" * 64
    bundle_sha256 = "b" * 64
    attestation_sha256 = "c" * 64
    source_entry = 0x1420
    candidate_entry = 0x2050
    authority_module = "StageA.GeneratedGnuHelloCompiledAuthority"
    authority_namespace = "StageA.GeneratedRelational.GnuHelloCompiledAuthority"
    execution_module = "StageA.GeneratedGnuHelloSourceExecution"
    execution_namespace = "StageA.GeneratedRelational.GnuHelloSourceExecution"
    runtime_module = "StageA.GnuHelloRuntimeEnvironmentFamily"
    runtime_namespace = "StageA.GnuHelloRuntimeEnvironmentFamily"
    static_module = "GeneratedGnuHelloCandidateStatic"
    static_namespace = "StageA.GeneratedRelational.GnuHelloCandidateStatic"

    def __init__(self, root: Path) -> None:
        self.root = root
        self.bundle_path = _write(root / "source-bundle.json", {"fixture": True})
        self.bundle = {
            "hashes": {"source_bundle_sha256": self.bundle_sha256},
            "entry_rva": self.source_entry,
        }
        self.authority_path = _write(
            root / "compiled-authority.json", self.authority()
        )
        self.execution_path = _write(
            root / "source-execution.json", self.execution()
        )
        self.runtime_path = self.write_runtime(version=2)
        self.static_path = self.write_static()

    @property
    def exact_compilation(self) -> str:
        return f"{self.authority_namespace}.exactCompilation"

    @property
    def launch_family(self) -> str:
        return f"{self.execution_namespace}.launchFamily"

    def authority(self) -> dict[str, object]:
        namespace = self.authority_namespace
        return {
            "format": "stage-a-relational-phase-v1",
            "phase": "native-source-compiled-authority",
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "inputs": {},
            "proof_authority": False,
            "acceptance_authority": False,
            "modules": [
                self.authority_module.removeprefix("StageA."),
                self.authority_module.removeprefix("StageA.") + "Audit",
            ],
            "exports": {
                "profile": f"{namespace}.profile",
                "project": f"{namespace}.project",
                "artifact": f"{namespace}.artifact",
                "machine_authority": f"{namespace}.machineAuthority",
                "project_valid": f"{namespace}.projectValid",
                "profile_pinned": f"{namespace}.profilePinned",
                "profile_matches": f"{namespace}.profileMatches",
                "built_from": f"{namespace}.builtFrom",
                "exact_compilation": self.exact_compilation,
            },
            "bindings": {
                "source_bundle_sha256": self.bundle_sha256,
                "attestation_core_sha256": self.attestation_sha256,
                "candidate_sha256": self.candidate_sha256,
                "candidate_entry_rva": self.candidate_entry,
                "candidate_imports_sha256": "d" * 64,
                "relocation_inventory_sha256": "e" * 64,
            },
        }

    def execution(self) -> dict[str, object]:
        namespace = self.execution_namespace
        return {
            "format": "stage-a-gnu-hello-source-execution-assembly-v2",
            "launch_scope": "all_checked_pe32_console_launches",
            "inputs": {},
            "counts": {},
            "lean": {
                "proof_module": self.execution_module,
                "audit_module": self.execution_module + "Audit",
                "domain": f"{namespace}.domain",
                "invariant_family_evidence": f"{namespace}.invariantFamily",
                "launch_family": self.launch_family,
            },
            "launch_family_complete": True,
            "acceptance_authority": False,
            "blockers": [],
            "frontiers": [],
        }

    def write_runtime(self, *, version: int) -> Path:
        symbols = {
            "environment": "environment",
            "context": "context",
            "sites": "sites",
            "static_authority": "staticAuthority",
            "pair_relation": "PairRelated",
            "pair_realizable": "pairRealizable",
            "external_evidence_at": "externalEvidenceAt",
            "source_family_at": "sourceFamilyAt",
            "launch_realizable_at": "launchRealizableAt",
        }
        source = self.root / "runtime" / "StageA" / "GnuHelloRuntimeEnvironmentFamily.lean"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(
            "\n".join(
                [
                    f"namespace {self.runtime_namespace}",
                    "def environment : True := True.intro",
                    "def context : True := True.intro",
                    "def sites : True := True.intro",
                    "def staticAuthority : True := True.intro",
                    "def PairRelated : True := True.intro",
                    "theorem pairRealizable : True := by trivial",
                    "theorem externalEvidenceAt : True := by trivial",
                    "theorem sourceFamilyAt : True := by trivial",
                    "theorem launchRealizableAt : True := by trivial",
                    f"end {self.runtime_namespace}",
                    "",
                ]
            ),
            encoding="ascii",
        )
        ref = lambda symbol, kind: {
            "module": self.runtime_module,
            "declaration": f"{self.runtime_namespace}.{symbol}",
            "kind": kind,
        }
        lean: dict[str, object] = {
            "module_sources": [
                {
                    "module": self.runtime_module,
                    "path": str(source),
                    "sha256": _sha(source),
                }
            ],
            "environment": ref("environment", "native_world_environment"),
            "indirect_targets": ref("environment", "native_indirect_target_inventory"),
            "indirect_targets_valid": ref("pairRealizable", "proof"),
            "callable_external": None,
            "callable_bound": None,
        }
        if version == 2:
            kinds = {
                "context": "static_proof_context",
                "sites": "opaque_lockstep_call_sites",
                "static_authority": "static_native_source_environment_family_authority",
                "pair_relation": "native_source_environment_pair_relation",
                "pair_realizable": "proof",
                "external_evidence_at": "exact_world_native_external_evidence_family",
                "source_family_at": "checked_native_source_launch_family",
                "launch_realizable_at": "native_compilation_launch_realizable_family",
            }
            lean["environment_family"] = {
                name: ref(symbols[name], kind) for name, kind in kinds.items()
            }
        return _write(
            self.root / "runtime" / "runtime-declarations.json",
            {
                "format": (
                    "stage-a-native-source-candidate-runtime-declarations-"
                    f"v{version}"
                ),
                "candidate_sha256": self.candidate_sha256,
                "lean": lean,
            },
        )

    def write_static(self) -> Path:
        source = self.root / "static" / "StageA" / f"{self.static_module}.lean"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(
            f"namespace {self.static_namespace}\n"
            "def compiledPe : True := True.intro\n"
            f"end {self.static_namespace}\n",
            encoding="ascii",
        )
        return _write(
            self.root / "static" / "phase-manifest.json",
            {
                "format": "stage-a-native-source-candidate-static-authority-v1",
                "phase": "native-source-candidate-static-authority",
                "status": "source-ready",
                "candidate": {
                    "path": "/nix/store/fixture-candidate.exe",
                    "sha256": self.candidate_sha256,
                    "size": 100,
                },
                "module": self.static_module,
                "compiled_identity_interface": {
                    "compiled_pe": f"{self.static_namespace}.compiledPe"
                },
            },
        )

    def generate(self, out: Path, *, runtime: Path | None = None):
        return write_gnu_hello_native_source_environment_family_inputs(
            out,
            source_execution_manifest=self.execution_path,
            compiled_authority_manifest=self.authority_path,
            source_bundle_manifest=self.bundle_path,
            candidate_runtime_declarations=runtime or self.runtime_path,
            candidate_static_authority=self.static_path,
            bundle_validator=lambda _path: copy.deepcopy(self.bundle),
        )


class StageAGnuHelloNativeSourceEnvironmentFamilyInputTests(unittest.TestCase):
    def test_current_runtime_inventory_fails_with_minimal_missing_interface(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            runtime_v1 = fixture.write_runtime(version=1)
            out = fixture.root / "out"
            with self.assertRaisesRegex(
                GnuHelloEnvironmentFamilyInputProducerError,
                "smallest missing upstream interface.*external_evidence_at.*launch_realizable_at",
            ):
                fixture.generate(out, runtime=runtime_v1)
            self.assertFalse(out.exists())

    def test_checked_v2_interface_emits_cacheable_consumer_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            first = fixture.generate(fixture.root / "first")
            second = fixture.generate(fixture.root / "second")

            self.assertEqual(first.module.read_bytes(), second.module.read_bytes())
            self.assertEqual(
                first.environment_inputs.read_bytes(),
                second.environment_inputs.read_bytes(),
            )
            source = first.module.read_text(encoding="ascii")
            self.assertNotRegex(source, r"(?m)^\s*(?:axiom|opaque)\s")
            self.assertNotIn("sorry", source)
            self.assertIn("ExactWorldNativeExternalEvidence", source)
            self.assertIn("forall sourceEnvironment nativeEnvironment", source)
            self.assertEqual(
                source.count(
                    "PairRelated sourceEnvironment nativeEnvironment ->"
                ),
                3,
            )
            self.assertIn("candidateRuntimeEnvironmentExact", source)
            self.assertIn("exactCandidatePeBound", source)
            self.assertIn(
                "CheckedNativeSourceAdmittedPairEvidence", source
            )
            self.assertIn("def admittedPairEvidence", source)

            inputs = json.loads(
                first.environment_inputs.read_text(encoding="ascii")
            )
            self.assertNotIn("status", inputs)
            self.assertEqual(
                inputs["lean"]["static_compilation"], fixture.exact_compilation
            )
            self.assertEqual(
                inputs["lean"]["source_launch_family"], fixture.launch_family
            )
            self.assertIn(
                f"StageA.{GNU_HELLO_ENVIRONMENT_FAMILY_INPUTS_MODULE}",
                inputs["lean"]["imports"],
            )
            report = json.loads(first.report.read_text(encoding="ascii"))
            self.assertEqual(
                report["format"],
                GNU_HELLO_ENVIRONMENT_FAMILY_INPUTS_REPORT_FORMAT,
            )
            self.assertFalse(report["executes_original_binary"])
            self.assertFalse(report["executes_candidate_binary"])
            self.assertFalse(report["proof_authority"])
            self.assertFalse(report["acceptance_authority"])

            with mock.patch(
                "spaghetti_extractor_target_gnu_hello."
                "gnu_hello_native_source_environment_family."
                "validate_native_source_bundle_manifest",
                return_value=copy.deepcopy(fixture.bundle),
            ):
                downstream = write_gnu_hello_native_source_environment_family(
                    fixture.root / "downstream",
                    compiled_authority_manifest=fixture.authority_path,
                    source_execution_manifest=fixture.execution_path,
                    source_bundle_manifest=fixture.bundle_path,
                    environment_inputs=first.environment_inputs,
                )
            self.assertTrue(downstream.evidence.is_file())


if __name__ == "__main__":
    unittest.main()
