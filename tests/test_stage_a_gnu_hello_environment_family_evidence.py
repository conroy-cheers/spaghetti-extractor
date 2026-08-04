from __future__ import annotations

import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor_target_gnu_hello.gnu_hello_environment_family_evidence import (
    GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_MODULE,
    GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_PROFILE_FORMAT,
    GnuHelloEnvironmentFamilyEvidenceError,
    write_gnu_hello_environment_family_evidence,
)


def _write_json(path: Path, value: object) -> Path:
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
    profile_module = "StageA.EnvironmentFamilyProfileFixture"
    profile_namespace = "StageA.EnvironmentFamilyProfileFixture"
    runtime_module = "StageA.EnvironmentFamilyRuntimeFixture"
    runtime_namespace = "StageA.EnvironmentFamilyRuntimeFixture"

    def __init__(self, root: Path) -> None:
        self.root = root
        self.profile_source = self._write_profile_source()
        self.runtime_source = self._write_runtime_source()
        self.profile = self._write_profile()
        self.runtime = self._write_runtime()
        self.source_execution = _write_json(
            root / "source-execution.json", self._source_execution()
        )
        self.compiled_authority = _write_json(
            root / "compiled-authority.json", self._compiled_authority()
        )
        self.source_bundle = _write_json(root / "source-bundle.json", {"fixture": True})
        self.static_authority = self._write_static_authority()
        self.bundle = {
            "hashes": {"source_bundle_sha256": self.bundle_sha256},
            "entry_rva": 0x1420,
        }

    def _write_profile_source(self) -> Path:
        path = self.root / "profile" / "StageA" / "EnvironmentFamilyProfileFixture.lean"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"""namespace {self.profile_namespace}

def context : True := True.intro
def sites : True := True.intro
def staticAuthority : True := True.intro
def PairRelated : True := True.intro
theorem pairRealizable : True := by trivial
theorem externalEvidenceAt : True := by trivial
theorem sourceFamilyAt : True := by trivial
theorem launchRealizableAt : True := by trivial

end {self.profile_namespace}
""",
            encoding="ascii",
        )
        return path

    def _write_runtime_source(self) -> Path:
        path = self.root / "runtime" / "StageA" / "EnvironmentFamilyRuntimeFixture.lean"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"""namespace {self.runtime_namespace}

def environment : True := True.intro
def indirectTargets : True := True.intro
theorem indirectTargetsValid : True := by trivial

end {self.runtime_namespace}
""",
            encoding="ascii",
        )
        return path

    def _profile_ref(self, name: str) -> dict[str, str]:
        return {
            "module": self.profile_module,
            "declaration": f"{self.profile_namespace}.{name}",
        }

    def _runtime_ref(self, name: str, kind: str) -> dict[str, str]:
        return {
            "module": self.runtime_module,
            "declaration": f"{self.runtime_namespace}.{name}",
            "kind": kind,
        }

    def _write_profile(self, *, source_scope: str = "admitted_pairs") -> Path:
        sites = [
            {
                "id": 7,
                "import_identity": "kernel32.dll!WriteFile",
                "disposition": "returns",
                "argument_sources": [{"stack_offset": 4}],
                "read_footprints": [{"argument": 1, "bytes": 5}],
                "write_footprints": [{"argument": 3, "bytes": 4}],
                "callbacks": [],
                "footprints_complete": True,
                "callbacks_complete": True,
            }
        ]
        lean = {
            "module_sources": [
                {
                    "module": self.profile_module,
                    "path": str(self.profile_source),
                    "sha256": _sha(self.profile_source),
                }
            ],
            "source_family_scope": source_scope,
            "launch_scope": "admitted_pairs",
            "context": self._profile_ref("context"),
            "sites": self._profile_ref("sites"),
            "static_authority": self._profile_ref("staticAuthority"),
            "pair_relation": self._profile_ref("PairRelated"),
            "pair_realizable": self._profile_ref("pairRealizable"),
            "external_evidence_at": self._profile_ref("externalEvidenceAt"),
            "source_family_at": self._profile_ref("sourceFamilyAt"),
            "launch_realizable_at": self._profile_ref("launchRealizableAt"),
        }
        return _write_json(
            self.root / "profile.json",
            {
                "format": GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_PROFILE_FORMAT,
                "candidate_sha256": self.candidate_sha256,
                "lockstep": {
                    "mode": "exact-1:1-machine-import-v1",
                    "sites": sites,
                },
                "lean": lean,
            },
        )

    def _write_runtime(self) -> Path:
        return _write_json(
            self.root / "runtime.json",
            {
                "format": "stage-a-native-source-candidate-runtime-declarations-v1",
                "candidate_sha256": self.candidate_sha256,
                "lean": {
                    "module_sources": [
                        {
                            "module": self.runtime_module,
                            "path": str(self.runtime_source),
                            "sha256": _sha(self.runtime_source),
                        }
                    ],
                    "environment": self._runtime_ref(
                        "environment", "native_world_environment"
                    ),
                    "indirect_targets": self._runtime_ref(
                        "indirectTargets", "native_indirect_target_inventory"
                    ),
                    "indirect_targets_valid": self._runtime_ref(
                        "indirectTargetsValid", "proof"
                    ),
                    "callable_external": None,
                    "callable_bound": None,
                },
            },
        )

    def _source_execution(self) -> dict[str, object]:
        ns = "StageA.GeneratedRelational.SourceExecutionFixture"
        return {
            "format": "stage-a-gnu-hello-source-execution-assembly-v2",
            "launch_scope": "all_checked_pe32_console_launches",
            "inputs": {},
            "counts": {},
            "lean": {
                "proof_module": "StageA.SourceExecutionFixture",
                "audit_module": "StageA.SourceExecutionFixtureAudit",
                "domain": f"{ns}.domain",
                "invariant_family_evidence": f"{ns}.invariantFamily",
                "launch_family": f"{ns}.launchFamily",
            },
            "launch_family_complete": True,
            "acceptance_authority": False,
            "blockers": [],
            "frontiers": [],
        }

    def _compiled_authority(self) -> dict[str, object]:
        ns = "StageA.GeneratedRelational.CompiledAuthorityFixture"
        return {
            "format": "stage-a-relational-phase-v1",
            "phase": "native-source-compiled-authority",
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "inputs": {},
            "proof_authority": False,
            "acceptance_authority": False,
            "modules": ["CompiledAuthorityFixture", "CompiledAuthorityFixtureAudit"],
            "exports": {"exact_compilation": f"{ns}.exactCompilation"},
            "bindings": {
                "source_bundle_sha256": self.bundle_sha256,
                "attestation_core_sha256": self.attestation_sha256,
                "candidate_sha256": self.candidate_sha256,
                "candidate_entry_rva": 0x2050,
            },
        }

    def _write_static_authority(self) -> Path:
        source = self.root / "static" / "StageA" / "StaticFixture.lean"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(
            "namespace StageA.GeneratedRelational.StaticFixture\n"
            "def compiledPe : True := True.intro\n"
            "end StageA.GeneratedRelational.StaticFixture\n",
            encoding="ascii",
        )
        return _write_json(
            self.root / "static" / "phase-manifest.json",
            {
                "format": "stage-a-native-source-candidate-static-authority-v1",
                "phase": "native-source-candidate-static-authority",
                "status": "source-ready",
                "candidate": {
                    "path": "/nix/store/fixture.exe",
                    "sha256": self.candidate_sha256,
                    "size": 100,
                },
                "module": "StaticFixture",
                "compiled_identity_interface": {
                    "compiled_pe": "StageA.GeneratedRelational.StaticFixture.compiledPe"
                },
            },
        )

    def generate(self, out: Path):
        return write_gnu_hello_environment_family_evidence(
            out,
            profile_manifest=self.profile,
            source_execution_manifest=self.source_execution,
            compiled_authority_manifest=self.compiled_authority,
            source_bundle_manifest=self.source_bundle,
            candidate_runtime_declarations=self.runtime,
            candidate_static_authority=self.static_authority,
            bundle_validator=lambda _path: copy.deepcopy(self.bundle),
        )


class StageAGnuHelloEnvironmentFamilyEvidenceTests(unittest.TestCase):
    def test_packages_checked_admitted_pair_profile_without_new_axioms(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root)
            outputs = fixture.generate(root / "out")
            runtime = json.loads(outputs.runtime_declarations.read_text())
            inputs = json.loads(outputs.acceptance_inputs.read_text())
            source = outputs.module.read_text(encoding="ascii")
            shutil.copyfile(
                fixture.profile_source,
                root / "out" / "StageA" / "EnvironmentFamilyProfileFixture.lean",
            )

            checked = _run_lean_relational(
                root / "out", bundle=GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_MODULE
            )

        self.assertEqual(checked["status"], "checked", checked)
        self.assertEqual(
            runtime["format"],
            "stage-a-native-source-candidate-runtime-declarations-v2",
        )
        self.assertEqual(
            inputs["format"],
            "stage-a-gnu-hello-native-source-environment-family-input-v1",
        )
        self.assertNotRegex(source, r"\b(?:axiom|opaque|sorry|admit)\b")
        self.assertIn("def external_evidence_at", source)
        self.assertEqual(runtime["lean"]["environment_family"]["pair_realizable"]["kind"], "proof")

    def test_universal_scope_is_rejected_instead_of_widening_pair_relation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root)
            fixture.profile = fixture._write_profile(
                source_scope="all_source_environments"
            )
            out = root / "out"
            with self.assertRaisesRegex(
                GnuHelloEnvironmentFamilyEvidenceError,
                "source_family_scope must be admitted_pairs",
            ):
                fixture.generate(out)
            self.assertFalse(out.exists())

    def test_universal_native_launch_scope_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root)
            profile = json.loads(fixture.profile.read_text())
            profile["lean"]["launch_scope"] = "all_native_environments"
            _write_json(fixture.profile, profile)
            with self.assertRaisesRegex(
                GnuHelloEnvironmentFamilyEvidenceError,
                "launch_scope must be admitted_pairs",
            ):
                fixture.generate(root / "out")

    def test_missing_import_or_callback_footprints_fail_closed(self) -> None:
        for field in ("footprints_complete", "callbacks_complete"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture = _Fixture(root)
                profile = json.loads(fixture.profile.read_text())
                profile["lockstep"]["sites"][0][field] = False
                _write_json(fixture.profile, profile)
                with self.assertRaisesRegex(
                    GnuHelloEnvironmentFamilyEvidenceError, "lacks complete"
                ):
                    fixture.generate(root / "out")

    def test_unchecked_profile_declaration_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root)
            fixture.profile_source.write_text(
                fixture.profile_source.read_text().replace(
                    "theorem externalEvidenceAt : True := by trivial",
                    "axiom externalEvidenceAt : True",
                ),
                encoding="ascii",
            )
            profile = json.loads(fixture.profile.read_text())
            profile["lean"]["module_sources"][0]["sha256"] = _sha(
                fixture.profile_source
            )
            _write_json(fixture.profile, profile)
            with self.assertRaisesRegex(
                GnuHelloEnvironmentFamilyEvidenceError, "unchecked"
            ):
                fixture.generate(root / "out")


if __name__ == "__main__":
    unittest.main()
