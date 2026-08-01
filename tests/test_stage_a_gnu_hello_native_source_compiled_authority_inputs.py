from __future__ import annotations

import copy
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.gnu_hello_native_source_compiled_authority_evidence import (
    PROFILE_IDENTIFIER,
    PROJECT_DECLARATIONS_FORMAT,
    RUNTIME_DECLARATIONS_FORMAT,
    TOOLCHAIN_PROFILE_FORMAT,
    _load_project_declarations,
    _source_closure,
)
from spaghetti_extractor.relational.lean.gnu_hello_native_source_compiled_authority_inputs import (
    GnuHelloCompiledAuthorityInputError,
    INPUTS_MANIFEST_FORMAT,
    RuntimeDeclarationSpec,
    write_gnu_hello_native_source_compiled_authority_inputs,
)
from spaghetti_extractor.util import sha256_file


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _json(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    return path


def _binding(
    path: Path, *, owner: str | None = None, role: str | None = None
) -> dict[str, object]:
    value: dict[str, object] = {
        "path": path.name,
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }
    if owner is not None:
        value["owner"] = owner
    if role is not None:
        value["role"] = role
    return value


def _copy_module_closure(source_root: Path, destination: Path, module: str) -> None:
    pending = [module]
    copied: set[str] = set()
    while pending:
        current = pending.pop()
        if current in copied:
            continue
        source = source_root / f"{current}.lean"
        text = source.read_text(encoding="utf-8")
        shutil.copyfile(source, destination / source.name)
        copied.add(current)
        pending.extend(_IMPORT.findall(text))


class _Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.project = root / "project"
        self.project.mkdir(parents=True)
        self.state_machine = _write(root / "state-machine.jsonl", b'{"pc":1}\n')
        self.load_image = _write(root / "load-image.json", b'{"base":4194304}\n')

        self.packages: dict[str, dict[str, object]] = {}
        package_specs = {
            "interpreter": (("program", b"program-source"),),
            "native_engine": (("plan", b"lowering-plan"),),
            "native_runtime": (
                ("native_runtime_header", b"runtime-header"),
                ("native_runtime_source", b"runtime-source"),
            ),
        }
        for owner, rows in package_specs.items():
            package_root = root / owner
            package_root.mkdir()
            artifacts = []
            for role, data in rows:
                path = _write(package_root / f"{role}.txt", data)
                artifacts.append(_binding(path, owner=owner, role=role))
            package_manifest = _write(
                package_root / f"{owner}-package.json",
                json.dumps({"owner": owner}).encode("ascii"),
            )
            self.packages[owner] = {
                "root": str(package_root),
                "manifest": _binding(package_manifest),
                "artifacts": artifacts,
            }

        self.bundle_path = _write(self.project / "native-source-bundle.json", b"{}\n")
        self.bundle = {
            "hashes": {"source_bundle_sha256": "1" * 64},
            "state_machine": {
                "path": str(self.state_machine),
                "sha256": sha256_file(self.state_machine),
                "size": self.state_machine.stat().st_size,
            },
            "load_image_contract": {
                "path": str(self.load_image),
                "artifact_sha256": sha256_file(self.load_image),
                "size": self.load_image.stat().st_size,
            },
            "packages": self.packages,
        }

        self.candidate = _write(root / "build" / "candidate.exe", b"MZ-candidate")
        self.tools = {
            role: _write(root / "tools" / role, role.encode("ascii"))
            for role in ("compiler", "assembler", "linker")
        }
        self.attestation_path = _write(root / "attestation.json", b"{}\n")
        self.attestation = {
            "source_bundle": {
                "path": str(self.bundle_path),
                "artifact_sha256": sha256_file(self.bundle_path),
                "source_bundle_sha256": self.bundle["hashes"][
                    "source_bundle_sha256"
                ],
            },
            "candidate": {
                "path": str(self.candidate),
                "sha256": sha256_file(self.candidate),
                "size": self.candidate.stat().st_size,
            },
            "tools": [
                {
                    "role": role,
                    "path": str(path),
                    "sha256": sha256_file(path),
                }
                for role, path in sorted(self.tools.items())
            ],
        }
        self.source_program_manifest = self._source_program()
        self.static_manifest = self._static_authority()
        self.runtime_source = self._runtime_source()

    def _source_program(self) -> Path:
        output = self.root / "source-program"
        source = _write(
            output / "StageA" / "GeneratedGnuHelloNativeSourceProgram.lean",
            b"""import StageA.GeneratedGnuHelloOriginalPE
namespace StageA.GeneratedRelational.GnuHelloNativeSourceProgram
def generatedNativeSourceProgram (worldProgram : DecodedWorldProgram) : Program := value
theorem generatedNativeSourceX87WitnessRvasNodup : True := by trivial
def generatedNativeSourceExactBindingPartition (worldProgram : DecodedWorldProgram) : True := True.intro
def generatedNativeSourceExactBinding : True := True.intro
end StageA.GeneratedRelational.GnuHelloNativeSourceProgram
""",
        )
        self.source_program_source = source
        return _json(
            output / "phase-manifest.json",
            {
                "format": "stage-a-relational-phase-v1",
                "phase": "native-source-program",
                "executes_original_binary": False,
                "executes_candidate_binary": False,
                "inputs": {},
                "status": "source-ready",
                "modules": ["GeneratedGnuHelloNativeSourceProgram"],
                "targets": ["GeneratedGnuHelloNativeSourceProgram"],
            },
        )

    def _static_authority(self) -> Path:
        output = self.root / "static-authority"
        namespace = (
            "StageA.GeneratedRelational."
            "GnuHelloNativeSourceCandidateStaticAuthority"
        )
        fields = {
            "compiled_identity": "generatedCandidateIdentity",
            "compiled_identity_valid": "generatedCandidateIdentityValid",
            "compiled_bytes": "generatedCandidateBytes",
            "compiled_pe": "generatedCandidatePe",
            "compiled_byte_length_exact": "generatedCandidateByteLengthExact",
            "compiled_pe_parsed_exact": "generatedCandidatePeParsedExact",
            "compiled_pe_bytes_exact": "generatedCandidatePeBytesExact",
            "import_certificate": "generatedCandidateImportCertificate",
            "imports_parsed": "generatedCandidateImportsParsed",
            "relocations": "generatedCandidateRelocations",
            "relocations_parsed": "generatedCandidateRelocationsParsed",
            "loader_image_valid": "generatedCandidateLoaderImageValid",
        }
        source_rows = [f"namespace {namespace}"]
        for symbol in fields.values():
            source_rows.append(f"def {symbol} : True := True.intro")
        source_rows.extend(
            (
                "def generatedCandidateArtifact : True := True.intro",
                "def generatedCandidateMachineAuthority : True := True.intro",
                f"end {namespace}",
            )
        )
        _write(
            output
            / "StageA"
            / "GeneratedGnuHelloNativeSourceCandidateStaticAuthority.lean",
            ("\n".join(source_rows) + "\n").encode("ascii"),
        )
        inventory = _json(
            output / "kernel-data-inventory.json",
            {
                "format": "stage-a-interpreter-kernel-data-inventory-v9",
                "candidate_sha256": sha256_file(self.candidate),
                "candidate_bytes": self.candidate.stat().st_size,
                "counts": {"relocation_packs": 2, "relocation_blocks": 3},
                "modules": [
                    {"name": "CandidatePE", "role": "candidate-pe-binding"},
                    {
                        "name": "CandidateRelocations",
                        "role": "candidate-relocation-bundle",
                    },
                ],
            },
        )
        return _json(
            output / "phase-manifest.json",
            {
                "format": "stage-a-native-source-candidate-static-authority-v1",
                "phase": "native-source-candidate-static-authority",
                "status": "source-ready",
                "candidate": {
                    "path": str(self.candidate),
                    "sha256": sha256_file(self.candidate),
                    "size": self.candidate.stat().st_size,
                },
                "kernel_data": {
                    "inventory": str(inventory),
                    "format": "stage-a-interpreter-kernel-data-inventory-v9",
                    "relocation_packs": 2,
                    "relocation_blocks": 3,
                },
                "module": "GeneratedGnuHelloNativeSourceCandidateStaticAuthority",
                "namespace": namespace,
                "compiled_identity_interface": {
                    name: f"{namespace}.{symbol}" for name, symbol in fields.items()
                },
                "constructors": {
                    "compiled_artifact": f"{namespace}.generatedCandidateArtifact",
                    "machine_authority": (
                        f"{namespace}.generatedCandidateMachineAuthority"
                    ),
                },
                "trust": {
                    "executes_original_binary": False,
                    "executes_candidate_binary": False,
                    "exact_candidate_bytes_checked_in_lean": True,
                    "imports_parsed_from_candidate_exe": True,
                    "relocations_parsed_from_candidate_exe": True,
                    "environment_parameterized": True,
                    "indirect_target_shape_is_completeness": False,
                    "indirect_target_completeness_proved": False,
                    "whole_program_acceptance_authority": False,
                },
            },
        )

    def _runtime_source(self) -> Path:
        return _write(
            self.root / "runtime" / "GnuHelloRuntime.lean",
            b"""import StageA.RelationalNativeSource
namespace StageA.GnuHelloRuntime
def environment : NativeWorldEnvironment := value
def indirectTargets : NativeIndirectTargetInventory := value
theorem indirectTargetsValid : indirectTargets.valid compiledPe = true := by trivial
end StageA.GnuHelloRuntime
""",
        )

    def runtime(self) -> RuntimeDeclarationSpec:
        return RuntimeDeclarationSpec(
            module="StageA.GnuHelloRuntime",
            source=self.runtime_source,
            environment="StageA.GnuHelloRuntime.environment",
            indirect_targets="StageA.GnuHelloRuntime.indirectTargets",
            indirect_targets_valid="StageA.GnuHelloRuntime.indirectTargetsValid",
        )

    def generate(self, out: Path, **changes: object):
        arguments = {
            "source_bundle": self.bundle_path,
            "compilation_attestation": self.attestation_path,
            "native_source_program_manifest": self.source_program_manifest,
            "candidate_static_authority": self.static_manifest,
            "runtime": self.runtime(),
            "out": out,
            "bundle_validator": lambda _path: copy.deepcopy(self.bundle),
            "attestation_validator": lambda _path: copy.deepcopy(self.attestation),
        }
        arguments.update(changes)
        return write_gnu_hello_native_source_compiled_authority_inputs(**arguments)


class StageAGnuHelloNativeSourceCompiledAuthorityInputTests(unittest.TestCase):
    def test_materializes_deterministic_downstream_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            first = fixture.generate(fixture.root / "first")
            second = fixture.generate(fixture.root / "second")

            first_files = {
                path.relative_to(fixture.root / "first"): path.read_bytes()
                for path in (fixture.root / "first").rglob("*")
                if path.is_file()
            }
            second_files = {
                path.relative_to(fixture.root / "second"): path.read_bytes()
                for path in (fixture.root / "second").rglob("*")
                if path.is_file()
            }
            self.assertEqual(first_files, second_files)

            project = json.loads(
                first.project_declarations.read_text(encoding="ascii")
            )
            runtime = json.loads(
                first.runtime_declarations.read_text(encoding="ascii")
            )
            profile = json.loads(first.toolchain_profile.read_text(encoding="ascii"))
            report = json.loads(first.inputs_manifest.read_text(encoding="ascii"))

            self.assertEqual(project["format"], PROJECT_DECLARATIONS_FORMAT)
            self.assertEqual(runtime["format"], RUNTIME_DECLARATIONS_FORMAT)
            self.assertEqual(profile["format"], TOOLCHAIN_PROFILE_FORMAT)
            self.assertEqual(profile["identifier"], PROFILE_IDENTIFIER)
            self.assertEqual(report["format"], INPUTS_MANIFEST_FORMAT)
            self.assertEqual(
                {row["role"] for row in profile["tools"]},
                {
                    "renderer",
                    "lowering",
                    "runtime",
                    "compiler",
                    "assembler",
                    "linker",
                    "abi",
                },
            )
            self.assertNotIn("status", project)
            self.assertNotIn("status", runtime)
            self.assertNotIn("status", profile)

            closure = _source_closure(fixture.bundle, fixture.bundle_path)
            attested_tools = {
                row["role"]: row["sha256"] for row in fixture.attestation["tools"]
            }
            parsed, modules = _load_project_declarations(
                first.project_declarations, closure, attested_tools
            )
            self.assertEqual(parsed["profile_identifier"], PROFILE_IDENTIFIER)
            self.assertIn(
                "StageA.GeneratedGnuHelloNativeSourceProjectDeclarations",
                modules,
            )

    def test_fails_closed_on_input_and_declaration_corruption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = []

            fixture = _Fixture(root / "source-program")
            fixture.source_program_source.write_text(
                "def unrelated : Nat := 0\n", encoding="ascii"
            )
            cases.append(("source program", fixture, {}))

            fixture = _Fixture(root / "source-bytes")
            source = Path(fixture.packages["interpreter"]["root"]) / "program.txt"
            source.write_bytes(b"changed-source")
            cases.append(("source bytes", fixture, {}))

            fixture = _Fixture(root / "static-trust")
            static = json.loads(fixture.static_manifest.read_text(encoding="ascii"))
            static["trust"]["whole_program_acceptance_authority"] = True
            _json(fixture.static_manifest, static)
            cases.append(("static trust", fixture, {}))

            fixture = _Fixture(root / "tool")
            fixture.tools["compiler"].write_bytes(b"changed-compiler")
            cases.append(("tool bytes", fixture, {}))

            fixture = _Fixture(root / "runtime")
            fixture.runtime_source.write_text(
                fixture.runtime_source.read_text(encoding="ascii").replace(
                    "def environment : NativeWorldEnvironment := value",
                    "axiom environment : NativeWorldEnvironment",
                ),
                encoding="ascii",
            )
            cases.append(("runtime axiom", fixture, {}))

            for label, fixture, changes in cases:
                with self.subTest(label=label):
                    with self.assertRaises(GnuHelloCompiledAuthorityInputError):
                        fixture.generate(fixture.root / "out", **changes)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_generated_exact_artifact_is_lean_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            outputs = fixture.generate(fixture.root / "out")
            project = json.loads(
                outputs.project_declarations.read_text(encoding="ascii")
            )
            artifact_ref = project["lean"]["bundle_manifest_artifact"]["ref"]
            module = artifact_ref["module"].split(".", 1)[1]
            source_root = (
                Path(__file__).parents[1]
                / "src"
                / "spaghetti_extractor"
                / "lean"
                / "StageA"
            )
            stage_a = fixture.root / "out" / "StageA"
            _copy_module_closure(source_root, stage_a, "RelationalNativeSource")
            result = _run_lean_relational(
                fixture.root / "out", bundle=module
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)


if __name__ == "__main__":
    unittest.main()
