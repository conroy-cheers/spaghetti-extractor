from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from spaghetti_extractor_target_gnu_hello.gnu_hello_native_source_compiled_authority_evidence import (
    CANDIDATE_STATIC_AUTHORITY_FORMAT,
    COMPILED_AUTHORITY_DECLARATIONS_FORMAT,
    GnuHelloCompiledAuthorityEvidenceError,
    NixRealizationIdentity,
    PROFILE_IDENTIFIER,
    PROJECT_DECLARATIONS_FORMAT,
    RUNTIME_DECLARATIONS_FORMAT,
    TOOLCHAIN_PROFILE_FILENAME,
    TOOLCHAIN_PROFILE_FORMAT,
    inspect_offline_nix_realization,
    write_gnu_hello_native_source_compiled_authority_evidence,
)
from spaghetti_extractor.relational.lean.native_source_compiled_authority import (
    NativeSourceCompiledAuthoritySpec,
    NixRealizationSpec,
    PinnedToolArtifactSpec,
)
from spaghetti_extractor.util import sha256_file


NAR = "sha256-" + "A" * 43 + "="


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


def _binding(path: Path, *, owner: str | None = None, role: str | None = None) -> dict[str, object]:
    row: dict[str, object] = {
        "path": path.name,
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }
    if owner is not None:
        row["owner"] = owner
    if role is not None:
        row["role"] = role
    return row


class _FakePEFile:
    def close(self) -> None:
        pass


class OfflineNixRealizationTests(unittest.TestCase):
    def test_offline_inspector_preserves_selected_deriver_and_rehashes_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir()
            derivation = root / "build.drv"
            derivation.write_text("Derive([])", encoding="ascii")
            expected = NixRealizationIdentity(output, derivation, NAR)
            with patch(
                "subprocess.run", return_value=SimpleNamespace(stdout=NAR + "\n")
            ) as run:
                observed = inspect_offline_nix_realization(expected)
            self.assertEqual(observed, expected)
            run.assert_called_once_with(
                [
                    "nix",
                    "--extra-experimental-features",
                    "nix-command",
                    "hash",
                    "path",
                    "--sri",
                    str(output.resolve()),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

    def test_offline_inspector_reports_different_live_nar_for_caller(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir()
            derivation = root / "build.drv"
            derivation.write_text("Derive([])", encoding="ascii")
            expected = NixRealizationIdentity(output, derivation, NAR)
            other_nar = "sha256-" + "B" * 43 + "="
            with patch(
                "subprocess.run",
                return_value=SimpleNamespace(stdout=other_nar + "\n"),
            ):
                observed = inspect_offline_nix_realization(expected)
            self.assertEqual(observed.output, expected.output)
            self.assertEqual(observed.derivation, expected.derivation)
            self.assertNotEqual(observed.nar_hash, expected.nar_hash)


class _Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.project = root / "project"
        self.profile = root / "profile"
        self.build = root / "build"
        self.evidence = root / "evidence"
        for path in (self.project, self.profile, self.build, self.evidence):
            path.mkdir()

        self.state_machine = _write(root / "state-machine.jsonl", b'{"pc":1}\n')
        self.load_image = _write(root / "load-image-contract.json", b'{"base":4194304}\n')

        self.package_rows: dict[str, dict[str, object]] = {}
        package_specs = {
            "interpreter": (("program", b"program-source"),),
            "native_engine": (("plan", b"lowering-plan"),),
            "native_runtime": (
                ("native_runtime_header", b"runtime-header"),
                ("native_runtime_source", b"runtime-source"),
            ),
        }
        for owner, artifacts in package_specs.items():
            package_root = root / owner
            package_root.mkdir()
            rows = []
            for role, data in artifacts:
                artifact = _write(package_root / f"{role}.txt", data)
                rows.append(_binding(artifact, owner=owner, role=role))
            manifest = _write(
                package_root / f"{owner}-package.json",
                json.dumps({"owner": owner}).encode("ascii"),
            )
            self.package_rows[owner] = {
                "root": str(package_root),
                "manifest": _binding(manifest),
                "artifacts": rows,
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
            "packages": self.package_rows,
        }

        self.candidate = _write(self.build / "candidate.exe", b"MZ-candidate")
        self.tools = {}
        for role in ("compiler", "assembler", "linker"):
            self.tools[role] = _write(root / "tools" / role, role.encode("ascii"))
        self.relocation = {
            "sha256": "2" * 64,
            "canonical_sha256": "3" * 64,
            "payload_sha256": "4" * 64,
            "count": 7,
            "complete": True,
        }

        self.realizations = {
            "project": self._realization("project", self.project),
            "profile": self._realization("profile", self.profile),
            "build": self._realization("build", self.build),
        }
        self.attestation_path = _write(root / "attestation.json", b"{}\n")
        self.attestation = {
            "hashes": {"attestation_core_sha256": "5" * 64},
            "source_bundle": {
                "path": str(self.bundle_path),
                "artifact_sha256": sha256_file(self.bundle_path),
                "source_bundle_sha256": self.bundle["hashes"]["source_bundle_sha256"],
            },
            "candidate": {
                "path": str(self.candidate),
                "sha256": sha256_file(self.candidate),
                "size": self.candidate.stat().st_size,
            },
            "relocations": self.relocation,
            "nix": self.realizations["build"].canonical_payload(),
            "tools": [
                {
                    "role": role,
                    "path": str(path),
                    "sha256": sha256_file(path),
                }
                for role, path in sorted(self.tools.items())
            ],
        }
        self.binary = SimpleNamespace(
            machine="i386",
            bitness=32,
            entrypoint_rva=0x1234,
            image_base=0x400000,
            imports=(
                SimpleNamespace(
                    dll="kernel32.dll",
                    symbol="ExitProcess",
                    ordinal=None,
                    thunk_rva=0x3010,
                ),
            ),
            pe=_FakePEFile(),
        )

        self.project_module = "StageA.GnuHelloProjectArtifacts"
        self.project_namespace = "StageA.GnuHelloProjectArtifacts"
        self.project_source = self._write_project_source()
        self.project_manifest = self._write_project_manifest()
        self.profile_manifest = self._write_profile_manifest()
        self.static_manifest = self._write_static_manifest()
        self.runtime_manifest = self._write_runtime_manifest()

    def _realization(self, label: str, output: Path) -> NixRealizationIdentity:
        derivation = _write(self.root / f"{label}.drv", f"Derive({label})".encode("ascii"))
        return NixRealizationIdentity(output, derivation, NAR)

    def _ref(self, symbol: str, kind: str) -> dict[str, str]:
        return {
            "module": self.project_module,
            "declaration": f"{self.project_namespace}.{symbol}",
            "kind": kind,
        }

    def _exact(self, symbol: str, digest: str) -> dict[str, object]:
        return {
            "ref": self._ref(symbol, "exact_source_artifact"),
            "evidence_sha256": digest,
        }

    def _write_project_source(self) -> Path:
        exact_symbols = [
            "bundleArtifact",
            "rendererArtifact",
            "rendererTool",
            "loweringTool",
            "runtimeTool",
            "compilerTool",
            "assemblerTool",
            "linkerTool",
            "abiTool",
        ]
        artifact_symbols = [
            f"sourceArtifact{index}"
            for index in range(sum(len(row["artifacts"]) for row in self.package_rows.values()))
        ]
        source = [
            f"namespace {self.project_namespace}",
            "def worldProgram : DecodedWorldProgram := value",
            "def checkedInput : CheckedNativeProgramInput worldProgram := value",
            "theorem checkedInputNonempty : True := by trivial",
            "theorem sourceRolesNodup : True := by trivial",
        ]
        source.extend(
            f"def {symbol} : ExactSourceArtifact := value"
            for symbol in (*exact_symbols, *artifact_symbols)
        )
        source.append(f"end {self.project_namespace}")
        path = self.evidence / "StageA" / "GnuHelloProjectArtifacts.lean"
        return _write(path, ("\n".join(source) + "\n").encode("ascii"))

    def _write_project_manifest(self) -> Path:
        source_digests = sorted(
            row["sha256"]
            for package in self.package_rows.values()
            for row in package["artifacts"]
        )
        exact_sources = [
            self._exact(f"sourceArtifact{index}", digest)
            for index, digest in enumerate(source_digests)
        ]
        tool_digests = {
            "renderer": sha256_file(self.state_machine),
            "lowering": next(
                row["sha256"]
                for row in self.package_rows["native_engine"]["artifacts"]
                if row["role"] == "plan"
            ),
            "runtime": next(
                row["sha256"]
                for row in self.package_rows["native_runtime"]["artifacts"]
                if row["role"] == "native_runtime_source"
            ),
            "compiler": sha256_file(self.tools["compiler"]),
            "assembler": sha256_file(self.tools["assembler"]),
            "linker": sha256_file(self.tools["linker"]),
            "abi": next(
                row["sha256"]
                for row in self.package_rows["native_runtime"]["artifacts"]
                if row["role"] == "native_runtime_header"
            ),
        }
        symbols = {
            "renderer": "rendererTool",
            "lowering": "loweringTool",
            "runtime": "runtimeTool",
            "compiler": "compilerTool",
            "assembler": "assemblerTool",
            "linker": "linkerTool",
            "abi": "abiTool",
        }
        return _json(
            self.evidence / "project-declarations.json",
            {
                "format": PROJECT_DECLARATIONS_FORMAT,
                "bindings": {
                    "source_bundle_sha256": self.bundle["hashes"]["source_bundle_sha256"],
                    "source_bundle_artifact_sha256": sha256_file(self.bundle_path),
                },
                "lean": {
                    "module_sources": [
                        {
                            "module": self.project_module,
                            "path": str(self.project_source),
                            "sha256": sha256_file(self.project_source),
                        }
                    ],
                    "world_program": self._ref("worldProgram", "decoded_world_program"),
                    "checked_input": self._ref("checkedInput", "checked_native_program_input"),
                    "checked_input_nonempty": self._ref("checkedInputNonempty", "proof"),
                    "bundle_manifest_artifact": self._exact(
                        "bundleArtifact", sha256_file(self.bundle_path)
                    ),
                    "renderer_input_artifact": self._exact(
                        "rendererArtifact", sha256_file(self.state_machine)
                    ),
                    "source_artifacts": exact_sources,
                    "source_artifact_roles_nodup": self._ref("sourceRolesNodup", "proof"),
                    "profile_identifier": PROFILE_IDENTIFIER,
                    "tools": {
                        role: {
                            "identifier": f"gnu-hello-{role}-v1",
                            "artifact": self._ref(symbols[role], "exact_source_artifact"),
                            "evidence_sha256": tool_digests[role],
                        }
                        for role in symbols
                    },
                },
            },
        )

    def _write_static_manifest(self) -> Path:
        namespace = "StageA.GnuHelloCandidateStatic"
        fields = {
            "compiled_identity": "compiledIdentity",
            "compiled_identity_valid": "compiledIdentityValid",
            "compiled_bytes": "compiledBytes",
            "compiled_pe": "compiledPe",
            "compiled_byte_length_exact": "compiledByteLengthExact",
            "compiled_pe_parsed_exact": "compiledPeParsedExact",
            "compiled_pe_bytes_exact": "compiledPeBytesExact",
            "import_certificate": "importCertificate",
            "imports_parsed": "importsParsed",
            "relocations": "relocations",
            "relocations_parsed": "relocationsParsed",
            "loader_image_valid": "loaderImageValid",
        }
        source = [f"namespace {namespace}"]
        for key, symbol in fields.items():
            prefix = "theorem" if key.endswith(("valid", "exact", "parsed")) else "def"
            source.append(f"{prefix} {symbol} : True := by trivial")
        source.append(f"end {namespace}")
        module = "GeneratedGnuHelloCandidateStatic"
        module_path = _write(
            self.evidence / "static" / "StageA" / f"{module}.lean",
            ("\n".join(source) + "\n").encode("ascii"),
        )
        del module_path
        return _json(
            self.evidence / "static" / "phase-manifest.json",
            {
                "format": CANDIDATE_STATIC_AUTHORITY_FORMAT,
                "candidate": {
                    "path": str(self.candidate),
                    "sha256": sha256_file(self.candidate),
                    "size": self.candidate.stat().st_size,
                },
                "module": module,
                "compiled_identity_interface": {
                    key: f"{namespace}.{symbol}" for key, symbol in fields.items()
                },
            },
        )

    def _package_artifact(self, owner: str, role: str) -> Path:
        package = self.package_rows[owner]
        row = next(
            item for item in package["artifacts"] if item["role"] == role
        )
        return Path(package["root"]) / row["path"]

    def _write_profile_manifest(self) -> Path:
        paths = {
            "renderer": self.state_machine,
            "lowering": self._package_artifact("native_engine", "plan"),
            "runtime": self._package_artifact(
                "native_runtime", "native_runtime_source"
            ),
            "compiler": self.tools["compiler"],
            "assembler": self.tools["assembler"],
            "linker": self.tools["linker"],
            "abi": self._package_artifact(
                "native_runtime", "native_runtime_header"
            ),
        }
        return _json(
            self.profile / TOOLCHAIN_PROFILE_FILENAME,
            {
                "format": TOOLCHAIN_PROFILE_FORMAT,
                "identifier": PROFILE_IDENTIFIER,
                "tools": [
                    {
                        "role": role,
                        "identifier": f"gnu-hello-{role}-v1",
                        "path": str(path),
                        "sha256": sha256_file(path),
                    }
                    for role, path in sorted(paths.items())
                ],
            },
        )

    def _write_runtime_manifest(self) -> Path:
        module = "StageA.GnuHelloCandidateRuntime"
        namespace = "StageA.GnuHelloCandidateRuntime"
        source = _write(
            self.evidence / "runtime" / "StageA" / "GnuHelloCandidateRuntime.lean",
            (
                f"namespace {namespace}\n"
                "def environment : NativeWorldEnvironment := value\n"
                "def indirectTargets : NativeIndirectTargetInventory := value\n"
                "theorem indirectTargetsValid : True := by trivial\n"
                f"end {namespace}\n"
            ).encode("ascii"),
        )
        ref = lambda symbol, kind: {
            "module": module,
            "declaration": f"{namespace}.{symbol}",
            "kind": kind,
        }
        return _json(
            self.evidence / "runtime" / "runtime-declarations.json",
            {
                "format": RUNTIME_DECLARATIONS_FORMAT,
                "candidate_sha256": sha256_file(self.candidate),
                "lean": {
                    "module_sources": [
                        {
                            "module": module,
                            "path": str(source),
                            "sha256": sha256_file(source),
                        }
                    ],
                    "environment": ref("environment", "native_world_environment"),
                    "indirect_targets": ref("indirectTargets", "native_indirect_target_inventory"),
                    "indirect_targets_valid": ref("indirectTargetsValid", "proof"),
                    "callable_external": None,
                    "callable_bound": None,
                },
            },
        )

    def generate(self, out: Path | None = None, **changes: object):
        arguments = {
            "source_bundle": self.bundle_path,
            "compilation_attestation": self.attestation_path,
            "project_declarations": self.project_manifest,
            "candidate_static_authority": self.static_manifest,
            "runtime_declarations": self.runtime_manifest,
            "project_realization": self.realizations["project"],
            "profile_realization": self.realizations["profile"],
            "build_realization": self.realizations["build"],
            "out": out or self.root / "out",
            "nix_inspector": lambda expected: expected,
            "bundle_validator": lambda _path: copy.deepcopy(self.bundle),
            "attestation_validator": lambda _path: copy.deepcopy(self.attestation),
            "pe_parser": lambda _path: self.binary,
        }
        arguments.update(changes)
        return write_gnu_hello_native_source_compiled_authority_evidence(**arguments)


class StageAGnuHelloNativeSourceCompiledAuthorityEvidenceTests(unittest.TestCase):
    def test_evidence_is_deterministic_and_matches_compiled_authority_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            first = fixture.generate(fixture.root / "first")
            second = fixture.generate(fixture.root / "second")
            self.assertEqual(
                [path.read_bytes() for path in first],
                [path.read_bytes() for path in second],
            )

            declarations = json.loads(first[0].read_text(encoding="ascii"))
            self.assertEqual(
                declarations["format"], COMPILED_AUTHORITY_DECLARATIONS_FORMAT
            )
            self.assertEqual(
                declarations["bindings"]["candidate_imports"],
                [
                    {
                        "dll": "kernel32.dll",
                        "symbol": "ExitProcess",
                        "ordinal": None,
                        "thunk_rva": 0x3010,
                    }
                ],
            )
            self.assertEqual(
                declarations["bindings"]["relocation_inventory"],
                fixture.relocation,
            )
            self.assertNotIn("status", declarations)

            lean = declarations["lean"]
            provenance = [
                json.loads(path.read_text(encoding="ascii")) for path in first[1:]
            ]
            nix = [
                NixRealizationSpec(
                    derivation_path=row["derivation"],
                    derivation_sha256=sha256_file(Path(row["derivation"])),
                    output_path=row["output"],
                    nar_hash=row["nar_hash"],
                )
                for row in provenance
            ]
            tools = {
                role: PinnedToolArtifactSpec(
                    identifier=value["identifier"],
                    exact_artifact=value["exact_artifact"],
                )
                for role, value in lean["tools"].items()
            }
            spec = NativeSourceCompiledAuthoritySpec(
                imports=tuple(lean["imports"]),
                world_program=lean["world_program"],
                checked_input=lean["checked_input"],
                checked_input_nonempty=lean["checked_input_nonempty"],
                bundle_manifest_artifact=lean["bundle_manifest_artifact"],
                renderer_input_artifact=lean["renderer_input_artifact"],
                source_artifacts=tuple(lean["source_artifacts"]),
                source_artifact_roles_nodup=lean["source_artifact_roles_nodup"],
                project_nix=nix[0],
                profile_identifier=lean["profile_identifier"],
                profile_nix=nix[1],
                renderer=tools["renderer"],
                lowering=tools["lowering"],
                runtime=tools["runtime"],
                compiler=tools["compiler"],
                assembler=tools["assembler"],
                linker=tools["linker"],
                abi=tools["abi"],
                compiled_identity=lean["compiled_identity"],
                compiled_identity_valid=lean["compiled_identity_valid"],
                compiled_bytes=lean["compiled_bytes"],
                compiled_pe=lean["compiled_pe"],
                compiled_byte_length_exact=lean["compiled_byte_length_exact"],
                compiled_pe_parsed_exact=lean["compiled_pe_parsed_exact"],
                compiled_pe_bytes_exact=lean["compiled_pe_bytes_exact"],
                build_nix=nix[2],
                import_certificate=lean["import_certificate"],
                imports_parsed=lean["imports_parsed"],
                relocations=lean["relocations"],
                relocations_parsed=lean["relocations_parsed"],
                loader_image_valid=lean["loader_image_valid"],
                environment=lean["environment"],
                indirect_targets=lean["indirect_targets"],
                indirect_targets_valid=lean["indirect_targets_valid"],
                callable_external=lean["callable_external"],
                callable_bound=lean["callable_bound"],
                namespace=lean["namespace"],
                output_module=lean["output_module"],
                audit_output_module=lean["audit_output_module"],
            )
            spec.validate()

    def test_fails_closed_on_nix_artifact_and_declaration_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = []

            fixture = _Fixture(root / "nar")
            wrong_nar = NixRealizationIdentity(
                fixture.profile,
                fixture.realizations["profile"].derivation,
                "sha256-" + "B" * 43 + "=",
            )
            cases.append(
                (
                    "live NAR mismatch",
                    fixture,
                    {
                        "profile_realization": wrong_nar,
                        "nix_inspector": lambda _expected: fixture.realizations["profile"],
                    },
                )
            )

            fixture = _Fixture(root / "module")
            fixture.project_source.write_text("def unrelated : Nat := 0\n", encoding="ascii")
            project = json.loads(fixture.project_manifest.read_text(encoding="ascii"))
            project["lean"]["module_sources"][0]["sha256"] = sha256_file(
                fixture.project_source
            )
            _json(fixture.project_manifest, project)
            cases.append(("missing exact declaration", fixture, {}))

            fixture = _Fixture(root / "source")
            project = json.loads(fixture.project_manifest.read_text(encoding="ascii"))
            project["lean"]["source_artifacts"][0]["evidence_sha256"] = "f" * 64
            _json(fixture.project_manifest, project)
            cases.append(("source closure mismatch", fixture, {}))

            fixture = _Fixture(root / "candidate")
            _write(fixture.candidate, b"changed candidate")
            cases.append(("candidate drift", fixture, {}))

            for label, fixture, changes in cases:
                with self.subTest(label=label):
                    with self.assertRaises(GnuHelloCompiledAuthorityEvidenceError):
                        fixture.generate(**changes)

    def test_rejects_status_authority_and_unchecked_exact_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root / "status")
            project = json.loads(fixture.project_manifest.read_text(encoding="ascii"))
            project["status"] = "pass"
            _json(fixture.project_manifest, project)
            with self.assertRaisesRegex(
                GnuHelloCompiledAuthorityEvidenceError, "must contain exactly"
            ):
                fixture.generate()

            fixture = _Fixture(root / "axiom")
            source = fixture.project_source.read_text(encoding="ascii").replace(
                "def bundleArtifact : ExactSourceArtifact := value",
                "axiom bundleArtifact : ExactSourceArtifact",
            )
            fixture.project_source.write_text(source, encoding="ascii")
            project = json.loads(fixture.project_manifest.read_text(encoding="ascii"))
            project["lean"]["module_sources"][0]["sha256"] = sha256_file(
                fixture.project_source
            )
            _json(fixture.project_manifest, project)
            with self.assertRaisesRegex(
                GnuHelloCompiledAuthorityEvidenceError, "unchecked declaration"
            ):
                fixture.generate()


if __name__ == "__main__":
    unittest.main()
