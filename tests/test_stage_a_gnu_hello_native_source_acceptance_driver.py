from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO = Path(__file__).parents[1]
DRIVER_PATH = REPO / "nix/gnu-hello-roundtrip-driver.py"
SPEC = importlib.util.spec_from_file_location(
    "gnu_hello_native_source_acceptance_driver", DRIVER_PATH
)
assert SPEC is not None and SPEC.loader is not None
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)

SHA = {
    name: sha256(name.encode("ascii")).hexdigest()
    for name in (
        "bundle-closure",
        "state-machine",
        "load-image",
        "source-a",
        "source-b",
        "package-manifest",
        "attestation-closure",
        "candidate",
        "relocation-artifact",
        "relocation-canonical",
        "payload",
        "compiler",
        "assembler",
        "linker",
    )
}
NAR = "sha256-" + "A" * 43 + "="


class _FakePE:
    def close(self) -> None:
        pass


class _Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.project = root / "project"
        self.profile = root / "profile"
        self.build = root / "build"
        for path in (self.project, self.profile, self.build):
            path.mkdir()

        self.source_bundle_path = self.project / "native-source-bundle.json"
        self.source_bundle_path.write_text("{}\n", encoding="ascii")
        self.candidate = self.build / "candidate.exe"
        self.candidate.write_bytes(b"static-candidate-pe-fixture")
        SHA["candidate"] = DRIVER.sha256_file(self.candidate)
        self.attestation_path = root / "compilation-attestation.json"
        self.attestation_path.write_text("{}\n", encoding="ascii")

        self.derivations: dict[str, Path] = {}
        self.provenance: dict[str, Path] = {}
        for label, output in (
            ("project", self.project),
            ("profile", self.profile),
            ("build", self.build),
        ):
            derivation = root / f"{label}.drv"
            derivation.write_text(f"Derive({label})\n", encoding="ascii")
            self.derivations[label] = derivation
            provenance = root / f"{label}-nix-provenance.json"
            provenance.write_text(
                json.dumps(
                    {
                        "output": str(output),
                        "derivation": str(derivation),
                        "registered_deriver": str(derivation),
                        "nar_hash": NAR,
                    },
                    sort_keys=True,
                ),
                encoding="ascii",
            )
            self.provenance[label] = provenance

        self.bundle = {
            "entry_rva": 0x1420,
            "hashes": {"source_bundle_sha256": SHA["bundle-closure"]},
            "state_machine": {"sha256": SHA["state-machine"]},
            "load_image_contract": {"artifact_sha256": SHA["load-image"]},
            "packages": {
                "interpreter": {
                    "manifest": {"sha256": SHA["package-manifest"]},
                    "artifacts": [
                        {"sha256": SHA["source-a"]},
                        {"sha256": SHA["source-b"]},
                    ],
                }
            },
        }
        self.imports = [
            {
                "dll": "kernel32.dll",
                "symbol": "ExitProcess",
                "ordinal": None,
                "thunk_rva": 0x3020,
            }
        ]
        self.relocation = {
            "path": str(self.build / "payload-relocations.json"),
            "size": 100,
            "sha256": SHA["relocation-artifact"],
            "format": "stage-b-pe-payload-relocation-inventory-v1",
            "canonical_sha256": SHA["relocation-canonical"],
            "payload_sha256": SHA["payload"],
            "count": 12,
            "complete": True,
        }
        self.attestation = {
            "hashes": {"attestation_core_sha256": SHA["attestation-closure"]},
            "source_bundle": {
                "path": str(self.source_bundle_path),
                "size": self.source_bundle_path.stat().st_size,
                "artifact_sha256": DRIVER.sha256_file(self.source_bundle_path),
                "source_bundle_sha256": SHA["bundle-closure"],
            },
            "candidate": {
                "path": str(self.candidate),
                "sha256": SHA["candidate"],
                "size": self.candidate.stat().st_size,
            },
            "relocations": self.relocation,
            "nix": {
                "output": str(self.build),
                "derivation": str(self.derivations["build"]),
                "registered_deriver": str(self.derivations["build"]),
                "nar_hash": NAR,
            },
            "tools": [
                {"role": "compiler", "sha256": SHA["compiler"]},
                {"role": "assembler", "sha256": SHA["assembler"]},
                {"role": "linker", "sha256": SHA["linker"]},
            ],
        }
        self.binary = SimpleNamespace(
            machine="i386",
            bitness=32,
            entrypoint_rva=0x2050,
            image_base=0x400000,
            imports=(
                SimpleNamespace(
                    dll="kernel32.dll",
                    symbol="ExitProcess",
                    ordinal=None,
                    thunk_rva=0x3020,
                ),
            ),
            pe=_FakePE(),
        )

    def authority_declarations(self) -> dict[str, object]:
        namespace = "StageA.GeneratedRelational.GnuHelloCompiledAuthority"
        tool = lambda role, digest: {
            "identifier": f"gnu-hello-{role}-v1",
            "exact_artifact": f"StageA.GnuHelloExactArtifacts.{role}Artifact",
            "evidence_sha256": digest,
        }
        return {
            "format": DRIVER.NATIVE_SOURCE_COMPILED_AUTHORITY_DECLARATIONS_FORMAT,
            "bindings": {
                "source_bundle_sha256": SHA["bundle-closure"],
                "source_bundle_artifact_sha256": DRIVER.sha256_file(
                    self.source_bundle_path
                ),
                "attestation_core_sha256": SHA["attestation-closure"],
                "attestation_artifact_sha256": DRIVER.sha256_file(
                    self.attestation_path
                ),
                "candidate_sha256": SHA["candidate"],
                "candidate_size": self.candidate.stat().st_size,
                "candidate_entry_rva": self.binary.entrypoint_rva,
                "candidate_image_base": self.binary.image_base,
                "candidate_imports": self.imports,
                "relocation_inventory": {
                    key: self.relocation[key]
                    for key in (
                        "sha256",
                        "canonical_sha256",
                        "payload_sha256",
                        "count",
                        "complete",
                    )
                },
                "project_nar_hash": NAR,
                "profile_nar_hash": NAR,
                "build_nar_hash": NAR,
            },
            "lean": {
                "imports": ["StageA.GnuHelloExactArtifacts"],
                "world_program": "StageA.GnuHelloExactArtifacts.worldProgram",
                "checked_input": "StageA.GnuHelloExactArtifacts.checkedInput",
                "checked_input_nonempty": (
                    "StageA.GnuHelloExactArtifacts.checkedInputNonempty"
                ),
                "bundle_manifest_artifact": (
                    "StageA.GnuHelloExactArtifacts.bundleManifestArtifact"
                ),
                "renderer_input_artifact": (
                    "StageA.GnuHelloExactArtifacts.rendererInputArtifact"
                ),
                "source_artifacts": [
                    "StageA.GnuHelloExactArtifacts.sourceArtifactA",
                    "StageA.GnuHelloExactArtifacts.sourceArtifactB",
                ],
                "source_artifact_evidence_sha256s": [
                    SHA["source-a"],
                    SHA["source-b"],
                ],
                "source_artifact_roles_nodup": (
                    "StageA.GnuHelloExactArtifacts.sourceRolesNodup"
                ),
                "profile_identifier": "gnu-hello-native-source-v1",
                "tools": {
                    "renderer": tool("renderer", SHA["source-a"]),
                    "lowering": tool("lowering", SHA["source-b"]),
                    "runtime": tool("runtime", SHA["source-a"]),
                    "compiler": tool("compiler", SHA["compiler"]),
                    "assembler": tool("assembler", SHA["assembler"]),
                    "linker": tool("linker", SHA["linker"]),
                    "abi": tool("abi", SHA["source-b"]),
                },
                "compiled_identity": (
                    "StageA.GnuHelloExactArtifacts.compiledIdentity"
                ),
                "compiled_identity_valid": (
                    "StageA.GnuHelloExactArtifacts.compiledIdentityValid"
                ),
                "compiled_bytes": "StageA.GnuHelloExactArtifacts.compiledBytes",
                "compiled_pe": "StageA.GnuHelloExactArtifacts.compiledPe",
                "compiled_byte_length_exact": (
                    "StageA.GnuHelloExactArtifacts.compiledByteLengthExact"
                ),
                "compiled_pe_parsed_exact": (
                    "StageA.GnuHelloExactArtifacts.compiledPeParsedExact"
                ),
                "compiled_pe_bytes_exact": (
                    "StageA.GnuHelloExactArtifacts.compiledPeBytesExact"
                ),
                "import_certificate": (
                    "StageA.GnuHelloExactArtifacts.importCertificate"
                ),
                "imports_parsed": "StageA.GnuHelloExactArtifacts.importsParsed",
                "relocations": "StageA.GnuHelloExactArtifacts.relocations",
                "relocations_parsed": (
                    "StageA.GnuHelloExactArtifacts.relocationsParsed"
                ),
                "loader_image_valid": (
                    "StageA.GnuHelloExactArtifacts.loaderImageValid"
                ),
                "environment": "StageA.GnuHelloExactArtifacts.environment",
                "indirect_targets": (
                    "StageA.GnuHelloExactArtifacts.indirectTargets"
                ),
                "indirect_targets_valid": (
                    "StageA.GnuHelloExactArtifacts.indirectTargetsValid"
                ),
                "callable_external": None,
                "callable_bound": None,
                "namespace": namespace,
                "output_module": "GeneratedGnuHelloNativeSourceCompiledAuthority",
                "audit_output_module": (
                    "GeneratedGnuHelloNativeSourceCompiledAuthorityAudit"
                ),
            },
        }

    def authority_args(self, declarations: Path, out: Path) -> SimpleNamespace:
        return SimpleNamespace(
            source_bundle=str(self.source_bundle_path),
            compilation_attestation=str(self.attestation_path),
            declarations=str(declarations),
            project_nix_provenance=str(self.provenance["project"]),
            profile_nix_provenance=str(self.provenance["profile"]),
            build_nix_provenance=str(self.provenance["build"]),
            out=str(out),
        )

    def patches(self):
        return (
            mock.patch.object(
                DRIVER,
                "validate_native_source_bundle_manifest",
                return_value=self.bundle,
            ),
            mock.patch.object(
                DRIVER,
                "validate_native_source_compilation_attestation",
                return_value=self.attestation,
            ),
            mock.patch.object(DRIVER, "_parse_stage_a_pe", return_value=self.binary),
        )


class StageAGnuHelloNativeSourceAcceptanceDriverTests(unittest.TestCase):
    def _write(self, path: Path, value: object) -> Path:
        path.write_text(json.dumps(value, sort_keys=True), encoding="ascii")
        return path

    def test_compiled_authority_is_deterministic_and_static(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            declarations = self._write(
                fixture.root / "authority-declarations.json",
                fixture.authority_declarations(),
            )
            first = fixture.root / "first"
            second = fixture.root / "second"
            patches = fixture.patches()
            with patches[0], patches[1], patches[2]:
                DRIVER._native_source_compiled_authority(
                    fixture.authority_args(declarations, first)
                )
                DRIVER._native_source_compiled_authority(
                    fixture.authority_args(declarations, second)
                )

            for name in (
                "GeneratedGnuHelloNativeSourceCompiledAuthority.lean",
                "GeneratedGnuHelloNativeSourceCompiledAuthorityAudit.lean",
            ):
                self.assertEqual(
                    (first / "StageA" / name).read_bytes(),
                    (second / "StageA" / name).read_bytes(),
                )
            manifest = json.loads(
                (first / "phase-manifest.json").read_text(encoding="utf-8")
            )
            self.assertFalse(manifest["executes_original_binary"])
            self.assertFalse(manifest["executes_candidate_binary"])
            self.assertFalse(manifest["proof_authority"])
            self.assertFalse(manifest["acceptance_authority"])
            self.assertNotIn("status", manifest)

    def test_compiled_authority_fails_closed_on_exact_binding_mismatches(self) -> None:
        mutations = {
            "candidate hash": lambda value: value["bindings"].__setitem__(
                "candidate_sha256", "0" * 64
            ),
            "imports": lambda value: value["bindings"].__setitem__(
                "candidate_imports", []
            ),
            "relocations": lambda value: value["bindings"][
                "relocation_inventory"
            ].__setitem__("count", 13),
            "NAR": lambda value: value["bindings"].__setitem__(
                "build_nar_hash", "sha256-" + "B" * 43 + "="
            ),
            "missing declaration": lambda value: value["lean"].pop(
                "compiled_pe_parsed_exact"
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    declaration = copy.deepcopy(fixture.authority_declarations())
                    mutate(declaration)
                    path = self._write(
                        fixture.root / f"authority-{label.replace(' ', '-')}.json",
                        declaration,
                    )
                    patches = fixture.patches()
                    with patches[0], patches[1], patches[2]:
                        with self.assertRaises(ValueError):
                            DRIVER._native_source_compiled_authority(
                                fixture.authority_args(
                                    path, fixture.root / f"out-{label}"
                                )
                            )

    def test_acceptance_requires_environment_family_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            authority_declarations = self._write(
                fixture.root / "authority-declarations.json",
                fixture.authority_declarations(),
            )
            authority_out = fixture.root / "authority"
            patches = fixture.patches()
            with patches[0], patches[1], patches[2]:
                DRIVER._native_source_compiled_authority(
                    fixture.authority_args(authority_declarations, authority_out)
                )
            authority_manifest = authority_out / "phase-manifest.json"
            environment_family = (
                "StageA.GeneratedRelational.GnuHelloEnvironmentFamily"
            )
            acceptance_declarations = {
                "format": DRIVER.NATIVE_SOURCE_ACCEPTANCE_DECLARATIONS_FORMAT,
                "bindings": {
                    "compiled_authority_manifest_sha256": DRIVER.sha256_file(
                        authority_manifest
                    ),
                    "source_bundle_sha256": SHA["bundle-closure"],
                    "attestation_core_sha256": SHA["attestation-closure"],
                    "candidate_sha256": SHA["candidate"],
                    "source_entry_rva": fixture.bundle["entry_rva"],
                    "compiled_entry_rva": fixture.binary.entrypoint_rva,
                },
                "lean": {
                    "imports": [
                        "StageA.GeneratedGnuHelloNativeSourceCompiledAuthority",
                        "StageA.GeneratedGnuHelloEnvironmentFamilyEvidence",
                    ],
                    "context": f"{environment_family}.context",
                    "sites": f"{environment_family}.sites",
                    "static_compilation": (
                        f"{environment_family}.staticCompilation"
                    ),
                    "static_authority": (
                        f"{environment_family}.staticAuthority"
                    ),
                    "pair_relation": f"{environment_family}.PairRelated",
                    "admitted_pair_evidence": (
                        f"{environment_family}.admittedPairEvidence"
                    ),
                    "toolchain_correct": f"{environment_family}.toolchainCorrect",
                    "namespace": (
                        "StageA.GeneratedRelational.GnuHelloNativeSourceAcceptance"
                    ),
                    "output_module": "GeneratedGnuHelloNativeSourceAcceptance",
                    "audit_output_module": (
                        "GeneratedGnuHelloNativeSourceAcceptanceAudit"
                    ),
                    "compilation_name": "generatedStaticExactNativeCompilation",
                    "environment_family_name": (
                        "generatedCheckedNativeSourceAdmittedEnvironmentFamily"
                    ),
                    "theorem_name": (
                        "gnuHelloNativeSourceEnvironmentFamilyEquivalence"
                    ),
                },
            }
            acceptance_path = self._write(
                fixture.root / "acceptance-declarations.json",
                acceptance_declarations,
            )
            acceptance_out = fixture.root / "acceptance"
            args = SimpleNamespace(
                source_bundle=str(fixture.source_bundle_path),
                compilation_attestation=str(fixture.attestation_path),
                compiled_authority_manifest=str(authority_manifest),
                declarations=str(acceptance_path),
                out=str(acceptance_out),
            )
            patches = fixture.patches()
            with patches[0], patches[1], patches[2]:
                DRIVER._native_source_acceptance(args)

            source = (
                acceptance_out
                / "StageA/GeneratedGnuHelloNativeSourceAcceptance.lean"
            ).read_text(encoding="ascii")
            self.assertIn("WorldExternalEnvironment", source)
            self.assertIn("NativeWorldEnvironment", source)
            self.assertIn("CheckedNativeSourceAdmittedEnvironmentFamily", source)
            self.assertIn(
                "ExactRawOriginalPECompiledArtifactAdmittedEnvironmentFamilyEquivalence",
                source,
            )
            self.assertIn(
                "compiledArtifactAdmittedEnvironmentFamilyEquivalentUnderPinnedNativeSourceStackHypothesis",
                source,
            )
            self.assertIn("admittedPairs :=", source)
            self.assertIn("toolchainCorrectAt :=", source)
            self.assertNotIn("(pinnedStackCorrect :", source)
            self.assertNotIn(
                "ExactRawOriginalPECompiledArtifactLaunchFamilyEquivalence",
                source,
            )
            for hidden_fixed_field in (
                "profile :=",
                "project :=",
                "artifact :=",
                "machineAuthority :=",
            ):
                self.assertNotIn(hidden_fixed_field, source)
            audit = (
                acceptance_out
                / "StageA/GeneratedGnuHelloNativeSourceAcceptanceAudit.lean"
            ).read_text(encoding="ascii")
            self.assertEqual(audit.count("#print axioms"), 1)
            manifest = json.loads(
                (acceptance_out / "phase-manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                manifest["conditional_on"],
                f"{environment_family}.toolchainCorrect",
            )
            self.assertFalse(manifest["acceptance_authority"])
            self.assertNotIn("status", manifest)

            mutations = {
                "fixed v1 schema": lambda value: value.__setitem__(
                    "format",
                    "stage-a-gnu-hello-native-source-acceptance-declarations-v1",
                ),
                "launch": lambda value: value["bindings"].__setitem__(
                    "compiled_entry_rva", fixture.binary.entrypoint_rva + 1
                ),
                "missing pair": lambda value: value["lean"].pop(
                    "admitted_pair_evidence"
                ),
                "hidden fixed project": lambda value: value["lean"].__setitem__(
                    "project", "StageA.Hidden.project"
                ),
                "authority hash": lambda value: value["bindings"].__setitem__(
                    "compiled_authority_manifest_sha256", "0" * 64
                ),
            }
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    broken = copy.deepcopy(acceptance_declarations)
                    mutate(broken)
                    broken_path = self._write(
                        fixture.root / f"acceptance-{label.replace(' ', '-')}.json",
                        broken,
                    )
                    broken_args = copy.copy(args)
                    broken_args.declarations = str(broken_path)
                    patches = fixture.patches()
                    with patches[0], patches[1], patches[2]:
                        with self.assertRaises(ValueError):
                            DRIVER._native_source_acceptance(broken_args)

    def test_declaration_status_cannot_authorize_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            declaration = fixture.authority_declarations()
            declaration["status"] = "conditional_pass"
            path = self._write(fixture.root / "authority.json", declaration)
            patches = fixture.patches()
            with patches[0], patches[1], patches[2]:
                with self.assertRaisesRegex(ValueError, "non-canonical schema"):
                    DRIVER._native_source_compiled_authority(
                        fixture.authority_args(path, fixture.root / "out")
                    )


if __name__ == "__main__":
    unittest.main()
