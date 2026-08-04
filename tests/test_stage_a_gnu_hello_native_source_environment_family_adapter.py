from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spaghetti_extractor.relational.lean.native_source_environment_family_evidence import (
    NATIVE_SOURCE_ACCEPTANCE_DECLARATIONS_FORMAT,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_native_source_environment_family import (
    GNU_HELLO_ENVIRONMENT_FAMILY_INPUT_FORMAT,
    GNU_HELLO_ENVIRONMENT_FAMILY_RESOLVED_FORMAT,
    GnuHelloEnvironmentFamilyAdapterError,
    write_gnu_hello_native_source_environment_family,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, value: object) -> Path:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    return path


class _Fixture:
    source_bundle_sha256 = "a" * 64
    attestation_core_sha256 = "b" * 64
    candidate_sha256 = "c" * 64
    source_entry_rva = 0x1420
    compiled_entry_rva = 0x2050
    authority_module = "StageA.GeneratedGnuHelloCompiledAuthority"
    source_execution_module = "StageA.GeneratedGnuHelloSourceExecution"
    evidence_module = "StageA.GnuHelloEnvironmentEvidence"
    authority_namespace = "StageA.GeneratedRelational.GnuHelloCompiledAuthority"
    source_execution_namespace = (
        "StageA.GeneratedRelational.GnuHelloSourceExecution"
    )
    evidence_namespace = "StageA.GnuHelloEnvironmentEvidence"

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.bundle_path = _write(root / "source-bundle.json", {"fixture": True})
        self.authority_path = _write(
            root / "compiled-authority.json", self.authority_manifest()
        )
        self.execution_path = _write(
            root / "source-execution.json", self.source_execution_manifest()
        )

    @property
    def exact_compilation(self) -> str:
        return f"{self.authority_namespace}.exactCompilation"

    @property
    def source_launch_family(self) -> str:
        return f"{self.source_execution_namespace}.launchFamily"

    def authority_manifest(self) -> dict[str, object]:
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
                "source_bundle_sha256": self.source_bundle_sha256,
                "attestation_core_sha256": self.attestation_core_sha256,
                "candidate_sha256": self.candidate_sha256,
                "candidate_entry_rva": self.compiled_entry_rva,
                "candidate_imports_sha256": "d" * 64,
                "relocation_inventory_sha256": "e" * 64,
            },
        }

    def source_execution_manifest(self) -> dict[str, object]:
        namespace = self.source_execution_namespace
        return {
            "format": "stage-a-gnu-hello-source-execution-assembly-v2",
            "launch_scope": "all_checked_pe32_console_launches",
            "inputs": {},
            "counts": {
                "frontiers": 31,
                "writable_static_slot": 19,
                "register_target": 9,
                "stack_dynamic": 3,
            },
            "lean": {
                "proof_module": self.source_execution_module,
                "audit_module": self.source_execution_module + "Audit",
                "domain": f"{namespace}.domainAt",
                "invariant_family_evidence": f"{namespace}.invariantFamily",
                "launch_family": self.source_launch_family,
            },
            "launch_family_complete": True,
            "acceptance_authority": False,
            "blockers": [],
            "frontiers": [],
        }

    def bundle(self, **changes: object) -> dict[str, object]:
        value: dict[str, object] = {
            "hashes": {"source_bundle_sha256": self.source_bundle_sha256},
            "entry_rva": self.source_entry_rva,
        }
        value.update(changes)
        return value

    def environment_inputs(self) -> dict[str, object]:
        evidence = self.evidence_namespace
        return {
            "format": GNU_HELLO_ENVIRONMENT_FAMILY_INPUT_FORMAT,
            "bindings": {
                "compiled_authority_manifest_sha256": _sha256(
                    self.authority_path
                ),
                "source_execution_manifest_sha256": _sha256(
                    self.execution_path
                ),
                "source_bundle_sha256": self.source_bundle_sha256,
                "attestation_core_sha256": self.attestation_core_sha256,
                "candidate_sha256": self.candidate_sha256,
                "source_entry_rva": self.source_entry_rva,
                "compiled_entry_rva": self.compiled_entry_rva,
            },
            "lean": {
                "imports": [
                    self.authority_module,
                    self.source_execution_module,
                    self.evidence_module,
                ],
                "context": f"{evidence}.context",
                "sites": f"{evidence}.sites",
                "static_compilation": self.exact_compilation,
                "static_authority": f"{evidence}.staticAuthority",
                "source_launch_family": self.source_launch_family,
                "pair_relation": f"{evidence}.PairRelated",
                "pair_realizable": f"{evidence}.pairRealizable",
                "external_evidence_at": f"{evidence}.externalEvidenceAt",
                "source_family_at": f"{evidence}.sourceFamilyAt",
                "launch_realizable_at": f"{evidence}.launchRealizableAt",
            },
        }

    def write_inputs(
        self, value: object | None = None, name: str = "inputs.json"
    ) -> Path:
        return _write(
            self.root / name,
            self.environment_inputs() if value is None else value,
        )

    def generate(
        self,
        out: Path,
        *,
        inputs: Path | None = None,
        bundle: dict[str, object] | None = None,
    ):
        with mock.patch(
            "spaghetti_extractor_target_gnu_hello."
            "gnu_hello_native_source_environment_family."
            "validate_native_source_bundle_manifest",
            return_value=self.bundle() if bundle is None else bundle,
        ):
            return write_gnu_hello_native_source_environment_family(
                out,
                compiled_authority_manifest=self.authority_path,
                source_execution_manifest=self.execution_path,
                source_bundle_manifest=self.bundle_path,
                environment_inputs=inputs or self.write_inputs(),
            )


class StageAGnuHelloNativeSourceEnvironmentFamilyAdapterTests(
    unittest.TestCase
):
    def test_emits_nonvacuous_admitted_machine_level_family(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            outputs = fixture.generate(fixture.root / "out")

            source = outputs.evidence.read_text(encoding="ascii")
            self.assertIn(fixture.exact_compilation, source)
            self.assertIn(fixture.source_execution_module, source)
            self.assertIn("externalEvidenceAt", source)
            self.assertIn("admittedPairEvidence", source)
            self.assertIn("forall sourceEnvironment nativeEnvironment", source)
            self.assertEqual(source.count("axiom pinnedCompilerLoweringCorrect"), 1)
            self.assertNotIn("sourceEnvironment = nativeEnvironment", source)

            declarations = json.loads(
                outputs.acceptance_declarations.read_text(encoding="ascii")
            )
            self.assertEqual(
                declarations["format"],
                NATIVE_SOURCE_ACCEPTANCE_DECLARATIONS_FORMAT,
            )
            self.assertEqual(
                declarations["bindings"]["compiled_authority_manifest_sha256"],
                _sha256(fixture.authority_path),
            )
            self.assertEqual(
                declarations["bindings"]["source_entry_rva"],
                fixture.source_entry_rva,
            )
            self.assertEqual(
                declarations["bindings"]["compiled_entry_rva"],
                fixture.compiled_entry_rva,
            )
            expectation = json.loads(
                outputs.axiom_expectation.read_text(encoding="ascii")
            )
            self.assertEqual(len(expectation["required_axioms"]), 1)
            self.assertEqual(
                expectation["required_axioms"],
                [declarations["lean"]["toolchain_correct"]],
            )

            resolved = json.loads(outputs.resolved_inputs.read_text(encoding="ascii"))
            self.assertEqual(
                resolved["format"], GNU_HELLO_ENVIRONMENT_FAMILY_RESOLVED_FORMAT
            )
            self.assertEqual(
                resolved["policy"]["external_evidence"],
                "ExactWorldNativeExternalEvidence",
            )
            self.assertTrue(
                resolved["policy"]["admitted_environment_pair_nonempty"]
            )
            self.assertTrue(resolved["policy"]["admission_witness_threaded"])
            self.assertEqual(
                resolved["lean"]["source_launch_family"],
                fixture.source_launch_family,
            )

    def test_output_is_deterministic_and_ascii(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            inputs = fixture.write_inputs()
            first = fixture.generate(fixture.root / "first", inputs=inputs)
            second = fixture.generate(fixture.root / "second", inputs=inputs)

            for left, right in zip(
                first.__dict__.values(), second.__dict__.values()
            ):
                self.assertEqual(Path(left).read_bytes(), Path(right).read_bytes())
                Path(left).read_bytes().decode("ascii")

    def test_hash_and_entry_mismatches_fail_closed(self) -> None:
        mutations = {
            "authority hash": lambda value: value["bindings"].__setitem__(
                "compiled_authority_manifest_sha256", "0" * 64
            ),
            "execution hash": lambda value: value["bindings"].__setitem__(
                "source_execution_manifest_sha256", "0" * 64
            ),
            "source closure": lambda value: value["bindings"].__setitem__(
                "source_bundle_sha256", "0" * 64
            ),
            "attestation closure": lambda value: value["bindings"].__setitem__(
                "attestation_core_sha256", "0" * 64
            ),
            "candidate": lambda value: value["bindings"].__setitem__(
                "candidate_sha256", "0" * 64
            ),
            "source entry": lambda value: value["bindings"].__setitem__(
                "source_entry_rva", 0x1421
            ),
            "compiled entry": lambda value: value["bindings"].__setitem__(
                "compiled_entry_rva", 0x2051
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    value = copy.deepcopy(fixture.environment_inputs())
                    mutate(value)
                    path = fixture.write_inputs(
                        value, f"broken-{label.replace(' ', '-')}.json"
                    )
                    with self.assertRaisesRegex(
                        GnuHelloEnvironmentFamilyAdapterError, "mismatch"
                    ):
                        fixture.generate(fixture.root / f"out-{label}", inputs=path)

    def test_environment_and_static_authority_mismatches_fail_closed(self) -> None:
        mutations = {
            "different compilation": lambda value: value["lean"].__setitem__(
                "static_compilation", "StageA.Other.compilation"
            ),
            "different launch family": lambda value: value["lean"].__setitem__(
                "source_launch_family", "StageA.Other.launchFamily"
            ),
            "missing authority import": lambda value: value["lean"]["imports"].remove(
                _Fixture.authority_module
            ),
            "missing execution import": lambda value: value["lean"]["imports"].remove(
                _Fixture.source_execution_module
            ),
            "missing external evidence": lambda value: value["lean"].pop(
                "external_evidence_at"
            ),
            "hidden status": lambda value: value.__setitem__(
                "status", "conditional_pass"
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    value = copy.deepcopy(fixture.environment_inputs())
                    mutate(value)
                    path = fixture.write_inputs(
                        value, f"broken-{label.replace(' ', '-')}.json"
                    )
                    with self.assertRaises(GnuHelloEnvironmentFamilyAdapterError):
                        fixture.generate(fixture.root / f"out-{label}", inputs=path)

    def test_manifest_trust_and_launch_completeness_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root)

            authority = fixture.authority_manifest()
            authority["acceptance_authority"] = True
            fixture.authority_path = _write(root / "bad-authority.json", authority)
            inputs = fixture.write_inputs(
                fixture.environment_inputs(), "authority-inputs.json"
            )
            with self.assertRaisesRegex(
                GnuHelloEnvironmentFamilyAdapterError, "invalid trust role"
            ):
                fixture.generate(root / "authority-out", inputs=inputs)

            fixture = _Fixture(root / "second")
            execution = fixture.source_execution_manifest()
            execution["launch_family_complete"] = False
            fixture.execution_path = _write(root / "bad-execution.json", execution)
            inputs = fixture.write_inputs(
                fixture.environment_inputs(), "execution-inputs.json"
            )
            with self.assertRaisesRegex(
                GnuHelloEnvironmentFamilyAdapterError,
                "complete all-launch proof",
            ):
                fixture.generate(root / "execution-out", inputs=inputs)

    def test_revalidated_source_bundle_entry_is_authoritative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            with self.assertRaisesRegex(
                GnuHelloEnvironmentFamilyAdapterError, "source_entry_rva mismatch"
            ):
                fixture.generate(
                    fixture.root / "out",
                    bundle=fixture.bundle(entry_rva=fixture.source_entry_rva + 1),
                )


if __name__ == "__main__":
    unittest.main()
