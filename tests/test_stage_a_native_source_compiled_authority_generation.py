from __future__ import annotations

import dataclasses
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.native_source_compiled_authority import (
    NATIVE_SOURCE_COMPILED_AUTHORITY_AUDIT_MODULE,
    NATIVE_SOURCE_COMPILED_AUTHORITY_MODULE,
    NativeSourceCompiledAuthorityGenerationError,
    NativeSourceCompiledAuthoritySpec,
    NixRealizationSpec,
    PinnedToolArtifactSpec,
    native_source_compiled_authority_axiom_audit_source,
    native_source_compiled_authority_source,
    write_native_source_compiled_authority,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_NAR_HASH = "sha256-" + "A" * 43 + "="


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


def _nix(label: str) -> NixRealizationSpec:
    return NixRealizationSpec(
        derivation_path=f"/nix/store/{label}.drv",
        derivation_sha256=(label[0] * 64),
        output_path=f"/nix/store/{label}",
        nar_hash=_NAR_HASH,
    )


def _tool(name: str) -> PinnedToolArtifactSpec:
    fixture = "StageA.NativeSourceCompiledAuthorityFixture"
    return PinnedToolArtifactSpec(
        identifier=f"pinned-{name}-v1",
        exact_artifact=f"{fixture}.toolArtifact",
    )


def _spec(**changes: object) -> NativeSourceCompiledAuthoritySpec:
    fixture = "StageA.NativeSourceCompiledAuthorityFixture"
    base = NativeSourceCompiledAuthoritySpec(
        imports=("StageA.NativeSourceCompiledAuthorityFixture",),
        world_program=f"{fixture}.worldProgram",
        checked_input=f"{fixture}.checkedInput",
        checked_input_nonempty=f"{fixture}.checkedInputNonempty",
        bundle_manifest_artifact=f"{fixture}.bundleArtifact",
        renderer_input_artifact=f"{fixture}.rendererInputArtifact",
        source_artifacts=(
            f"{fixture}.sourceArtifactA",
            f"{fixture}.sourceArtifactB",
        ),
        source_artifact_roles_nodup=f"{fixture}.sourceRolesNodup",
        project_nix=_nix("a-project"),
        profile_identifier="checked-native-toolchain-v1",
        profile_nix=_nix("b-toolchain"),
        renderer=_tool("renderer"),
        lowering=_tool("lowering"),
        runtime=_tool("runtime"),
        compiler=_tool("compiler"),
        assembler=_tool("assembler"),
        linker=_tool("linker"),
        abi=_tool("abi"),
        compiled_identity=f"{fixture}.compiledIdentity",
        compiled_identity_valid=f"{fixture}.compiledIdentityValid",
        compiled_bytes=f"{fixture}.compiledBytes",
        compiled_pe=f"{fixture}.compiledPe",
        compiled_byte_length_exact=f"{fixture}.compiledByteLengthExact",
        compiled_pe_parsed_exact=f"{fixture}.compiledPeParsedExact",
        compiled_pe_bytes_exact=f"{fixture}.compiledPeBytesExact",
        build_nix=_nix("c-build"),
        import_certificate=f"{fixture}.importCertificate",
        imports_parsed=f"{fixture}.importsParsed",
        relocations=f"{fixture}.relocations",
        relocations_parsed=f"{fixture}.relocationsParsed",
        loader_image_valid=f"{fixture}.loaderImageValid",
        environment=f"{fixture}.environment",
        indirect_targets=f"{fixture}.indirectTargets",
        indirect_targets_valid=f"{fixture}.indirectTargetsValid",
    )
    return dataclasses.replace(base, **changes)


class StageANativeSourceCompiledAuthorityGenerationTests(unittest.TestCase):
    def test_static_authority_is_root_independent(self) -> None:
        source = native_source_compiled_authority_source(_spec())

        for required in (
            "def generatedNativeSourceProject : NativeSourceProject",
            "theorem generatedNativeSourceProjectValid",
            "def generatedPinnedNativeSourceToolchainProfile :",
            "def generatedNativeSourceCompiledArtifact : CompiledArtifact",
            "def generatedNativeSourceArtifactBuiltFrom :",
            "def generatedNativeSourceCompiledPE32Authority :",
            "def checkedNativeSourceLaunch\n    (sourceRoot : SourceExecution)",
            "def exactNativeSourceCompilation : ExactNativeCompilation",
            "sourceProjectNarHash := generatedNativeSourceProject.nixIdentity.narHash",
            "toolchainNarHash := generatedPinnedNativeSourceToolchainProfile.nixIdentity.narHash",
            "identity := StageA.NativeSourceCompiledAuthorityFixture.compiledIdentity",
        ):
            self.assertIn(required, source)

        static_prefix = source.split("def checkedNativeSourceLaunch", 1)[0]
        self.assertNotIn("sourceRoot", static_prefix)
        self.assertNotIn("compiledRoot", static_prefix)
        compilation = source.split(
            "def exactNativeSourceCompilation : ExactNativeCompilation", 1
        )[1]
        self.assertNotIn("sourceRoot", compilation)
        self.assertNotIn("compiledRoot", compilation)
        self.assertNotIn("launchChecked", compilation)
        self.assertNotIn("#print axioms", source)
        for forbidden in (
            r"\baxiom\b",
            r"\bsorry\b",
            r"\badmit\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bhello\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_optional_callable_authority_is_explicit(self) -> None:
        fixture = "StageA.NativeSourceCompiledAuthorityFixture"
        source = native_source_compiled_authority_source(
            _spec(
                callable_external=f"{fixture}.callableExternal",
                callable_bound=f"{fixture}.callableBound",
            )
        )

        self.assertIn(
            f"callableExternal := some {fixture}.callableExternal", source
        )
        self.assertIn(f"using {fixture}.callableBound", source)
        self.assertNotIn("callableBound := by simp", source)

    def test_malformed_or_incomplete_inputs_fail_closed(self) -> None:
        malformed = (
            _spec(imports=()),
            _spec(imports=("Fixture",)),
            _spec(source_artifacts=()),
            _spec(source_artifacts=("StageA.Fixture.one", "StageA.Fixture.one")),
            _spec(world_program="program; axiom injected : False"),
            _spec(profile_identifier=""),
            _spec(callable_external="StageA.Fixture.callable"),
            _spec(callable_bound="StageA.Fixture.bound"),
            _spec(output_module="../Escape"),
            _spec(
                output_module="GeneratedSameAuthority",
                audit_output_module="GeneratedSameAuthority",
            ),
            _spec(project_name="exactNativeSourceCompilation"),
            _spec(
                project_nix=dataclasses.replace(
                    _nix("project"), nar_hash="not-an-sri-hash"
                )
            ),
        )
        for spec in malformed:
            with self.subTest(spec=spec):
                with self.assertRaises(NativeSourceCompiledAuthorityGenerationError):
                    native_source_compiled_authority_source(spec)

    def test_audit_is_separate_and_complete(self) -> None:
        source = native_source_compiled_authority_axiom_audit_source(_spec())

        self.assertEqual(
            source.count("#print axioms "),
            7,
            source,
        )
        self.assertTrue(
            source.startswith(
                "import StageA.GeneratedNativeSourceCompiledAuthority\n\n"
            )
        )
        self.assertIn(
            ".exactNativeSourceCompilation", source
        )

    def test_writer_is_byte_reproducible(self) -> None:
        spec = _spec(
            output_module="GeneratedAlternateNativeSourceAuthority",
            audit_output_module="GeneratedAlternateNativeSourceAuthorityAudit",
        )
        expected = (
            native_source_compiled_authority_source(spec).encode("ascii"),
            native_source_compiled_authority_axiom_audit_source(spec).encode(
                "ascii"
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            first = write_native_source_compiled_authority(temporary, spec)
            first_bytes = tuple(path.read_bytes() for path in first)
            second = write_native_source_compiled_authority(temporary, spec)
            second_bytes = tuple(path.read_bytes() for path in second)

        self.assertEqual(first_bytes, expected)
        self.assertEqual(second_bytes, expected)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_authority_elaborates_against_current_kernel(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(source_root, stage_a, "RelationalNativeSource")
            (stage_a / "NativeSourceCompiledAuthorityFixture.lean").write_text(
                _LEAN_FIXTURE,
                encoding="ascii",
            )
            write_native_source_compiled_authority(root, _spec())
            authority = _run_lean_relational(
                root,
                bundle=NATIVE_SOURCE_COMPILED_AUTHORITY_MODULE,
            )
            audit = _run_lean_relational(
                root,
                bundle=NATIVE_SOURCE_COMPILED_AUTHORITY_AUDIT_MODULE,
            )

        # Provider axioms exercise the imported exact-fact interface.  The
        # generated modules themselves contain no unchecked declarations.
        self.assertEqual(authority["status"], "unchecked_marker", authority)
        self.assertEqual(audit["status"], "unchecked_marker", audit)
        output = (
            authority["stdout"]
            + authority["stderr"]
            + audit["stdout"]
            + audit["stderr"]
        )
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertNotIn("GeneratedNativeSourceCompiledAuthority.lean:", output)
        self.assertNotIn(
            "GeneratedNativeSourceCompiledAuthorityAudit.lean:", output
        )
        self.assertIn("exactNativeSourceCompilation", output)


_LEAN_FIXTURE = r'''import StageA.RelationalNativeSource

namespace StageA.NativeSourceCompiledAuthorityFixture

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.NativeSource

axiom worldProgram : DecodedWorldProgram
axiom checkedInput : CheckedNativeProgramInput worldProgram
axiom checkedInputNonempty :
  0 < checkedInput.ir.records.length + checkedInput.ir.x87Witnesses.length

axiom bundleArtifact : ExactSourceArtifact
axiom rendererInputArtifact : ExactSourceArtifact
axiom sourceArtifactA : ExactSourceArtifact
axiom sourceArtifactB : ExactSourceArtifact
axiom sourceRolesNodup :
  ([sourceArtifactA.identity, sourceArtifactB.identity].map
    (fun identity => identity.role)).Nodup
axiom toolArtifact : ExactSourceArtifact

axiom compiledIdentity : ArtifactIdentity
axiom compiledIdentityValid : compiledIdentity.Valid
axiom compiledBytes : ByteTree
axiom compiledPe : PE32
axiom compiledByteLengthExact :
  compiledIdentity.byteLength = compiledBytes.length
axiom compiledPeParsedExact : parsePE32Tree compiledBytes = some compiledPe
axiom compiledPeBytesExact : compiledPe.bytes = compiledBytes

axiom importCertificate : ImportTableCertificate
axiom importsParsed : importTableValid compiledPe importCertificate = true
axiom relocations : List BaseRelocation
axiom relocationsParsed : parseRelocations compiledPe = some relocations
axiom loaderImageValid : preferredBaseLoaderImageValid compiledPe = true
axiom environment : NativeWorldEnvironment
axiom indirectTargets : NativeIndirectTargetInventory
axiom indirectTargetsValid : indirectTargets.valid compiledPe = true

axiom callableExternal : NativeCallableExternalConfig
axiom callableBound : callableExternal.BoundTo compiledPe importCertificate.imports

end StageA.NativeSourceCompiledAuthorityFixture
'''


if __name__ == "__main__":
    unittest.main()
