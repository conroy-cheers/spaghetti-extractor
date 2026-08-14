"""Tests for the Stage A source-to-native-v3 ingestion boundary."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_image
from spaghetti_extractor.authority_inputs.external_inputs import (
    adapt_external_inputs_v3,
)
from spaghetti_extractor.authority.external_site_records import (
    EXTERNAL_PROFILE_CODEC_V3,
)
from spaghetti_extractor.authority.root_closure import (
    LAUNCH_ROOT_EVIDENCE_CODEC_V3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactSetReaderV3,
    canonical_json_bytes_v3,
)


def _unit(
    unit_id: str = "unit:entry",
    *,
    instruction_digest: str,
) -> dict[str, object]:
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": unit_id,
        "status": "qualified",
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1001},
            "instruction_bytes_sha256": instruction_digest,
        },
        "expression_model": "stage-a-semantic-ir-v1",
        "instructions": [],
        "semantics": {
            "pre_state": {
                "registers": {},
                "flags": {},
                "memory": {
                    "op": "memory",
                    "name": "mem0",
                    "address_width": 32,
                    "value_width": 8,
                },
            },
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": [],
            "faults": [],
            "ordered_events": [],
            "edge_conditions": [],
            "outcome": {"kind": "return"},
            "stack_delta": None,
            "counts": {
                "register_writes": 0,
                "flag_writes": 0,
                "memory_events": 0,
                "external_events": 0,
                "faults": 0,
                "ordered_events": 0,
                "edge_conditions": 0,
            },
        },
        "control": {
            "kind": "return",
            "direct_targets": [],
            "has_indirect_target": False,
        },
    }


def _profile(*, variadic: bool = False) -> dict[str, object]:
    arity: dict[str, object] = (
        {"kind": "variadic", "minimum_words": 1}
        if variadic
        else {"kind": "fixed", "words": 1}
    )
    return {
        "format": "stage-a-static-machine-import-profile-v1",
        "id": "fixture-profile",
        "default_callback_effect": "none",
        "machine_import_signatures": [
            {
                "id": "fixture.dll!Exact",
                "import": {"dll": "Fixture.DLL", "symbol": "Exact"},
                "abi_template": "pe32-stdcall-v1",
                "arity": arity,
                "disposition": "returns",
                "result_register_relations": [
                    {"register": "eax", "relation": "exact"}
                ],
                "memory_effect": "none",
                "memory_footprints": [],
                "world_effect": "none",
                "out_pointer_relations": [],
                "out_interface_relations": [],
            }
        ],
    }


def _launch_template() -> dict[str, object]:
    return {
        "format": "spaghetti-extractor-pe32-launch-assumption-template-v1",
        "schema_version": 1,
        "assumptions": {
            "initial_stack": {"contract": "fixture-stack-v1"},
            "argv": {"contract": "fixture-argv-v1"},
            "environment": {"contract": "fixture-environment-v1"},
            "fs": {"contract": "fixture-fs-v1"},
            "iat": {"contract": "fixture-iat-v1"},
            "relocations": {"contract": "fixture-relocations-v1"},
        },
        "feature_inventory": {
            "threads": [],
            "unmodelled_seh": [],
            "direct_syscalls": [],
            "executable_writes": [],
            "unknown_async_callbacks": [],
        },
    }


class ExternalInputsV3Tests(unittest.TestCase):
    def _sources(
        self,
        root: Path,
        *,
        units: list[dict[str, object]] | None = None,
        profile: dict[str, object] | None = None,
        with_template: bool = True,
    ) -> tuple[Path, Path, Path, Path | None]:
        import hashlib

        binary = root / "fixture.exe"
        binary.write_bytes(pe32_image(b"\xc3"))
        machine_ir = root / "machine-ir.jsonl"
        rows = units or [
            _unit(instruction_digest=hashlib.sha256(b"\xc3").hexdigest())
        ]
        machine_ir.write_bytes(
            b"".join(canonical_json_bytes_v3(row) + b"\n" for row in rows)
        )
        profile_path = root / "profile.json"
        profile_path.write_text(
            json.dumps(profile or _profile(), sort_keys=True), encoding="utf-8"
        )
        template = None
        if with_template:
            template = root / "launch.json"
            template.write_text(
                json.dumps(_launch_template(), sort_keys=True), encoding="utf-8"
            )
        return binary, machine_ir, profile_path, template

    def _adapt(
        self,
        root: Path,
        *,
        units: list[dict[str, object]] | None = None,
        profile: dict[str, object] | None = None,
        with_template: bool = True,
        output_name: str = "out",
    ) -> tuple[dict[str, object], Path]:
        binary, machine_ir, profile_path, template = self._sources(
            root,
            units=units,
            profile=profile,
            with_template=with_template,
        )
        output = root / output_name
        metadata = adapt_external_inputs_v3(
            binary=binary,
            machine_ir=machine_ir,
            binary_identity="fixture.exe",
            profile_paths=(profile_path,),
            launch_template=template,
            output_directory=output,
        )
        return metadata, output

    def test_exact_profile_and_launch_root_are_native_v3_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata, output = self._adapt(root)
            profiles = ArtifactSetReaderV3(output / "external-profiles")
            roots = ArtifactSetReaderV3(output / "launch-roots")
            self.assertEqual(profiles.manifest.status, "complete")
            self.assertEqual(roots.manifest.status, "complete")
            profile = EXTERNAL_PROFILE_CODEC_V3.read(
                next(profiles.iter_records())
            ).value
            self.assertEqual(
                profile.identity.to_value(),
                {
                    "kind": "import",
                    "dll": "fixture.dll",
                    "symbol": "Exact",
                    "ordinal": None,
                },
            )
            self.assertEqual(profile.argument_words, 1)
            launch = LAUNCH_ROOT_EVIDENCE_CODEC_V3.read(
                next(roots.iter_records())
            ).value
            self.assertEqual(launch.root_kind, "pe_entrypoint")
            self.assertEqual(launch.unit_id, "unit:entry")
            self.assertEqual(launch.status, "complete")
            self.assertIsNotNone(launch.entry_state)
            self.assertEqual(
                metadata["external_profiles"]["coverage_status"], "complete"  # type: ignore[index]
            )
            self.assertTrue(
                any(binding.kind == "machine-import-profile" for binding in profiles.manifest.bindings)
            )

    def test_unsupported_variadic_entry_is_absent_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            metadata, output = self._adapt(
                Path(temporary), profile=_profile(variadic=True)
            )
            profiles = ArtifactSetReaderV3(output / "external-profiles")
            self.assertEqual(profiles.manifest.status, "complete")
            self.assertEqual(tuple(profiles.iter_records()), ())
            family = metadata["external_profiles"]  # type: ignore[index]
            self.assertEqual(family["coverage_status"], "incomplete")
            self.assertEqual(
                family["issues"][0]["code"], "external_profile_arity_not_exact"
            )

    def test_copied_profile_authority_status_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = _profile()
            profile["status"] = "complete"
            metadata, output = self._adapt(Path(temporary), profile=profile)
            profiles = ArtifactSetReaderV3(output / "external-profiles")
            self.assertEqual(profiles.manifest.status, "violated")
            self.assertEqual(tuple(profiles.iter_records()), ())
            self.assertEqual(
                metadata["external_profiles"]["issues"][0]["code"],  # type: ignore[index]
                "external_profile_source_violated",
            )

    def test_missing_launch_template_preserves_root_as_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _metadata, output = self._adapt(
                Path(temporary), with_template=False
            )
            roots = ArtifactSetReaderV3(output / "launch-roots")
            self.assertEqual(roots.manifest.status, "incomplete")
            root = LAUNCH_ROOT_EVIDENCE_CODEC_V3.read(
                next(roots.iter_records())
            ).value
            self.assertEqual(root.status, "incomplete")
            self.assertIsNone(root.entry_state)
            self.assertEqual(
                root.primary_blocker.code, "launch_assumption_profile_missing"  # type: ignore[union-attr]
            )

    def test_root_unit_byte_contradiction_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            units = [_unit(instruction_digest="0" * 64)]
            metadata, output = self._adapt(Path(temporary), units=units)
            roots = ArtifactSetReaderV3(output / "launch-roots")
            self.assertEqual(roots.manifest.status, "violated")
            root = LAUNCH_ROOT_EVIDENCE_CODEC_V3.read(
                next(roots.iter_records())
            ).value
            self.assertEqual(root.status, "violated")
            self.assertEqual(
                metadata["launch_roots"]["issues"][0]["code"],  # type: ignore[index]
                "launch_root_unit_bytes_contradiction",
            )

    def test_ambiguous_root_unit_inventory_is_violated(self) -> None:
        import hashlib

        with tempfile.TemporaryDirectory() as temporary:
            digest = hashlib.sha256(b"\xc3").hexdigest()
            units = [
                _unit("unit:first", instruction_digest=digest),
                _unit("unit:second", instruction_digest=digest),
            ]
            metadata, output = self._adapt(Path(temporary), units=units)
            roots = ArtifactSetReaderV3(output / "launch-roots")
            self.assertEqual(roots.manifest.status, "violated")
            self.assertEqual(tuple(roots.iter_records()), ())
            self.assertEqual(
                metadata["launch_roots"]["issues"][0]["code"],  # type: ignore[index]
                "launch_root_unit_ambiguous",
            )

    def test_repeated_adaptation_has_identical_artifact_identities(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary, machine_ir, profile, template = self._sources(root)
            results = []
            for name in ("first", "second"):
                output = root / name
                metadata = adapt_external_inputs_v3(
                    binary=binary,
                    machine_ir=machine_ir,
                    binary_identity="fixture.exe",
                    profile_paths=(profile,),
                    launch_template=template,
                    output_directory=output,
                )
                results.append(metadata)
            self.assertEqual(results[0], results[1])


if __name__ == "__main__":
    unittest.main()
