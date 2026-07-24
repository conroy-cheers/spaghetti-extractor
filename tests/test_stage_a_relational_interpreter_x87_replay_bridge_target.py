from __future__ import annotations

import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

import pefile

from spaghetti_extractor.relational.lean.interpreter_x87_replay_bridge_target import (
    X87_REPLAY_BRIDGE_RELOCATION_DATA_MODULE,
    X87_REPLAY_BRIDGE_TARGET_LEAN_BUNDLE,
    X87_REPLAY_BRIDGE_TARGET_PACK_PREFIX,
    build_x87_replay_bridge_target_plan,
    x87_replay_bridge_target_lean_sources,
)
from spaghetti_extractor.util import sha256_file


_CANDIDATE_ROOT = Path(
    "/nix/store/hwabmhf3h9ps6gcsxnji81pisdij1lg9-stage-b-gnu-hello-roundtrip-candidate"
)
_CANDIDATE = _CANDIDATE_ROOT / "candidate.exe"
_MANIFEST = _CANDIDATE_ROOT / "interpreter-native-build-manifest.json"
_ENGINE_PLAN = Path(
    "/nix/store/1g0649s09cyqwbj5fdx81v0vq79dcic8-"
    "stage-b-gnu-hello-roundtrip-native-engine/native-engine-plan.json"
)
_EXPECTED_SHA256 = "953a4e7ea653785dd89d74fa629dc8941657cf1b40faabdb475ccc7740ae6362"
_CALL_SITE_RVA = 0x48F20
_TABLE_RVA = 0x55E80


@unittest.skipUnless(
    _CANDIDATE.is_file() and _MANIFEST.is_file() and _ENGINE_PLAN.is_file(),
    "authoritative GNU hello round-trip candidate is not in the Nix store",
)
class StageAX87ReplayBridgeTargetGenerationTests(unittest.TestCase):
    def _build(
        self,
        *,
        candidate: Path = _CANDIDATE,
        manifest: Path = _MANIFEST,
        call_site_rva: int | None = _CALL_SITE_RVA,
    ):
        return build_x87_replay_bridge_target_plan(
            candidate_pe=candidate,
            build_manifest=manifest,
            native_engine_plan=_ENGINE_PLAN,
            call_site_rva=call_site_rva,
        )

    def _mutable_copy(self) -> tuple[Path, Path]:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        candidate = root / "candidate.exe"
        manifest = root / "interpreter-native-build-manifest.json"
        shutil.copyfile(_CANDIDATE, candidate)
        shutil.copyfile(_MANIFEST, manifest)
        return candidate, manifest

    def _rebind_manifest(self, candidate: Path, manifest: Path) -> None:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        payload["outputs"]["candidate"]["sha256"] = sha256_file(candidate)
        payload["outputs"]["candidate"]["size"] = candidate.stat().st_size
        manifest.write_text(json.dumps(payload), encoding="utf-8")

    def test_authoritative_candidate_has_exact_finite_inventory(self) -> None:
        self.assertEqual(sha256_file(_CANDIDATE), _EXPECTED_SHA256)
        plan = self._build()

        self.assertTrue(plan.evidence_ready, plan.issues)
        self.assertEqual(plan.candidate_sha256, _EXPECTED_SHA256)
        self.assertIsNotNone(plan.table)
        assert plan.table is not None
        self.assertEqual(plan.table.call_site_rva, _CALL_SITE_RVA)
        self.assertEqual(plan.table.call_instruction_bytes, b"\xff\xd0")
        self.assertEqual(plan.table.continuation_rva, 0x48F22)
        self.assertEqual(plan.table.table_rva, _TABLE_RVA)
        self.assertEqual(len(plan.table.descriptors), 313)
        self.assertEqual(plan.table.active_frame_pointer_rva, 0x974008)
        self.assertEqual(plan.table.active_frame_store_operand_rva, 0x48F16)
        self.assertEqual(plan.table.active_frame_load_operand_rva, 0x48F24)
        self.assertEqual(plan.table.descriptors[0].bridge_target_rva, 0x354D2)
        self.assertEqual(plan.table.descriptors[-1].bridge_target_rva, 0x48312)
        self.assertEqual(len(plan.table.frame_mappings), 313)
        self.assertEqual(plan.table.frame_mappings[0].descriptor_id, 0)
        self.assertEqual(plan.table.frame_mappings[0].instruction_rva, 0x4D000)
        self.assertEqual(plan.table.frame_mappings[0].capture_rva, 0x35514)
        self.assertEqual(plan.table.frame_mappings[0].return_rva, 0x355C9)
        self.assertEqual(
            plan.table.frame_mappings[-1].descriptor_id,
            plan.table.descriptors[-1].id,
        )
        self.assertEqual(
            len({row.bridge_target_rva for row in plan.table.descriptors}),
            313,
        )
        payload = plan.payload()
        self.assertEqual(payload["status"], "evidence_ready")
        self.assertFalse(payload["acceptance_authority"])
        self.assertTrue(
            all(
                row["status"].startswith("pending_lean")
                for row in payload["proof_obligations"]
            )
        )

    def test_changed_call_rva_fails_closed_and_reports_current_match(self) -> None:
        plan = self._build(call_site_rva=_CALL_SITE_RVA + 1)

        self.assertFalse(plan.evidence_ready)
        self.assertEqual(plan.issues[0].code, "x87_replay_call_site_changed")
        self.assertIn("0x48f20", plan.issues[0].message)
        self.assertEqual(plan.payload()["status"], "incomplete")

    def test_unique_call_path_is_discovered_without_a_pinned_rva(self) -> None:
        plan = self._build(call_site_rva=None)

        self.assertTrue(plan.evidence_ready, plan.issues)
        self.assertIsNone(plan.requested_call_site_rva)
        self.assertIsNotNone(plan.table)
        assert plan.table is not None
        self.assertEqual(plan.table.call_site_rva, _CALL_SITE_RVA)
        self.assertEqual(plan.payload()["table"]["call_site_rva"], _CALL_SITE_RVA)

    def test_candidate_manifest_mismatch_fails_before_static_evidence(self) -> None:
        candidate, manifest = self._mutable_copy()
        data = bytearray(candidate.read_bytes())
        parsed = pefile.PE(data=data)
        try:
            offset = parsed.get_offset_from_rva(_CALL_SITE_RVA)
        finally:
            parsed.close()
        data[offset] ^= 1
        candidate.write_bytes(data)

        plan = self._build(candidate=candidate, manifest=manifest)

        self.assertEqual(plan.issues[0].code, "candidate_manifest_mismatch")
        self.assertIsNone(plan.table)

    def test_changed_call_bytes_fail_closed_after_manifest_rebinding(self) -> None:
        candidate, manifest = self._mutable_copy()
        data = bytearray(candidate.read_bytes())
        parsed = pefile.PE(data=data)
        try:
            offset = parsed.get_offset_from_rva(_CALL_SITE_RVA)
        finally:
            parsed.close()
        data[offset : offset + 2] = b"\x90\x90"
        candidate.write_bytes(data)
        self._rebind_manifest(candidate, manifest)

        plan = self._build(candidate=candidate, manifest=manifest)

        self.assertEqual(plan.issues[0].code, "x87_replay_call_site_changed")
        self.assertEqual(plan.issues[0].rva, _CALL_SITE_RVA)

    def test_missing_function_pointer_relocation_is_incomplete(self) -> None:
        candidate, manifest = self._mutable_copy()
        data = bytearray(candidate.read_bytes())
        parsed = pefile.PE(data=data)
        try:
            target_cell = _TABLE_RVA + 32
            entries = [
                entry
                for block in parsed.DIRECTORY_ENTRY_BASERELOC
                for entry in block.entries
                if entry.rva == target_cell and entry.type == 3
            ]
            self.assertEqual(len(entries), 1)
            entry_offset = entries[0].struct.get_file_offset()
            raw = struct.unpack_from("<H", data, entry_offset)[0]
            struct.pack_into("<H", data, entry_offset, raw & 0x0FFF)
        finally:
            parsed.close()
        candidate.write_bytes(data)
        self._rebind_manifest(candidate, manifest)

        plan = self._build(candidate=candidate, manifest=manifest)

        self.assertEqual(plan.issues[0].code, "x87_pointer_relocation_not_unique")
        self.assertEqual(plan.issues[0].rva, target_cell)

    def test_writable_descriptor_table_is_incomplete(self) -> None:
        candidate, manifest = self._mutable_copy()
        data = bytearray(candidate.read_bytes())
        parsed = pefile.PE(data=data)
        try:
            sections = [
                section
                for section in parsed.sections
                if section.VirtualAddress
                <= _TABLE_RVA
                < section.VirtualAddress
                + max(section.Misc_VirtualSize, section.SizeOfRawData)
            ]
            self.assertEqual(len(sections), 1)
            characteristics_offset = sections[0].get_file_offset() + 36
            characteristics = struct.unpack_from("<I", data, characteristics_offset)[0]
            struct.pack_into(
                "<I",
                data,
                characteristics_offset,
                characteristics | 0x80000000,
            )
        finally:
            parsed.close()
        candidate.write_bytes(data)
        self._rebind_manifest(candidate, manifest)

        plan = self._build(candidate=candidate, manifest=manifest)

        self.assertEqual(plan.issues[0].code, "mutable_x87_descriptor_table")
        self.assertEqual(plan.issues[0].rva, _TABLE_RVA)

    def test_duplicate_bridge_target_is_incomplete(self) -> None:
        candidate, manifest = self._mutable_copy()
        data = bytearray(candidate.read_bytes())
        parsed = pefile.PE(data=data)
        try:
            first_offset = parsed.get_offset_from_rva(_TABLE_RVA + 32)
            second_offset = parsed.get_offset_from_rva(_TABLE_RVA + 36 + 32)
            data[second_offset : second_offset + 4] = data[
                first_offset : first_offset + 4
            ]
        finally:
            parsed.close()
        candidate.write_bytes(data)
        self._rebind_manifest(candidate, manifest)

        plan = self._build(candidate=candidate, manifest=manifest)

        self.assertEqual(plan.issues[0].code, "ambiguous_x87_bridge_targets")

    def test_unknown_bridge_target_is_incomplete(self) -> None:
        candidate, manifest = self._mutable_copy()
        data = bytearray(candidate.read_bytes())
        parsed = pefile.PE(data=data)
        try:
            pointer_offset = parsed.get_offset_from_rva(_TABLE_RVA + 32)
            struct.pack_into("<I", data, pointer_offset, 0xDEADBEEF)
        finally:
            parsed.close()
        candidate.write_bytes(data)
        self._rebind_manifest(candidate, manifest)

        plan = self._build(candidate=candidate, manifest=manifest)

        self.assertEqual(plan.issues[0].code, "x87_pointer_outside_image")

    def test_changed_dynamic_frame_mapping_fails_closed(self) -> None:
        candidate, manifest = self._mutable_copy()
        data = bytearray(candidate.read_bytes())
        parsed = pefile.PE(data=data)
        try:
            offset = parsed.get_offset_from_rva(0x354D2 + 15)
        finally:
            parsed.close()
        data[offset] = 0x10
        candidate.write_bytes(data)
        self._rebind_manifest(candidate, manifest)

        plan = self._build(candidate=candidate, manifest=manifest)

        self.assertFalse(plan.evidence_ready)
        self.assertEqual(
            plan.issues[0].code,
            "x87_bridge_dynamic_frame_mapping_unproved",
        )
        self.assertEqual(plan.issues[0].rva, 0x354D2 + 13)

    def test_generated_modules_export_checks_and_dynamic_goal_only(self) -> None:
        plan = self._build()
        sources = x87_replay_bridge_target_lean_sources(plan, pack_size=32)
        bundle = sources[f"{X87_REPLAY_BRIDGE_TARGET_LEAN_BUNDLE}.lean"]
        first_pack = sources[f"{X87_REPLAY_BRIDGE_TARGET_PACK_PREFIX}0000.lean"]

        self.assertEqual(len(sources), 11)
        self.assertIn(
            f"import StageA.{X87_REPLAY_BRIDGE_RELOCATION_DATA_MODULE}",
            first_pack,
        )
        self.assertIn("set_option autoImplicit false", first_pack)
        self.assertIn("generatedX87ReplayBridgeStaticCertificate", bundle)
        self.assertIn("generatedX87ReplayBridgeNativeTargetInventory", bundle)
        self.assertIn("generatedX87ReplayBridgeTargetInventory", bundle)
        self.assertIn("generatedX87ReplayBridgeTargetBinding0000", bundle)
        self.assertIn("generatedX87ReplayBridgeTargetBinding0312", bundle)
        self.assertIn("generatedX87ReplayBridgeTargetBinding0312RuntimeGoal", bundle)
        self.assertIn(_EXPECTED_SHA256, bundle)
        self.assertIn("GeneratedX87ReplayBridgeExecutionGoal", bundle)
        self.assertIn("GeneratedX87ReplayBridgeTargetRuntimeGoal", bundle)
        self.assertIn("generatedInterpreterKernelRelocationsParsed", bundle)
        self.assertNotIn("acceptance", bundle.lower())
        runtime_obligation = plan.payload()["proof_obligations"][1]
        self.assertEqual(
            runtime_obligation["requirements"],
            [
                "selected_descriptor_membership",
                "target_cell_holds_before_call",
                "target_cell_holds_after_return",
            ],
        )


if __name__ == "__main__":
    unittest.main()
