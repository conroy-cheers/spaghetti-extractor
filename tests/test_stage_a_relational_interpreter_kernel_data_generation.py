from __future__ import annotations

import json
import re
import shutil
import struct
import sys
import tempfile
import types
import unittest
from pathlib import Path

import pefile

if "tests" not in sys.modules:
    tests_package = types.ModuleType("tests")
    tests_package.__path__ = [str(Path(__file__).parent)]
    sys.modules["tests"] = tests_package

from tests.test_stage_b_interpreter_native_build import _Packages

from spaghetti_extractor.relational.lean.interpreter_kernel_data import (
    INTERPRETER_KERNEL_DATA_AUTHORITY,
    INTERPRETER_KERNEL_DATA_AUTHORITY_PACK_PREFIX,
    INTERPRETER_KERNEL_DATA_BASE,
    INTERPRETER_KERNEL_DATA_BUNDLE,
    INTERPRETER_KERNEL_DATA_BYTE_PACK_PREFIX,
    INTERPRETER_KERNEL_DATA_BYTE_PACK_SIZE,
    INTERPRETER_KERNEL_DATA_CANDIDATE_AUTHORITY,
    INTERPRETER_KERNEL_DATA_CERTIFICATE_PACK_PREFIX,
    INTERPRETER_KERNEL_DATA_CERTIFICATE_PACK_SIZE,
    INTERPRETER_KERNEL_DATA_FORMAT,
    INTERPRETER_KERNEL_DATA_LOCAL_CONTEXT,
    INTERPRETER_KERNEL_DATA_RELOCATION_BUNDLE,
    INTERPRETER_KERNEL_DATA_RELOCATION_CHAIN_PACK_SIZE,
    INTERPRETER_KERNEL_DATA_RELOCATION_PACK_SIZE,
    INTERPRETER_KERNEL_DATA_SHARD_FACADE_PREFIX,
    InterpreterKernelDataGenerationError,
    generate_interpreter_kernel_data_bundle,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.stage_b_interpreter_native_build import (
    build_stage_b_interpreter_native_candidate,
)
from spaghetti_extractor.util import sha256_bytes


class StageARelationalInterpreterKernelDataArchitectureTests(unittest.TestCase):
    def test_default_byte_pack_count_keeps_pe_literal_leaves_bounded(self) -> None:
        candidate_size = 10 * 1024 * 1024

        self.assertEqual(
            (candidate_size + INTERPRETER_KERNEL_DATA_BYTE_PACK_SIZE - 1)
            // INTERPRETER_KERNEL_DATA_BYTE_PACK_SIZE,
            160,
        )

    def test_default_relocation_pack_size_keeps_literals_bounded(self) -> None:
        self.assertEqual(INTERPRETER_KERNEL_DATA_RELOCATION_PACK_SIZE, 512)

    def test_default_certificate_pack_count_stays_below_derivation_budget(self) -> None:
        self.assertEqual(INTERPRETER_KERNEL_DATA_CERTIFICATE_PACK_SIZE, 16)
        self.assertEqual(
            (5326 + INTERPRETER_KERNEL_DATA_CERTIFICATE_PACK_SIZE - 1)
            // INTERPRETER_KERNEL_DATA_CERTIFICATE_PACK_SIZE,
            333,
        )


@unittest.skipUnless(
    shutil.which("i686-w64-mingw32-gcc"), "i686 MinGW compiler unavailable"
)
class StageARelationalInterpreterKernelDataGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.packages = _Packages(self.root / "inputs")
        self.candidate = self.root / "candidate"
        build_stage_b_interpreter_native_candidate(
            interpreter_package=self.packages.interpreter,
            native_engine_package=self.packages.engine,
            native_runtime_package=self.packages.runtime,
            load_image_contract=self.packages.contract,
            anchor_manifest=self.packages.anchors,
            out_dir=self.candidate,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _generate(self, destination: Path, *, candidate: Path | None = None):
        return generate_interpreter_kernel_data_bundle(
            candidate_pe=candidate or self.candidate / "candidate.exe",
            linker_map=self.candidate / "payload.map",
            state_machine=self.packages.root / "state-machine.jsonl",
            out_dir=destination,
            shard_size=1,
            byte_pack_size=32 * 1024,
        )

    def test_real_candidate_generates_deterministic_packed_proof_graph(self) -> None:
        first = self.root / "first"
        second = self.root / "second"
        first_inventory = self._generate(first)
        second_inventory = self._generate(second)

        self.assertEqual(first_inventory.payload(), second_inventory.payload())
        self.assertEqual(first_inventory.payload()["format"], INTERPRETER_KERNEL_DATA_FORMAT)
        self.assertEqual(first_inventory.transfer_count, 1)
        self.assertEqual(first_inventory.transfer_shard_count, 1)
        self.assertEqual(first_inventory.certificate_pack_count, 1)
        self.assertEqual(first_inventory.authority_pack_count, 1)
        self.assertEqual(first_inventory.pointer_field_count, 5)
        self.assertEqual(first_inventory.descriptor_count, 1)
        self.assertEqual(first_inventory.component_count, 5)
        self.assertEqual(first_inventory.record_count, 1)

        candidate_bytes = (self.candidate / "candidate.exe").read_bytes()
        expected_byte_packs = (
            len(candidate_bytes) + 32 * 1024 - 1
        ) // (32 * 1024)
        self.assertEqual(first_inventory.byte_pack_count, expected_byte_packs)
        self.assertEqual(
            first_inventory.payload()["candidate_sha256"], sha256_bytes(candidate_bytes)
        )
        self.assertEqual(
            json.loads((first / "module-inventory.json").read_text()),
            first_inventory.payload(),
        )

        rows = {row["name"]: row for row in first_inventory.modules}
        roles = [row["role"] for row in first_inventory.modules]
        self.assertEqual(roles.count("transfer-certificate-pack"), 1)
        self.assertEqual(roles.count("candidate-data-authority-pack"), 1)
        self.assertEqual(roles.count("candidate-data-shard-facade"), 1)
        self.assertNotIn("pointer-relocation-field", roles)
        self.assertNotIn("transfer-descriptor", roles)
        self.assertNotIn("transfer-component", roles)
        self.assertNotIn("transfer-record-composition", roles)
        self.assertNotIn("transfer-table-shard", roles)

        standalone = json.loads((first / "standalone-modules.json").read_text())
        self.assertEqual(
            standalone,
            json.loads((second / "standalone-modules.json").read_text()),
        )
        self.assertIn("RelationalFiniteIndex", standalone)
        self.assertIn("RelationalPEBytePacks", standalone)
        self.assertEqual(first_inventory.standalone_module_count, len(standalone))
        self.assertLess(len(standalone), 100)

        byte_pack_names = [
            name
            for name, row in rows.items()
            if row["role"] == "candidate-byte-pack"
        ]
        offset = 0
        for name in byte_pack_names:
            row = rows[name]
            size = row["candidate_bytes"]
            self.assertEqual(row["imports"], ["Formal"])
            self.assertEqual(row["candidate_offset"], offset)
            self.assertEqual(
                row["candidate_sha256"],
                sha256_bytes(candidate_bytes[offset : offset + size]),
            )
            self.assertEqual(row["resource_class"], "medium")
            self.assertEqual(row["estimated_memory_mb"], 4096)
            offset += size
        self.assertEqual(offset, len(candidate_bytes))

        base_row = rows[INTERPRETER_KERNEL_DATA_BASE]
        self.assertEqual(
            base_row["imports"], [INTERPRETER_KERNEL_DATA_LOCAL_CONTEXT, *byte_pack_names]
        )
        self.assertEqual(base_row["resource_class"], "high-memory")
        self.assertEqual(base_row["estimated_memory_mb"], 12288)
        base = (first / f"StageA/{INTERPRETER_KERNEL_DATA_BASE}.lean").read_text()
        self.assertIn("ByteTreePackAt", base)
        self.assertIn("PEBytePackCertificate", base)

        candidate_authority_row = rows[
            INTERPRETER_KERNEL_DATA_CANDIDATE_AUTHORITY
        ]
        candidate_authority = (
            first
            / f"StageA/{INTERPRETER_KERNEL_DATA_CANDIDATE_AUTHORITY}.lean"
        ).read_text()
        self.assertEqual(
            candidate_authority_row["imports"],
            [INTERPRETER_KERNEL_DATA_BASE],
        )
        self.assertEqual(
            candidate_authority_row["role"],
            "candidate-pe-authority-facade",
        )
        self.assertEqual(
            first_inventory.payload()["candidate_authority"],
            {
                "module": INTERPRETER_KERNEL_DATA_CANDIDATE_AUTHORITY,
                "namespace": (
                    "StageA.GeneratedRelational.CandidatePEAuthority"
                ),
                "exports": [
                    "candidateBytes",
                    "candidatePe",
                    "importCertificate",
                    "imports",
                    "candidateMetadataParsed",
                    "candidateParsed",
                    "importsChecked",
                    "candidateDataLayout",
                    "candidateDataLayoutExact",
                    "candidateBytePackCatalog",
                    "candidateBytePackCatalogChecked",
                ],
            },
        )
        self.assertIn(
            "namespace StageA.GeneratedRelational.CandidatePEAuthority",
            candidate_authority,
        )
        self.assertIn("abbrev candidateBytes", candidate_authority)
        self.assertIn("abbrev candidatePe", candidate_authority)
        self.assertIn("theorem candidateParsed", candidate_authority)
        self.assertIn("theorem importsChecked", candidate_authority)
        self.assertNotIn("_lean_pe", candidate_authority)

        relocation_bundle = (
            first / f"StageA/{INTERPRETER_KERNEL_DATA_RELOCATION_BUNDLE}.lean"
        ).read_text()
        self.assertIn("RelocationRvaIndexCertificate", relocation_bundle)
        self.assertIn(
            "generatedInterpreterKernelRelocationIndexRangesChecked",
            relocation_bundle,
        )
        self.assertNotIn("relocationQueriesChecked", relocation_bundle)
        self.assertEqual(
            rows[INTERPRETER_KERNEL_DATA_RELOCATION_BUNDLE]["resource_class"],
            "high-memory",
        )

        certificate_name = f"{INTERPRETER_KERNEL_DATA_CERTIFICATE_PACK_PREFIX}0000"
        certificate_row = rows[certificate_name]
        certificate = (first / f"StageA/{certificate_name}.lean").read_text()
        self.assertEqual(
            certificate_row["imports"], [INTERPRETER_KERNEL_DATA_LOCAL_CONTEXT]
        )
        self.assertEqual(certificate_row["transfer_start"], 0)
        self.assertEqual(certificate_row["transfer_count"], 1)
        self.assertEqual(certificate_row["boolean_certificate_count"], 2)
        self.assertEqual(certificate_row["pack_boolean_certificate_count"], 1)
        self.assertEqual(certificate_row["local_decode_certificate_count"], 1)
        self.assertGreater(certificate_row["byte_range_count"], 0)
        self.assertEqual(certificate_row["pointer_field_count"], 5)
        self.assertEqual(certificate_row["resource_class"], "medium")
        self.assertIn("TransferCertificatePack", certificate)
        self.assertIn("entries := (#[", certificate)
        self.assertIn("IndexChecked", certificate)
        self.assertIn("IndexCertificate", certificate)
        self.assertIn("LocalImmutableByteCache", certificate)
        self.assertIn("DescriptorDecoded", certificate)
        self.assertIn("WordNodesDecoded", certificate)
        self.assertIn("X87NodesDecoded", certificate)
        self.assertIn("ActionsDecoded", certificate)
        self.assertIn("CallsDecoded", certificate)
        self.assertIn("X87ReplaysDecoded", certificate)
        self.assertIn(
            "TransferCertificateData.LocalCertificate", certificate
        )
        self.assertNotIn("DecodedTransferCertificateData", certificate)
        self.assertNotIn("decodeTransferAtFrom", certificate)
        self.assertNotIn("decodeManyAux (fun index", certificate)
        self.assertNotIn("PEBytePackSliceChain", certificate)
        self.assertNotIn("generatedInterpreterKernelCandidatePe", certificate)
        self.assertNotIn("generatedInterpreterKernelRelocations", certificate)
        self.assertNotIn("generatedInterpreterKernelRelocationIndexCertificate", certificate)
        self.assertNotIn("QueryOrdinals", certificate)
        self.assertNotIn("relocationFieldPresent", certificate)
        self.assertNotIn("relocationFieldAbsent", certificate)
        self.assertNotIn("relocationQueriesChecked", certificate)
        self.assertIn("rfl", certificate)

        shard_facade_name = f"{INTERPRETER_KERNEL_DATA_SHARD_FACADE_PREFIX}0000"
        shard_facade_row = rows[shard_facade_name]
        shard_facade = (
            first / f"StageA/{shard_facade_name}.lean"
        ).read_text()
        self.assertEqual(
            shard_facade_row["imports"],
            [f"{INTERPRETER_KERNEL_DATA_AUTHORITY_PACK_PREFIX}0000"],
        )
        self.assertEqual(
            shard_facade_row["role"],
            "candidate-data-shard-facade",
        )
        self.assertFalse(shard_facade_row["proof_authority"])
        self.assertIn(
            "generatedInterpreterKernelDataCertificatePack0000CompiledEntries",
            shard_facade,
        )
        self.assertIn(
            "generatedInterpreterKernelDataCertificatePack0000Shard",
            shard_facade,
        )
        self.assertNotIn("transferWordNodesChecked", certificate)
        self.assertNotIn("DescriptorsChecked", certificate)
        self.assertNotIn("decodeProgramTableRangeCertificate", certificate)
        self.assertNotIn("ProgramTableShardCertificate", certificate)
        self.assertNotIn("valueAndRelocationFieldsChecked", certificate)

        bundle = (first / f"StageA/{INTERPRETER_KERNEL_DATA_BUNDLE}.lean").read_text()
        self.assertEqual(
            rows[INTERPRETER_KERNEL_DATA_BUNDLE]["imports"],
            [INTERPRETER_KERNEL_DATA_AUTHORITY],
        )
        self.assertIn("semanticInterpreterProgramRecords", bundle)
        self.assertIn("ProgramTableShardMetadataChain", bundle)
        self.assertIn("generatedInterpreterKernelSourceRvas", bundle)
        self.assertIn("semanticInterpreterProgramSourceRvasExact", bundle)
        self.assertIn(
            "generatedInterpreterKernelShardMetadataChain.coverage", bundle
        )
        self.assertNotRegex(
            bundle,
            r"shardCoverageEnd[\s\S]*:= by\s+decide \+kernel",
        )
        self.assertIn("semanticInterpreterProgramLookupAgreesWithCandidateTable", bundle)
        self.assertIn("semanticInterpreterProgramSourceRvasIncreasing", bundle)
        self.assertIn("strictlyIncreasing_nodup", bundle)
        self.assertIn("generatedInterpreterKernelShardMetadataChain", bundle)
        self.assertIn("semanticInterpreterProgramSourceRvasExact", bundle)
        self.assertIn("generatedInterpreterKernelShardMetadataChain.coverage", bundle)
        self.assertNotIn("sourceRva)).Nodup := by\n  decide +kernel", bundle)

        authority_row = rows[INTERPRETER_KERNEL_DATA_AUTHORITY]
        authority = (
            first / f"StageA/{INTERPRETER_KERNEL_DATA_AUTHORITY}.lean"
        ).read_text()
        authority_pack_name = f"{INTERPRETER_KERNEL_DATA_AUTHORITY_PACK_PREFIX}0000"
        authority_pack_row = rows[authority_pack_name]
        authority_pack = (
            first / f"StageA/{authority_pack_name}.lean"
        ).read_text()
        self.assertEqual(
            authority_row["imports"],
            [authority_pack_name],
        )
        self.assertEqual(authority_row["role"], "candidate-data-global-authority")
        self.assertEqual(authority_row["candidate_sha256"], first_inventory.candidate_sha256)
        self.assertEqual(authority_row["metadata_certificate_count"], 1)
        self.assertIn("generatedInterpreterKernelDataShards", authority)
        self.assertNotIn("decide", authority)
        self.assertEqual(
            authority_pack_row["imports"],
            [INTERPRETER_KERNEL_DATA_RELOCATION_BUNDLE, certificate_name],
        )
        self.assertEqual(
            authority_pack_row["role"], "candidate-data-authority-pack"
        )
        self.assertEqual(authority_pack_row["metadata_certificate_count"], 1)
        self.assertEqual(
            authority_pack_row["source_rva_count"],
            authority_pack_row["transfer_count"],
        )
        self.assertIn("generatedInterpreterKernelCandidateBytePackCatalog", authority_pack)
        self.assertIn("ImmutableRangeBindingPlan", authority_pack)
        self.assertIn("immutableRangeBindingsChecked", authority_pack)
        self.assertNotIn("PEBytePackSliceChain", authority_pack)
        self.assertIn("generatedInterpreterKernelCandidateDataLayoutExact", authority_pack)
        self.assertIn(
            "generatedInterpreterKernelRelocationIndexCertificate", authority_pack
        )
        self.assertIn(".exactCertificate", authority_pack)
        self.assertIn(
            "ProgramTableShardMetadataCertificate", authority_pack
        )
        self.assertIn("SourceRvasExact", authority_pack)

        resources = json.loads((first / "module-resources.json").read_text())
        self.assertEqual(set(resources), set(standalone))
        self.assertEqual(
            resources[certificate_name],
            {"resource_class": "medium", "estimated_memory_mb": 4096},
        )
        self.assertEqual(
            resources[authority_pack_name],
            {"resource_class": "high-memory", "estimated_memory_mb": 12288},
        )
        self.assertLessEqual(
            first_inventory.relocation_chain_count,
            (
                first_inventory.relocation_block_count
                + INTERPRETER_KERNEL_DATA_RELOCATION_CHAIN_PACK_SIZE
                - 1
            )
            // INTERPRETER_KERNEL_DATA_RELOCATION_CHAIN_PACK_SIZE,
        )

        for row in first_inventory.modules:
            source = (first / f"StageA/{row['name']}.lean").read_text()
            self.assertEqual(row["source_sha256"], sha256_bytes(source.encode()))
            for marker in ("sorry", "axiom", "unsafe", "native_decide"):
                self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_candidate_byte_mutation_is_leaf_scoped_and_dependency_bound(self) -> None:
        original = self._generate(self.root / "original")
        candidate = bytearray((self.candidate / "candidate.exe").read_bytes())
        candidate[0x42] ^= 1
        mutated_candidate = self.root / "mutated-padding.exe"
        mutated_candidate.write_bytes(candidate)
        mutated = self._generate(self.root / "mutated", candidate=mutated_candidate)

        original_rows = {row["name"]: row for row in original.modules}
        mutated_rows = {row["name"]: row for row in mutated.modules}
        changed_sources = {
            name
            for name in original_rows
            if original_rows[name]["source_sha256"] != mutated_rows[name]["source_sha256"]
        }
        self.assertEqual(
            changed_sources, {f"{INTERPRETER_KERNEL_DATA_BYTE_PACK_PREFIX}0000"}
        )
        self.assertNotEqual(original.candidate_sha256, mutated.candidate_sha256)
        self.assertIn(
            f"{INTERPRETER_KERNEL_DATA_BYTE_PACK_PREFIX}0000",
            original_rows[INTERPRETER_KERNEL_DATA_BASE]["imports"],
        )
        certificate_name = f"{INTERPRETER_KERNEL_DATA_CERTIFICATE_PACK_PREFIX}0000"
        self.assertEqual(
            original_rows[certificate_name]["imports"],
            [INTERPRETER_KERNEL_DATA_LOCAL_CONTEXT],
        )
        certificate = (
            self.root / "original" / f"StageA/{certificate_name}.lean"
        ).read_text()
        self.assertIn("Entry0000ByteRange0000", certificate)
        self.assertIn("Entry0000WordNodesDecoded", certificate)
        self.assertNotIn("ByteBindingsChecked", certificate)

    def test_packed_authority_and_bundle_compile(self) -> None:
        destination = self.root / "compiled-bundle"
        self._generate(destination)

        result = _run_lean_relational(
            destination, bundle=INTERPRETER_KERNEL_DATA_BUNDLE
        )

        self.assertEqual(result["status"], "checked", result)

    def test_x87_shard_compatibility_facade_compiles(self) -> None:
        destination = self.root / "compiled-shard-facade"
        self._generate(destination)

        result = _run_lean_relational(
            destination,
            bundle=f"{INTERPRETER_KERNEL_DATA_SHARD_FACADE_PREFIX}0000",
        )

        self.assertEqual(result["status"], "checked", result)

    def test_exact_byte_cache_rejects_mutated_expected_record(self) -> None:
        destination = self.root / "mutated-record-proof"
        self._generate(destination)
        certificate_name = f"{INTERPRETER_KERNEL_DATA_CERTIFICATE_PACK_PREFIX}0000"
        certificate_path = destination / f"StageA/{certificate_name}.lean"
        source = certificate_path.read_text()
        marker = "bytes := [1, 0, 0, 0"
        self.assertIn(marker, source)
        certificate_path.write_text(source.replace(marker, "bytes := [2, 0, 0, 0", 1))

        result = _run_lean_relational(
            destination, bundle=INTERPRETER_KERNEL_DATA_BUNDLE
        )

        self.assertEqual(result["status"], "failed", result)
        self.assertIn(
            f"{INTERPRETER_KERNEL_DATA_CERTIFICATE_PACK_PREFIX}0000",
            " ".join(result["failed_command"]),
        )

    def test_relocation_index_rejects_mutated_branch_split(self) -> None:
        destination = self.root / "mutated-relocation-index"
        generate_interpreter_kernel_data_bundle(
            candidate_pe=self.candidate / "candidate.exe",
            linker_map=self.candidate / "payload.map",
            state_machine=self.packages.root / "state-machine.jsonl",
            out_dir=destination,
            shard_size=1,
            byte_pack_size=32 * 1024,
            relocation_pack_size=4,
        )
        bundle_path = (
            destination / f"StageA/{INTERPRETER_KERNEL_DATA_RELOCATION_BUNDLE}.lean"
        )
        source = bundle_path.read_text()
        branch = re.search(r"\(\.branch (\d+)", source)
        self.assertIsNotNone(branch)
        split_rva = int(branch.group(1))
        bundle_path.write_text(
            source[: branch.start(1)]
            + str(split_rva + 1)
            + source[branch.end(1) :]
        )

        result = _run_lean_relational(
            destination, bundle=INTERPRETER_KERNEL_DATA_RELOCATION_BUNDLE
        )

        self.assertEqual(result["status"], "failed", result)
        self.assertIn(
            INTERPRETER_KERNEL_DATA_RELOCATION_BUNDLE,
            " ".join(result["failed_command"]),
        )

    def test_candidate_count_tampering_is_rejected_before_proof_generation(self) -> None:
        inventory = self._generate(self.root / "valid")
        candidate = bytearray((self.candidate / "candidate.exe").read_bytes())
        pe = pefile.PE(data=bytes(candidate), fast_load=False)
        try:
            offset = pe.get_offset_from_rva(inventory.count_rva)
        finally:
            pe.close()
        struct.pack_into("<I", candidate, offset, inventory.transfer_count + 1)
        tampered = self.root / "tampered.exe"
        tampered.write_bytes(candidate)

        with self.assertRaisesRegex(
            InterpreterKernelDataGenerationError, "transfer count differs"
        ):
            generate_interpreter_kernel_data_bundle(
                candidate_pe=tampered,
                linker_map=self.candidate / "payload.map",
                state_machine=self.packages.root / "state-machine.jsonl",
                out_dir=self.root / "tampered-proof",
                shard_size=1,
            )


if __name__ == "__main__":
    unittest.main()
