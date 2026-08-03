import copy

from tests.stage_a_relational_support import *

from spaghetti_extractor.relational.binary_inventory import (
    parse_binary_cutpoint_inventory,
    side_extraction_request_from_inventory,
    stage_a_inventory_binary,
)
from spaghetti_extractor.relational.extraction import (
    _raw_extraction_semantics_sha256,
)
from spaghetti_extractor.relational.lean.compiler import (
    _lean_memory_arguments,
    _lean_runtime_arguments,
    _lean_stack_arguments,
)
from spaghetti_extractor.relational.pair_normalization import (
    pair_normalization_semantics_sha256,
)
from spaghetti_extractor.relational.schema import (
    RELATIONAL_ANALYSIS_KERNEL_MODULES,
    STAGE_A_RELATIONAL_MODEL_ID,
    STAGE_A_RELATIONAL_PROFILE_ID,
)
from spaghetti_extractor.relational.side_extraction import (
    stage_a_merge_side_extraction_requests,
    stage_a_merge_side_extractions,
    stage_a_project_missing_side_extraction_request,
)
from spaghetti_extractor.relational.side_extraction_artifact import (
    parse_request,
    parse_result_unbound,
    result_payload,
)
from spaghetti_extractor.stage_binary import (
    BlockSide,
    StageAInputError,
    _direct_cfg_edges,
    _parse_stage_a_pe,
)
from spaghetti_extractor.util import sha256_bytes, sha256_file, write_json


class StageABinaryInventoryTests(StageARelationalTestBase):
    def test_direct_cfg_edges_do_not_dereference_writable_control_slot(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary_path = Path(temporary) / "writable-jump.exe"
            binary_path.write_bytes(
                _pe32_image_with_immutable_indirect_call(
                    0x2000,
                    callee_rva=0x1030,
                    writable=True,
                    jump=True,
                )
            )
            binary = _parse_stage_a_pe(binary_path)

            self.assertEqual(
                _direct_cfg_edges(binary, BlockSide(0x1000, 0x1006)),
                [],
            )

    def test_direct_cfg_edges_may_resolve_readonly_control_slot(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary_path = Path(temporary) / "readonly-jump.exe"
            binary_path.write_bytes(
                _pe32_image_with_immutable_indirect_call(
                    0x2000,
                    callee_rva=0x1030,
                    writable=False,
                    jump=True,
                )
            )
            binary = _parse_stage_a_pe(binary_path)

            self.assertEqual(
                _direct_cfg_edges(binary, BlockSide(0x1000, 0x1006)),
                [{
                    "kind": "jump",
                    "target_rva": 0x1030,
                    "instruction_rva": 0x1000,
                    "mnemonic": "jmp",
                }],
            )

    def test_raw_extraction_identity_covers_driver_kernel_and_toolchain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for module in RELATIONAL_ANALYSIS_KERNEL_MODULES:
                (root / f"{module}.lean").write_text(
                    f"def {module.lower()}Version := 1\n",
                    encoding="utf-8",
                )
            arguments = {
                "lean_root": root,
                "driver_sha256": "a" * 64,
                "lean_toolchain": "Lean test-v1",
            }
            initial = _raw_extraction_semantics_sha256(**arguments)
            self.assertNotEqual(
                _raw_extraction_semantics_sha256(
                    **{**arguments, "driver_sha256": "b" * 64}
                ),
                initial,
            )
            self.assertNotEqual(
                _raw_extraction_semantics_sha256(
                    **{**arguments, "lean_toolchain": "Lean test-v2"}
                ),
                initial,
            )
            self.assertNotEqual(
                _raw_extraction_semantics_sha256(
                    **{**arguments, "output_protocol_sha256": "c" * 64}
                ),
                initial,
            )
            changed = root / "Relational.lean"
            changed.write_text("def relationalVersion := 2\n", encoding="utf-8")
            self.assertNotEqual(
                _raw_extraction_semantics_sha256(**arguments), initial
            )

    def test_lean_memory_limit_is_explicit_and_fail_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(_lean_memory_arguments(), [])
        with patch.dict(
            os.environ,
            {"SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_MEMORY_MB": "8192"},
            clear=True,
        ):
            self.assertEqual(_lean_memory_arguments(), ["-M", "8192"])
        for malformed in ("0", "-1", "many"):
            with patch.dict(
                os.environ,
                {"SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_MEMORY_MB": malformed},
                clear=True,
            ):
                with self.assertRaisesRegex(StageAInputError, "must be"):
                    _lean_memory_arguments()

    def test_lean_thread_stack_is_large_and_fail_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(_lean_stack_arguments(), ["--tstack=65536"])
        with patch.dict(
            os.environ,
            {"SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_THREAD_STACK_KB": "131072"},
            clear=True,
        ):
            self.assertEqual(_lean_stack_arguments(), ["--tstack=131072"])
        for malformed in ("0", "-1", "many"):
            with patch.dict(
                os.environ,
                {
                    "SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_THREAD_STACK_KB": malformed
                },
                clear=True,
            ):
                with self.assertRaisesRegex(StageAInputError, "must be"):
                    _lean_stack_arguments()

    def test_lean_runtime_arguments_cover_extraction_and_compilation_resources(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                _lean_runtime_arguments(),
                ["--tstack=65536"],
            )
        with patch.dict(
            os.environ,
            {
                "SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_THREAD_STACK_KB": "131072",
                "SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_MEMORY_MB": "8192",
            },
            clear=True,
        ):
            self.assertEqual(
                _lean_runtime_arguments(),
                ["--tstack=131072", "-M", "8192"],
            )

    def test_pair_normalization_identity_covers_sources_kernel_and_toolchain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for module in RELATIONAL_ANALYSIS_KERNEL_MODULES:
                (root / f"{module}.lean").write_text(
                    f"def {module.lower()}Version := 1\n",
                    encoding="utf-8",
                )
            arguments = {
                "lean_root": root,
                "lean_toolchain": "Lean test-v1",
                "normalizer_source_sha256": "a" * 64,
                "source_generator_sha256": "b" * 64,
            }
            initial = pair_normalization_semantics_sha256(**arguments)
            for field, value in (
                ("lean_toolchain", "Lean test-v2"),
                ("normalizer_source_sha256", "c" * 64),
                ("source_generator_sha256", "d" * 64),
            ):
                self.assertNotEqual(
                    pair_normalization_semantics_sha256(
                        **{**arguments, field: value}
                    ),
                    initial,
                )
            (root / "Relational.lean").write_text(
                "def relationalVersion := 2\n", encoding="utf-8"
            )
            self.assertNotEqual(
                pair_normalization_semantics_sha256(**arguments), initial
            )

    def test_tiny_pe_inventory_is_deterministic_and_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = self._write_pe(root / "hello.exe", b"\xeb\xfe")
            linker_map = root / "hello.map"
            linker_map.write_text("0x401000 entry\n", encoding="utf-8")
            first_path = root / "first.json"
            second_path = root / "second.json"

            first = stage_a_inventory_binary(
                binary=binary,
                linker_map=linker_map,
                side="original",
                out=first_path,
            )
            second = stage_a_inventory_binary(
                binary=binary,
                linker_map=linker_map,
                side="original",
                out=second_path,
            )

            self.assertEqual(first["status"], "pass")
            self.assertEqual(sha256_file(first_path), sha256_file(second_path))
            self.assertEqual(first, second)
            self.assertEqual(first["counts"]["regions"], 1)
            self.assertEqual(
                first["regions"][0]["span"],
                {"rva_start": 0x1000, "size": 2},
            )
            parsed = parse_binary_cutpoint_inventory(first)
            request = parse_request(side_extraction_request_from_inventory(parsed))
            self.assertEqual(request.side, "original")
            self.assertEqual(request.binary_sha256, sha256_file(binary))
            self.assertNotIn("candidate", json.dumps(request.to_payload()))

    def test_tiny_pe_inventory_without_linker_map_is_static_and_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = self._write_pe(root / "hello.exe", b"\xeb\xfe")

            payload = stage_a_inventory_binary(
                binary=binary,
                side="original",
                out=root / "inventory.json",
            )

            self.assertEqual(payload["status"], "pass")
            self.assertEqual(
                payload["linker_map_sha256"], sha256_bytes(b"")
            )
            self.assertEqual(payload["counts"]["regions"], 1)
            self.assertEqual(
                payload["regions"][0]["span"],
                {"rva_start": 0x1000, "size": 2},
            )
            self.assertEqual(
                payload["regions"][0]["source"]["kind"],
                "static_executable_section_block",
            )
            parse_binary_cutpoint_inventory(payload)

    def test_inventory_classifies_undecodable_zero_fill_suffix_as_padding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = self._write_pe(root / "hello.exe", b"\xeb\xfe\x00")

            payload = stage_a_inventory_binary(
                binary=binary,
                side="original",
                out=root / "inventory.json",
            )

            self.assertEqual(payload["status"], "pass")
            self.assertEqual(
                [row["span"] for row in payload["regions"]],
                [{"rva_start": 0x1000, "size": 2}],
            )
            self.assertEqual(
                [
                    {"rva": row["rva"], "size": row["size"]}
                    for row in payload["padding_waivers"]
                ],
                [{"rva": 0x1002, "size": 1}],
            )
            parse_binary_cutpoint_inventory(payload)

    def test_duplicate_executable_section_names_are_valid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = self._write_pe(root / "hello.exe", b"\xeb\xfe")
            payload = stage_a_inventory_binary(
                binary=binary,
                side="candidate",
                out=root / "inventory.json",
            )

            section = copy.deepcopy(payload["executable_sections"][0])
            section_size = section["rva_end"] - section["rva_start"]
            section["rva_start"] += 0x1000
            section["rva_end"] = section["rva_start"] + section_size
            payload["executable_sections"].append(section)
            for field in ("regions", "extraction_regions"):
                region = copy.deepcopy(payload[field][0])
                region["index"] = 1
                region["numeric_id"] = 1
                region["id"] += "-duplicate-section"
                region["span"]["rva_start"] += 0x1000
                payload[field].append(region)
                payload["counts"][field] = 2

            parse_binary_cutpoint_inventory(payload)

    def test_tampering_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = self._write_pe(root / "hello.exe", b"\xeb\xfe")
            linker_map = root / "hello.map"
            linker_map.write_text("0x401000 entry\n", encoding="utf-8")
            payload = stage_a_inventory_binary(
                binary=binary,
                linker_map=linker_map,
                side="candidate",
                out=root / "inventory.json",
            )
            for mutation in (
                lambda value: value.__setitem__("binary_sha256", "0" * 63),
                lambda value: value["regions"][0]["span"].__setitem__("size", 1),
                lambda value: value["executable_sections"][0].__setitem__(
                    "unchecked", True
                ),
                lambda value: value["regions"].append(
                    copy.deepcopy(value["regions"][0])
                ),
            ):
                tampered = copy.deepcopy(payload)
                mutation(tampered)
                with self.assertRaises(StageAInputError):
                    parse_binary_cutpoint_inventory(tampered)

            vacuous = copy.deepcopy(payload)
            vacuous["executable_sections"] = []
            vacuous["regions"] = []
            vacuous["extraction_regions"] = []
            vacuous["padding_waivers"] = []
            vacuous["counts"] = {
                "regions": 0,
                "extraction_regions": 0,
                "padding_waivers": 0,
                "issues": 0,
            }
            with self.assertRaisesRegex(StageAInputError, "no executable sections"):
                parse_binary_cutpoint_inventory(vacuous)

            if payload["padding_waivers"]:
                malformed_waiver = copy.deepcopy(payload)
                malformed_waiver["padding_waivers"][0]["unchecked"] = True
                with self.assertRaisesRegex(StageAInputError, "waiver"):
                    parse_binary_cutpoint_inventory(malformed_waiver)

            escaped = copy.deepcopy(payload)
            escaped_index = len(escaped["extraction_regions"])
            escaped["extraction_regions"].append({
                "index": escaped_index,
                "id": "candidate-extraction-escaped",
                "numeric_id": escaped_index,
                "span": {"rva_start": 0x70000000, "size": 2},
                "source": {"kind": "tampered"},
            })
            escaped["counts"]["extraction_regions"] += 1
            with self.assertRaisesRegex(StageAInputError, "escapes"):
                parse_binary_cutpoint_inventory(escaped)

    def test_extraction_regions_are_bounded_by_executable_sections(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = self._write_pe(root / "hello.exe", b"\xeb\xfe")
            linker_map = root / "hello.map"
            linker_map.write_text("0x401000 entry\n", encoding="utf-8")
            payload = stage_a_inventory_binary(
                binary=binary,
                linker_map=linker_map,
                side="candidate",
                out=root / "inventory.json",
            )

            section = payload["executable_sections"][0]
            extraction_span = payload["extraction_regions"][0]["span"]
            self.assertEqual(extraction_span["rva_start"], section["rva_start"])
            self.assertEqual(
                extraction_span["rva_start"] + extraction_span["size"],
                section["rva_end"],
            )
            parse_binary_cutpoint_inventory(payload)

            uint32_boundary = copy.deepcopy(payload)
            uint32_boundary["executable_sections"][0]["rva_start"] = 2**32 - 2
            uint32_boundary["executable_sections"][0]["rva_end"] = 2**32
            for field in ("regions", "extraction_regions"):
                uint32_boundary[field][0]["span"] = {
                    "rva_start": 2**32 - 2,
                    "size": 2,
                }
            parse_binary_cutpoint_inventory(uint32_boundary)

            for start, size in (
                (section["rva_start"] - 1, 2),
                (section["rva_end"] - 1, 2),
                (section["rva_end"], 1),
            ):
                escaped = copy.deepcopy(payload)
                escaped["extraction_regions"][0]["span"] = {
                    "rva_start": start,
                    "size": size,
                }
                with self.assertRaisesRegex(StageAInputError, "escapes"):
                    parse_binary_cutpoint_inventory(escaped)

            overflowed = copy.deepcopy(uint32_boundary)
            overflowed["extraction_regions"][0]["span"]["size"] = 3
            with self.assertRaisesRegex(StageAInputError, "span is invalid"):
                parse_binary_cutpoint_inventory(overflowed)

    def test_extraction_inventory_contains_both_cutpoint_policies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = self._write_pe(
                root / "hello.exe", b"\x90\x90\x90\x90\xeb\xfa"
            )
            linker_map = root / "hello.map"
            linker_map.write_text("0x401000 entry\n", encoding="utf-8")

            payload = stage_a_inventory_binary(
                binary=binary,
                linker_map=linker_map,
                side="original",
                out=root / "inventory.json",
            )

            self.assertEqual(payload["status"], "pass")
            self.assertEqual(
                [row["span"] for row in payload["regions"]],
                [
                    {"rva_start": 0x1000, "size": 4},
                    {"rva_start": 0x1004, "size": 2},
                ],
            )
            self.assertEqual(
                [row["span"] for row in payload["extraction_regions"]],
                [
                    {"rva_start": 0x1000, "size": 4},
                    {"rva_start": 0x1000, "size": 6},
                    {"rva_start": 0x1004, "size": 2},
                ],
            )
            base = parse_request(side_extraction_request_from_inventory(payload))
            superset = parse_request(
                side_extraction_request_from_inventory(
                    payload, scope="superset"
                )
            )
            self.assertEqual(len(base.regions), 2)
            self.assertEqual(len(superset.regions), 3)
            with self.assertRaisesRegex(StageAInputError, "scope is invalid"):
                side_extraction_request_from_inventory(payload, scope="pair")

    def test_side_extraction_request_merge_is_deterministic_and_deduplicated(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            common = {
                "format": "stage-a-relational-side-extraction-request-v1",
                "profile": STAGE_A_RELATIONAL_PROFILE_ID,
                "model": STAGE_A_RELATIONAL_MODEL_ID,
                "side": "original",
                "binary_sha256": "a" * 64,
            }
            first = root / "first.json"
            second = root / "second.json"
            write_json(first, {
                **common,
                "regions": [
                    {
                        "index": 0,
                        "id": "first",
                        "numeric_id": 0,
                        "span": {"rva_start": 0x1000, "size": 4},
                    },
                ],
            })
            write_json(second, {
                **common,
                "regions": [
                    {
                        "index": 0,
                        "id": "duplicate",
                        "numeric_id": 0,
                        "span": {"rva_start": 0x1000, "size": 4},
                    },
                    {
                        "index": 1,
                        "id": "supplement",
                        "numeric_id": 1,
                        "span": {"rva_start": 0x2000, "size": 8},
                    },
                ],
            })

            result = stage_a_merge_side_extraction_requests(
                inputs=[second, first],
                out=root / "merged.json",
            )
            merged = parse_request(
                json.loads(
                    (root / "merged.json").read_text(encoding="utf-8")
                )
            )

            self.assertEqual(result["regions"], 2)
            self.assertEqual(
                [
                    (region.span.rva_start, region.span.size)
                    for region in merged.regions
                ],
                [(0x1000, 4), (0x2000, 8)],
            )

    def test_unsupported_side_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = self._write_pe(root / "hello.exe", b"\xeb\xfe")
            linker_map = root / "hello.map"
            linker_map.write_text("0x401000 entry\n", encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "side is invalid"):
                stage_a_inventory_binary(
                    binary=binary,
                    linker_map=linker_map,
                    side="both",
                    out=root / "inventory.json",
                )

    def test_pair_supplement_and_merge_are_exact_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = self._write_pe(
                root / "hello.exe", b"\x90\x90\x90\x90\xeb\xfa"
            )
            linker_map = root / "hello.map"
            linker_map.write_text("0x401000 entry\n", encoding="utf-8")
            inventory_path = root / "inventory.json"
            inventory = stage_a_inventory_binary(
                binary=binary,
                linker_map=linker_map,
                side="original",
                out=inventory_path,
            )
            relation = root / "relation.json"
            write_json(relation, {
                "format": "stage-a-relation-contract-v1",
                "regions": [{
                    "id": "whole-block",
                    "numeric_id": 0,
                    "original": {"rva_start": 0x1000, "size": 6},
                }],
            })
            supplement_request_path = root / "supplement-request.json"

            projected = stage_a_project_missing_side_extraction_request(
                binary=binary,
                side="original",
                relation_contract=relation,
                inventory=inventory_path,
                out=supplement_request_path,
            )

            self.assertEqual(projected["regions"], 1)

            incomplete = copy.deepcopy(inventory)
            incomplete["issues"] = [{"category": "deliberate-test-gap"}]
            incomplete["status"] = "incomplete"
            incomplete["counts"]["issues"] = 1
            incomplete_path = root / "incomplete-inventory.json"
            write_json(incomplete_path, incomplete)
            with self.assertRaisesRegex(
                StageAInputError, "cannot authorize supplementary extraction"
            ):
                stage_a_project_missing_side_extraction_request(
                    binary=binary,
                    side="original",
                    relation_contract=relation,
                    inventory=incomplete_path,
                    out=root / "incomplete-request.json",
                )
            supplement_request = parse_request(
                json.loads(supplement_request_path.read_text(encoding="utf-8"))
            )
            self.assertEqual(
                supplement_request.regions[0].span.to_payload(),
                {"rva_start": 0x1000, "size": 6},
            )
            base_request = parse_request(
                side_extraction_request_from_inventory(inventory)
            )
            decoder_sha256 = _raw_extraction_semantics_sha256()
            base_path = root / "base.json"
            supplement_path = root / "supplement.json"
            write_json(
                base_path,
                result_payload(
                    base_request,
                    decoder_sha256,
                    [f"base-term-{index}" for index in range(len(base_request.regions))],
                ),
            )
            write_json(
                supplement_path,
                result_payload(
                    supplement_request,
                    decoder_sha256,
                    ["supplement-term"],
                ),
            )
            merged_path = root / "merged.json"
            with patch(
                "spaghetti_extractor.relational.side_extraction."
                "_raw_extraction_semantics_sha256",
                side_effect=AssertionError("merge must preserve input identity"),
            ):
                merged = stage_a_merge_side_extractions(
                    binary=binary,
                    side="original",
                    inputs=[base_path, supplement_path],
                    out=merged_path,
                )
            self.assertEqual(merged["regions"], 3)
            merged_request, _ = parse_result_unbound(
                json.loads(merged_path.read_text(encoding="utf-8")),
                expected_side="original",
                expected_binary_sha256=sha256_file(binary),
                expected_decoder_semantics_sha256=decoder_sha256,
            )
            self.assertEqual(
                [region.span.to_payload() for region in merged_request.regions],
                [
                    {"rva_start": 0x1000, "size": 4},
                    {"rva_start": 0x1000, "size": 6},
                    {"rva_start": 0x1004, "size": 2},
                ],
            )
            with self.assertRaisesRegex(StageAInputError, "duplicates span"):
                stage_a_merge_side_extractions(
                    binary=binary,
                    side="original",
                    inputs=[base_path, base_path],
                    out=root / "duplicate.json",
                )


if __name__ == "__main__":
    unittest.main()
