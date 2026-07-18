import inspect

from tests.stage_a_relational_support import *

from spaghetti_extractor.relational.contract import _load_contract, _normalize_contract
from spaghetti_extractor.relational.extraction import (
    _canonicalize_raw_behavior_term,
    _parse_normalized_behavior_output,
    _parse_raw_behavior_output,
    _raw_behavior_output_protocol_sha256,
    _raw_extraction_semantics_sha256,
)
from spaghetti_extractor.relational.isa_requirements import (
    extract_lean_instruction_forms_side,
)
from spaghetti_extractor.relational.pipeline import stage_a_analyze_relational
from spaghetti_extractor.relational.pair_normalization import (
    stage_a_normalize_pair,
)
from spaghetti_extractor.relational.schema import (
    RELATIONAL_ANALYSIS_KERNEL_MODULES,
)
from spaghetti_extractor.relational.side_extraction import (
    stage_a_extract_side,
    stage_a_extract_side_isa,
    stage_a_project_side_extraction_request,
)
from spaghetti_extractor.relational.side_extraction_artifact import (
    request_payload,
)
from spaghetti_extractor.stage_binary import _parse_stage_a_pe
from spaghetti_extractor.util import sha256_file, write_json


class StageASideExtractionIntegrationTests(StageARelationalTestBase):
    def test_raw_pack_output_rejects_duplicate_and_unexpected_rows(self):
        def marker(
            side: str,
            index: int,
            value: str = "some { outcome := none }",
        ) -> str:
            return (
                f"STAGE_A_RAW_BEHAVIOR_BEGIN {side} {index}\n"
                f"{value}\n"
                "STAGE_A_RAW_BEHAVIOR_END\n"
            )

        valid = {
            "status": "checked",
            "stdout": marker("original", 0),
            "stderr": "",
        }
        parsed, _ = _parse_raw_behavior_output(
            valid, side="original", expected={0}
        )
        self.assertEqual(parsed, {0: "{ outcome := none }"})

        for malformed in (
            valid["stdout"] + marker("original", 0),
            valid["stdout"] + marker("candidate", 0),
            marker("original", 1),
            (
                "STAGE_A_RAW_BEHAVIOR_BEGIN original 0\n"
                "some { outcome := none }\n"
                "STAGE_A_RAW_BEHAVIOR_BEGIN original 0\n"
                "some { outcome := none }\n"
                "STAGE_A_RAW_BEHAVIOR_END\n"
            ),
            marker("original", -1) + valid["stdout"],
        ):
            parsed, evidence = _parse_raw_behavior_output(
                {**valid, "stdout": malformed},
                side="original",
                expected={0},
            )
            self.assertIsNone(parsed)
            self.assertEqual(evidence["status"], "malformed_output")

        canonicalized, _ = _parse_raw_behavior_output(
            {
                **valid,
                "stdout": marker(
                    "original",
                    0,
                    "some  { outcome :=\n\t none }",
                ),
            },
            side="original",
            expected={0},
        )
        self.assertEqual(
            (canonicalized or {})[0].encode("utf-8"),
            b"{ outcome := none }",
        )

    def test_raw_output_protocol_identity_binds_python_behavior(self):
        baseline = _raw_behavior_output_protocol_sha256()
        getsource = inspect.getsource
        for changed_function in (
            _parse_raw_behavior_output,
            _canonicalize_raw_behavior_term,
        ):

            def changed_source(function, *, changed=changed_function):
                source = getsource(function)
                return source + "\n# changed\n" if function is changed else source

            with patch(
                "spaghetti_extractor.relational.extraction.inspect.getsource",
                side_effect=changed_source,
            ):
                self.assertNotEqual(
                    _raw_behavior_output_protocol_sha256(),
                    baseline,
                )

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
            with patch(
                "spaghetti_extractor.relational.extraction."
                "_raw_behavior_output_protocol_sha256",
                return_value="b" * 64,
            ):
                initial = _raw_extraction_semantics_sha256(**arguments)
            with patch(
                "spaghetti_extractor.relational.extraction."
                "_raw_behavior_output_protocol_sha256",
                return_value="c" * 64,
            ):
                changed = _raw_extraction_semantics_sha256(**arguments)
            self.assertNotEqual(changed, initial)

    def test_normalization_pack_output_rejects_duplicate_and_missing_rows(self):
        def marker(side: str, index: int) -> str:
            return (
                f"STAGE_A_NORMALIZED_BEHAVIOR_BEGIN {side} {index}\n"
                "some { outcome := none }\n"
                "STAGE_A_NORMALIZED_BEHAVIOR_IR\n"
                '{"format":"stage-a-normalized-behavior-v1"}\n'
                "STAGE_A_NORMALIZED_BEHAVIOR_END\n"
            )

        expected = {("original", 0), ("candidate", 0)}
        valid = {
            "status": "checked",
            "stdout": marker("original", 0) + marker("candidate", 0),
            "stderr": "",
        }
        parsed, _ = _parse_normalized_behavior_output(valid, expected=expected)
        self.assertEqual(set(parsed or {}), expected)

        duplicate = {
            **valid,
            "stdout": valid["stdout"] + marker("candidate", 0),
        }
        parsed, evidence = _parse_normalized_behavior_output(
            duplicate, expected=expected
        )
        self.assertIsNone(parsed)
        self.assertEqual(evidence["status"], "malformed_output")

        missing = {**valid, "stdout": marker("original", 0)}
        parsed, evidence = _parse_normalized_behavior_output(
            missing, expected=expected
        )
        self.assertIsNone(parsed)
        self.assertIn("incomplete", evidence["stderr"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for extraction")
    def test_split_raw_extraction_matches_monolithic_analysis(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = b"\xeb\xfe\xeb\xfe\xeb\xfe"
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            register_pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax",
                    "ebx",
                    "ecx",
                    "edx",
                    "esi",
                    "edi",
                    "ebp",
                    "esp",
                )
            ]
            contract = root / "relation.json"
            write_json(contract, {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {
                        "id": index,
                        "original_rva": 0x1000 + 2 * index,
                        "candidate_rva": 0x1000 + 2 * index,
                    }
                    for index in range(3)
                ],
                "regions": [
                    {
                        "id": f"loop-{index}",
                        "root": index == 0,
                        "original": {"rva": 0x1000 + 2 * index, "size": 2},
                        "candidate": {"rva": 0x1000 + 2 * index, "size": 2},
                        "inputs": register_pairs,
                        "outputs": register_pairs,
                    }
                    for index in range(3)
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            })
            original_binary = _parse_stage_a_pe(original)
            candidate_binary = _parse_stage_a_pe(candidate)
            normalized_contract, issues = _normalize_contract(
                _load_contract(contract), original_binary, candidate_binary
            )
            self.assertEqual(issues, [])
            projected_contract = root / "normalized-relation.json"
            write_json(projected_contract, normalized_contract)
            extractions: dict[str, Path] = {}
            isa_artifacts: dict[str, Path] = {}
            for side, binary in (
                ("original", original),
                ("candidate", candidate),
            ):
                request = root / f"{side}-request.json"
                extraction = root / f"{side}-extraction.json"
                isa_artifact = root / f"{side}-isa.json"
                projected = stage_a_project_side_extraction_request(
                    binary=binary,
                    side=side,
                    relation_contract=projected_contract,
                    out=request,
                )
                self.assertEqual(projected["status"], "generated")
                extracted = stage_a_extract_side(
                    binary=binary,
                    request=request,
                    out=extraction,
                )
                self.assertEqual(extracted["status"], "extracted")
                isa_extracted = stage_a_extract_side_isa(
                    binary=binary,
                    request=request,
                    out=isa_artifact,
                )
                self.assertEqual(isa_extracted["status"], "extracted")
                extractions[side] = extraction
                isa_artifacts[side] = isa_artifact

            split = root / "split"
            monolithic = root / "monolithic"
            normalized_behaviors = root / "normalized-behaviors.json"
            with patch.dict(
                os.environ,
                {
                    "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_NORMALIZATION_BATCH": "1",
                    "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_NORMALIZATION_JOBS": "2",
                },
            ):
                normalized_result = stage_a_normalize_pair(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    original_extraction=extractions["original"],
                    candidate_extraction=extractions["candidate"],
                    out=normalized_behaviors,
                )
                self.assertEqual(normalized_result["status"], "normalized")
                split_result = stage_a_analyze_relational(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    original_extraction=extractions["original"],
                    candidate_extraction=extractions["candidate"],
                    normalized_behaviors=normalized_behaviors,
                    original_isa=isa_artifacts["original"],
                    candidate_isa=isa_artifacts["candidate"],
                    out=split,
                )
            with patch.dict(
                os.environ,
                {
                    "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_NORMALIZATION_BATCH": "3",
                    "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_NORMALIZATION_JOBS": "1",
                },
            ):
                monolithic_result = stage_a_analyze_relational(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    out=monolithic,
                )
            self.assertEqual(split_result["status"], "analyzed")
            self.assertEqual(monolithic_result["status"], "analyzed")
            for relative in (
                "relation-contract.json",
                "relational-decoded-behaviors.json",
                "relational-semantic-ir.json",
                "relational-product-graph.json",
                "relational-segment-candidates.json",
                "isa-requirements.json",
            ):
                self.assertEqual(
                    sha256_file(split / relative),
                    sha256_file(monolithic / relative),
                    relative,
                )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for extraction")
    def test_side_isa_extraction_is_exactly_span_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary_path = self._write_pe(root / "original.exe", b"\xeb\xfe")
            binary = _parse_stage_a_pe(binary_path)
            contract_path = self._write_contract(
                root / "relation.json", region_size=2
            )
            contract, issues = _normalize_contract(
                _load_contract(contract_path), binary, binary
            )
            self.assertEqual(issues, [])
            request = request_payload(contract, "original", binary.sha256)

            rows, evidence = extract_lean_instruction_forms_side(
                binary=binary_path,
                request=request,
            )

            self.assertEqual(evidence["status"], "lean_extracted_untrusted")
            self.assertEqual(
                [(row["rva"], row["size"]) for row in rows[("original", 0)]],
                [(0x1000, 2)],
            )


if __name__ == "__main__":
    unittest.main()
