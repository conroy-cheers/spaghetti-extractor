from __future__ import annotations

import copy
import unittest
from typing import Any

from spaghetti_extractor.isa_semantic_forms import (
    lean_semantic_form_classifier_sha256,
)
from spaghetti_extractor.isa_catalog_enrichment import (
    enrich_side_isa_catalog,
    resolved_isa_catalog,
)
from spaghetti_extractor.isa_conformance import isa_conformance_corpus_sha256
from spaghetti_extractor.isa_conformance_shards import (
    partition_isa_conformance_corpus,
)
from spaghetti_extractor.isa_corpus_generator import (
    generate_boundary_isa_corpus,
    generated_corpus_executor_input,
)
from spaghetti_extractor.machine_ir_isa_catalog_v2 import (
    MachineIRISACatalogV2Error,
    build_machine_ir_isa_catalog_proposal_v2,
)
from spaghetti_extractor.machine_ir_isa_requirements_v2 import (
    build_machine_ir_isa_extraction_request_v2,
    build_machine_ir_isa_requirements_v2,
)


PE_SHA = "a" * 64
MACHINE_SHA = "b" * 64


def _unit() -> dict[str, Any]:
    return {
        "id": "unit-1000",
        "reachable": True,
        "source": {"original": {"rva_start": 0x1000, "rva_end": 0x1004}},
        "instructions": [
            {"rva_start": 0x1000, "rva_end": 0x1001},
            {"rva_start": 0x1001, "rva_end": 0x1003},
            {"rva_start": 0x1003, "rva_end": 0x1004},
        ],
    }


def _requirements() -> dict[str, Any]:
    request = build_machine_ir_isa_extraction_request_v2(
        units=[_unit()], binary_sha256=PE_SHA
    )
    return build_machine_ir_isa_requirements_v2(
        request=request,
        machine_ir_sha256=MACHINE_SHA,
        lean_rows={
            ("original", 0): (
                {"rva": 0x1000, "size": 1, "bytes": "50", "form": "push-r32"},
            ),
            ("original", 1): (
                {"rva": 0x1001, "size": 2, "bytes": "ff30", "form": "push-rm32"},
            ),
            ("original", 2): (
                {"rva": 0x1003, "size": 1, "bytes": "51", "form": "push-r32"},
            ),
        },
        lean_evidence={
            "status": "lean_extracted_untrusted",
            "classifier_sha256": lean_semantic_form_classifier_sha256(),
            "extractor_sha256": "c" * 64,
            "source_sha256": "d" * 64,
        },
    )


def _rehash(payload: dict[str, Any]) -> None:
    from spaghetti_extractor.machine_ir_isa_requirements_v2 import (
        _canonical_sha256,
    )

    body = copy.deepcopy(payload)
    body.pop("requirements_sha256", None)
    payload["requirements_sha256"] = _canonical_sha256(body)


def _single_requirements(
    *,
    machine_ir_sha256: str = MACHINE_SHA,
    unit_id: str = "profile-a-unit",
    profile_id: str = "profile-a",
    encoded: str = "50",
    semantic_form: str = "push-r32",
) -> dict[str, Any]:
    request = build_machine_ir_isa_extraction_request_v2(
        units=[{
            "id": unit_id,
            "reachable": True,
            "profile": {
                "id": profile_id,
                "provenance": f"{profile_id}-reviewed-metadata",
            },
            "source": {"original": {"rva_start": 0x1000, "rva_end": 0x1001}},
            "instructions": [{
                "rva_start": 0x1000,
                "rva_end": 0x1001,
                "mnemonic": f"{profile_id}-diagnostic",
            }],
        }],
        binary_sha256=PE_SHA,
    )
    return build_machine_ir_isa_requirements_v2(
        request=request,
        machine_ir_sha256=machine_ir_sha256,
        lean_rows={
            ("original", 0): ({
                "rva": 0x1000,
                "size": 1,
                "bytes": encoded,
                "form": semantic_form,
            },),
        },
        lean_evidence={
            "status": "lean_extracted_untrusted",
            "classifier_sha256": lean_semantic_form_classifier_sha256(),
            "extractor_sha256": "c" * 64,
            "source_sha256": "d" * 64,
        },
    )


def _corpus_and_shard_identities(
    requirements: dict[str, Any],
) -> tuple[str, tuple[str, ...]]:
    proposal = build_machine_ir_isa_catalog_proposal_v2(requirements)
    metadata = {}
    for encoding in proposal["encodings"]:
        instruction_hex = encoding["instruction_hex"]
        metadata[encoding["encoding_id"]] = {
            "encoding_id": encoding["encoding_id"],
            "status": "decoded",
            "semantic_form": encoding["semantic_form"],
            "decoded_size": len(encoding["instruction_bytes"]),
            "instruction": {
                "constructor": "pushReg",
                "source": "ecx" if instruction_hex == "51" else "eax",
            },
        }
    enrichment = enrich_side_isa_catalog(
        proposal,
        metadata,
        lean_binding={
            "classifier_sha256": lean_semantic_form_classifier_sha256(),
            "metadata_exporter_sha256": "e" * 64,
            "lean_version": "Lean fixture",
        },
    )
    generated = generate_boundary_isa_corpus(resolved_isa_catalog(enrichment), seed=0)
    corpus = generated_corpus_executor_input(generated).corpus
    shards = tuple(
        partition_isa_conformance_corpus(
            corpus, shard_index=index, shard_count=2
        )
        for index in range(2)
    )
    return (
        isa_conformance_corpus_sha256(corpus),
        tuple(isa_conformance_corpus_sha256(shard) for shard in shards),
    )


class MachineIRISACatalogV2Tests(unittest.TestCase):
    def test_profile_provenance_mutation_reuses_corpus_and_shard_identities(self) -> None:
        first = _single_requirements()
        metadata_only = _single_requirements(
            machine_ir_sha256="f" * 64,
            unit_id="profile-b-renamed-unit",
            profile_id="profile-b",
        )

        self.assertNotEqual(first["requirements_sha256"], metadata_only["requirements_sha256"])
        self.assertEqual(
            build_machine_ir_isa_catalog_proposal_v2(first),
            build_machine_ir_isa_catalog_proposal_v2(metadata_only),
        )
        self.assertEqual(
            _corpus_and_shard_identities(first),
            _corpus_and_shard_identities(metadata_only),
        )

    def test_instruction_bytes_and_forms_change_corpus_and_shard_identities(self) -> None:
        baseline = _corpus_and_shard_identities(_single_requirements())
        changed_bytes = _corpus_and_shard_identities(
            _single_requirements(encoded="51")
        )
        changed_form = _corpus_and_shard_identities(
            _single_requirements(semantic_form="push-register-alias")
        )

        self.assertNotEqual(baseline, changed_bytes)
        self.assertNotEqual(baseline, changed_form)

    def test_reviewed_increment_metadata_is_enrichable(self) -> None:
        from spaghetti_extractor.isa_catalog_enrichment import _derive_enrichment

        semantic_form = "unary-increment-memory"
        encoding = {
            "encoding_id": "encoding-inc",
            "instruction_bytes": [0xFF, 0x05, 0, 0, 0, 0],
            "semantic_form": semantic_form,
        }
        enrichment = _derive_enrichment(encoding, {
            "encoding_id": "encoding-inc",
            "status": "decoded",
            "semantic_form": semantic_form,
            "decoded_size": 6,
            "instruction": {
                "constructor": "unary",
                "operation": "StageA.Formal.UnaryOperation.increment",
                "destination": {
                    "kind": "memory",
                    "address": {
                        "base": None,
                        "index": None,
                        "scale_shift": 0,
                        "displacement": 0x431C48,
                    },
                },
            },
        })

        self.assertEqual(enrichment["status"], "resolved")
        self.assertEqual(enrichment["effects"][0]["access"], "read_write")

    def test_reviewed_x87_int64_store_width_is_exported(self) -> None:
        from spaghetti_extractor.isa_catalog_enrichment import _x87_format_width

        self.assertEqual(
            _x87_format_width(
                "StageA.Formal.X87StoreFormat.int64", "x87 store format"
            ),
            64,
        )

    def test_groups_exact_encodings_and_selects_one_representative(self) -> None:
        first = build_machine_ir_isa_catalog_proposal_v2(_requirements())
        second = build_machine_ir_isa_catalog_proposal_v2(_requirements())

        self.assertEqual(first, second)
        self.assertEqual(first["counts"], {
            "forms": 2,
            "encodings": 3,
            "occurrences": 3,
            "representatives": 2,
        })
        push_form = next(
            row for row in first["forms"] if row["semantic_form"] == "push-r32"
        )
        push_encodings = [
            row for row in first["encodings"] if row["form_id"] == push_form["form_id"]
        ]
        self.assertEqual(sum(row["representative"] for row in push_encodings), 1)
        self.assertEqual(
            push_form["representative_encoding_id"],
            next(row["encoding_id"] for row in push_encodings if row["representative"]),
        )

    def test_stale_classifier_is_rejected_by_typed_requirements(self) -> None:
        payload = _requirements()
        payload["binding"]["classifier_sha256"] = "e" * 64
        _rehash(payload)

        with self.assertRaisesRegex(MachineIRISACatalogV2Error, "identity is stale"):
            build_machine_ir_isa_catalog_proposal_v2(payload)

    def test_unknown_form_and_length_mismatch_fail_closed(self) -> None:
        unknown = _requirements()
        unknown["occurrences"][0]["form_id"] = "unknown"
        _rehash(unknown)
        with self.assertRaisesRegex(MachineIRISACatalogV2Error, "unknown form"):
            build_machine_ir_isa_catalog_proposal_v2(unknown)

        length = _requirements()
        length["occurrences"][0]["byte_length"] = 2
        _rehash(length)
        with self.assertRaisesRegex(MachineIRISACatalogV2Error, "bytes are invalid"):
            build_machine_ir_isa_catalog_proposal_v2(length)

    def test_duplicate_occurrence_and_missing_form_occurrence_fail_closed(self) -> None:
        duplicate = _requirements()
        duplicate["occurrences"].append(copy.deepcopy(duplicate["occurrences"][0]))
        duplicate["counts"]["occurrences"] += 1
        _rehash(duplicate)
        with self.assertRaisesRegex(MachineIRISACatalogV2Error, "duplicate"):
            build_machine_ir_isa_catalog_proposal_v2(duplicate)

        missing = _requirements()
        removed_form = missing["forms"].pop()
        missing["fallback_capability_ids"] = [
            row
            for row in missing["fallback_capability_ids"]
            if row["form_id"] != removed_form["id"]
        ]
        missing["occurrences"] = [
            row for row in missing["occurrences"] if row["form_id"] != removed_form["id"]
        ]
        missing["counts"]["forms"] -= 1
        missing["counts"]["occurrences"] = len(missing["occurrences"])
        _rehash(missing)

        with self.assertRaisesRegex(MachineIRISACatalogV2Error, "not closed"):
            build_machine_ir_isa_catalog_proposal_v2(missing)


if __name__ == "__main__":
    unittest.main()
