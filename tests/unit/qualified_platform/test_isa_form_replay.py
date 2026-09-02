from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.isa.semantic_forms import (
    lean_semantic_form_classifier_sha256,
    lean_semantic_form_id,
)
from spaghetti_extractor.qualified_platform.isa_form_inventory import (
    build_qualified_platform_isa_form_inventory_v1,
)
from spaghetti_extractor.qualified_platform.isa_form_replay import (
    QualifiedPlatformISAFormReplayError,
    parse_qualified_platform_isa_form_replay_v1,
    reduce_qualified_platform_isa_form_replay_v1,
)


SHA0 = "0" * 64
SHA1 = "1" * 64
SHA2 = "2" * 64
SEMANTIC_FORM = "SpaghettiExtractor.ISA.Formal.InstructionSemanticForm.nop"


class QualifiedPlatformISAFormReplayTests(unittest.TestCase):
    def _inventory(self) -> dict[str, object]:
        classifier = lean_semantic_form_classifier_sha256()
        return build_qualified_platform_isa_form_inventory_v1([{
            "form_id": lean_semantic_form_id(
                SEMANTIC_FORM, classifier_sha256=classifier
            ),
            "semantic_form": SEMANTIC_FORM,
            "representative_instruction_hex": "90",
        }])

    def _replay(self, *, semantic_form: str = SEMANTIC_FORM) -> dict[str, object]:
        inventory = self._inventory()
        form_id = inventory["forms"][0]["form_id"]
        return reduce_qualified_platform_isa_form_replay_v1(
            inventory=inventory,
            inventory_content_sha256=SHA0,
            semantic_kernel={
                "id": "lean:test",
                "decoder_sha256": SHA1,
                "semantics_sha256": SHA2,
            },
            semantic_kernel_content_sha256=SHA0,
            decoded_metadata={
                form_id: {
                    "encoding_id": form_id,
                    "status": "decoded",
                    "semantic_form": semantic_form,
                    "decoded_size": 1,
                    "instruction": {"constructor": "nop"},
                }
            },
            lean_binding={
                "classifier_sha256": inventory["classifier_sha256"],
                "metadata_exporter_sha256": SHA1,
                "lean_version": "Lean test",
            },
        )

    def test_exact_replay_is_complete_but_never_qualifying(self) -> None:
        payload = self._replay()
        self.assertEqual(payload["status"], "complete")
        self.assertFalse(payload["authority"])
        self.assertEqual(payload["counts"], {"forms": 1, "checked": 1, "rejected": 0})
        self.assertFalse(payload["trust"]["qualifies_decoder"])
        self.assertEqual(parse_qualified_platform_isa_form_replay_v1(payload), payload)

    def test_semantic_disagreement_is_a_veto(self) -> None:
        payload = self._replay(semantic_form=SEMANTIC_FORM + " changed")
        self.assertEqual(payload["status"], "violated")
        self.assertEqual(payload["forms"][0]["status"], "rejected")
        self.assertEqual(
            payload["issues"][0]["kind"],
            "representative_semantic_form_mismatch",
        )

    def test_stale_outer_hash_fails_closed(self) -> None:
        payload = self._replay()
        changed = copy.deepcopy(payload)
        changed["forms"][0]["status"] = "rejected"
        with self.assertRaisesRegex(
            QualifiedPlatformISAFormReplayError, "self hash is stale"
        ):
            parse_qualified_platform_isa_form_replay_v1(changed)


if __name__ == "__main__":
    unittest.main()
