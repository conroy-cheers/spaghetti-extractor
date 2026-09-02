from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.errors import ToolkitInputError
from spaghetti_extractor.qualified_platform.release import (
    QualifiedPlatformError,
    QualifiedPlatformV1,
    write_qualified_platform_v1,
)
from spaghetti_extractor.qualified_platform.isa_form_inventory import (
    write_qualified_platform_isa_form_inventory_v1,
)
from spaghetti_extractor.qualified_platform.isa_form_replay import (
    reduce_qualified_platform_isa_form_replay_v1,
)
from spaghetti_extractor.qualified_platform.replay import (
    replay_qualified_platform_v1,
)
from spaghetti_extractor.transfer.operations import (
    operation_registry_payload_v2,
    runtime_provider_catalog_payload_v2,
)
from spaghetti_extractor.isa.semantic_forms import (
    lean_semantic_form_classifier_sha256,
    lean_semantic_form_id,
)
from spaghetti_extractor.isa.kernel_qualification import (
    BackendBinding,
    BackendRole,
    CorpusBinding,
    GeneratorBinding,
    ISAProfileBinding,
    ObservationAvailability,
    OracleSuiteBinding,
    SemanticKernelBinding,
    build_form_qualification,
    build_isa_kernel_qualification,
    build_oracle_consensus,
    build_oracle_observation,
    serialize_kernel_qualification,
)
from spaghetti_extractor.isa.qualification_certificate import (
    build_isa_kernel_qualification_certificate_v1,
)
from spaghetti_extractor.util import sha256_file, write_json


class QualifiedPlatformV1Tests(unittest.TestCase):
    def _kernel(self, root: Path) -> Path:
        path = root / "semantic-kernel-input.json"
        path.write_text(json.dumps({
            "format": "spaghetti-extractor-isa-semantic-kernel-binding-v1",
            "id": "lean-machine-semantics:test",
            "decoder_sha256": "0" * 64,
            "semantics_sha256": "1" * 64,
            "lean_version": "Lean test",
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def _platform(self, root: Path) -> Path:
        output = root / "platform" / "qualified-platform.json"
        output.parent.mkdir(parents=True)
        kernel = self._kernel(root)
        inventory = self._inventory(root)
        write_qualified_platform_v1(
            semantic_kernel=kernel,
            isa_form_inventory=inventory,
            isa_form_replay=self._replay(
                output.parent, kernel=kernel, inventory=inventory
            ),
            isa_form_qualification_certificate=self._qualification(
                output.parent, kernel=kernel, inventory=inventory
            ),
            link_member=True,
            out=output,
        )
        return output

    def _qualification(
        self, root: Path, *, kernel: Path, inventory: Path
    ) -> Path:
        kernel_payload = json.loads(kernel.read_text(encoding="utf-8"))
        inventory_payload = json.loads(inventory.read_text(encoding="utf-8"))
        form_row = inventory_payload["forms"][0]
        profile = ISAProfileBinding(
            id="pe32-i686-v1",
            architecture="x86",
            cpu="i686",
            execution_mode="protected-32",
            environment="pe32",
            features=(),
        )
        semantic_kernel = SemanticKernelBinding(
            id=kernel_payload["id"],
            decoder_sha256=kernel_payload["decoder_sha256"],
            semantics_sha256=kernel_payload["semantics_sha256"],
            lean_version=kernel_payload["lean_version"],
        )
        generator = GeneratorBinding(id="test-generator", version="1")
        backends = tuple(
            BackendBinding(role, f"{role.value}-test", "1")
            for role in (
                BackendRole.BOCHS,
                BackendRole.UNICORN,
                BackendRole.LEAN,
            )
        )
        suite = OracleSuiteBinding(backends)
        corpus = CorpusBinding("test-corpus", "3" * 64)
        observations = tuple(
            build_oracle_observation(
                form_id=form_row["form_id"],
                case_id="test-case",
                profile=profile,
                semantic_kernel=semantic_kernel,
                corpus=corpus,
                generator=generator,
                backend=backend,
                availability=ObservationAvailability.COMPLETE,
                result={"state": {"eax": 0}},
                detail="",
            )
            for backend in backends
        )
        consensus = build_oracle_consensus(
            form_id=form_row["form_id"],
            case_id="test-case",
            profile=profile,
            semantic_kernel=semantic_kernel,
            corpus=corpus,
            generator=generator,
            oracle_suite=suite,
            observations=observations,
        )
        form = build_form_qualification(
            form_id=form_row["form_id"],
            semantic_form=form_row["semantic_form"],
            profile=profile,
            semantic_kernel=semantic_kernel,
            generator=generator,
            oracle_suite=suite,
            corpora=(corpus,),
            consensuses=(consensus,),
        )
        qualification = build_isa_kernel_qualification(
            profile=profile,
            semantic_kernel=semantic_kernel,
            generator=generator,
            oracle_suite=suite,
            corpora=(corpus,),
            required_form_ids=(form.form_id,),
            forms=(form,),
        )
        qualification_payload = serialize_kernel_qualification(qualification)
        full = root / "full-isa-form-qualification.json"
        write_json(full, qualification_payload)
        output = root / "isa-form-qualification-certificate.json"
        write_json(
            output,
            build_isa_kernel_qualification_certificate_v1(
                qualification=qualification,
                qualification_payload=qualification_payload,
                qualification_content_sha256=sha256_file(full),
            ),
        )
        return output

    def _replay(self, root: Path, *, kernel: Path, inventory: Path) -> Path:
        inventory_payload = json.loads(inventory.read_text(encoding="utf-8"))
        kernel_payload = json.loads(kernel.read_text(encoding="utf-8"))
        form = inventory_payload["forms"][0]
        output = root / "isa-form-replay.json"
        payload = reduce_qualified_platform_isa_form_replay_v1(
            inventory=inventory_payload,
            inventory_content_sha256=sha256_file(inventory),
            semantic_kernel=kernel_payload,
            semantic_kernel_content_sha256=sha256_file(kernel),
            decoded_metadata={
                form["form_id"]: {
                    "encoding_id": form["form_id"],
                    "status": "decoded",
                    "semantic_form": form["semantic_form"],
                    "decoded_size": 1,
                    "instruction": {"constructor": "nop"},
                }
            },
            lean_binding={
                "classifier_sha256": inventory_payload["classifier_sha256"],
                "metadata_exporter_sha256": "2" * 64,
                "lean_version": "Lean test",
            },
        )
        write_json(output, payload)
        return output

    def _inventory(self, root: Path) -> Path:
        semantic_form = "SpaghettiExtractor.ISA.Formal.InstructionSemanticForm.nop"
        output = root / "isa-form-inventory.json"
        write_qualified_platform_isa_form_inventory_v1(
            forms=[{
                "form_id": lean_semantic_form_id(
                    semantic_form,
                    classifier_sha256=lean_semantic_form_classifier_sha256(),
                ),
                "semantic_form": semantic_form,
                "representative_instruction_hex": "90",
            }],
            out=output,
        )
        return output

    def test_release_is_total_for_transfer_primitives_and_non_authorizing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = self._platform(Path(temporary))
            parsed = QualifiedPlatformV1.load(output)
            replay = replay_qualified_platform_v1(output)
            payload = parsed.payload
            self.assertTrue(payload["target_independent"])
            self.assertTrue(payload["authority"])
            self.assertEqual(payload["status"], "complete")
            self.assertEqual(
                payload["counts"]["transfer_primitives"],
                len(operation_registry_payload_v2()),
            )
            self.assertEqual(
                payload["runtime_provider_catalog"],
                runtime_provider_catalog_payload_v2(),
            )
            self.assertEqual(payload["counts"]["behavioral_c_rejections"], 0)
            self.assertEqual(payload["counts"]["abi_profiles"], 2)
            self.assertEqual(payload["counts"]["native_primitives"], 8)
            self.assertEqual(
                {row["profile_id"] for row in payload["abi_profiles"]},
                {"pe32-i686-mingw32", "pe32-i686-msvc"},
            )
            self.assertNotIn(
                "abi_profile_catalog_unlinked",
                {row["kind"] for row in payload["holes"]},
            )
            self.assertTrue(all(
                row["qualification"]["status"] == "complete"
                and row["qualification"]["test_results_authorizing"] is False
                for row in payload["native_primitives"]
            ))
            self.assertEqual(replay["platform_sha256"], parsed.identity)
            self.assertEqual(payload["counts"]["isa_forms"], 1)
            self.assertEqual(
                payload["isa_form_catalog"][0]["lean_decode"]["status"],
                "checked",
            )
            self.assertNotIn(
                "finite_isa_form_inventory_unreviewed",
                {row["kind"] for row in payload["holes"]},
            )
            self.assertEqual(payload["counts"]["isa_form_constructors"], 95)
            self.assertEqual(
                QualifiedPlatformV1.load(output, require_complete=True).identity,
                parsed.identity,
            )

    def test_same_intrinsic_inputs_produce_same_release_without_target_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            kernel = self._kernel(root)
            inventory = self._inventory(root)
            replay = self._replay(root, kernel=kernel, inventory=inventory)
            qualification = self._qualification(
                root, kernel=kernel, inventory=inventory
            )
            outputs = []
            for name in ("hello", "dx-ball"):
                output = root / name / "qualified-platform.json"
                write_qualified_platform_v1(
                    semantic_kernel=kernel,
                    isa_form_inventory=inventory,
                    isa_form_replay=replay,
                    isa_form_qualification_certificate=qualification,
                    out=output,
                )
                outputs.append(output)
            self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())
            payload = json.loads(outputs[0].read_text(encoding="utf-8"))
            text = json.dumps(payload, sort_keys=True).lower()
            self.assertNotIn("hello", text)
            self.assertNotIn("dx-ball", text)
            self.assertNotIn("jq", text)

    def test_corruption_fails_closed_even_after_outer_rehash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = self._platform(Path(temporary))
            payload = json.loads(output.read_text(encoding="utf-8"))
            payload["primitive_catalog"][0]["behavioral_c_lowering"][
                "status"
            ] = "rejected"
            payload["platform_sha256"] = canonical_sha256_v3({
                key: value for key, value in payload.items()
                if key != "platform_sha256"
            })
            write_json(output, payload)
            with self.assertRaisesRegex(
                QualifiedPlatformError, "intrinsic registries"
            ):
                QualifiedPlatformV1.load(output)
            with self.assertRaisesRegex(ToolkitInputError, "lowering status"):
                replay_qualified_platform_v1(output)

if __name__ == "__main__":
    unittest.main()
