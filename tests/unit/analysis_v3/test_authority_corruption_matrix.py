"""Uniform fail-closed corruption coverage for every v3 authority record.

The matrix deliberately generates separate unittest cases. A newly registered
authority family cannot inherit wire-format trust merely because another
family happened to exercise the shared codec helpers.
"""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from typing import Any, ClassVar

from spaghetti_extractor.analysis_v3._schema import AnalysisV3Error
from spaghetti_extractor.analysis_v3.callbacks import CALLBACK_AUTHORITY_CODEC_V3
from spaghetti_extractor.analysis_v3.exceptional_transitions import (
    EXCEPTIONAL_TRANSITION_CODEC_V3,
)
from spaghetti_extractor.analysis_v3.exact_units import (
    EXACT_UNIT_CODEC_V3,
    EXACT_UNITS_PHASE_V3,
)
from spaghetti_extractor.analysis_v3.external_sites import (
    CANONICAL_EXTERNAL_SITE_CODEC_V3,
)
from spaghetti_extractor.analysis_v3.fallback_coverage import (
    FALLBACK_COVERAGE_CODEC_V3,
)
from spaghetti_extractor.analysis_v3.final_authority import (
    FINAL_AUTHORITY_CODEC_V3,
    FINAL_AUTHORITY_PHASE_V3,
)
from spaghetti_extractor.analysis_v3.inductive import INDUCTIVE_AUTHORITY_CODEC_V3
from spaghetti_extractor.analysis_v3.isa_qualification import (
    ISA_QUALIFICATION_CODEC_V3,
)
from spaghetti_extractor.analysis_v3.memory_versions import (
    MEMORY_VERSION_CODEC_V3,
    MEMORY_VERSIONS_PHASE_V3,
)
from spaghetti_extractor.analysis_v3.root_closure import (
    LAUNCH_ROOT_CLOSURE_CODEC_V3,
)
from spaghetti_extractor.analysis_v3.semantic_index import (
    SEMANTIC_INDEX_CODEC_V3,
    SEMANTIC_INDEX_PHASE_V3,
)
from spaghetti_extractor.analysis_v3.structural_targets import (
    STRUCTURAL_TARGET_UNIT_CODEC_V3,
    STRUCTURAL_TARGETS_PHASE_V3,
)
from spaghetti_extractor.analysis_v3.target_certificates import (
    INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3,
)
from spaghetti_extractor.analysis_v3.transition_summaries import (
    TRANSITION_SUMMARY_CODEC_V3,
    TRANSITION_SUMMARIES_PHASE_V3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    ArtifactV3Error,
    DependencyNodePlanV3,
    DependencySchedulingManifestV3,
)
from tests.unit.analysis_v3 import test_final_authority as final_fixture
from tests.unit.analysis_v3 import test_phase_chain as phase_fixture
from tests.unit.analysis_v3 import test_target_certificates as target_fixture
from tests.unit.analysis_v3.test_isa_qualification import BINDING


_CODECS = {
    "callbacks": CALLBACK_AUTHORITY_CODEC_V3,
    "exceptional_transitions": EXCEPTIONAL_TRANSITION_CODEC_V3,
    "exact_units": EXACT_UNIT_CODEC_V3,
    "external_sites": CANONICAL_EXTERNAL_SITE_CODEC_V3,
    "fallback_coverage": FALLBACK_COVERAGE_CODEC_V3,
    "final_authority": FINAL_AUTHORITY_CODEC_V3,
    "inductive_authority": INDUCTIVE_AUTHORITY_CODEC_V3,
    "indirect_target_certificates": INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3,
    "isa_qualification": ISA_QUALIFICATION_CODEC_V3,
    "memory_versions": MEMORY_VERSION_CODEC_V3,
    "root_closure": LAUNCH_ROOT_CLOSURE_CODEC_V3,
    "semantic_index": SEMANTIC_INDEX_CODEC_V3,
    "structural_targets": STRUCTURAL_TARGET_UNIT_CODEC_V3,
    "transition_summaries": TRANSITION_SUMMARY_CODEC_V3,
}


class AuthorityCorruptionMatrixV3Tests(unittest.TestCase):
    temporary: ClassVar[tempfile.TemporaryDirectory[str]]
    payloads: ClassVar[dict[str, dict[str, Any]]]
    corruptions: ClassVar[dict[str, tuple[tuple[str, Any], ...]]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        root = Path(cls.temporary.name)

        final_inputs = final_fixture.FinalAuthorityV3Tests()._chain(
            root / "final-chain"
        )
        final_path = FINAL_AUTHORITY_PHASE_V3.run(
            output_directory=root / "final-authority",
            inputs=final_inputs,
            bindings=(BINDING,),
        ).output_directory

        local_root = root / "local-chain"
        machine_ir_path = local_root / "machine-ir"
        unit = phase_fixture._unit("local:unit", 0x1000, 0x1000, 1)
        ArtifactSetWriterV3(
            artifact_kind="machine-ir-v3-input", bindings=(BINDING,)
        ).write(
            machine_ir_path,
            (ArtifactRecordV3.create("local:unit", unit),),
        )
        exact_path = EXACT_UNITS_PHASE_V3.run(
            output_directory=local_root / "exact",
            inputs={"machine_ir": machine_ir_path},
            bindings=(BINDING,),
        ).output_directory
        exact = EXACT_UNIT_CODEC_V3.read(
            next(ArtifactSetReaderV3(exact_path).iter_records())
        ).value
        semantic_path = SEMANTIC_INDEX_PHASE_V3.run(
            output_directory=local_root / "semantic-index",
            inputs={"exact_units": exact_path},
            bindings=(BINDING,),
        ).output_directory
        transitions_path = TRANSITION_SUMMARIES_PHASE_V3.run(
            output_directory=root / "transitions",
            inputs={"exact_units": exact_path},
            bindings=(BINDING,),
        ).output_directory
        schedule = DependencySchedulingManifestV3.create(
            "f" * 64,
            (DependencyNodePlanV3.create(exact.unit_id),),
        )
        memory_path = MEMORY_VERSIONS_PHASE_V3.run(
            output_directory=root / "memory",
            inputs={
                "semantic_index": semantic_path,
                "transition_summaries": transitions_path,
            },
            bindings=(BINDING,),
            schedule=schedule,
        ).output_directory
        hints_path = root / "target-hints"
        ArtifactSetWriterV3(
            artifact_kind="target-hints-v3", bindings=(BINDING,)
        ).write(hints_path, ())
        targets_path = STRUCTURAL_TARGETS_PHASE_V3.run(
            output_directory=root / "targets",
            inputs={
                "semantic_index": semantic_path,
                "target_hints": hints_path,
            },
            bindings=(BINDING,),
        ).output_directory
        target_inputs, _target_schedule, _exit_id = (
            target_fixture.IndirectTargetCertificatesV3Tests()._chain(
                root / "target-certificate-chain",
                include_evidence=True,
            )
        )

        paths = {
            **final_inputs,
            "final_authority": final_path,
            "indirect_target_certificates": target_inputs[
                "target_certificates"
            ],
            "exact_units": exact_path,
            "memory_versions": memory_path,
            "structural_targets": targets_path,
            "transition_summaries": transitions_path,
        }
        cls.payloads = {}
        for name in _CODECS:
            record = next(ArtifactSetReaderV3(paths[name]).iter_records())
            payload = record.value.to_value()
            if not isinstance(payload, dict) or len(payload) < 6:
                raise AssertionError(
                    f"{name} does not expose the expected strict v3 record"
                )
            _CODECS[name].decode(copy.deepcopy(payload))
            cls.payloads[name] = payload
        cls.corruptions = {}
        for name, payload in cls.payloads.items():
            rejected = []
            for label, mutate in _corruption_specs(payload):
                try:
                    _CODECS[name].decode(mutate(copy.deepcopy(payload)))
                except ArtifactV3Error:
                    rejected.append((label, mutate))
            if len(rejected) < 16:
                raise AssertionError(
                    f"{name} exposes only {len(rejected)} independently rejected corruptions"
                )
            cls.corruptions[name] = tuple(rejected)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def _reject(self, family: str, mutate: Any) -> None:
        payload = copy.deepcopy(self.payloads[family])
        candidate = mutate(payload)
        with self.assertRaises(ArtifactV3Error):
            _CODECS[family].decode(candidate)


def _corruption_specs(payload: dict[str, Any]):
    """Return deterministic, structurally distinct corruptions of one record."""

    specs: list[tuple[str, Any]] = []

    def locate(root: Any, path: tuple[object, ...]) -> Any:
        value = root
        for component in path:
            value = value[component]
        return value

    def parent(root: Any, path: tuple[object, ...]) -> tuple[Any, object]:
        return locate(root, path[:-1]), path[-1]

    def walk(value: Any, path: tuple[object, ...]) -> None:
        if path:
            label = "_".join(str(item) for item in path)

            def replace(root: Any, *, target=path, original=value) -> Any:
                container, key = parent(root, target)
                if isinstance(original, bool):
                    replacement: Any = "not-a-boolean"
                elif isinstance(original, int):
                    replacement = "not-an-integer"
                elif isinstance(original, str):
                    replacement = None
                elif original is None:
                    replacement = {"unexpected": True}
                elif isinstance(original, list):
                    replacement = {"unexpected": True}
                else:
                    replacement = []
                container[key] = replacement
                return root

            specs.append((f"replace_{label}", replace))
            if isinstance(value, str):
                def empty_text(root: Any, *, target=path) -> Any:
                    container, key = parent(root, target)
                    container[key] = ""
                    return root

                specs.append((f"empty_{label}", empty_text))
            elif isinstance(value, bool):
                def invert_boolean(root: Any, *, target=path) -> Any:
                    container, key = parent(root, target)
                    container[key] = not container[key]
                    return root

                specs.append((f"invert_{label}", invert_boolean))
            elif isinstance(value, int):
                def negative_integer(root: Any, *, target=path) -> Any:
                    container, key = parent(root, target)
                    container[key] = -1
                    return root

                specs.append((f"negative_{label}", negative_integer))
            elif value is None:
                def text_for_null(root: Any, *, target=path) -> Any:
                    container, key = parent(root, target)
                    container[key] = "unexpected"
                    return root

                specs.append((f"text_{label}", text_for_null))
        if isinstance(value, dict):
            for key in sorted(value):
                child_path = (*path, key)

                def remove(root: Any, *, target=child_path) -> Any:
                    container, item = parent(root, target)
                    del container[item]
                    return root

                specs.append((f"remove_{'_'.join(map(str, child_path))}", remove))
                walk(value[key], child_path)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, (*path, index))
            target = path

            def append_invalid(root: Any, *, selected=target) -> Any:
                locate(root, selected).append({"unexpected": True})
                return root

            specs.append(
                (f"append_{'_'.join(map(str, path)) or 'root'}", append_invalid)
            )

    walk(payload, ())
    # Keep the first occurrence of each deterministic structural operation.
    result: list[tuple[str, Any]] = []
    seen: set[str] = set()
    for label, operation in specs:
        if label not in seen:
            result.append((label, operation))
            seen.add(label)
    return result


def _missing_field_test(family: str, field_index: int):
    def test(self: AuthorityCorruptionMatrixV3Tests) -> None:
        def mutate(payload: dict[str, Any]) -> dict[str, Any]:
            del payload[sorted(payload)[field_index]]
            return payload

        self._reject(family, mutate)

    return test


def _unknown_field_test(family: str):
    def test(self: AuthorityCorruptionMatrixV3Tests) -> None:
        def mutate(payload: dict[str, Any]) -> dict[str, Any]:
            payload["unexpected_authority_field"] = True
            return payload

        self._reject(family, mutate)

    return test


def _wrong_schema_test(family: str):
    def test(self: AuthorityCorruptionMatrixV3Tests) -> None:
        def mutate(payload: dict[str, Any]) -> dict[str, Any]:
            payload["schema"] = "spaghetti-extractor-wrong-record-v3"
            return payload

        self._reject(family, mutate)

    return test


def _empty_id_test(family: str):
    def test(self: AuthorityCorruptionMatrixV3Tests) -> None:
        def mutate(payload: dict[str, Any]) -> dict[str, Any]:
            payload["id"] = ""
            return payload

        self._reject(family, mutate)

    return test


def _wrong_container_test(family: str, container: Any, label: str):
    def test(self: AuthorityCorruptionMatrixV3Tests) -> None:
        self._reject(family, lambda _payload: copy.deepcopy(container))

    test.__name__ = f"test_{family}_rejects_{label}_container"
    return test


def _structural_corruption_test(family: str, corruption_index: int):
    def test(self: AuthorityCorruptionMatrixV3Tests) -> None:
        specs = self.corruptions[family]
        _label, mutate = specs[corruption_index]
        self._reject(family, mutate)

    return test


for _family in sorted(_CODECS):
    for _index in range(6):
        setattr(
            AuthorityCorruptionMatrixV3Tests,
            f"test_{_family}_rejects_missing_top_level_field_{_index}",
            _missing_field_test(_family, _index),
        )
    setattr(
        AuthorityCorruptionMatrixV3Tests,
        f"test_{_family}_rejects_unknown_top_level_field",
        _unknown_field_test(_family),
    )
    setattr(
        AuthorityCorruptionMatrixV3Tests,
        f"test_{_family}_rejects_wrong_schema",
        _wrong_schema_test(_family),
    )
    setattr(
        AuthorityCorruptionMatrixV3Tests,
        f"test_{_family}_rejects_empty_id",
        _empty_id_test(_family),
    )
    for _label, _container in (
        ("array", []),
        ("null", None),
        ("scalar", "record"),
    ):
        setattr(
            AuthorityCorruptionMatrixV3Tests,
            f"test_{_family}_rejects_{_label}_container",
            _wrong_container_test(_family, _container, _label),
        )
    for _index in range(16):
        setattr(
            AuthorityCorruptionMatrixV3Tests,
            f"test_{_family}_rejects_structural_corruption_{_index:02d}",
            _structural_corruption_test(_family, _index),
        )


if __name__ == "__main__":
    unittest.main()
