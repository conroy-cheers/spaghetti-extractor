from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.unit.authority_inputs import test_external_site_evidence as site_fixture
from spaghetti_extractor.authority.external_site_checker import (
    CANONICAL_EXTERNAL_SITES_PHASE_V3,
    _callback_source_replay_blocker,
)
from spaghetti_extractor.authority.external_site_records import (
    CANONICAL_EXTERNAL_SITE_CODEC_V3,
    CallbackSourceDecisionV3,
    ExternalContractV3,
    ExternalProfileV3,
)
from spaghetti_extractor.authority.incoming_call_frames import (
    INCOMING_CALL_FRAMES_PHASE_V3,
)
from spaghetti_extractor.artifacts.io import ArtifactSetReaderV3
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3


CALLBACK_ABI = {
    "kind": "generic_callback",
    "argument_words": 1,
    "stack_cleanup_bytes": 0,
    "nullable": False,
}


def _constant(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def _register(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _finite_choice(
    first: dict[str, object], second: dict[str, object]
) -> dict[str, object]:
    return {
        "op": "ite",
        "args": [_register("eax"), first, second],
    }


def _requirement(rva: int = 0x2000) -> dict[str, object]:
    return {
        "target_unit_id": f"callback:{rva:x}",
        "target_rva": rva,
        "abi_sha256": canonical_sha256_v3(CALLBACK_ABI),
        "lifetime": "process",
    }


def _callback_event(
    handler: dict[str, object],
    *,
    callback_requirements: object = ...,
) -> dict[str, object]:
    event = site_fixture._event()
    event["symbol"] = "Register"
    event["arguments"] = [_constant(4), handler]
    abi = event["abi_contract"]
    assert isinstance(abi, dict)
    abi["argument_words"] = 2
    abi["world_effect"] = "callbackRegistration"
    abi["callback_effect"] = "registers"
    if callback_requirements is ...:
        event.pop("callback_requirements")
    else:
        event["callback_requirements"] = callback_requirements
    return event


def _callback_profile() -> ExternalProfileV3:
    machine_contract = {
        "abi_template": "pe32-cdecl-v1",
        "argument_words": 2,
        "disposition": "returns",
        "memory_effect": "none",
        "memory_footprints": [],
        "world_effect": "callbackRegistration",
        "callback_effect": "registers",
        "callback_behavior": "registration",
        "callback_source": {
            "kind": "argument_word",
            "argument": 1,
            "non_callback_sentinel_words": [0, 1],
        },
        "callback_lifetime": "process",
        "callback_abi": CALLBACK_ABI,
        "result_register_relations": [],
        "out_pointer_relations": [],
        "out_interface_relations": [],
    }
    return ExternalProfileV3.create(
        profile_id="fixture-profile",
        profile_sha256=site_fixture.PROFILE_SHA256,
        identity={
            "kind": "import",
            "dll": "fixture.dll",
            "symbol": "Register",
            "ordinal": None,
        },
        allowed_transfers=("call",),
        allowed_dispositions=("returns",),
        argument_words=2,
        memory_effect="none",
        world_effect="callbackRegistration",
        callback_effect="registers",
        machine_contract=machine_contract,
    )


def _tail_callback_profile() -> ExternalProfileV3:
    machine_contract = {
        "abi_template": "pe32-cdecl-v1",
        "argument_words": 1,
        "disposition": "tail_jump",
        "memory_effect": "none",
        "memory_footprints": [],
        "world_effect": "callbackRegistration",
        "callback_effect": "registers",
        "callback_behavior": "registration",
        "callback_source": {
            "kind": "argument_word",
            "argument": 0,
            "non_callback_sentinel_words": [0],
        },
        "callback_lifetime": "process",
        "callback_abi": CALLBACK_ABI,
        "result_register_relations": [],
        "out_pointer_relations": [],
        "out_interface_relations": [],
    }
    return ExternalProfileV3.create(
        profile_id="fixture-profile",
        profile_sha256=site_fixture.PROFILE_SHA256,
        identity={
            "kind": "import",
            "dll": "fixture.dll",
            "symbol": "RegisterTail",
            "ordinal": None,
        },
        allowed_transfers=("jump",),
        allowed_dispositions=("tail_jump",),
        argument_words=1,
        memory_effect="none",
        world_effect="callbackRegistration",
        callback_effect="registers",
        machine_contract=machine_contract,
    )


def _tail_callback_event() -> dict[str, object]:
    event = site_fixture._event()
    event.update(
        {
            "kind": "external_jump",
            "symbol": "RegisterTail",
            "arguments": [],
            "register_inputs": {"esp": _register("esp")},
            "stack_inputs": [],
        }
    )
    event.pop("callback_requirements")
    abi = event["abi_contract"]
    assert isinstance(abi, dict)
    abi.update(
        {
            "argument_words": 1,
            "disposition": "tail_jump",
            "world_effect": "callbackRegistration",
            "callback_effect": "registers",
        }
    )
    return event


def _incoming_callback_caller(
    callback_va: int, *, adjusted_esp: bool = False
) -> dict[str, object]:
    call_esp = (
        {
            "op": "sub32",
            "args": [_register("esp"), _constant(4)],
        }
        if adjusted_esp
        else _register("esp")
    )
    memory_write = {
        "family": "memory",
        "kind": "write",
        "width": 4,
        "address": call_esp,
        "value": _constant(callback_va),
    }
    call = {
        "family": "external",
        "kind": "internal_call",
        "target_rva": 0x1000,
        "return_rva": 0x3008,
        "register_inputs": {"esp": call_esp},
        "stack_inputs": [
            {
                "offset": 0,
                "width": 4,
                "value": {
                    "op": "load",
                    "width": 4,
                    "address": call_esp,
                },
            }
        ],
        "flag_inputs": {},
        "effect_model": "uninterpreted_internal_call_response_v1",
    }
    unit = site_fixture._unit(call, ordered_prefix=(memory_write,))
    unit["id"] = "caller:unit"
    source = unit["source"]
    assert isinstance(source, dict)
    source["original"] = {"rva_start": 0x3000, "rva_end": 0x3008}
    return unit


def _incoming_frames(root: Path, semantic: Path, transitions: Path) -> Path:
    return INCOMING_CALL_FRAMES_PHASE_V3.run(
        output_directory=root / "incoming-call-frames",
        inputs={
            "semantic_index": semantic,
            "transition_summaries": transitions,
        },
        bindings=(site_fixture.BINDING,),
    ).output_directory


class ExternalCallbackSentinelTests(unittest.TestCase):
    def _generate(
        self,
        root: Path,
        *,
        event: dict[str, object],
        ordered_prefix: tuple[dict[str, object], ...] = (),
        additional_units: tuple[dict[str, object], ...] = (),
    ):
        fixture = site_fixture.StandardExternalSiteEvidenceV3Tests()
        return fixture._generate(
            root,
            event=event,
            profile=_callback_profile(),
            ordered_prefix=ordered_prefix,
            additional_units=additional_units,
        )

    def test_exact_sentinel_authorizes_without_registration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                _manifest,
                evidence,
                output,
                semantic,
                transitions,
                targets,
                profiles,
                exact,
                _event_value,
            ) = self._generate(root, event=_callback_event(_constant(1)))
            self.assertEqual(evidence.status, "complete")
            assert evidence.contract is not None
            self.assertEqual(evidence.contract.callbacks, ())
            self.assertEqual(
                evidence.contract.callback_source_decision,
                CallbackSourceDecisionV3.create(
                    kind="non_callback_sentinel",
                    argument_index=1,
                    source_expression=_constant(1),
                    sentinel_word=1,
                ),
            )

            canonical = CANONICAL_EXTERNAL_SITES_PHASE_V3.run(
                output_directory=root / "canonical",
                inputs={
                    "external_profiles": profiles,
                    "external_site_evidence": output,
                    "incoming_call_frames": _incoming_frames(
                        root, semantic, transitions
                    ),
                    "semantic_index": semantic,
                    "static_value_origins": root / "static-values",
                    "target_certificates": targets,
                    "transition_summaries": transitions,
                },
                bindings=(site_fixture.BINDING,),
            ).output_directory
            checked = CANONICAL_EXTERNAL_SITE_CODEC_V3.read(
                ArtifactSetReaderV3(canonical).get_record(exact.unit_id)
            ).value
            self.assertEqual(checked.status, "complete")
            self.assertTrue(checked.authorizing)

    def test_exact_image_callback_derives_checked_entry_requirement(self) -> None:
        callback_unit = site_fixture._unit(site_fixture._event())
        callback_unit["id"] = "callback:unit"
        source = callback_unit["source"]
        assert isinstance(source, dict)
        source["original"] = {"rva_start": 0x2000, "rva_end": 0x2008}
        semantics = callback_unit["semantics"]
        assert isinstance(semantics, dict)
        semantics["external_events"] = []
        semantics["ordered_events"] = []
        counts = semantics["counts"]
        assert isinstance(counts, dict)
        counts["external_events"] = 0
        counts["ordered_events"] = 0
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                _manifest,
                evidence,
                output,
                semantic,
                transitions,
                targets,
                profiles,
                exact,
                _event_value,
            ) = self._generate(
                root,
                event=_callback_event(_constant(site_fixture.IMAGE_BASE + 0x2000)),
                additional_units=(callback_unit,),
            )
            self.assertEqual(evidence.status, "complete")
            assert evidence.contract is not None
            self.assertEqual(len(evidence.contract.callbacks), 1)
            callback = evidence.contract.callbacks[0]
            self.assertEqual(callback.target_unit_id, "callback:unit")
            self.assertEqual(callback.target_rva, 0x2000)
            self.assertEqual(callback.abi_sha256, canonical_sha256_v3(CALLBACK_ABI))
            self.assertEqual(callback.lifetime, "process")

            canonical = CANONICAL_EXTERNAL_SITES_PHASE_V3.run(
                output_directory=root / "canonical-derived-callback",
                inputs={
                    "external_profiles": profiles,
                    "external_site_evidence": output,
                    "incoming_call_frames": _incoming_frames(
                        root, semantic, transitions
                    ),
                    "semantic_index": semantic,
                    "static_value_origins": root / "static-values",
                    "target_certificates": targets,
                    "transition_summaries": transitions,
                },
                bindings=(site_fixture.BINDING,),
            ).output_directory
            checked = CANONICAL_EXTERNAL_SITE_CODEC_V3.read(
                ArtifactSetReaderV3(canonical).get_record(exact.unit_id)
            ).value
            self.assertEqual(checked.status, "complete")
            self.assertTrue(checked.authorizing)

    def test_tail_thunk_callback_is_instantiated_from_incoming_call_frame(self) -> None:
        callback_unit = site_fixture._unit(site_fixture._event())
        callback_unit["id"] = "callback:unit"
        callback_source = callback_unit["source"]
        assert isinstance(callback_source, dict)
        callback_source["original"] = {
            "rva_start": 0x2000,
            "rva_end": 0x2008,
        }
        callback_semantics = callback_unit["semantics"]
        assert isinstance(callback_semantics, dict)
        callback_semantics["external_events"] = []
        callback_semantics["ordered_events"] = []
        callback_counts = callback_semantics["counts"]
        assert isinstance(callback_counts, dict)
        callback_counts["external_events"] = 0
        callback_counts["ordered_events"] = 0

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = site_fixture.StandardExternalSiteEvidenceV3Tests()
            (
                _manifest,
                evidence,
                output,
                semantic,
                transitions,
                targets,
                profiles,
                exact,
                _event_value,
            ) = fixture._generate(
                root,
                event=_tail_callback_event(),
                profile=_tail_callback_profile(),
                additional_units=(
                    callback_unit,
                    _incoming_callback_caller(site_fixture.IMAGE_BASE + 0x2000),
                ),
            )
            self.assertEqual(evidence.status, "complete")
            assert evidence.contract is not None
            self.assertEqual(
                tuple(row.target_unit_id for row in evidence.contract.callbacks),
                ("callback:unit",),
            )
            dependency_ids = {
                (row.input_name, row.record_id)
                for row in ArtifactSetReaderV3(output)
                .get_record(evidence.record_id)
                .dependencies
            }
            self.assertIn(("semantic_index", "caller:unit"), dependency_ids)
            self.assertIn(
                ("transition_summaries", "caller:unit"), dependency_ids
            )

            canonical = CANONICAL_EXTERNAL_SITES_PHASE_V3.run(
                output_directory=root / "canonical-tail-frame",
                inputs={
                    "external_profiles": profiles,
                    "external_site_evidence": output,
                    "incoming_call_frames": _incoming_frames(
                        root, semantic, transitions
                    ),
                    "semantic_index": semantic,
                    "static_value_origins": root / "static-values",
                    "target_certificates": targets,
                    "transition_summaries": transitions,
                },
                bindings=(site_fixture.BINDING,),
            ).output_directory
            checked = CANONICAL_EXTERNAL_SITE_CODEC_V3.read(
                ArtifactSetReaderV3(canonical).get_record(exact.unit_id)
            ).value
            self.assertEqual(checked.status, "complete")
            self.assertTrue(checked.authorizing)

    def test_tail_thunk_call_frame_tracks_adjusted_esp(self) -> None:
        callback_unit = site_fixture._unit(site_fixture._event())
        callback_unit["id"] = "callback:unit"
        callback_source = callback_unit["source"]
        assert isinstance(callback_source, dict)
        callback_source["original"] = {
            "rva_start": 0x2000,
            "rva_end": 0x2008,
        }
        callback_semantics = callback_unit["semantics"]
        assert isinstance(callback_semantics, dict)
        callback_semantics["external_events"] = []
        callback_semantics["ordered_events"] = []
        callback_counts = callback_semantics["counts"]
        assert isinstance(callback_counts, dict)
        callback_counts["external_events"] = 0
        callback_counts["ordered_events"] = 0
        with tempfile.TemporaryDirectory() as temporary:
            evidence = site_fixture.StandardExternalSiteEvidenceV3Tests()._generate(
                Path(temporary),
                event=_tail_callback_event(),
                profile=_tail_callback_profile(),
                additional_units=(
                    callback_unit,
                    _incoming_callback_caller(
                        site_fixture.IMAGE_BASE + 0x2000,
                        adjusted_esp=True,
                    ),
                ),
            )[1]
            self.assertEqual(evidence.status, "complete")
            assert evidence.contract is not None
            self.assertEqual(
                tuple(row.target_unit_id for row in evidence.contract.callbacks),
                ("callback:unit",),
            )

    def test_source_without_exact_provenance_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence = self._generate(
                Path(temporary),
                event=_callback_event(site_fixture._register("edx")),
            )[1]
            self.assertEqual(evidence.status, "incomplete")
            assert evidence.primary_blocker is not None
            self.assertEqual(
                evidence.primary_blocker.code,
                "external_callback_source_provenance_missing",
            )

    def test_exact_register_origin_authorizes_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = _callback_event(_register("edx"))
            event["register_inputs"] = {"edx": _constant(1)}
            evidence = self._generate(Path(temporary), event=event)[1]

            self.assertEqual(evidence.status, "complete")
            assert evidence.contract is not None
            self.assertEqual(
                evidence.contract.callback_source_decision,
                CallbackSourceDecisionV3.create(
                    kind="non_callback_sentinel",
                    argument_index=1,
                    source_expression=_register("edx"),
                    sentinel_word=1,
                ),
            )

    def test_exact_stack_origin_authorizes_sentinel(self) -> None:
        handler = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [_register("esp"), _constant(4)],
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            event = _callback_event(handler)
            event["stack_inputs"] = [
                {"offset": 4, "width": 4, "value": _constant(0)}
            ]
            evidence = self._generate(Path(temporary), event=event)[1]

            self.assertEqual(evidence.status, "complete")
            assert evidence.contract is not None
            decision = evidence.contract.callback_source_decision
            assert decision is not None
            self.assertEqual(decision.kind, "non_callback_sentinel")
            self.assertEqual(decision.source_expression.to_value(), handler)
            self.assertEqual(decision.sentinel_word, 0)

    def test_preceding_stack_write_authorizes_sentinel_and_replays(self) -> None:
        handler = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [_register("esp"), _constant(4)],
            },
        }
        event = _callback_event(handler)
        event["register_inputs"] = {"esp": _register("esp")}
        write = {
            "family": "memory",
            "kind": "write",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [_register("esp"), _constant(4)],
            },
            "value": _constant(1),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                _manifest,
                evidence,
                output,
                semantic,
                transitions,
                targets,
                profiles,
                exact,
                _event_value,
            ) = self._generate(
                root,
                event=event,
                ordered_prefix=(write,),
            )
            self.assertEqual(evidence.status, "complete")
            assert evidence.contract is not None
            decision = evidence.contract.callback_source_decision
            assert decision is not None
            self.assertEqual(decision.kind, "non_callback_sentinel")
            self.assertEqual(decision.sentinel_word, 1)

            canonical = CANONICAL_EXTERNAL_SITES_PHASE_V3.run(
                output_directory=root / "canonical",
                inputs={
                    "external_profiles": profiles,
                    "external_site_evidence": output,
                    "incoming_call_frames": _incoming_frames(
                        root, semantic, transitions
                    ),
                    "semantic_index": semantic,
                    "static_value_origins": root / "static-values",
                    "target_certificates": targets,
                    "transition_summaries": transitions,
                },
                bindings=(site_fixture.BINDING,),
            ).output_directory
            checked = CANONICAL_EXTERNAL_SITE_CODEC_V3.read(
                ArtifactSetReaderV3(canonical).get_record(exact.unit_id)
            ).value
            self.assertEqual(checked.status, "complete")
            self.assertTrue(checked.authorizing)

    def test_overlapping_stack_write_keeps_callback_source_incomplete(self) -> None:
        handler = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [_register("esp"), _constant(4)],
            },
        }
        event = _callback_event(handler)
        event["register_inputs"] = {"esp": _register("esp")}
        overlapping_write = {
            "family": "memory",
            "kind": "write",
            "width": 2,
            "address": {
                "op": "add32",
                "args": [_register("esp"), _constant(5)],
            },
            "value": _constant(1),
        }
        with tempfile.TemporaryDirectory() as temporary:
            evidence = self._generate(
                Path(temporary),
                event=event,
                ordered_prefix=(overlapping_write,),
            )[1]
            self.assertEqual(evidence.status, "incomplete")
            assert evidence.primary_blocker is not None
            self.assertEqual(
                evidence.primary_blocker.code,
                "external_callback_source_provenance_missing",
            )

    def test_bounded_non_sentinel_alternatives_authorize_callback(self) -> None:
        handler = _finite_choice(_constant(0x401000), _constant(0x402000))
        with tempfile.TemporaryDirectory() as temporary:
            event = _callback_event(
                handler,
                callback_requirements=[_requirement(0x1000), _requirement(0x2000)],
            )
            evidence = self._generate(Path(temporary), event=event)[1]

            self.assertEqual(evidence.status, "complete")
            assert evidence.contract is not None
            decision = evidence.contract.callback_source_decision
            assert decision is not None
            self.assertEqual(decision.kind, "callback_target")
            self.assertEqual(decision.source_expression.to_value(), handler)
            self.assertIsNone(
                _callback_source_replay_blocker(
                    evidence.contract,
                    _callback_profile(),
                    event,
                )
            )

    def test_mixed_sentinel_and_callback_alternatives_are_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence = self._generate(
                Path(temporary),
                event=_callback_event(
                    _finite_choice(_constant(0), _constant(0x401000)),
                    callback_requirements=[_requirement()],
                ),
            )[1]

            self.assertEqual(evidence.status, "incomplete")
            assert evidence.primary_blocker is not None
            self.assertEqual(
                evidence.primary_blocker.code,
                "external_callback_source_provenance_missing",
            )

    def test_oversized_finite_alternative_set_is_incomplete(self) -> None:
        handler = _constant(0x401000)
        for index in range(32):
            handler = _finite_choice(_constant(0x401001 + index), handler)
        with tempfile.TemporaryDirectory() as temporary:
            evidence = self._generate(
                Path(temporary),
                event=_callback_event(
                    handler,
                    callback_requirements=[_requirement()],
                ),
            )[1]

            self.assertEqual(evidence.status, "incomplete")
            assert evidence.primary_blocker is not None
            self.assertEqual(
                evidence.primary_blocker.code,
                "external_callback_source_provenance_missing",
            )

    def test_contradictory_register_and_stack_origins_are_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = _callback_event(_register("edx"))
            event["register_inputs"] = {"edx": _constant(0)}
            event["stack_inputs"] = [
                {"offset": 4, "width": 4, "value": _constant(2)}
            ]
            evidence = self._generate(Path(temporary), event=event)[1]

            self.assertEqual(evidence.status, "violated")
            assert evidence.primary_blocker is not None
            self.assertEqual(
                evidence.primary_blocker.code,
                "external_callback_source_contradiction",
            )

    def test_sentinel_with_targets_is_violated(self) -> None:
        requirement = {
            "target_unit_id": "callback:unit",
            "target_rva": 0x2000,
            "abi_sha256": "d" * 64,
            "lifetime": "process",
        }
        with tempfile.TemporaryDirectory() as temporary:
            evidence = self._generate(
                Path(temporary),
                event=_callback_event(
                    _constant(0),
                    callback_requirements=[requirement],
                ),
            )[1]
            self.assertEqual(evidence.status, "violated")
            assert evidence.primary_blocker is not None
            self.assertEqual(
                evidence.primary_blocker.code,
                "external_callback_source_contradiction",
            )

    def test_canonical_checker_replays_sentinel_decision(self) -> None:
        profile = _callback_profile()
        contract = ExternalContractV3.create(
            identity=profile.identity.to_value(),
            transfer_kind="call",
            disposition="returns",
            profile_id=profile.profile_id,
            profile_sha256=profile.profile_sha256,
            argument_words=2,
            arguments=(_constant(4), _constant(0)),
            memory_effect=profile.memory_effect,
            world_effect=profile.world_effect,
            callback_effect=profile.callback_effect,
            machine_contract=profile.machine_contract.to_value(),
            callback_source_decision=CallbackSourceDecisionV3.create(
                kind="non_callback_sentinel",
                argument_index=1,
                source_expression=_constant(0),
                sentinel_word=1,
            ),
        )
        blocker = _callback_source_replay_blocker(contract, profile)
        assert blocker is not None
        self.assertEqual(blocker.status, "violated")
        self.assertEqual(
            blocker.code,
            "external_callback_source_contradiction",
        )

    def test_canonical_checker_replays_register_origin(self) -> None:
        profile = _callback_profile()
        expression = _register("edx")
        contract = ExternalContractV3.create(
            identity=profile.identity.to_value(),
            transfer_kind="call",
            disposition="returns",
            profile_id=profile.profile_id,
            profile_sha256=profile.profile_sha256,
            argument_words=2,
            arguments=(_constant(4), expression),
            memory_effect=profile.memory_effect,
            world_effect=profile.world_effect,
            callback_effect=profile.callback_effect,
            machine_contract=profile.machine_contract.to_value(),
            callback_source_decision=CallbackSourceDecisionV3.create(
                kind="non_callback_sentinel",
                argument_index=1,
                source_expression=expression,
                sentinel_word=0,
            ),
        )
        event = _callback_event(expression, callback_requirements=[])
        event["register_inputs"] = {"edx": _constant(1)}

        blocker = _callback_source_replay_blocker(contract, profile, event)

        assert blocker is not None
        self.assertEqual(blocker.status, "violated")
        self.assertEqual(
            blocker.code,
            "external_callback_source_contradiction",
        )


if __name__ == "__main__":
    unittest.main()
