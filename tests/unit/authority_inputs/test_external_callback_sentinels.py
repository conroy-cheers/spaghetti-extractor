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
from spaghetti_extractor.artifacts.io import ArtifactSetReaderV3


def _constant(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


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
        "callback_abi": {
            "kind": "generic_callback",
            "argument_words": 1,
            "stack_cleanup_bytes": 0,
            "nullable": False,
        },
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


class ExternalCallbackSentinelTests(unittest.TestCase):
    def _generate(self, root: Path, *, event: dict[str, object]):
        fixture = site_fixture.StandardExternalSiteEvidenceV3Tests()
        return fixture._generate(
            root,
            event=event,
            profile=_callback_profile(),
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
                    "semantic_index": semantic,
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


if __name__ == "__main__":
    unittest.main()
