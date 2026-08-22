from __future__ import annotations

import unittest

from spaghetti_extractor.authority.callbacks import CALLBACK_AUTHORITY_PHASE_V3
from spaghetti_extractor.authority.exceptional_transitions import (
    EXCEPTIONAL_TRANSITIONS_PHASE_V3,
)
from spaghetti_extractor.authority.external_site_checker import (
    CANONICAL_EXTERNAL_SITES_PHASE_V3,
)
from spaghetti_extractor.authority.incoming_call_frames import (
    INCOMING_CALL_FRAMES_PHASE_V3,
)
from spaghetti_extractor.authority.root_closure import (
    LAUNCH_ROOT_CLOSURE_PHASE_V3,
)


class LateAuthorityPhaseContractV3Tests(unittest.TestCase):
    def test_phase_forms_kinds_and_input_kind_contracts_are_exact(self) -> None:
        observed = {
            phase.name: (
                phase.form,
                phase.output_artifact_kind,
                dict(phase.input_artifact_kinds),
                phase.completeness is not None,
            )
            for phase in (
                CANONICAL_EXTERNAL_SITES_PHASE_V3,
                INCOMING_CALL_FRAMES_PHASE_V3,
                CALLBACK_AUTHORITY_PHASE_V3,
                LAUNCH_ROOT_CLOSURE_PHASE_V3,
                EXCEPTIONAL_TRANSITIONS_PHASE_V3,
            )
        }
        self.assertEqual(
            observed,
            {
                "canonical-external-sites-v3": (
                    "map_units",
                    "canonical-external-sites-v3",
                    {
                        "external_profiles": "external-profile-authority-v3",
                        "external_site_evidence": "external-site-evidence-v3",
                        "incoming_call_frames": "incoming-call-frames-v3",
                        "semantic_index": "semantic-index-v3",
                        "static_value_origins": "pe32-static-value-origins-v3",
                        "target_certificates": "indirect-target-certificates-v3",
                        "transition_summaries": "transition-summaries-v3",
                    },
                    True,
                ),
                "incoming-call-frames-v3": (
                    "reduce",
                    "incoming-call-frames-v3",
                    {
                        "semantic_index": "semantic-index-v3",
                        "transition_summaries": "transition-summaries-v3",
                    },
                    True,
                ),
                "callback-authority-v4": (
                    "map_units",
                    "callback-authority-v4",
                    {
                        "callback_evidence": "callback-evidence-v4",
                        "external_sites": "canonical-external-sites-v3",
                        "incoming_call_frames": "incoming-call-frames-v3",
                    },
                    True,
                ),
                "launch-root-closure-v3": (
                    "reduce",
                    "launch-root-closure-v3",
                    {
                        "callbacks": "callback-authority-v4",
                        "external_sites": "canonical-external-sites-v3",
                        "launch_roots": "launch-root-evidence-v3",
                        "semantic_index": "semantic-index-v3",
                        "target_certificates": "indirect-target-certificates-v3",
                    },
                    True,
                ),
                "exceptional-transitions-v3": (
                    "map_units",
                    "exceptional-transitions-v3",
                    {
                        "exception_evidence": "exception-evidence-v3",
                        "semantic_index": "semantic-index-v3",
                    },
                    True,
                ),
            },
        )


if __name__ == "__main__":
    unittest.main()
