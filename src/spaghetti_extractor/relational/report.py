from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ..stage_binary import StageAInputError


STAGE_A_NIX_BUILD_REPORT_FORMAT = "stage-a-relational-nix-build-v1"
STAGE_A_PROOF_HANDOFF_FORMAT = "stage-a-proof-handoff-v1"
_DISPOSITIONS = frozenset({"fail", "incomplete", "pass"})


@dataclass(frozen=True)
class NixBuildReport:
    payload: Mapping[str, Any]
    verdict: str
    status: str

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "NixBuildReport":
        if payload.get("format") != STAGE_A_NIX_BUILD_REPORT_FORMAT:
            raise StageAInputError(
                "Stage A proof callback requires a "
                f"{STAGE_A_NIX_BUILD_REPORT_FORMAT} verdict"
            )
        verdict = payload.get("verdict")
        status = payload.get("status")
        if verdict not in _DISPOSITIONS or status not in _DISPOSITIONS:
            raise StageAInputError(
                "Stage A Nix proof report has an unsupported disposition"
            )
        if verdict != status:
            raise StageAInputError(
                "Stage A Nix proof report status and verdict disagree"
            )
        return cls(payload=payload, verdict=verdict, status=status)

    @property
    def declares_checked_pass(self) -> bool:
        audit = self.payload.get("lean_audit")
        checks = self.payload.get("checks")
        return (
            self.verdict == "pass"
            and isinstance(checks, Mapping)
            and bool(checks)
            and all(value is True for value in checks.values())
            and isinstance(audit, Mapping)
            and audit.get("status") == "checked"
            and audit.get("lean_trust") == 0
            and audit.get("theorem")
            == self.payload.get("expected_final_theorem")
        )


__all__ = [
    "NixBuildReport",
    "STAGE_A_NIX_BUILD_REPORT_FORMAT",
    "STAGE_A_PROOF_HANDOFF_FORMAT",
]
