from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


# Final-theorem audit policy is intentionally outside static-analysis closures.
_SEPARATE_AXIOM_AUDIT_DECLARATIONS = {
    "RelationalBundle": (
        "StageA.GeneratedRelational.candidateRelationalEvidenceBundle",
    ),
    "RelationalAcceptance": (
        "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentMixedChunked",
        "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked",
        "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent",
    ),
}


@dataclass(frozen=True)
class LeanAxiomAuditResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    elapsed_seconds: float


def _separate_axiom_audit_declaration(
    *, bundle: str, bundle_source: str,
) -> str | None:
    declarations = _SEPARATE_AXIOM_AUDIT_DECLARATIONS.get(bundle)
    if declarations is None:
        return None
    return next(
        (
            candidate
            for candidate in declarations
            if re.search(
                r"^theorem "
                + re.escape(candidate.rsplit(".", maxsplit=1)[-1])
                + r"(?:\s|:)",
                bundle_source,
                re.MULTILINE,
            )
        ),
        declarations[0] if len(declarations) == 1 else None,
    )


def run_separate_axiom_audit(
    *,
    lean: str,
    lean_dir: Path,
    bundle: str,
    memory_arguments: tuple[str, ...],
) -> LeanAxiomAuditResult | None:
    stage_a_dir = lean_dir / "StageA"
    declaration = _separate_axiom_audit_declaration(
        bundle=bundle,
        bundle_source=(stage_a_dir / f"{bundle}.lean").read_text(
            encoding="utf-8"
        ),
    )
    if declaration is None:
        return None

    command = (lean, *memory_arguments, "AxiomAudit.lean")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(
        prefix=".axiom-audit-", dir=lean_dir
    ) as audit_dir_name:
        audit_dir = Path(audit_dir_name)
        (audit_dir / "AxiomAudit.lean").write_text(
            f"import StageA.{bundle}\n"
            f"#print axioms {declaration}\n",
            encoding="utf-8",
        )
        completed = subprocess.run(
            command,
            cwd=audit_dir,
            env={**os.environ, "LEAN_PATH": str(lean_dir)},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
            check=False,
        )
    return LeanAxiomAuditResult(
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        elapsed_seconds=round(time.monotonic() - started, 3),
    )
