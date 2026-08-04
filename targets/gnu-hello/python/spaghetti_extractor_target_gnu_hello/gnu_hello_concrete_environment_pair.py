"""Generate a non-vacuous GNU hello source/native environment pair profile.

The input names one already Lean-checked concrete pair.  The generated module
turns that value into the singleton admitted relation consumed by the native
source environment-family pipeline.  Static JSON inventories are diagnostic
cross-checks only: the pair's ``ExactWorldNativeExternalEvidence`` remains the
authority for complete 1:1 site coverage and its strengthened ABI field remains
the authority for returned machine state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from spaghetti_extractor.errors import StageAInputError


GNU_HELLO_CONCRETE_ENVIRONMENT_PAIR_INPUT_FORMAT = (
    "stage-a-gnu-hello-concrete-environment-pair-input-v1"
)
GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_PROFILE_FORMAT = (
    "stage-a-gnu-hello-environment-family-evidence-profile-v1"
)
GNU_HELLO_CONCRETE_ENVIRONMENT_PAIR_REPORT_FORMAT = (
    "stage-a-gnu-hello-concrete-environment-pair-v1"
)
GNU_HELLO_CONCRETE_ENVIRONMENT_PAIR_MODULE = (
    "GeneratedGnuHelloConcreteEnvironmentPair"
)
GNU_HELLO_CONCRETE_ENVIRONMENT_PAIR_NAMESPACE = (
    "StageA.GeneratedRelational.GnuHelloConcreteEnvironmentPair"
)

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LEAN_NAME = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)


class GnuHelloConcreteEnvironmentPairError(StageAInputError):
    """Concrete pair input is incomplete or internally inconsistent."""


@dataclass(frozen=True)
class GnuHelloConcreteEnvironmentPairOutputs:
    module: Path
    profile: Path
    report: Path


def write_gnu_hello_concrete_environment_pair(
    out: Path | str, *, input_manifest: Path | str
) -> GnuHelloConcreteEnvironmentPairOutputs:
    input_path = Path(input_manifest)
    payload = _read_json(input_path)
    _exact_keys(
        payload,
        {
            "format",
            "candidate_sha256",
            "reachable_external_site_ids",
            "lockstep_sites",
            "lean",
        },
        "concrete environment-pair input",
    )
    if payload["format"] != GNU_HELLO_CONCRETE_ENVIRONMENT_PAIR_INPUT_FORMAT:
        raise GnuHelloConcreteEnvironmentPairError(
            "unsupported concrete environment-pair input format"
        )
    candidate_sha256 = _sha(payload["candidate_sha256"], "candidate_sha256")
    reachable_ids = _site_ids(
        payload["reachable_external_site_ids"], "reachable_external_site_ids"
    )
    sites = _lockstep_sites(payload["lockstep_sites"])
    site_ids = tuple(site["id"] for site in sites)
    if site_ids != reachable_ids:
        missing = sorted(set(reachable_ids) - set(site_ids))
        extra = sorted(set(site_ids) - set(reachable_ids))
        raise GnuHelloConcreteEnvironmentPairError(
            "lockstep site inventory is not exact for reachable external sites: "
            f"missing={missing}, extra={extra}"
        )

    lean = _object(payload["lean"], "concrete environment-pair Lean input")
    _exact_keys(
        lean,
        {
            "imports",
            "context",
            "sites",
            "static_compilation",
            "static_authority",
            "checked_pair",
        },
        "concrete environment-pair Lean input",
    )
    imports = _imports(lean["imports"])
    refs = {
        key: _lean_name(lean[key], key)
        for key in (
            "context",
            "sites",
            "static_compilation",
            "static_authority",
            "checked_pair",
        )
    }

    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    module_path = stage_a / f"{GNU_HELLO_CONCRETE_ENVIRONMENT_PAIR_MODULE}.lean"
    module_path.write_text(_lean_source(imports, refs), encoding="ascii")
    module_name = f"StageA.{GNU_HELLO_CONCRETE_ENVIRONMENT_PAIR_MODULE}"
    row = {
        "module": module_name,
        "path": str(module_path.resolve()),
        "sha256": _file_sha256(module_path),
    }
    profile_path = root / "environment-family-profile.json"
    profile = {
        "format": GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_PROFILE_FORMAT,
        "candidate_sha256": candidate_sha256,
        "lockstep": {
            "mode": "exact-1:1-machine-import-v1",
            "sites": sites,
        },
        "lean": {
            "module_sources": [row],
            "source_family_scope": "admitted_pairs",
            "launch_scope": "admitted_pairs",
            **{
                name: {
                    "module": module_name,
                    "declaration": (
                        f"{GNU_HELLO_CONCRETE_ENVIRONMENT_PAIR_NAMESPACE}.{decl}"
                    ),
                }
                for name, decl in {
                    "context": "context",
                    "sites": "sites",
                    "static_authority": "staticAuthority",
                    "pair_relation": "PairRelated",
                    "pair_realizable": "pairRealizable",
                    "external_evidence_at": "externalEvidenceAt",
                    "source_family_at": "sourceFamilyAt",
                    "launch_realizable_at": "launchRealizableAt",
                }.items()
            },
        },
    }
    _write_json(profile_path, profile)
    report_path = root / "concrete-environment-pair.json"
    _write_json(
        report_path,
        {
            "format": GNU_HELLO_CONCRETE_ENVIRONMENT_PAIR_REPORT_FORMAT,
            "status": "source-ready",
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "proof_authority": False,
            "acceptance_authority": False,
            "candidate_sha256": candidate_sha256,
            "reachable_external_sites": len(reachable_ids),
            "lockstep_sites": len(sites),
            "site_coverage": "exact",
            "pair_cardinality": 1,
            "returned_result_contract": (
                "opaque-state-rel-plus-machine-call-abi-v1"
            ),
            "module": module_name,
            "module_sha256": row["sha256"],
        },
    )
    return GnuHelloConcreteEnvironmentPairOutputs(
        module=module_path, profile=profile_path, report=report_path
    )


def _lean_source(imports: Sequence[str], refs: Mapping[str, str]) -> str:
    import_lines = "\n".join(
        f"import {module}"
        for module in dict.fromkeys(
            ("StageA.RelationalNativeSourceConcreteEnvironmentPair", *imports)
        )
    )
    ns = GNU_HELLO_CONCRETE_ENVIRONMENT_PAIR_NAMESPACE
    return f"""{import_lines}

namespace {ns}

open StageA.Relational
open StageA.Relational.NativeSource

abbrev context : StaticProofContext := {refs['context']}
def sites : List OpaqueLockstepCallSite := {refs['sites']}
abbrev staticCompilation : ExactNativeCompilation := {refs['static_compilation']}
def staticAuthority :
    StaticNativeSourceEnvironmentFamilyAuthority context staticCompilation :=
  {refs['static_authority']}
def checkedPair :
    CheckedConcreteWorldNativeEnvironmentPair context sites staticCompilation :=
  {refs['checked_pair']}

abbrev PairRelated := checkedPair.Related

theorem pairRealizable : exists sourceEnvironment nativeEnvironment,
    PairRelated sourceEnvironment nativeEnvironment :=
  checkedPair.realizable

theorem externalEvidenceAt : forall sourceEnvironment nativeEnvironment,
    PairRelated sourceEnvironment nativeEnvironment ->
    ExactWorldNativeExternalEvidence context
      (exactNativeCompilationAtEnvironments staticCompilation sourceEnvironment
        nativeEnvironment).project.worldProgram
      (exactNativeCompilationAtEnvironments staticCompilation sourceEnvironment
        nativeEnvironment).machineAuthority.program sites sourceEnvironment :=
  checkedPair.externalEvidenceAt

theorem sourceFamilyAt : forall sourceEnvironment nativeEnvironment,
    PairRelated sourceEnvironment nativeEnvironment ->
    CheckedNativeSourceLaunchFamily
      (exactNativeCompilationAtEnvironments staticCompilation sourceEnvironment
        nativeEnvironment).project :=
  checkedPair.sourceFamilyAt

theorem launchRealizableAt : forall sourceEnvironment nativeEnvironment,
    PairRelated sourceEnvironment nativeEnvironment ->
    NativeCompilationLaunchRealizable
      (exactNativeCompilationAtEnvironments staticCompilation sourceEnvironment
        nativeEnvironment).machineAuthority :=
  checkedPair.launchRealizableAt

end {ns}
"""


def _lockstep_sites(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value:
        raise GnuHelloConcreteEnvironmentPairError(
            "lockstep_sites must be a non-empty array"
        )
    result: list[dict[str, object]] = []
    expected = {
        "id",
        "import_identity",
        "disposition",
        "argument_sources",
        "read_footprints",
        "write_footprints",
        "callbacks",
        "footprints_complete",
        "callbacks_complete",
    }
    for index, raw in enumerate(value):
        label = f"lockstep_sites[{index}]"
        site = _object(raw, label)
        _exact_keys(site, expected, label)
        site_id = _natural(site["id"], f"{label}.id")
        if site["disposition"] not in {"returns", "terminates"}:
            raise GnuHelloConcreteEnvironmentPairError(
                f"{label}.disposition is unsupported"
            )
        _nonempty_string(site["import_identity"], f"{label}.import_identity")
        for field in (
            "argument_sources",
            "read_footprints",
            "write_footprints",
            "callbacks",
        ):
            if not isinstance(site[field], list):
                raise GnuHelloConcreteEnvironmentPairError(
                    f"{label}.{field} must be an explicit array"
                )
        if site["footprints_complete"] is not True:
            raise GnuHelloConcreteEnvironmentPairError(
                f"{label} has incomplete memory footprints"
            )
        if site["callbacks_complete"] is not True:
            raise GnuHelloConcreteEnvironmentPairError(
                f"{label} has incomplete callback footprints"
            )
        result.append({**site, "id": site_id})
    ids = tuple(site["id"] for site in result)
    if ids != tuple(sorted(set(ids))):
        raise GnuHelloConcreteEnvironmentPairError(
            "lockstep site IDs must be unique and canonically sorted"
        )
    return result


def _site_ids(value: object, label: str) -> tuple[int, ...]:
    if not isinstance(value, list) or not value:
        raise GnuHelloConcreteEnvironmentPairError(
            f"{label} must be a non-empty array"
        )
    result = tuple(_natural(item, f"{label}[{index}]") for index, item in enumerate(value))
    if result != tuple(sorted(set(result))):
        raise GnuHelloConcreteEnvironmentPairError(
            f"{label} must be unique and canonically sorted"
        )
    return result


def _imports(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise GnuHelloConcreteEnvironmentPairError("lean.imports must be an array")
    result = tuple(_stage_a_module(item, f"lean.imports[{index}]") for index, item in enumerate(value))
    if len(result) != len(set(result)):
        raise GnuHelloConcreteEnvironmentPairError("lean.imports contains duplicates")
    return result


def _read_json(path: Path) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), str(path))
    except (OSError, json.JSONDecodeError) as exc:
        raise GnuHelloConcreteEnvironmentPairError(
            f"cannot read concrete environment-pair input {path}: {exc}"
        ) from exc


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _object(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise GnuHelloConcreteEnvironmentPairError(f"{label} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing or extra:
        raise GnuHelloConcreteEnvironmentPairError(
            f"{label} fields differ: missing={missing}, extra={extra}"
        )


def _natural(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GnuHelloConcreteEnvironmentPairError(
            f"{label} must be a natural number"
        )
    return value


def _nonempty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise GnuHelloConcreteEnvironmentPairError(
            f"{label} must be a non-empty string"
        )
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise GnuHelloConcreteEnvironmentPairError(
            f"{label} must be a lowercase SHA-256"
        )
    return value


def _lean_name(value: object, label: str) -> str:
    if not isinstance(value, str) or _LEAN_NAME.fullmatch(value) is None:
        raise GnuHelloConcreteEnvironmentPairError(
            f"{label} must be a canonical Lean declaration"
        )
    return value


def _stage_a_module(value: object, label: str) -> str:
    if not isinstance(value, str) or _STAGE_A_MODULE.fullmatch(value) is None:
        raise GnuHelloConcreteEnvironmentPairError(
            f"{label} must be a canonical StageA module"
        )
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    outputs = write_gnu_hello_concrete_environment_pair(
        args.out, input_manifest=args.input
    )
    print(outputs.profile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "GNU_HELLO_CONCRETE_ENVIRONMENT_PAIR_INPUT_FORMAT",
    "GNU_HELLO_CONCRETE_ENVIRONMENT_PAIR_MODULE",
    "GNU_HELLO_CONCRETE_ENVIRONMENT_PAIR_NAMESPACE",
    "GnuHelloConcreteEnvironmentPairError",
    "GnuHelloConcreteEnvironmentPairOutputs",
    "write_gnu_hello_concrete_environment_pair",
]
