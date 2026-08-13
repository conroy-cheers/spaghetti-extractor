"""Native v3 adapters for exact external profiles and PE launch roots.

Legacy profile files are source specifications, not authority artifacts.  This
module re-parses their exact bytes, rejects ambiguous inputs, and emits only
the subset that the native v3 schemas can represent soundly.  Unsupported
profile entries are omitted deliberately: an exact external site that needs
one then fails closed with ``external_profile_missing``.

Static roots are independently recovered from the PE and bound to one exact
machine-IR unit whose instruction bytes are checked against the image.  A
launch-assumption template is conditional evidence, never a copied status.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetWriterV3,
    CanonicalValueV3,
    canonical_json_bytes_v3,
    parse_canonical_json_v3,
)
from .behavioral_roots import (
    BehavioralRootsError,
    generate_behavioral_roots,
)
from .machine_import_profiles import (
    MACHINE_IMPORT_PROFILE_FORMATS,
    MachineImportProfileError,
    MachineImportProfileSet,
    SelectedMachineImportContract,
    load_machine_import_profile_set,
)
from .stage_binary import StageABinary, StageAInputError, _parse_stage_a_pe
from .analysis_v3._schema import AnalysisV3Error, mapping, sequence, text, uint
from .analysis_v3.authority_common import PrimaryBlockerV3
from .analysis_v3.exact_units import ExactUnitV3
from .analysis_v3.external_sites import (
    EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
    EXTERNAL_PROFILE_CODEC_V3,
    ExternalProfileV3,
)
from .analysis_v3.root_closure import (
    LAUNCH_ROOT_EVIDENCE_ARTIFACT_KIND_V3,
    LAUNCH_ROOT_EVIDENCE_CODEC_V3,
    LaunchRootEvidenceV3,
    launch_root_id_v3,
)


EXTERNAL_INPUT_ADAPTER_FORMAT_V3 = (
    "spaghetti-extractor-external-input-adapter-v3"
)
LAUNCH_ASSUMPTION_TEMPLATE_FORMAT_V1 = (
    "spaghetti-extractor-pe32-launch-assumption-template-v1"
)

_LAUNCH_ASSUMPTIONS = frozenset(
    {"initial_stack", "argv", "environment", "fs", "iat", "relocations"}
)
_UNSUPPORTED_FEATURES = frozenset(
    {
        "threads",
        "unmodelled_seh",
        "direct_syscalls",
        "executable_writes",
        "unknown_async_callbacks",
    }
)
_COPIED_AUTHORITY_FIELDS = frozenset(
    {"status", "authorizing", "authority_id", "failure", "primary_blocker"}
)


class ExternalInputAdapterV3Error(ValueError):
    """An exact adapter source is malformed or ambiguous."""


class _DuplicateKeyError(ValueError):
    pass


@dataclass(frozen=True, order=True)
class AdapterIssueV3:
    status: str
    code: str
    subject: str
    detail: str

    def __post_init__(self) -> None:
        if self.status not in {"incomplete", "violated"}:
            raise ExternalInputAdapterV3Error("adapter issue status is invalid")
        text(self.code, "adapter issue code", maximum=128)
        text(self.subject, "adapter issue subject")
        text(self.detail, "adapter issue detail", maximum=4096)

    def to_payload(self) -> dict[str, str]:
        return {
            "status": self.status,
            "code": self.code,
            "subject": self.subject,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class _ProfileAdaptation:
    records: tuple[ArtifactRecordV3, ...]
    bindings: tuple[ArtifactBindingV3, ...]
    artifact_status: str
    coverage_status: str
    issues: tuple[AdapterIssueV3, ...]


@dataclass(frozen=True)
class _RootAdaptation:
    records: tuple[ArtifactRecordV3, ...]
    bindings: tuple[ArtifactBindingV3, ...]
    artifact_status: str
    issues: tuple[AdapterIssueV3, ...]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _load_json_object(path: Path, *, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON constant {value}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ExternalInputAdapterV3Error(
            f"cannot parse {context} {path}: {exc}"
        ) from exc
    if not isinstance(value, Mapping):
        raise ExternalInputAdapterV3Error(f"{context} {path} must be an object")
    return value


def _preflight_profile_graph(
    roots: Sequence[Path],
) -> tuple[tuple[Path, Mapping[str, Any]], ...]:
    loaded: list[tuple[Path, Mapping[str, Any]]] = []
    visited: set[Path] = set()
    visiting: list[Path] = []

    def visit(raw: Path, *, relative_to: Path | None = None) -> None:
        path = raw if raw.is_absolute() or relative_to is None else relative_to / raw
        path = path.resolve()
        if path in visited:
            return
        if path in visiting:
            cycle = " -> ".join(item.name for item in (*visiting, path))
            raise ExternalInputAdapterV3Error(
                f"machine-import profile include cycle: {cycle}"
            )
        payload = _load_json_object(path, context="machine-import profile")
        if payload.get("format") not in MACHINE_IMPORT_PROFILE_FORMATS:
            raise ExternalInputAdapterV3Error(
                f"unsupported machine-import profile format in {path}"
            )
        profile_id = payload.get("id")
        if not isinstance(profile_id, str) or not profile_id:
            raise ExternalInputAdapterV3Error(
                f"machine-import profile {path} has no nonempty id"
            )
        copied = sorted(_COPIED_AUTHORITY_FIELDS & set(payload))
        if copied:
            raise ExternalInputAdapterV3Error(
                f"machine-import profile {profile_id!r} contains copied authority "
                f"fields {copied!r}"
            )
        includes = payload.get("includes", [])
        if not isinstance(includes, list) or any(
            not isinstance(item, str) or not item for item in includes
        ):
            raise ExternalInputAdapterV3Error(
                f"machine-import profile {profile_id!r} has malformed includes"
            )
        visiting.append(path)
        try:
            for include in includes:
                visit(Path(include), relative_to=path.parent)
        finally:
            visiting.pop()
        visited.add(path)
        loaded.append((path, payload))

    for root in roots:
        visit(root)
    profile_ids = [str(payload["id"]) for _path, payload in loaded]
    if len(profile_ids) != len(set(profile_ids)):
        raise ExternalInputAdapterV3Error(
            "machine-import profile graph repeats a profile id"
        )
    return tuple(loaded)


def _profile_binding(
    index: int, path: Path, profile_id: str
) -> ArtifactBindingV3:
    return ArtifactBindingV3(
        name=f"external-profile-source-{index:04d}",
        kind="machine-import-profile",
        identity=profile_id,
        sha256=_sha256_file(path),
    )


def _import_identity(
    selected: SelectedMachineImportContract,
) -> dict[str, Any]:
    identity = selected.identity
    return {
        "kind": "import",
        "dll": identity.dll.lower(),
        "symbol": identity.value if identity.kind == "symbol" else None,
        "ordinal": identity.value if identity.kind == "ordinal" else None,
    }


def _adapt_profile_contract(
    selected: SelectedMachineImportContract,
) -> ExternalProfileV3 | AdapterIssueV3:
    contract = selected.contract
    subject = f"{selected.identity.dll}!{selected.identity.value}"
    if selected.arity_kind != "fixed" or selected.argument_words is None:
        return AdapterIssueV3(
            "incomplete",
            "external_profile_arity_not_exact",
            subject,
            "native v3 external profiles currently require one exact argument-word count",
        )
    disposition = contract.get("disposition", "returns")
    dispositions = {
        "returns": "returns",
        "terminates": "noreturn",
        "noreturn": "noreturn",
        "tail_jump": "tail_jump",
    }
    if disposition not in dispositions:
        return AdapterIssueV3(
            "incomplete",
            "external_profile_disposition_unsupported",
            subject,
            f"disposition {disposition!r} has no native v3 representation",
        )
    memory_effect = contract.get("memory_effect")
    world_effect = contract.get("world_effect")
    callback_effect = contract.get("callback_effect")
    if callback_effect is None and world_effect == "callbackRegistration":
        callback_effect = "explicit"
    mapped_callback = {"none": "none", "explicit": "registers"}.get(
        callback_effect
    )
    if (
        not isinstance(contract.get("abi_template"), str)
        or not isinstance(memory_effect, str)
        or not isinstance(world_effect, str)
        or mapped_callback is None
    ):
        return AdapterIssueV3(
            "incomplete",
            "external_profile_machine_contract_incomplete",
            subject,
            "profile entry lacks an exact ABI, memory, world, or callback effect",
        )
    return ExternalProfileV3.create(
        profile_id=selected.profile_id,
        profile_sha256=selected.profile_sha256,
        identity=_import_identity(selected),
        allowed_transfers=("call", "jump"),
        allowed_dispositions=(dispositions[str(disposition)],),
        argument_words=selected.argument_words,
        memory_effect=memory_effect,
        world_effect=world_effect,
        callback_effect=mapped_callback,
    )


def _fallback_profile_bindings(
    paths: Sequence[Path],
) -> tuple[ArtifactBindingV3, ...]:
    result: list[ArtifactBindingV3] = []
    for index, path in enumerate(dict.fromkeys(item.resolve() for item in paths)):
        try:
            digest = _sha256_file(path)
        except OSError:
            continue
        result.append(
            ArtifactBindingV3(
                name=f"external-profile-source-{index:04d}",
                kind="machine-import-profile",
                identity=path.name,
                sha256=digest,
            )
        )
    return tuple(result)


def _adapt_external_profiles(
    profile_paths: Sequence[Path], *, binary_binding: ArtifactBindingV3
) -> _ProfileAdaptation:
    if not profile_paths:
        return _ProfileAdaptation((), (binary_binding,), "complete", "complete", ())
    try:
        graph = _preflight_profile_graph(profile_paths)
        profile_set: MachineImportProfileSet = load_machine_import_profile_set(
            profile_paths
        )
        loaded_by_path = {row.path.resolve(): row for row in profile_set.profiles}
        if set(loaded_by_path) != {path for path, _payload in graph}:
            raise ExternalInputAdapterV3Error(
                "profile preflight and selected include graphs disagree"
            )
        bindings = [binary_binding]
        for index, (path, payload) in enumerate(graph):
            loaded = loaded_by_path[path]
            if loaded.profile_id != payload["id"] or loaded.sha256 != _sha256_file(path):
                raise ExternalInputAdapterV3Error(
                    f"profile binding changed while adapting {payload['id']!r}"
                )
            bindings.append(_profile_binding(index, path, loaded.profile_id))
        records: list[ArtifactRecordV3] = []
        issues: list[AdapterIssueV3] = []
        for selected in profile_set.contracts:
            adapted = _adapt_profile_contract(selected)
            if isinstance(adapted, AdapterIssueV3):
                issues.append(adapted)
            else:
                records.append(
                    EXTERNAL_PROFILE_CODEC_V3.write(adapted.record_id, adapted)
                )
        return _ProfileAdaptation(
            tuple(sorted(records, key=lambda row: row.record_id)),
            tuple(sorted(bindings)),
            "complete",
            "incomplete" if issues else "complete",
            tuple(sorted(issues)),
        )
    except (
        ExternalInputAdapterV3Error,
        MachineImportProfileError,
        AnalysisV3Error,
        OSError,
    ) as exc:
        issue = AdapterIssueV3(
            "violated",
            "external_profile_source_violated",
            "machine-import-profile-graph",
            str(exc),
        )
        return _ProfileAdaptation(
            (),
            tuple(sorted((binary_binding, *_fallback_profile_bindings(profile_paths)))),
            "violated",
            "violated",
            (issue,),
        )


def _load_machine_units(
    machine_ir: Path, *, pe_sha256: str
) -> tuple[ExactUnitV3, ...]:
    result: list[ExactUnitV3] = []
    seen: set[str] = set()
    with machine_ir.open("rb") as stream:
        for line_number, raw in enumerate(stream, start=1):
            if not raw.strip():
                continue
            value = parse_canonical_json_v3(
                raw.rstrip(b"\r\n"), location=f"{machine_ir}:{line_number}"
            )
            row = mapping(value, f"machine-IR unit {line_number}")
            exact = ExactUnitV3.create(row, pe_sha256=pe_sha256)
            if exact.unit_id in seen:
                raise ExternalInputAdapterV3Error(
                    f"machine IR repeats unit {exact.unit_id!r}"
                )
            seen.add(exact.unit_id)
            result.append(exact)
    if not result:
        raise ExternalInputAdapterV3Error("machine IR has no exact units")
    return tuple(sorted(result, key=lambda row: row.unit_id))


def _exact_unit_bytes(binary: StageABinary, unit: ExactUnitV3) -> bytes:
    candidates = [
        section
        for section in binary.sections
        if section.rva_start <= unit.rva_start
        and unit.rva_end <= section.rva_start + section.raw_size
    ]
    if len(candidates) != 1:
        raise ExternalInputAdapterV3Error(
            f"unit {unit.unit_id!r} is not in exactly one raw-backed PE section"
        )
    section = candidates[0]
    start = section.raw_pointer + unit.rva_start - section.rva_start
    end = start + unit.rva_end - unit.rva_start
    data = binary.path.read_bytes()[start:end]
    if len(data) != unit.rva_end - unit.rva_start:
        raise ExternalInputAdapterV3Error(
            f"unit {unit.unit_id!r} extends beyond exact PE bytes"
        )
    return data


def _validate_root_unit(binary: StageABinary, unit: ExactUnitV3) -> None:
    observed = hashlib.sha256(_exact_unit_bytes(binary, unit)).hexdigest()
    if observed != unit.instruction_bytes_sha256:
        raise ExternalInputAdapterV3Error(
            f"unit {unit.unit_id!r} instruction digest contradicts exact PE bytes"
        )


def _load_launch_template(
    path: Path | None,
) -> tuple[Mapping[str, Any] | None, str | None, AdapterIssueV3 | None]:
    if path is None:
        return (
            None,
            None,
            AdapterIssueV3(
                "incomplete",
                "launch_assumption_profile_missing",
                "static-launch-roots",
                "no exact launch-assumption template was supplied",
            ),
        )
    try:
        payload = _load_json_object(path, context="launch-assumption template")
        if set(payload) != {
            "format",
            "schema_version",
            "assumptions",
            "feature_inventory",
        }:
            raise ExternalInputAdapterV3Error(
                "launch-assumption template has noncanonical top-level fields"
            )
        if (
            payload.get("format") != LAUNCH_ASSUMPTION_TEMPLATE_FORMAT_V1
            or payload.get("schema_version") != 1
        ):
            raise ExternalInputAdapterV3Error(
                "launch-assumption template format is unsupported"
            )
        assumptions = mapping(payload.get("assumptions"), "launch assumptions")
        features = mapping(payload.get("feature_inventory"), "launch features")
        if set(assumptions) != _LAUNCH_ASSUMPTIONS or set(features) != _UNSUPPORTED_FEATURES:
            raise ExternalInputAdapterV3Error(
                "launch-assumption template has an incomplete assumption or feature inventory"
            )
        if any(not mapping(assumptions[key], f"launch assumption {key}") for key in assumptions):
            raise ExternalInputAdapterV3Error(
                "launch assumptions must be nonempty exact objects"
            )
        nonempty = [key for key in sorted(features) if sequence(features[key], key)]
        if nonempty:
            return (
                payload,
                _sha256_file(path),
                AdapterIssueV3(
                    "incomplete",
                    "launch_profile_unsupported_feature",
                    "static-launch-roots",
                    f"unsupported launch feature inventories are nonempty: {nonempty!r}",
                ),
            )
        return payload, _sha256_file(path), None
    except (ExternalInputAdapterV3Error, AnalysisV3Error, OSError) as exc:
        return (
            None,
            _sha256_file(path) if path.exists() else None,
            AdapterIssueV3(
                "violated",
                "launch_assumption_profile_violated",
                "static-launch-roots",
                str(exc),
            ),
        )


def _root_entry_state(
    *,
    behavioral_roots: Mapping[str, Any],
    root: Mapping[str, Any],
    template: Mapping[str, Any],
    template_sha256: str,
) -> CanonicalValueV3:
    return CanonicalValueV3.of(
        {
            "model": "conditional-exact-pe32-launch-v3",
            "pe": behavioral_roots["pe"],
            "behavioral_roots_sha256": behavioral_roots["contract_sha256"],
            "root": dict(root),
            "launch_assumption_template": {
                "format": template["format"],
                "sha256": template_sha256,
                "assumptions": template["assumptions"],
            },
        }
    )


def _adapt_launch_roots(
    *,
    binary_path: Path,
    machine_ir: Path,
    binary_binding: ArtifactBindingV3,
    launch_template: Path | None,
) -> _RootAdaptation:
    machine_binding = ArtifactBindingV3(
        "machine-ir-source",
        "machine-ir",
        machine_ir.name,
        _sha256_file(machine_ir),
    )
    bindings = [binary_binding, machine_binding]
    template, template_sha256, template_issue = _load_launch_template(
        launch_template
    )
    if launch_template is not None and template_sha256 is not None:
        bindings.append(
            ArtifactBindingV3(
                "launch-profile-source",
                "launch-assumption-template",
                LAUNCH_ASSUMPTION_TEMPLATE_FORMAT_V1,
                template_sha256,
            )
        )
    try:
        binary = _parse_stage_a_pe(binary_path)
        if binary.machine != "i386" or binary.bitness != 32:
            raise ExternalInputAdapterV3Error("launch-root adapter requires PE32 i386")
        roots = generate_behavioral_roots(binary_path)
        units = _load_machine_units(machine_ir, pe_sha256=binary.sha256)
        by_rva: dict[int, list[ExactUnitV3]] = {}
        for unit in units:
            by_rva.setdefault(unit.rva_start, []).append(unit)
        issues: list[AdapterIssueV3] = []
        if template_issue is not None:
            issues.append(template_issue)
        records: list[ArtifactRecordV3] = []
        for raw_root in sequence(roots.get("roots"), "behavioral roots"):
            root = mapping(raw_root, "behavioral root")
            identity = text(root.get("identity"), "behavioral root identity")
            root_kind = text(root.get("kind"), "behavioral root kind")
            rva = uint(root.get("rva"), "behavioral root RVA")
            candidates = by_rva.get(rva, [])
            if len(candidates) != 1:
                status = "violated" if len(candidates) > 1 else "incomplete"
                issues.append(
                    AdapterIssueV3(
                        status,
                        (
                            "launch_root_unit_ambiguous"
                            if len(candidates) > 1
                            else "launch_root_unit_missing"
                        ),
                        identity,
                        f"root RVA {rva:#x} maps to {len(candidates)} exact units",
                    )
                )
                continue
            unit = candidates[0]
            unit_issue: AdapterIssueV3 | None = None
            try:
                _validate_root_unit(binary, unit)
            except ExternalInputAdapterV3Error as exc:
                unit_issue = AdapterIssueV3(
                    "violated",
                    "launch_root_unit_bytes_contradiction",
                    identity,
                    str(exc),
                )
                issues.append(unit_issue)
            blocker_issue = unit_issue or template_issue
            status = "complete" if blocker_issue is None else blocker_issue.status
            entry_state = (
                _root_entry_state(
                    behavioral_roots=roots,
                    root=root,
                    template=template,
                    template_sha256=str(template_sha256),
                )
                if status == "complete"
                else None
            )
            blocker = (
                None
                if blocker_issue is None
                else PrimaryBlockerV3(blocker_issue.status, blocker_issue.code)
            )
            evidence = LaunchRootEvidenceV3(
                record_id=launch_root_id_v3(root_kind, identity, unit.unit_id),
                root_kind=root_kind,
                identity=identity,
                unit_id=unit.unit_id,
                unit_sha256=unit.unit_sha256,
                entry_state=entry_state,
                callback_id=None,
                status=status,
                primary_blocker=blocker,
            )
            records.append(
                LAUNCH_ROOT_EVIDENCE_CODEC_V3.write(evidence.record_id, evidence)
            )
        artifact_status = _aggregate_status(issues)
        return _RootAdaptation(
            tuple(sorted(records, key=lambda row: row.record_id)),
            tuple(sorted(bindings)),
            artifact_status,
            tuple(sorted(set(issues))),
        )
    except (
        ExternalInputAdapterV3Error,
        BehavioralRootsError,
        StageAInputError,
        AnalysisV3Error,
        OSError,
    ) as exc:
        issue = AdapterIssueV3(
            "violated",
            "launch_root_source_violated",
            "static-launch-roots",
            str(exc),
        )
        return _RootAdaptation(
            (), tuple(sorted(bindings)), "violated", (issue,)
        )


def _aggregate_status(issues: Iterable[AdapterIssueV3]) -> str:
    statuses = {issue.status for issue in issues}
    if "violated" in statuses:
        return "violated"
    if "incomplete" in statuses:
        return "incomplete"
    return "complete"


def adapt_external_inputs_v3(
    *,
    binary: Path,
    machine_ir: Path,
    binary_identity: str,
    profile_paths: Sequence[Path],
    launch_template: Path | None,
    output_directory: Path,
) -> dict[str, Any]:
    """Emit exact v3 external-profile and launch-root artifact sets."""

    text(binary_identity, "binary identity")
    binary_sha256 = _sha256_file(binary)
    binary_binding = ArtifactBindingV3(
        "binary", "pe32", binary_identity, binary_sha256
    )
    profiles = _adapt_external_profiles(
        profile_paths, binary_binding=binary_binding
    )
    roots = _adapt_launch_roots(
        binary_path=binary,
        machine_ir=machine_ir,
        binary_binding=binary_binding,
        launch_template=launch_template,
    )
    output_directory.mkdir(parents=True, exist_ok=False)
    profile_output = output_directory / "external-profiles"
    root_output = output_directory / "launch-roots"
    profile_manifest = ArtifactSetWriterV3(
        artifact_kind=EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
        bindings=profiles.bindings,
        status=profiles.artifact_status,
    ).write(profile_output, profiles.records)
    root_manifest = ArtifactSetWriterV3(
        artifact_kind=LAUNCH_ROOT_EVIDENCE_ARTIFACT_KIND_V3,
        bindings=roots.bindings,
        status=roots.artifact_status,
    ).write(root_output, roots.records)
    metadata = {
        "format": EXTERNAL_INPUT_ADAPTER_FORMAT_V3,
        "binary": {
            "identity": binary_identity,
            "sha256": binary_sha256,
        },
        "machine_ir_sha256": _sha256_file(machine_ir),
        "external_profiles": {
            "artifact_kind": EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
            "artifact_id": profile_manifest.artifact_id,
            "artifact_status": profile_manifest.status,
            "coverage_status": profiles.coverage_status,
            "record_ids": [record.record_id for record in profiles.records],
            "issues": [issue.to_payload() for issue in profiles.issues],
        },
        "launch_roots": {
            "artifact_kind": LAUNCH_ROOT_EVIDENCE_ARTIFACT_KIND_V3,
            "artifact_id": root_manifest.artifact_id,
            "artifact_status": root_manifest.status,
            "record_ids": [record.record_id for record in roots.records],
            "issues": [issue.to_payload() for issue in roots.issues],
        },
    }
    (output_directory / "metadata.json").write_bytes(
        canonical_json_bytes_v3(metadata)
    )
    return metadata


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Adapt exact machine-import profiles and PE roots to native v3 inputs"
    )
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--machine-ir", type=Path, required=True)
    parser.add_argument("--binary-identity", required=True)
    parser.add_argument("--profile", type=Path, action="append", default=[])
    parser.add_argument("--launch-template", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    adapt_external_inputs_v3(
        binary=arguments.binary,
        machine_ir=arguments.machine_ir,
        binary_identity=arguments.binary_identity,
        profile_paths=tuple(arguments.profile),
        launch_template=arguments.launch_template,
        output_directory=arguments.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "AdapterIssueV3",
    "EXTERNAL_INPUT_ADAPTER_FORMAT_V3",
    "ExternalInputAdapterV3Error",
    "adapt_external_inputs_v3",
    "main",
]
