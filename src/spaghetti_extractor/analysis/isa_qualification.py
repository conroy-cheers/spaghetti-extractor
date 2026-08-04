"""Fail-closed joins between exact-PE ISA requirements and concrete evidence.

The resulting matrix is assurance evidence only.  A disagreement can veto a
semantic form, but agreement never qualifies a reconstructed candidate.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..isa_conformance import (
    ISAConformanceError,
    ObservationStatus,
    parse_isa_conformance_corpus,
    parse_isa_conformance_report,
)
from ..isa_conformance_bochs import BOCHS_BACKEND_ID
from ..isa_conformance_lean import LEAN_ISA_BACKEND_ID
from ..isa_conformance_unicorn import UNICORN_BACKEND_ID
from ..stage_binary import StageAInputError
from ..util import sha256_bytes, sha256_file, write_json
from .isa_requirements import ISARequirementInventory


ISA_SEMANTIC_QUALIFICATION_FORMAT = "stage-a-isa-semantic-qualification-v1"
ISA_EVIDENCE_EXECUTION_FORMAT = "stage-a-bochs-conformance-execution-v1"
LEAN_SEMANTIC_FORMS_FORMAT = "stage-a-lean-isa-semantic-forms-v1"
_FORM_STATUSES = {"qualified", "incomplete", "vetoed"}


def _canonical_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    return value


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise StageAInputError(f"{context} must be a non-empty string")
    return value


def _sha256(value: Any, context: str) -> str:
    digest = _string(value, context)
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise StageAInputError(f"{context} must be a lowercase SHA-256 digest")
    return digest


def _load_json(path: Path, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {context} {path}: {exc}") from exc
    return _mapping(value, context)


def _checked_relative_file(
    manifest_path: Path,
    descriptor: Any,
    context: str,
) -> Path:
    payload = _mapping(descriptor, context)
    relative = Path(_string(payload.get("path"), f"{context}.path"))
    if relative.is_absolute() or ".." in relative.parts:
        raise StageAInputError(f"{context}.path must remain below the shard directory")
    path = manifest_path.parent / relative
    expected = _sha256(payload.get("sha256"), f"{context}.sha256")
    if not path.is_file() or sha256_file(path) != expected:
        raise StageAInputError(f"{context} is missing or has the wrong SHA-256")
    return path


@dataclass(frozen=True)
class _EvidenceCase:
    shard_id: str
    corpus_id: str
    case_id: str
    semantic_form: str
    bochs_status: str
    unicorn_status: str
    lean_status: str

    @property
    def status(self) -> str:
        if "mismatch" in {
            self.bochs_status,
            self.unicorn_status,
            self.lean_status,
        }:
            return "vetoed"
        if (
            self.bochs_status
            == self.unicorn_status
            == self.lean_status
            == "match"
        ):
            return "qualified"
        return "incomplete"

    def to_payload(self) -> dict[str, Any]:
        return {
            "shard_id": self.shard_id,
            "corpus_id": self.corpus_id,
            "case_id": self.case_id,
            "semantic_form": self.semantic_form,
            "bochs_status": self.bochs_status,
            "unicorn_status": self.unicorn_status,
            "lean_status": self.lean_status,
            "status": self.status,
        }


@dataclass(frozen=True)
class ISASemanticQualification:
    payload: dict[str, Any]

    @classmethod
    def parse(cls, value: Any) -> "ISASemanticQualification":
        payload = _mapping(value, "ISA semantic qualification")
        if payload.get("format") != ISA_SEMANTIC_QUALIFICATION_FORMAT:
            raise StageAInputError("unsupported ISA semantic qualification format")
        status = payload.get("status")
        if status not in _FORM_STATUSES:
            raise StageAInputError("ISA semantic qualification has invalid status")
        forms = payload.get("forms")
        if not isinstance(forms, list) or any(
            not isinstance(row, Mapping) for row in forms
        ):
            raise StageAInputError("ISA semantic qualification forms must be objects")
        form_ids = [row.get("form_id") for row in forms]
        if form_ids != sorted(set(form_ids)):
            raise StageAInputError(
                "ISA semantic qualification form IDs must be unique and ordered"
            )
        if any(row.get("status") not in _FORM_STATUSES for row in forms):
            raise StageAInputError("ISA semantic qualification has invalid form status")
        expected_status = (
            "vetoed"
            if any(row.get("status") == "vetoed" for row in forms)
            else "incomplete"
            if any(row.get("status") != "qualified" for row in forms)
            else "qualified"
        )
        if status != expected_status:
            raise StageAInputError(
                "ISA semantic qualification status disagrees with its forms"
            )
        trust = _mapping(payload.get("trust"), "ISA semantic qualification trust")
        if (
            trust.get("role") != "isa_conformance_evidence_only"
            or trust.get("proof_authority") is not False
            or trust.get("closes_stage_a_proof") is not False
        ):
            raise StageAInputError(
                "ISA semantic qualification cannot claim proof authority"
            )
        return cls(dict(payload))

    def to_payload(self) -> dict[str, Any]:
        return dict(self.payload)


def _discover_manifests(
    paths: Iterable[Path],
) -> tuple[list[Path], list[dict[str, Any]]]:
    manifests: set[Path] = set()
    evidence_sets: list[dict[str, Any]] = []
    for raw in paths:
        path = Path(raw)
        if path.is_file():
            if path.name != "execution-manifest.json":
                raise StageAInputError(
                    f"ISA evidence file must be execution-manifest.json: {path}"
                )
            manifests.add(path.resolve())
        elif path.is_dir():
            discovered = {
                candidate.resolve()
                for candidate in path.rglob("execution-manifest.json")
                if candidate.is_file()
            }
            manifests.update(discovered)
            index_path = path / "index.json"
            if index_path.is_file():
                index = _load_json(index_path, "ISA evidence-set index")
                if index.get("format") != "stage-a-isa-conformance-evidence-set-v1":
                    raise StageAInputError("unsupported ISA evidence-set index format")
                trust = _mapping(index.get("trust"), "ISA evidence-set trust")
                if (
                    trust.get("role") != "isa_conformance_evidence_only"
                    or trust.get("proof_authority") is not False
                    or trust.get("closes_stage_a_proof") is not False
                ):
                    raise StageAInputError(
                        "ISA evidence-set index cannot claim proof authority"
                    )
                rows = index.get("shards")
                if not isinstance(rows, list) or any(
                    not isinstance(row, Mapping) for row in rows
                ):
                    raise StageAInputError("ISA evidence-set shards must be objects")
                declared_paths: set[Path] = set()
                declared_ids: list[str] = []
                declared_coordinates: list[tuple[str, int, int]] = []
                for row in rows:
                    if set(row) != {"opcode", "shard_index", "shard_count", "path"}:
                        raise StageAInputError(
                            "ISA evidence-set shard has unexpected fields"
                        )
                    opcode = _string(row.get("opcode"), "ISA evidence-set opcode")
                    shard_index = row.get("shard_index")
                    shard_count = row.get("shard_count")
                    relative = Path(
                        _string(row.get("path"), "ISA evidence-set manifest path")
                    )
                    if (
                        isinstance(shard_index, bool)
                        or not isinstance(shard_index, int)
                        or isinstance(shard_count, bool)
                        or not isinstance(shard_count, int)
                        or not 0 <= shard_index < shard_count
                        or relative.is_absolute()
                        or ".." in relative.parts
                        or relative.name != "execution-manifest.json"
                    ):
                        raise StageAInputError(
                            "ISA evidence-set shard coordinates are invalid"
                        )
                    declared_ids.append(f"{opcode}:{shard_index}/{shard_count}")
                    declared_coordinates.append((opcode, shard_index, shard_count))
                    declared_paths.add((path / relative).resolve())
                if declared_coordinates != sorted(set(declared_coordinates)):
                    raise StageAInputError(
                        "ISA evidence-set shard IDs must be unique and ordered"
                    )
                if any(not manifest.is_file() for manifest in declared_paths):
                    raise StageAInputError(
                        "ISA evidence-set index references a missing manifest"
                    )
                if discovered - declared_paths:
                    raise StageAInputError(
                        "ISA evidence-set index omits a directly discoverable manifest"
                    )
                manifests.update(declared_paths)
                evidence_sets.append(
                    {
                        "index_sha256": sha256_file(index_path),
                        "suite": _string(index.get("suite"), "ISA evidence-set suite"),
                        "shard_ids": declared_ids,
                    }
                )
        else:
            raise StageAInputError(f"ISA evidence path does not exist: {path}")
    result = sorted(manifests, key=str)
    if not result:
        raise StageAInputError("no ISA evidence execution manifests were found")
    evidence_sets.sort(key=lambda row: str(row["index_sha256"]))
    return result, evidence_sets


def _corpus_path(manifest_path: Path, source: Mapping[str, Any]) -> Path:
    local = manifest_path.parent / "corpus.json"
    if local.is_file():
        return local
    store_path = Path(
        _string(source.get("corpus_store_path"), "ISA evidence corpus store path")
    )
    path = store_path / "corpus.json"
    if not path.is_file():
        raise StageAInputError("ISA evidence corpus is unavailable")
    return path


def _parse_forms(
    value: Any,
    *,
    corpus_id: str,
    case_ids: list[str],
    classifier_sha256: str,
) -> dict[str, str]:
    payload = _mapping(value, "Lean semantic forms")
    if payload.get("format") != LEAN_SEMANTIC_FORMS_FORMAT:
        raise StageAInputError("unsupported Lean semantic forms format")
    if payload.get("corpus_id") != corpus_id:
        raise StageAInputError("Lean semantic forms name the wrong corpus")
    if payload.get("classifier_sha256") != classifier_sha256:
        raise StageAInputError(
            "Lean semantic forms use a different classifier than the PE inventory"
        )
    trust = _mapping(payload.get("trust"), "Lean semantic forms trust")
    if (
        trust.get("role") != "isa_conformance_evidence_only"
        or trust.get("proof_authority") is not False
        or trust.get("closes_stage_a_proof") is not False
    ):
        raise StageAInputError("Lean semantic forms cannot claim proof authority")
    rows = payload.get("cases")
    if not isinstance(rows, list) or any(not isinstance(row, Mapping) for row in rows):
        raise StageAInputError("Lean semantic form cases must be objects")
    result: dict[str, str] = {}
    ordered_ids: list[str] = []
    for row in rows:
        if set(row) != {"case_id", "semantic_form"}:
            raise StageAInputError("Lean semantic form case has unexpected fields")
        case_id = _string(row.get("case_id"), "Lean semantic form case ID")
        semantic_form = _string(
            row.get("semantic_form"), "Lean semantic form identity"
        )
        if case_id in result:
            raise StageAInputError("Lean semantic forms contain a duplicate case")
        result[case_id] = semantic_form
        ordered_ids.append(case_id)
    if ordered_ids != case_ids:
        raise StageAInputError(
            "Lean semantic forms must classify every corpus case exactly once in order"
        )
    return result


def _verify_bochs_package(
    manifest: Mapping[str, Any], *, report_version: str
) -> dict[str, Any]:
    backend = _mapping(manifest.get("backend"), "Bochs execution backend")
    store_path = Path(
        _string(backend.get("store_path"), "Bochs execution store path")
    )
    files = {
        "runner_sha256": store_path / "bin" / "spaghetti-bochs-conformance-runner",
        "guest_sha256": store_path
        / "libexec"
        / "spaghetti-extractor"
        / "bochs-conformance"
        / "guest.img",
        "bochs_binary_sha256": store_path
        / "libexec"
        / "spaghetti-extractor"
        / "bochs-conformance"
        / "bochs-raw",
    }
    for field, path in files.items():
        expected = _sha256(backend.get(field), f"Bochs execution {field}")
        if not path.is_file() or sha256_file(path) != expected:
            raise StageAInputError(
                f"Bochs execution {field} does not bind the pinned store artifact"
            )
    metadata_path = (
        store_path
        / "share"
        / "spaghetti-extractor"
        / "bochs-conformance"
        / "package-metadata.json"
    )
    metadata = _load_json(metadata_path, "Bochs package metadata")
    if backend.get("package") != metadata:
        raise StageAInputError(
            "Bochs execution metadata differs from the pinned package metadata"
        )
    bochs = _mapping(metadata.get("bochs"), "Bochs package version")
    execution = _mapping(metadata.get("execution"), "Bochs package execution profile")
    cpu = _mapping(metadata.get("cpu"), "Bochs package CPU profile")
    if (
        bochs.get("version") != report_version
        or execution.get("headless") is not True
        or execution.get("displayLibrary") != "nogui"
        or cpu.get("architecture") != "x86"
        or cpu.get("executionMode") != "protected-32"
    ):
        raise StageAInputError("Bochs package does not use the qualified headless PE32 profile")
    return {
        "store_path": str(store_path),
        "runner_sha256": str(backend["runner_sha256"]),
        "guest_sha256": str(backend["guest_sha256"]),
        "bochs_binary_sha256": str(backend["bochs_binary_sha256"]),
        "package_metadata_sha256": sha256_file(metadata_path),
    }


def _read_evidence_shard(
    manifest_path: Path,
    *,
    classifier_sha256: str,
) -> tuple[dict[str, Any], list[_EvidenceCase]]:
    manifest = _load_json(manifest_path, "ISA evidence execution manifest")
    if manifest.get("format") != ISA_EVIDENCE_EXECUTION_FORMAT:
        raise StageAInputError("unsupported ISA evidence execution manifest format")
    trust = _mapping(manifest.get("trust"), "ISA evidence execution trust")
    if (
        trust.get("role") != "isa_conformance_evidence_only"
        or trust.get("proof_authority") is not False
        or trust.get("closes_stage_a_proof") is not False
    ):
        raise StageAInputError("ISA evidence execution cannot claim proof authority")
    source = _mapping(manifest.get("source"), "ISA evidence source")
    corpus_path = _corpus_path(manifest_path, source)
    corpus_sha256 = _sha256(source.get("corpus_sha256"), "ISA evidence corpus SHA-256")
    if sha256_file(corpus_path) != corpus_sha256:
        raise StageAInputError("ISA evidence corpus SHA-256 does not match its manifest")
    corpus_payload = _load_json(corpus_path, "ISA conformance corpus")
    try:
        corpus = parse_isa_conformance_corpus(corpus_payload)
    except ISAConformanceError as exc:
        raise StageAInputError(f"invalid ISA conformance corpus: {exc}") from exc
    import_manifest_path = manifest_path.parent / "import-manifest.json"
    import_manifest_sha256 = _sha256(
        source.get("import_manifest_sha256"),
        "ISA evidence import manifest SHA-256",
    )
    if (
        not import_manifest_path.is_file()
        or sha256_file(import_manifest_path) != import_manifest_sha256
    ):
        raise StageAInputError(
            "ISA evidence import manifest is missing or has the wrong SHA-256"
        )
    declared_store = Path(
        _string(source.get("corpus_store_path"), "ISA evidence corpus store path")
    )
    declared_import = declared_store / "manifest.json"
    if (
        not declared_import.is_file()
        or import_manifest_path.resolve() != declared_import.resolve()
    ):
        raise StageAInputError(
            "ISA evidence import manifest does not come from its corpus store path"
        )
    import_manifest = _load_json(
        import_manifest_path, "ISA conformance import manifest"
    )
    imported_corpus = _mapping(
        import_manifest.get("corpus"), "ISA conformance import corpus"
    )
    if (
        imported_corpus.get("id") != corpus.id
        or imported_corpus.get("sha256") != _canonical_sha256(corpus_payload)
        or imported_corpus.get("case_count") != len(corpus.cases)
    ):
        raise StageAInputError(
            "ISA evidence import manifest does not bind the exact corpus"
        )
    import_trust = _mapping(
        import_manifest.get("trust"), "ISA conformance import trust"
    )
    if (
        import_trust.get("role") != "isa_conformance_evidence_only"
        or import_trust.get("proof_authority") is not False
        or import_trust.get("closes_stage_a_proof") is not False
    ):
        raise StageAInputError(
            "ISA conformance import manifest cannot claim proof authority"
        )

    bochs_report_path = _checked_relative_file(
        manifest_path, manifest.get("report"), "Bochs evidence report"
    )
    lean_report_path = _checked_relative_file(
        manifest_path, manifest.get("lean_report"), "Lean evidence report"
    )
    unicorn_report_path = _checked_relative_file(
        manifest_path, manifest.get("unicorn_report"), "Unicorn evidence report"
    )
    forms_path = _checked_relative_file(
        manifest_path, manifest.get("lean_forms"), "Lean semantic forms"
    )
    try:
        bochs = parse_isa_conformance_report(
            _load_json(bochs_report_path, "Bochs evidence report"), corpus=corpus
        )
        lean = parse_isa_conformance_report(
            _load_json(lean_report_path, "Lean evidence report"), corpus=corpus
        )
        unicorn = parse_isa_conformance_report(
            _load_json(unicorn_report_path, "Unicorn evidence report"),
            corpus=corpus,
        )
    except ISAConformanceError as exc:
        raise StageAInputError(f"invalid ISA conformance report: {exc}") from exc
    if bochs.backend.id != BOCHS_BACKEND_ID:
        raise StageAInputError("ISA evidence report was not produced by pinned Bochs")
    if lean.backend.id != LEAN_ISA_BACKEND_ID:
        raise StageAInputError("ISA evidence Lean report used the wrong semantic model")
    if unicorn.backend.id != UNICORN_BACKEND_ID:
        raise StageAInputError("ISA evidence report was not produced by pinned Unicorn")
    expected_case_order = [case.id for case in corpus.cases]
    if (
        [row.case_id for row in bochs.observations] != expected_case_order
        or [row.case_id for row in unicorn.observations] != expected_case_order
        or [row.case_id for row in lean.observations] != expected_case_order
    ):
        raise StageAInputError(
            "ISA evidence reports must preserve exact corpus case order"
        )
    bochs_package = _verify_bochs_package(
        manifest, report_version=bochs.backend.version
    )

    case_ids = [case.id for case in corpus.cases]
    forms = _parse_forms(
        _load_json(forms_path, "Lean semantic forms"),
        corpus_id=corpus.id,
        case_ids=case_ids,
        classifier_sha256=classifier_sha256,
    )
    bochs_by_id = {row.case_id: row for row in bochs.observations}
    unicorn_by_id = {row.case_id: row for row in unicorn.observations}
    lean_by_id = {row.case_id: row for row in lean.observations}
    opcode = _string(source.get("opcode"), "ISA evidence opcode")
    shard_index = source.get("shard_index")
    shard_count = source.get("shard_count")
    if (
        isinstance(shard_index, bool)
        or not isinstance(shard_index, int)
        or isinstance(shard_count, bool)
        or not isinstance(shard_count, int)
        or not 0 <= shard_index < shard_count
    ):
        raise StageAInputError("ISA evidence shard coordinates are invalid")
    shard_id = f"{opcode}:{shard_index}/{shard_count}"
    rows = [
        _EvidenceCase(
            shard_id=shard_id,
            corpus_id=corpus.id,
            case_id=case.id,
            semantic_form=forms[case.id],
            bochs_status=bochs_by_id[case.id].status.value,
            unicorn_status=unicorn_by_id[case.id].status.value,
            lean_status=lean_by_id[case.id].status.value,
        )
        for case in corpus.cases
    ]
    metadata = {
        "shard_id": shard_id,
        "manifest_sha256": sha256_file(manifest_path),
        "corpus_id": corpus.id,
        "corpus_sha256": corpus_sha256,
        "import_manifest_sha256": import_manifest_sha256,
        "bochs_backend": {
            "id": bochs.backend.id,
            "version": bochs.backend.version,
            "report_sha256": sha256_file(bochs_report_path),
            **bochs_package,
        },
        "lean_backend": {
            "id": lean.backend.id,
            "version": lean.backend.version,
            "report_sha256": sha256_file(lean_report_path),
            "forms_sha256": sha256_file(forms_path),
            "classifier_sha256": classifier_sha256,
        },
        "unicorn_backend": {
            "id": unicorn.backend.id,
            "version": unicorn.backend.version,
            "report_sha256": sha256_file(unicorn_report_path),
        },
        "counts": {
            "cases": len(rows),
            "qualified": sum(row.status == "qualified" for row in rows),
            "incomplete": sum(row.status == "incomplete" for row in rows),
            "vetoed": sum(row.status == "vetoed" for row in rows),
        },
    }
    return metadata, rows


def build_isa_semantic_qualification(
    requirements_payload: Mapping[str, Any],
    evidence_directories: Iterable[Path],
) -> ISASemanticQualification:
    """Join required Lean forms to paired Bochs/Lean concrete evidence."""
    requirements = ISARequirementInventory.parse(requirements_payload).to_payload()
    formal_binding = _mapping(
        requirements.get("formal_binding"), "ISA requirement formal binding"
    )
    classifier_sha256 = _sha256(
        formal_binding.get("classifier_sha256"),
        "ISA requirement classifier SHA-256",
    )
    forms_value = requirements.get("forms")
    if not isinstance(forms_value, list) or any(
        not isinstance(row, Mapping) for row in forms_value
    ):
        raise StageAInputError("ISA requirement forms must be objects")
    required_forms: dict[str, Mapping[str, Any]] = {}
    for row in forms_value:
        counts = _mapping(row.get("counts"), "ISA requirement form counts")
        required_count = counts.get("conservative_required_occurrences")
        if isinstance(required_count, bool) or not isinstance(required_count, int):
            raise StageAInputError("ISA requirement form count must be an integer")
        if required_count > 0:
            form_id = _string(row.get("id"), "ISA requirement form ID")
            if row.get("classifier_sha256") != classifier_sha256:
                raise StageAInputError(
                    "ISA requirement form uses a different Lean classifier"
                )
            required_forms[form_id] = row
    if not required_forms:
        raise StageAInputError("ISA requirements contain no conservative forms")

    manifests, evidence_sets = _discover_manifests(evidence_directories)
    shard_rows: list[dict[str, Any]] = []
    cases: list[_EvidenceCase] = []
    seen_shards: set[str] = set()
    seen_cases: set[tuple[str, str]] = set()
    for manifest in manifests:
        shard, rows = _read_evidence_shard(
            manifest, classifier_sha256=classifier_sha256
        )
        shard_id = str(shard["shard_id"])
        if shard_id in seen_shards:
            raise StageAInputError(f"duplicate ISA evidence shard {shard_id}")
        seen_shards.add(shard_id)
        for row in rows:
            identity = (row.corpus_id, row.case_id)
            if identity in seen_cases:
                raise StageAInputError(
                    f"duplicate ISA evidence case {row.corpus_id}:{row.case_id}"
                )
            seen_cases.add(identity)
        shard_rows.append(shard)
        cases.extend(rows)
    shard_rows.sort(key=lambda row: str(row["shard_id"]))
    cases.sort(key=lambda row: (row.semantic_form, row.corpus_id, row.case_id))

    cases_by_form: dict[str, list[_EvidenceCase]] = {}
    for row in cases:
        cases_by_form.setdefault(row.semantic_form, []).append(row)
    result_forms: list[dict[str, Any]] = []
    for form_id in sorted(required_forms):
        required = required_forms[form_id]
        semantic_form = _string(
            required.get("semantic_form"), "ISA requirement semantic form"
        )
        evidence = cases_by_form.get(semantic_form, [])
        known_model_blockers = (
            ["formal_x87_semantics_placeholder"]
            if ".x87" in semantic_form
            else []
        )
        status = (
            "vetoed"
            if any(row.status == "vetoed" for row in evidence)
            else "qualified"
            if (
                evidence
                and all(row.status == "qualified" for row in evidence)
                and not known_model_blockers
            )
            else "incomplete"
        )
        blockers: list[str] = list(known_model_blockers)
        if not evidence:
            blockers.append("no_paired_conformance_cases")
        if any(row.status == "incomplete" for row in evidence):
            blockers.append("backend_unsupported_or_error")
        if any(row.status == "vetoed" for row in evidence):
            blockers.append("backend_disagreement")
        result_forms.append(
            {
                "form_id": form_id,
                "semantic_form": semantic_form,
                "status": status,
                "required_occurrences": required["counts"][
                    "conservative_required_occurrences"
                ],
                "represented_rooted_occurrences": required["counts"][
                    "represented_rooted_occurrences"
                ],
                "evidence_case_count": len(evidence),
                "blockers": blockers,
                "evidence": [row.to_payload() for row in evidence],
            }
        )
    status = (
        "vetoed"
        if any(row["status"] == "vetoed" for row in result_forms)
        else "incomplete"
        if any(row["status"] != "qualified" for row in result_forms)
        else "qualified"
    )
    represented_ids = {
        row["form_id"]
        for row in result_forms
        if row["represented_rooted_occurrences"] > 0
    }
    represented_qualified = sum(
        row["form_id"] in represented_ids and row["status"] == "qualified"
        for row in result_forms
    )
    scope = _mapping(requirements.get("scope"), "ISA requirement scope")
    payload = {
        "format": ISA_SEMANTIC_QUALIFICATION_FORMAT,
        "status": status,
        "inputs": {
            "requirements_sha256": _canonical_sha256(requirements),
            "classifier_sha256": classifier_sha256,
            "evidence_manifest_sha256s": [
                row["manifest_sha256"] for row in shard_rows
            ],
        },
        "scope": {
            "control_closed": bool(scope.get("control_closed")),
            "control_frontier_node_ids": list(
                scope.get("control_frontier_node_ids", [])
            ),
            "formal_occurrence_replay": formal_binding.get("status"),
        },
        "forms": result_forms,
        "evidence_shards": shard_rows,
        "evidence_sets": evidence_sets,
        "unrequired_evidence_semantic_forms": sorted(
            set(cases_by_form)
            - {str(row["semantic_form"]) for row in required_forms.values()}
        ),
        "counts": {
            "required_forms": len(result_forms),
            "qualified_forms": sum(
                row["status"] == "qualified" for row in result_forms
            ),
            "incomplete_forms": sum(
                row["status"] == "incomplete" for row in result_forms
            ),
            "vetoed_forms": sum(row["status"] == "vetoed" for row in result_forms),
            "represented_rooted_forms": len(represented_ids),
            "represented_rooted_qualified_forms": represented_qualified,
            "evidence_shards": len(shard_rows),
            "evidence_cases": len(cases),
        },
        "trust": {
            "role": "isa_conformance_evidence_only",
            "proof_authority": False,
            "closes_stage_a_proof": False,
            "rule": (
                "a concrete disagreement vetoes semantic qualification; "
                "concrete agreement never proves universal instruction semantics"
            ),
        },
    }
    return ISASemanticQualification.parse(payload)


def write_isa_semantic_qualification(
    *,
    requirements: Path,
    evidence: Iterable[Path],
    out: Path,
) -> dict[str, Any]:
    requirements_payload = _load_json(Path(requirements), "ISA requirements")
    qualification = build_isa_semantic_qualification(
        requirements_payload, [Path(path) for path in evidence]
    )
    write_json(Path(out), qualification.to_payload())
    counts = qualification.payload["counts"]
    return {
        "format": "stage-a-isa-semantic-qualification-result-v1",
        "status": qualification.payload["status"],
        "out": str(out),
        "sha256": sha256_file(Path(out)),
        "counts": counts,
        "proof_authority": False,
        "closes_stage_a_proof": False,
    }


__all__ = [
    "ISA_EVIDENCE_EXECUTION_FORMAT",
    "ISA_SEMANTIC_QUALIFICATION_FORMAT",
    "ISASemanticQualification",
    "build_isa_semantic_qualification",
    "write_isa_semantic_qualification",
]
