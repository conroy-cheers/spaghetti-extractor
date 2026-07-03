from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .util import public_text, sha256_file, utc_now, write_json


CLEAN_SPEC_FORMAT_VERSION = "wincr-clean-specs-v1"
DIRTY_CORPUS_FORMAT_PREFIX = "wincr-dirty-corpus-"
PUBLISH_DECISIONS = {"publish", "public", "approved", "reviewed_public"}
PUBLISHABLE_TAINT_LEVELS = {"reviewed_public"}
PUBLISHABLE_REVIEW_STATUSES = {"reviewed"}
SPEC_ENTITY_TYPES = {
    "behavior_contract",
    "internal_routine_contract",
    "data_structure",
    "interface_contract",
}
TEST_ENTITY_TYPES = {
    "behavior_observation",
    "process_behavior_observation",
    "oracle_test_case",
    "interface_test_case",
    "data_state_test_case",
    "mutation_test_case",
    "internal_harness",
    "internal_harness_run",
}
PUBLIC_FIELDS = (
    "schema_version",
    "source_dirty_packet_label",
    "source_dirty_packet_category",
    "entity_type",
    "public_label",
    "contract_id",
    "version",
    "title",
    "test_id",
    "taint_level",
    "review_status",
    "status",
    "evidence_labels",
    "sanitized_name",
    "public_name",
    "purpose_summary",
    "calling_convention",
    "signature",
    "contract",
    "inputs",
    "outputs",
    "input_shape",
    "output_shape",
    "preconditions",
    "postconditions",
    "side_effects",
    "state_transitions",
    "fixtures",
    "test_vectors",
    "evidence_source",
    "confidence",
    "publication_decision",
)
PRIVATE_KEY_PATTERN = re.compile(
    r"(^|_)(rva|image_base|module_sha256|source_path|fixture_path|trace_log|"
    r"stdout_path|stderr_path|result_path|expected_path|dirty|disassembly|pseudocode)(_|$)"
    r"|^(command|command_template)$",
    re.IGNORECASE,
)


def derive_clean_specs(corpus_dir: Path, out_dir: Path) -> dict[str, Any]:
    corpus_dir = corpus_dir.resolve()
    manifest = _load_manifest(corpus_dir)
    templates = list(_iter_clean_templates(corpus_dir))
    included: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []

    for path in templates:
        template = _load_json(path)
        rel_path = path.relative_to(corpus_dir).as_posix()
        decision = _publication_state(template)
        if decision["state"] == "skip":
            skipped.append({"path": rel_path, **decision})
            continue
        try:
            included.append(_public_record(template, rel_path))
        except ValueError as exc:
            rejected.append({"path": rel_path, "reason": str(exc)})

    status = "pass" if not rejected else "fail"
    specs = _specs_json(manifest, included, skipped, rejected, status)
    tests = _tests_json(specs)
    out_dir.mkdir(parents=True, exist_ok=True)
    specs_path = out_dir / "specs.json"
    specs_md_path = out_dir / "specs.md"
    tests_path = out_dir / "tests.json"
    tests_md_path = out_dir / "tests.md"
    report_path = out_dir / "derivation-report.json"
    write_json(specs_path, specs)
    specs_md_path.write_text(clean_specs_markdown(specs), encoding="utf-8")
    write_json(tests_path, tests)
    tests_md_path.write_text(clean_tests_markdown(tests), encoding="utf-8")
    write_json(
        report_path,
        {
            "status": status,
            "generated_at": specs["generated_at"],
            "source_corpus": specs["source_corpus"],
            "counts": specs["summary"],
            "outputs": {
                "specs_json": str(specs_path),
                "specs_markdown": str(specs_md_path),
                "tests_json": str(tests_path),
                "tests_markdown": str(tests_md_path),
            },
            "skipped": skipped,
            "rejected": rejected,
        },
    )
    return {
        "status": status,
        "source_corpus": specs["source_corpus"],
        "summary": specs["summary"],
        "rejected": rejected,
        "outputs": {
            "specs_json": str(specs_path),
            "specs_markdown": str(specs_md_path),
            "tests_json": str(tests_path),
            "tests_markdown": str(tests_md_path),
            "derivation_report": str(report_path),
        },
    }


def promote_clean_templates(
    corpus_dir: Path,
    *,
    reviewer: str,
    entity_types: tuple[str, ...] = (),
    categories: tuple[str, ...] = (),
    publication_decision: str = "publish",
    note: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Mark selected clean templates as reviewed/public after validation.

    This is a review bookkeeping helper. It does not rewrite dirty evidence into
    clean facts; it only records that a reviewer has accepted existing
    packet-local clean-template content and proves that the publishable fields
    pass the same leakage checks used by ``derive_clean_specs``.
    """

    if not reviewer.strip():
        raise ValueError("reviewer is required")
    if publication_decision not in PUBLISH_DECISIONS:
        raise ValueError(f"publication_decision must be one of {sorted(PUBLISH_DECISIONS)}")
    corpus_dir = corpus_dir.resolve()
    manifest = _load_manifest(corpus_dir)
    filters = {"entity_types": sorted(entity_types), "categories": sorted(categories)}
    promoted: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    rejected: list[dict[str, str]] = []
    rewritten_paths: list[Path] = []
    for path in _iter_clean_templates(corpus_dir):
        template = _load_json(path)
        rel_path = path.relative_to(corpus_dir).as_posix()
        entity_type = str(template.get("entity_type", ""))
        category = str(template.get("source_dirty_packet_category", ""))
        if entity_types and entity_type not in entity_types:
            skipped.append({"path": rel_path, "reason": f"entity_type={entity_type or 'missing'}"})
            continue
        if categories and category not in categories:
            skipped.append({"path": rel_path, "reason": f"category={category or 'missing'}"})
            continue
        candidate = dict(template)
        candidate["review_status"] = "reviewed"
        candidate["taint_level"] = "reviewed_public"
        candidate["publication_decision"] = publication_decision
        candidate["reviewer"] = reviewer
        notes = candidate.get("review_notes")
        if not isinstance(notes, list):
            notes = [str(notes)] if notes else []
        notes.append(f"Clean template reviewed for publication by {reviewer}.")
        if note:
            notes.append(public_text(note))
        candidate["review_notes"] = notes
        try:
            _public_record(candidate, rel_path)
        except ValueError as exc:
            rejected.append({"path": rel_path, "reason": str(exc)})
            continue
        promoted.append({"path": rel_path, "entity_type": entity_type, "category": category})
        if not dry_run:
            write_json(path, candidate)
            rewritten_paths.append(path)
    manifest_refresh = (
        _refresh_content_manifest_entries(corpus_dir, rewritten_paths)
        if rewritten_paths and not dry_run
        else {"updated": 0, "missing": 0, "content_manifest": None}
    )
    return {
        "status": "pass" if not rejected else "fail",
        "source_corpus": _public_source_corpus(manifest),
        "dry_run": dry_run,
        "filters": filters,
        "reviewer": reviewer,
        "publication_decision": publication_decision,
        "summary": {
            "templates": len(promoted) + len(skipped) + len(rejected),
            "promoted_templates": len(promoted),
            "skipped_templates": len(skipped),
            "rejected_templates": len(rejected),
        },
        "content_manifest": manifest_refresh,
        "promoted": promoted,
        "skipped": skipped,
        "rejected": rejected,
    }


def _refresh_content_manifest_entries(corpus_dir: Path, changed_paths: list[Path]) -> dict[str, Any]:
    manifest_path = corpus_dir / "content-manifest.json"
    if not manifest_path.exists():
        return {"updated": 0, "missing": len(changed_paths), "content_manifest": None}
    manifest = _load_json(manifest_path)
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return {"updated": 0, "missing": len(changed_paths), "content_manifest": str(manifest_path)}

    by_path: dict[str, dict[str, Any]] = {
        str(artifact.get("path") or ""): artifact for artifact in artifacts if isinstance(artifact, dict)
    }
    updated = 0
    missing = 0
    for path in changed_paths:
        rel_path = path.relative_to(corpus_dir).as_posix()
        artifact = by_path.get(rel_path)
        if artifact is None:
            missing += 1
            continue
        artifact["sha256"] = sha256_file(path)
        artifact["size"] = path.stat().st_size
        updated += 1
    if updated:
        manifest["artifact_count"] = len(artifacts)
        write_json(manifest_path, manifest)
    return {"updated": updated, "missing": missing, "content_manifest": str(manifest_path)}


def validate_clean_specs(spec_json: Path, tests_json: Path | None = None) -> dict[str, Any]:
    spec_json = spec_json.resolve()
    spec = _load_json(spec_json)
    tests = _load_json(tests_json.resolve()) if tests_json is not None else None
    errors: list[str] = []
    warnings: list[str] = []

    if spec.get("format") != CLEAN_SPEC_FORMAT_VERSION:
        errors.append(f"spec format must be {CLEAN_SPEC_FORMAT_VERSION}")
    if spec.get("status") != "pass":
        errors.append("spec status must be pass")
    for key in ("source_corpus", "summary", "spec_records", "test_records", "other_records"):
        if key not in spec:
            errors.append(f"missing top-level field: {key}")
    _validate_payload_for_report(spec.get("source_corpus", {}), "$.source_corpus", errors)

    spec_records = _record_list(spec, "spec_records", errors)
    test_records = _record_list(spec, "test_records", errors)
    other_records = _record_list(spec, "other_records", errors)
    _validate_summary_counts(spec.get("summary", {}), spec_records, test_records, other_records, errors)
    _validate_records(spec_records + test_records + other_records, errors, warnings)
    _validate_behavior_contract_links(spec_records, test_records, errors)
    _validate_contract_coverage_requirements(spec_records, test_records, other_records, errors)
    if tests is not None:
        _validate_tests_json(tests, spec, test_records, errors)

    return {
        "status": "pass" if not errors else "fail",
        "spec_json": str(spec_json),
        "tests_json": str(tests_json.resolve()) if tests_json is not None else None,
        "summary": {
            "spec_records": len(spec_records),
            "test_records": len(test_records),
            "other_records": len(other_records),
            "errors": len(errors),
            "warnings": len(warnings),
        },
        "errors": errors,
        "warnings": warnings,
    }


def clean_specs_markdown(specs: dict[str, Any]) -> str:
    summary = specs["summary"]
    lines = [
        "# Clean Specs",
        "",
        "Generated from reviewed clean templates.",
        "",
        "## Summary",
        "",
        f"- Status: `{specs['status']}`",
        f"- Reviewed records: {summary['reviewed_records']}",
        f"- Skipped templates: {summary['skipped_templates']}",
        f"- Rejected templates: {summary['rejected_templates']}",
        f"- Spec records: {summary['spec_records']}",
        f"- Test records: {summary['test_records']}",
        "",
    ]
    for section, title in (("spec_records", "Spec Records"), ("test_records", "Test Records")):
        records = specs[section]
        lines.extend([f"## {title}", ""])
        if not records:
            lines.append("- None.")
            lines.append("")
            continue
        for record in records[:200]:
            name = record.get("sanitized_name") or record["public_label"]
            lines.append(
                f"- `{record['public_label']}` `{record['entity_type']}` "
                f"name={_md_inline(name)} confidence={record.get('confidence', 'unknown')}"
            )
            if record.get("purpose_summary"):
                lines.append(f"  - Purpose: {_md_inline(record['purpose_summary'])}")
        lines.append("")
    return "\n".join(lines)


def clean_tests_markdown(tests: dict[str, Any]) -> str:
    lines = [
        "# Clean Tests",
        "",
        "Reviewed public test vectors and behavioral observations from clean templates.",
        "",
        "## Summary",
        "",
        f"- Test records: {tests['summary']['test_records']}",
        "",
    ]
    for record in tests["test_records"][:200]:
        name = record.get("sanitized_name") or record["public_label"]
        lines.append(f"- `{record['public_label']}` `{record['entity_type']}` name={_md_inline(name)}")
    if not tests["test_records"]:
        lines.append("- None.")
    lines.append("")
    return "\n".join(lines)


def _load_manifest(corpus_dir: Path) -> dict[str, Any]:
    manifest_path = corpus_dir / "manifest.json"
    manifest = _load_json(manifest_path)
    fmt = str(manifest.get("format", ""))
    if not fmt.startswith(DIRTY_CORPUS_FORMAT_PREFIX):
        raise ValueError(f"{manifest_path} is not a wincr dirty corpus manifest")
    return {
        "artifact_set_id": manifest.get("artifact_set_id"),
        "format": fmt,
        "target": manifest.get("target", {}),
        "manifest_sha256": sha256_file(manifest_path),
    }


def _iter_clean_templates(corpus_dir: Path) -> list[Path]:
    review_dir = corpus_dir / "review"
    if not review_dir.exists():
        return []
    return sorted(review_dir.glob("**/clean-template.json"))


def _publication_state(template: dict[str, Any]) -> dict[str, str]:
    review_status = str(template.get("review_status", ""))
    taint_level = str(template.get("taint_level", ""))
    publication_decision = str(template.get("publication_decision", ""))
    if (
        review_status in PUBLISHABLE_REVIEW_STATUSES
        and taint_level in PUBLISHABLE_TAINT_LEVELS
        and publication_decision in PUBLISH_DECISIONS
    ):
        return {"state": "publish", "reason": "reviewed public template"}
    return {
        "state": "skip",
        "reason": (
            f"review_status={review_status or 'missing'} "
            f"taint_level={taint_level or 'missing'} "
            f"publication_decision={publication_decision or 'missing'}"
        ),
    }


def _public_record(template: dict[str, Any], rel_path: str) -> dict[str, Any]:
    record = {key: template.get(key) for key in PUBLIC_FIELDS if key in template}
    required = ("source_dirty_packet_label", "entity_type", "public_label")
    missing = [key for key in required if not str(record.get(key) or "").strip()]
    if missing:
        raise ValueError(f"missing required clean fields: {', '.join(missing)}")
    record.pop("source_dirty_packet_label")
    record.pop("source_dirty_packet_category", None)
    _validate_public_payload(template.get("review_notes", []), path="$.review_notes")
    _validate_public_payload(record)
    return record


def _validate_public_payload(value: Any, *, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if PRIVATE_KEY_PATTERN.search(key_text):
                raise ValueError(f"private key is not publishable at {path}.{key_text}")
            _validate_public_payload(item, path=f"{path}.{key_text}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_public_payload(item, path=f"{path}[{index}]")
        return
    if isinstance(value, str):
        if public_text(value) != value:
            raise ValueError(f"private path is not publishable at {path}")
        if "[private path]" in value.lower():
            raise ValueError(f"redacted private path placeholder is not publishable at {path}")
        if "module_sha256" in value.lower() or " rva" in value.lower() or "0x" in value and "rva" in value.lower():
            raise ValueError(f"private identity text is not publishable at {path}")


def _record_list(spec: dict[str, Any], key: str, errors: list[str]) -> list[dict[str, Any]]:
    value = spec.get(key, [])
    if not isinstance(value, list):
        errors.append(f"{key} must be a list")
        return []
    records: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"{key}[{index}] must be an object")
            continue
        records.append(item)
    return records


def _validate_summary_counts(
    summary: Any,
    spec_records: list[dict[str, Any]],
    test_records: list[dict[str, Any]],
    other_records: list[dict[str, Any]],
    errors: list[str],
) -> None:
    if not isinstance(summary, dict):
        errors.append("summary must be an object")
        return
    expected = {
        "spec_records": len(spec_records),
        "test_records": len(test_records),
        "other_records": len(other_records),
    }
    for key, value in expected.items():
        if int(summary.get(key, -1) or 0) != value:
            errors.append(f"summary.{key}={summary.get(key)!r} does not match actual {value}")
    templates = summary.get("templates")
    if templates is not None:
        actual_templates = (
            len(spec_records)
            + len(test_records)
            + len(other_records)
            + int(summary.get("skipped_templates", 0) or 0)
            + int(summary.get("rejected_templates", 0) or 0)
        )
        if int(templates or 0) != actual_templates:
            errors.append(f"summary.templates={templates!r} does not match actual {actual_templates}")


def _validate_records(records: list[dict[str, Any]], errors: list[str], warnings: list[str]) -> None:
    labels: set[str] = set()
    for index, record in enumerate(records):
        path = f"record[{index}]"
        _validate_payload_for_report(record, path, errors)
        public_label = str(record.get("public_label") or "")
        entity_type = str(record.get("entity_type") or "")
        if not public_label:
            errors.append(f"{path} is missing public_label")
        elif public_label in labels:
            errors.append(f"duplicate public_label: {public_label}")
        labels.add(public_label)
        if not entity_type:
            errors.append(f"{path} is missing entity_type")
        elif entity_type not in SPEC_ENTITY_TYPES and entity_type not in TEST_ENTITY_TYPES:
            errors.append(f"{path} has unknown entity_type {entity_type!r}")
        if record.get("review_status") != "reviewed":
            errors.append(f"{public_label or path} review_status must be reviewed")
        if record.get("taint_level") != "reviewed_public":
            errors.append(f"{public_label or path} taint_level must be reviewed_public")
        if record.get("publication_decision") not in PUBLISH_DECISIONS:
            errors.append(f"{public_label or path} publication_decision must be approved")
        _validate_record_shape(record, public_label or path, entity_type, errors, warnings)


def _validate_record_shape(
    record: dict[str, Any],
    label: str,
    entity_type: str,
    errors: list[str],
    warnings: list[str],
) -> None:
    if entity_type == "behavior_contract":
        if not str(record.get("contract_id") or ""):
            errors.append(f"{label} behavior_contract is missing contract_id")
        if not isinstance(record.get("contract"), dict):
            errors.append(f"{label} behavior_contract is missing contract object")
        return
    if entity_type == "internal_routine_contract":
        for key in ("public_name", "purpose_summary", "calling_convention", "signature"):
            if not str(record.get(key) or ""):
                errors.append(f"{label} internal_routine_contract is missing {key}")
        for key in ("inputs", "outputs"):
            if key in record and not isinstance(record.get(key), dict):
                errors.append(f"{label} internal_routine_contract {key} must be an object")
        return
    if entity_type == "behavior_observation":
        _require_clean_test_common(record, label, errors)
        if record.get("status") != "pass":
            errors.append(f"{label} behavior_observation status must be pass")
        if not isinstance(record.get("outputs"), dict) or not record.get("outputs"):
            errors.append(f"{label} behavior_observation outputs must be a non-empty object")
        return
    if entity_type == "process_behavior_observation":
        _require_clean_test_common(record, label, errors)
        if record.get("status") != "pass":
            errors.append(f"{label} process_behavior_observation status must be pass")
        inputs = record.get("inputs")
        outputs = record.get("outputs")
        if not isinstance(inputs, dict):
            errors.append(f"{label} process_behavior_observation inputs must be an object")
        elif "argv" not in inputs or not isinstance(inputs.get("argv"), list):
            errors.append(f"{label} process_behavior_observation inputs.argv must be a list")
        if not isinstance(outputs, dict):
            errors.append(f"{label} process_behavior_observation outputs must be an object")
        else:
            for key in ("returncode", "timed_out"):
                if key not in outputs:
                    errors.append(f"{label} process_behavior_observation outputs.{key} is required")
        return
    if entity_type in TEST_ENTITY_TYPES:
        _require_clean_test_common(record, label, errors)
        if "status" not in record:
            warnings.append(f"{label} test record has no status field")


def _require_clean_test_common(record: dict[str, Any], label: str, errors: list[str]) -> None:
    if not str(record.get("test_id") or ""):
        errors.append(f"{label} test record is missing test_id")


def _validate_behavior_contract_links(
    spec_records: list[dict[str, Any]],
    test_records: list[dict[str, Any]],
    errors: list[str],
) -> None:
    contract_ids = {
        str(record.get("contract_id"))
        for record in spec_records
        if record.get("entity_type") == "behavior_contract" and record.get("contract_id")
    }
    for record in test_records:
        entity_type = record.get("entity_type")
        if entity_type not in {"behavior_observation", "process_behavior_observation"}:
            continue
        contract_id = str(record.get("contract_id") or "")
        if not contract_id:
            errors.append(f"{record.get('public_label')} {entity_type} is missing contract_id")
        elif contract_id not in contract_ids:
            errors.append(f"{record.get('public_label')} references unknown behavior contract {contract_id}")


def _validate_contract_coverage_requirements(
    spec_records: list[dict[str, Any]],
    test_records: list[dict[str, Any]],
    other_records: list[dict[str, Any]],
    errors: list[str],
) -> None:
    all_records = spec_records + test_records + other_records
    for contract_record in spec_records:
        if contract_record.get("entity_type") != "behavior_contract":
            continue
        contract = contract_record.get("contract")
        if not isinstance(contract, dict):
            continue
        requirements = contract.get("coverage_requirements")
        if requirements in (None, {}):
            continue
        if not isinstance(requirements, dict):
            errors.append(f"{contract_record.get('public_label')} contract.coverage_requirements must be an object")
            continue
        required_records = requirements.get("required_records", [])
        if not isinstance(required_records, list):
            errors.append(f"{contract_record.get('public_label')} coverage_requirements.required_records must be a list")
            continue
        for index, requirement in enumerate(required_records):
            label = f"{contract_record.get('public_label')} coverage requirement {index}"
            if not isinstance(requirement, dict):
                errors.append(f"{label} must be an object")
                continue
            requirement_id = str(requirement.get("id") or f"requirement-{index}")
            entity_type = str(requirement.get("entity_type") or "")
            match = requirement.get("match") or {}
            if not entity_type:
                errors.append(f"{label} {requirement_id} is missing entity_type")
                continue
            if not isinstance(match, dict) or not match:
                errors.append(f"{label} {requirement_id} match must be a non-empty object")
                continue
            if not _coverage_requirement_matches(all_records, entity_type, match):
                errors.append(
                    f"{contract_record.get('public_label')} coverage requirement {requirement_id} "
                    f"has no matching {entity_type} record"
                )


def _coverage_requirement_matches(
    records: list[dict[str, Any]],
    entity_type: str,
    match: dict[str, Any],
) -> bool:
    for record in records:
        if record.get("entity_type") != entity_type:
            continue
        if all(_lookup_public_path(record, path) == expected for path, expected in match.items()):
            return True
    return False


def _lookup_public_path(record: dict[str, Any], path: str) -> Any:
    value: Any = record
    for part in str(path).split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return None
    return value


def _validate_tests_json(
    tests: dict[str, Any],
    spec: dict[str, Any],
    test_records: list[dict[str, Any]],
    errors: list[str],
) -> None:
    if tests.get("format") != CLEAN_SPEC_FORMAT_VERSION:
        errors.append(f"tests format must be {CLEAN_SPEC_FORMAT_VERSION}")
    if tests.get("status") != spec.get("status"):
        errors.append("tests status does not match spec status")
    if tests.get("source_corpus") != spec.get("source_corpus"):
        errors.append("tests source_corpus does not match spec source_corpus")
    if tests.get("test_records") != test_records:
        errors.append("tests test_records do not match spec test_records")
    summary = tests.get("summary")
    if not isinstance(summary, dict) or int(summary.get("test_records", -1) or 0) != len(test_records):
        errors.append("tests summary.test_records does not match actual test record count")
    _validate_payload_for_report(tests, "$.tests", errors)


def _validate_payload_for_report(value: Any, path: str, errors: list[str]) -> None:
    try:
        _validate_public_payload(value, path=path)
    except ValueError as exc:
        errors.append(str(exc))


def _specs_json(
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
    skipped: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    status: str,
) -> dict[str, Any]:
    spec_records = [record for record in records if record["entity_type"] in SPEC_ENTITY_TYPES]
    test_records = [record for record in records if record["entity_type"] in TEST_ENTITY_TYPES]
    other_records = [
        record
        for record in records
        if record["entity_type"] not in SPEC_ENTITY_TYPES and record["entity_type"] not in TEST_ENTITY_TYPES
    ]
    return {
        "schema_version": 1,
        "format": CLEAN_SPEC_FORMAT_VERSION,
        "status": status,
        "generated_at": utc_now(),
        "source_corpus": _public_source_corpus(manifest),
        "summary": {
            "templates": len(records) + len(skipped) + len(rejected),
            "reviewed_records": len(records),
            "skipped_templates": len(skipped),
            "rejected_templates": len(rejected),
            "spec_records": len(spec_records),
            "test_records": len(test_records),
            "other_records": len(other_records),
        },
        "spec_records": spec_records,
        "test_records": test_records,
        "other_records": other_records,
    }


def _tests_json(specs: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "format": CLEAN_SPEC_FORMAT_VERSION,
        "status": specs["status"],
        "generated_at": specs["generated_at"],
        "source_corpus": specs["source_corpus"],
        "summary": {"test_records": len(specs["test_records"])},
        "test_records": specs["test_records"],
    }


def _public_source_corpus(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "target": manifest.get("target", {}),
        "source_manifest_sha256": manifest.get("manifest_sha256"),
        "source_kind": "review_corpus",
    }


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"missing JSON file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"expected JSON object in {path}")
    return data


def _md_inline(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")
