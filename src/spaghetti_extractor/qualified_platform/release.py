"""Closed codec for the target-independent qualified-platform-v1 release.

The release authorizes only individually qualified entries.  Disputed or
incomplete veto evidence stays in the same structurally complete catalog as an
explicit blocker and cannot be selected by a target.  No target, PE, semantic
object, component, or occurrence is an input.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..transfer import behavioral_c_render, runtime_helpers
from ..transfer.behavioral_c_render import behavioral_c_operation_coverage_v2
from ..errors import ToolkitInputError
from ..isa.catalog import ISA_PROFILE_ID
from ..isa.qualification_certificate import (
    parse_isa_kernel_qualification_certificate_v1,
)
from ..isa.semantic_forms import lean_semantic_form_classifier_sha256
from ..transfer import (
    definedness,
    evaluator,
    operations,
    provenance_coverage,
    z3_domain,
)
from ..transfer.definedness import definedness_operation_coverage_v2
from ..transfer.evaluator import concrete_operation_coverage_v2
from ..transfer.interpretation import operation_coverage_matrix_v2
from ..transfer.operations import (
    operation_registry_payload_v2,
    runtime_provider_catalog_payload_v2,
)
from ..transfer.provenance_coverage import reference_operation_coverage_v2
from ..transfer.z3_domain import z3_operation_coverage_v2
from ..util import sha256_bytes, sha256_file, write_json
from .formats import ISA_SEMANTIC_KERNEL_BINDING_FORMAT, QUALIFIED_PLATFORM_FORMAT
from .isa_form_inventory import (
    load_qualified_platform_isa_form_inventory_v1,
)
from .isa_form_replay import parse_qualified_platform_isa_form_replay_v1
from .isa_surface_review import isa_surface_review_payload_v1
from .native_catalog import (
    abi_profile_catalog_payload_v1,
    native_primitive_catalog_payload_v1,
)


MAX_QUALIFIED_PLATFORM_BYTES = 32 * 1024 * 1024
_SEMANTIC_KERNEL_FORMAT = ISA_SEMANTIC_KERNEL_BINDING_FORMAT
_FIELDS = {
    "format", "status", "role", "authority", "target_independent",
    "bindings", "members", "primitive_catalog", "runtime_provider_catalog",
    "isa_form_catalog", "abi_profiles", "native_primitives", "evidence",
    "holes", "counts", "platform_sha256",
}
_KERNEL_FIELDS = {
    "format", "id", "decoder_sha256", "semantics_sha256", "lean_version",
}


class QualifiedPlatformError(ToolkitInputError):
    """The qualified platform release failed closed."""


def _fail(message: str) -> None:
    raise QualifiedPlatformError(message)


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an object")
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(f"{context} must be an array")
    return value


def _sha256(value: object, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(f"{context} must be lowercase SHA-256")
    return value


def _source_sha256(module: ModuleType) -> str:
    source = getattr(module, "__file__", None)
    if not isinstance(source, str):
        _fail(f"platform implementation module {module.__name__} has no source")
    return sha256_file(Path(source))


def _load_json(path: Path, context: str) -> tuple[dict[str, Any], str]:
    source = Path(path)
    try:
        if source.stat().st_size > MAX_QUALIFIED_PLATFORM_BYTES:
            _fail(f"{context} exceeds the platform release byte bound")
        data = source.read_bytes()
        payload = dict(_object(json.loads(data), context))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"cannot read {context}: {exc}")
    return payload, sha256_bytes(data)


def _semantic_kernel(path: Path) -> tuple[dict[str, Any], str]:
    payload, content_sha256 = _load_json(path, "Lean semantic-kernel binding")
    if set(payload) != _KERNEL_FIELDS or payload.get("format") != _SEMANTIC_KERNEL_FORMAT:
        _fail("Lean semantic-kernel binding is malformed")
    for field in ("decoder_sha256", "semantics_sha256"):
        _sha256(payload[field], f"Lean semantic-kernel {field}")
    if not all(isinstance(payload[field], str) and payload[field] for field in (
        "id", "lean_version",
    )):
        _fail("Lean semantic-kernel identity is malformed")
    return payload, content_sha256


def _coverage() -> dict[str, Any]:
    return operation_coverage_matrix_v2((
        behavioral_c_operation_coverage_v2(),
        concrete_operation_coverage_v2(),
        definedness_operation_coverage_v2(),
        reference_operation_coverage_v2(),
        z3_operation_coverage_v2(),
    ))


def _source_bindings() -> dict[str, str]:
    return {
        "behavioral_c_lowering_sha256": _source_sha256(behavioral_c_render),
        "runtime_helper_source_sha256": _source_sha256(runtime_helpers),
        "transfer_operations_sha256": _source_sha256(operations),
        "veto_concrete_evaluator_sha256": _source_sha256(evaluator),
        "veto_definedness_sha256": _source_sha256(definedness),
        "reference_provenance_coverage_sha256": _source_sha256(
            provenance_coverage
        ),
        "veto_z3_reconstruction_sha256": _source_sha256(z3_domain),
    }


def _providers_by_operation(
    provider_catalog: list[dict[str, object]],
) -> dict[tuple[str, str], list[str]]:
    result: dict[tuple[str, str], set[str]] = {}
    field_for = {
        "expression": "expression_operations",
        "effect": "effect_operations",
        "terminator": "terminator_operations",
    }
    for provider in provider_catalog:
        for category, field in field_for.items():
            for operation in provider[field]:
                result.setdefault((category, str(operation)), set()).add(
                    str(provider["provider"])
                )
    return {key: sorted(value) for key, value in result.items()}


def _primitive_catalog() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    registry = operation_registry_payload_v2()
    coverage = _coverage()
    coverage_by_key = {
        (str(row["category"]), str(row["operation"])): row["domains"]
        for row in coverage["operations"]
    }
    providers = runtime_provider_catalog_payload_v2()
    providers_by_key = _providers_by_operation(providers)
    primitives = []
    for operation in registry:
        category, name = str(operation["category"]), str(operation["name"])
        domains = dict(coverage_by_key[(category, name)])
        primitives.append({
            "primitive_id": f"transfer-v2:{category}:{name}",
            "semantic_form": f"transfer-v2/{category}/{name}",
            "category": category,
            "operation": name,
            "transfer_template": operation,
            "transfer_template_sha256": canonical_sha256_v3(operation),
            "lean_qualification": {
                "status": "upstream_form_binding_pending",
                "evidence_id": None,
            },
            "veto_oracle_observations": {
                domain: status
                for domain, status in domains.items()
                if domain != "behavioral_c"
            },
            "behavioral_c_lowering": {
                "status": domains["behavioral_c"],
                "implementation": "behavioral_c_render_v2",
            },
            "required_runtime_providers": providers_by_key.get(
                (category, name), []
            ),
        })
    return primitives, coverage


def _isa_form_replay(path: Path) -> tuple[dict[str, Any], str]:
    payload, content_sha256 = _load_json(path, "Lean ISA form replay")
    return parse_qualified_platform_isa_form_replay_v1(payload), content_sha256


def _isa_form_qualification(
    path: Path,
) -> tuple[dict[str, Any], str]:
    payload, content_sha256 = _load_json(
        path, "shared ISA form qualification certificate"
    )
    return (
        parse_isa_kernel_qualification_certificate_v1(payload),
        content_sha256,
    )


def _isa_form_catalog(
    inventory: Mapping[str, Any],
    replay: Mapping[str, Any],
    qualification: Mapping[str, Any],
) -> list[dict[str, Any]]:
    replay_by_id = {row["form_id"]: row for row in replay["forms"]}
    qualification_by_id = {
        row["form_id"]: row for row in qualification["forms"]
    }
    return [
        {
            **dict(row),
            "lean_decode": {
                "status": replay_by_id[row["form_id"]]["status"],
                "evidence_id": replay["replay_sha256"],
            },
            "qualification": {
                "status": qualification_by_id[
                    row["form_id"]
                ]["oracle_status"],
                "structural_status": qualification_by_id[
                    row["form_id"]
                ]["structural_status"],
                "evidence_id": qualification_by_id[
                    row["form_id"]
                ]["qualification_sha256"],
            },
        }
        for row in inventory["forms"]
    ]


def _holes(
    qualification: Mapping[str, Any],
    native_primitives: list[dict[str, Any]],
) -> list[dict[str, str]]:
    pending_native = [
        row["provider_id"] for row in native_primitives
        if row["qualification"]["status"] != "complete"
    ]
    holes = []
    if pending_native:
        holes.append({
            "kind": "native_primitive_qualification_unlinked",
            "subject": "qualified-platform",
            "detail": (
                f"{len(pending_native)} declared ingress, SEH, TLS, object, "
                "capability, x87, atomic, and outcome providers still require "
                "reviewed contract qualification"
            ),
        })
    for status in ("incomplete", "disputed", "vetoed"):
        count = int(qualification["counts"][status])
        if count:
            holes.append({
                "kind": f"isa_form_oracle_{status}",
                "subject": "qualified-platform",
                "detail": (
                    f"{count} intrinsic ISA semantic forms have {status} "
                    "concrete-oracle evidence"
                ),
            })
    return holes


def build_qualified_platform_v1(
    *,
    semantic_kernel: Path,
    isa_form_inventory: Path,
    isa_form_replay: Path,
    isa_form_qualification_certificate: Path,
) -> dict[str, Any]:
    """Build the target-independent migration release from intrinsic inputs."""

    kernel, kernel_content_sha256 = _semantic_kernel(Path(semantic_kernel))
    inventory_path = Path(isa_form_inventory)
    inventory = load_qualified_platform_isa_form_inventory_v1(inventory_path)
    inventory_content_sha256 = sha256_file(inventory_path)
    replay, replay_content_sha256 = _isa_form_replay(Path(isa_form_replay))
    qualification, qualification_certificate_content_sha256 = (
        _isa_form_qualification(Path(isa_form_qualification_certificate))
    )
    if (
        replay["status"] != "complete"
        or replay["inventory"]
        != {
            "sha256": inventory["inventory_sha256"],
            "content_sha256": inventory_content_sha256,
        }
        or replay["semantic_kernel"]
        != {
            "id": kernel["id"],
            "decoder_sha256": kernel["decoder_sha256"],
            "semantics_sha256": kernel["semantics_sha256"],
            "content_sha256": kernel_content_sha256,
        }
        or [
            (row["form_id"], row["representative_instruction_hex"], row["status"])
            for row in replay["forms"]
        ]
        != [
            (row["form_id"], row["representative_instruction_hex"], "checked")
            for row in inventory["forms"]
        ]
        or replay["lean_exporter"]["classifier_sha256"]
        != inventory["classifier_sha256"]
    ):
        _fail("Lean ISA form replay does not bind the exact platform inputs")
    inventory_forms = [
        (row["form_id"], row["semantic_form"])
        for row in inventory["forms"]
    ]
    qualification_forms = [
        (row["form_id"], row["semantic_form"])
        for row in qualification["forms"]
    ]
    if (
        qualification["profile"]["id"] != ISA_PROFILE_ID
        or qualification["classifier_sha256"]
        != inventory["classifier_sha256"]
        or qualification["profile"]["architecture"] != "x86"
        or qualification["profile"]["cpu"] != "i686"
        or qualification["profile"]["execution_mode"] != "protected-32"
        or qualification["profile"]["environment"] != "pe32"
        or qualification["semantic_kernel"]["id"] != kernel["id"]
        or qualification["semantic_kernel"]["decoder_sha256"]
        != kernel["decoder_sha256"]
        or qualification["semantic_kernel"]["semantics_sha256"]
        != kernel["semantics_sha256"]
        or qualification_forms != inventory_forms
    ):
        _fail(
            "shared ISA qualification does not bind every intrinsic platform "
            "form and the exact semantic kernel"
        )
    primitives, coverage = _primitive_catalog()
    providers = runtime_provider_catalog_payload_v2()
    abi_profiles = abi_profile_catalog_payload_v1()
    native_primitives = native_primitive_catalog_payload_v1()
    isa_surface_review = isa_surface_review_payload_v1(inventory)
    source_bindings = _source_bindings()
    holes = _holes(qualification, native_primitives)
    payload: dict[str, Any] = {
        "format": QUALIFIED_PLATFORM_FORMAT,
        "status": "complete",
        "role": "qualified_platform_release",
        "authority": True,
        "target_independent": True,
        "bindings": {
            "classifier_sha256": lean_semantic_form_classifier_sha256(),
            "semantic_kernel_id": kernel["id"],
            "semantic_kernel_decoder_sha256": kernel["decoder_sha256"],
            "semantic_kernel_semantics_sha256": kernel["semantics_sha256"],
            "semantic_kernel_content_sha256": kernel_content_sha256,
            "isa_form_inventory_sha256": inventory["inventory_sha256"],
            "isa_form_inventory_content_sha256": inventory_content_sha256,
            "isa_surface_review_sha256": isa_surface_review["review_sha256"],
            "isa_form_replay_sha256": replay["replay_sha256"],
            "isa_form_replay_content_sha256": replay_content_sha256,
            "isa_form_qualification_sha256": qualification[
                "qualification"
            ]["sha256"],
            "isa_form_qualification_content_sha256": (
                qualification["qualification"]["content_sha256"]
            ),
            "isa_form_qualification_certificate_sha256": qualification[
                "certificate_sha256"
            ],
            "isa_form_qualification_certificate_content_sha256": (
                qualification_certificate_content_sha256
            ),
            "operation_registry_sha256": canonical_sha256_v3(
                operation_registry_payload_v2()
            ),
            "operation_coverage_sha256": coverage["coverage_sha256"],
            "runtime_provider_catalog_sha256": canonical_sha256_v3(providers),
            "abi_profile_catalog_sha256": canonical_sha256_v3(abi_profiles),
            "native_primitive_catalog_sha256": canonical_sha256_v3(
                native_primitives
            ),
            **source_bindings,
        },
        "members": {
            "semantic_kernel": {
                "path": "semantic-kernel.json",
                "content_sha256": kernel_content_sha256,
                "id": kernel["id"],
            },
            "isa_form_inventory": {
                "path": "isa-form-inventory.json",
                "content_sha256": inventory_content_sha256,
                "identity": inventory["inventory_sha256"],
            },
            "isa_form_replay": {
                "path": "isa-form-replay.json",
                "content_sha256": replay_content_sha256,
                "identity": replay["replay_sha256"],
            },
            "isa_form_qualification_certificate": {
                "path": "isa-form-qualification-certificate.json",
                "content_sha256": (
                    qualification_certificate_content_sha256
                ),
                "identity": qualification["certificate_sha256"],
            },
        },
        "primitive_catalog": primitives,
        "runtime_provider_catalog": providers,
        "isa_form_catalog": _isa_form_catalog(
            inventory,
            replay,
            qualification,
        ),
        "abi_profiles": abi_profiles,
        "native_primitives": native_primitives,
        "evidence": [{
            "kind": "lean_semantic_kernel_binding",
            "identity": kernel["id"],
            "content_sha256": kernel_content_sha256,
            "authority": "kernel_identity_only",
        }, {
            "kind": "target_independent_reviewed_isa_form_allowlist",
            "identity": inventory["inventory_sha256"],
            "content_sha256": inventory_content_sha256,
            "authority": "finite_exact_allowlist",
            "surface_review": isa_surface_review,
        }, {
            "kind": "lean_isa_form_replay",
            "identity": replay["replay_sha256"],
            "content_sha256": replay_content_sha256,
            "authority": "veto_only",
        }, {
            "kind": "shared_isa_form_qualification",
            "identity": qualification["qualification"]["sha256"],
            "content_sha256": qualification["qualification"][
                "content_sha256"
            ],
            "certificate_sha256": qualification["certificate_sha256"],
            "authority": "lean_structural_with_veto_only_oracles",
        }],
        "holes": holes,
        "counts": {
            "transfer_primitives": len(primitives),
            "runtime_providers": len(providers),
            "isa_forms": inventory["counts"]["forms"],
            "isa_form_constructors": isa_surface_review["counts"]["constructors"],
            "isa_forms_qualified": qualification["counts"]["qualified"],
            "isa_forms_incomplete": qualification["counts"]["incomplete"],
            "isa_forms_disputed": qualification["counts"]["disputed"],
            "isa_forms_vetoed": qualification["counts"]["vetoed"],
            "abi_profiles": len(abi_profiles),
            "native_primitives": len(native_primitives),
            "veto_domains": len(coverage["domain_ids"]) - 1,
            "behavioral_c_rejections": sum(
                row["behavioral_c_lowering"]["status"] == "rejected"
                for row in primitives
            ),
            "holes": len(holes),
        },
    }
    payload["platform_sha256"] = canonical_sha256_v3(payload)
    return payload


@dataclass(frozen=True)
class QualifiedPlatformV1:
    payload: Mapping[str, Any]
    semantic_kernel: Mapping[str, Any]
    isa_form_inventory: Mapping[str, Any]
    isa_form_replay: Mapping[str, Any]
    isa_form_qualification_certificate: Mapping[str, Any]
    package_root: Path | None = None

    @property
    def identity(self) -> str:
        return str(self.payload["platform_sha256"])

    @classmethod
    def parse(
        cls, value: object, *, semantic_kernel: Path, isa_form_inventory: Path,
        isa_form_replay: Path, isa_form_qualification_certificate: Path,
        require_complete: bool = False,
    ) -> "QualifiedPlatformV1":
        payload = dict(_object(value, "qualified platform"))
        if set(payload) != _FIELDS or payload.get("format") != QUALIFIED_PLATFORM_FORMAT:
            _fail("qualified platform fields or format are unsupported")
        declared = _sha256(payload.get("platform_sha256"), "platform SHA-256")
        core = {key: item for key, item in payload.items() if key != "platform_sha256"}
        if declared != canonical_sha256_v3(core):
            _fail("qualified platform self hash is stale")
        expected = build_qualified_platform_v1(
            semantic_kernel=semantic_kernel,
            isa_form_inventory=isa_form_inventory,
            isa_form_replay=isa_form_replay,
            isa_form_qualification_certificate=(
                isa_form_qualification_certificate
            ),
        )
        if payload != expected:
            _fail("qualified platform does not replay from intrinsic registries")
        if (
            payload.get("status") != "complete"
            or payload.get("role") != "qualified_platform_release"
            or payload.get("authority") is not True
            or payload.get("target_independent") is not True
            or not isinstance(payload.get("holes"), list)
        ):
            _fail("qualified platform release authority is malformed")
        kernel, _ = _semantic_kernel(semantic_kernel)
        inventory = load_qualified_platform_isa_form_inventory_v1(
            isa_form_inventory
        )
        replay, _ = _isa_form_replay(isa_form_replay)
        qualification, _ = _isa_form_qualification(
            isa_form_qualification_certificate
        )
        return cls(payload, kernel, inventory, replay, qualification)

    @classmethod
    def load(
        cls, path: Path, *, require_complete: bool = False,
    ) -> "QualifiedPlatformV1":
        source = Path(path)
        payload, _ = _load_json(source, "qualified platform")
        parsed = cls.parse(
            payload,
            semantic_kernel=source.parent / "semantic-kernel.json",
            isa_form_inventory=source.parent / "isa-form-inventory.json",
            isa_form_replay=source.parent / "isa-form-replay.json",
            isa_form_qualification_certificate=(
                source.parent / "isa-form-qualification-certificate.json"
            ),
            require_complete=require_complete,
        )
        return cls(
            parsed.payload,
            parsed.semantic_kernel,
            parsed.isa_form_inventory,
            parsed.isa_form_replay,
            parsed.isa_form_qualification_certificate,
            source.parent,
        )


def write_qualified_platform_v1(
    *, semantic_kernel: Path, isa_form_inventory: Path, isa_form_replay: Path,
    isa_form_qualification_certificate: Path,
    out: Path,
    link_member: bool = False,
) -> dict[str, Any]:
    payload = build_qualified_platform_v1(
        semantic_kernel=semantic_kernel,
        isa_form_inventory=isa_form_inventory,
        isa_form_replay=isa_form_replay,
        isa_form_qualification_certificate=isa_form_qualification_certificate,
    )
    destination = Path(out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    for source, member_name in (
        (Path(semantic_kernel), "semantic-kernel.json"),
        (Path(isa_form_inventory), "isa-form-inventory.json"),
        (Path(isa_form_replay), "isa-form-replay.json"),
        (
            Path(isa_form_qualification_certificate),
            "isa-form-qualification-certificate.json",
        ),
    ):
        member = destination.parent / member_name
        if source.absolute() == member.absolute():
            continue
        if member.exists() or member.is_symlink():
            member.unlink()
        if link_member:
            member.symlink_to(source.resolve())
        else:
            shutil.copyfile(source, member)
    write_json(destination, payload)
    return payload


__all__ = [
    "MAX_QUALIFIED_PLATFORM_BYTES", "QualifiedPlatformError",
    "QualifiedPlatformV1", "build_qualified_platform_v1",
    "write_qualified_platform_v1",
]
