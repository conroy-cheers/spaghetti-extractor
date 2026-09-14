"""Independent veto-only replay for qualified-platform-v1."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..transfer.behavioral_c_render import behavioral_c_operation_coverage_v2
from ..errors import ToolkitInputError
from ..isa.catalog import ISA_PROFILE_ID
from ..isa.qualification_certificate import (
    parse_isa_kernel_qualification_certificate_v1,
)
from ..isa.semantic_forms import lean_semantic_form_classifier_sha256
from ..transfer.definedness import definedness_operation_coverage_v2
from ..transfer.evaluator import concrete_operation_coverage_v2
from ..transfer.interpretation import operation_coverage_matrix_v2
from ..transfer.operations import (
    operation_registry_payload_v2,
    runtime_provider_catalog_payload_v2,
)
from ..transfer.provenance_coverage import reference_operation_coverage_v2
from ..transfer.z3_domain import z3_operation_coverage_v2
from ..util import sha256_bytes
from .formats import QUALIFIED_PLATFORM_FORMAT
from .isa_form_inventory import (
    parse_qualified_platform_isa_form_inventory_v1,
)
from .isa_form_replay import parse_qualified_platform_isa_form_replay_v1
from .isa_surface_review import isa_surface_review_payload_v1
from .native_catalog import (
    abi_profile_catalog_payload_v1,
    native_primitive_catalog_payload_v1,
)


def _fail(message: str) -> None:
    raise ToolkitInputError(f"qualified-platform independent replay: {message}")


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{context} is not an object")
    return value


def replay_qualified_platform_v1(path: Path) -> dict[str, Any]:
    source = Path(path)
    try:
        payload = dict(_object(json.loads(source.read_bytes()), "platform"))
        kernel_bytes = (source.parent / "semantic-kernel.json").read_bytes()
        kernel = dict(_object(json.loads(kernel_bytes), "semantic kernel"))
        inventory_bytes = (source.parent / "isa-form-inventory.json").read_bytes()
        inventory = parse_qualified_platform_isa_form_inventory_v1(
            json.loads(inventory_bytes)
        )
        form_replay_bytes = (source.parent / "isa-form-replay.json").read_bytes()
        form_replay = parse_qualified_platform_isa_form_replay_v1(
            json.loads(form_replay_bytes)
        )
        qualification_certificate_bytes = (
            source.parent / "isa-form-qualification-certificate.json"
        ).read_bytes()
        qualification = parse_isa_kernel_qualification_certificate_v1(
            json.loads(qualification_certificate_bytes)
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"cannot read package: {exc}")
    if payload.get("format") != QUALIFIED_PLATFORM_FORMAT:
        _fail("format is unsupported")
    core = {key: value for key, value in payload.items() if key != "platform_sha256"}
    if payload.get("platform_sha256") != canonical_sha256_v3(core):
        _fail("self hash is stale")
    if (
        payload.get("status") != "complete"
        or payload.get("role") != "qualified_platform_release"
        or payload.get("authority") is not True
        or payload.get("target_independent") is not True
    ):
        _fail("platform release authority or target independence is malformed")
    bindings = _object(payload.get("bindings"), "bindings")
    registry = operation_registry_payload_v2()
    providers = runtime_provider_catalog_payload_v2()
    abi_profiles = abi_profile_catalog_payload_v1()
    native_primitives = native_primitive_catalog_payload_v1()
    isa_surface_review = isa_surface_review_payload_v1(inventory)
    coverage = operation_coverage_matrix_v2((
        behavioral_c_operation_coverage_v2(),
        concrete_operation_coverage_v2(),
        definedness_operation_coverage_v2(),
        reference_operation_coverage_v2(),
        z3_operation_coverage_v2(),
    ))
    expected_bindings = {
        "classifier_sha256": lean_semantic_form_classifier_sha256(),
        "semantic_kernel_id": kernel.get("id"),
        "semantic_kernel_decoder_sha256": kernel.get("decoder_sha256"),
        "semantic_kernel_semantics_sha256": kernel.get("semantics_sha256"),
        "semantic_kernel_content_sha256": sha256_bytes(kernel_bytes),
        "isa_form_inventory_sha256": inventory["inventory_sha256"],
        "isa_form_inventory_content_sha256": sha256_bytes(inventory_bytes),
        "isa_surface_review_sha256": isa_surface_review["review_sha256"],
        "isa_form_replay_sha256": form_replay["replay_sha256"],
        "isa_form_replay_content_sha256": sha256_bytes(form_replay_bytes),
        "isa_form_qualification_sha256": qualification[
            "qualification"
        ]["sha256"],
        "isa_form_qualification_content_sha256": qualification[
            "qualification"
        ]["content_sha256"],
        "isa_form_qualification_certificate_sha256": qualification[
            "certificate_sha256"
        ],
        "isa_form_qualification_certificate_content_sha256": sha256_bytes(
            qualification_certificate_bytes
        ),
        "operation_registry_sha256": canonical_sha256_v3(registry),
        "operation_coverage_sha256": coverage["coverage_sha256"],
        "runtime_provider_catalog_sha256": canonical_sha256_v3(providers),
        "abi_profile_catalog_sha256": canonical_sha256_v3(abi_profiles),
        "native_primitive_catalog_sha256": canonical_sha256_v3(
            native_primitives
        ),
    }
    for key, value in expected_bindings.items():
        if bindings.get(key) != value:
            _fail(f"binding {key} is stale")
    primitives = payload.get("primitive_catalog")
    if not isinstance(primitives, list) or len(primitives) != len(registry):
        _fail("transfer primitive inventory is not total")
    keys = [(row.get("category"), row.get("operation")) for row in primitives]
    expected_keys = [(row["category"], row["name"]) for row in registry]
    if keys != expected_keys or len(set(keys)) != len(keys):
        _fail("transfer primitive identities are stale or duplicated")
    coverage_by_key = {
        (row["category"], row["operation"]): row["domains"]
        for row in coverage["operations"]
    }
    for row in primitives:
        key = (row["category"], row["operation"])
        if row.get("behavioral_c_lowering", {}).get("status") != coverage_by_key[key]["behavioral_c"]:
            _fail(f"Behavioral-C lowering status is stale for {key!r}")
    if payload.get("runtime_provider_catalog") != providers:
        _fail("runtime provider catalog is stale")
    if (
        form_replay.get("status") != "complete"
        or form_replay.get("inventory")
        != {
            "sha256": inventory["inventory_sha256"],
            "content_sha256": sha256_bytes(inventory_bytes),
        }
        or form_replay.get("semantic_kernel")
        != {
            "id": kernel.get("id"),
            "decoder_sha256": kernel.get("decoder_sha256"),
            "semantics_sha256": kernel.get("semantics_sha256"),
            "content_sha256": sha256_bytes(kernel_bytes),
        }
        or [
            (
                row.get("form_id"),
                row.get("representative_instruction_hex"),
                row.get("status"),
            )
            for row in form_replay["forms"]
        ]
        != [
            (
                row["form_id"],
                row["representative_instruction_hex"],
                "checked",
            )
            for row in inventory["forms"]
        ]
    ):
        _fail("Lean form replay does not bind the intrinsic inventory and kernel")
    inventory_forms = [
        (row["form_id"], row["semantic_form"])
        for row in inventory["forms"]
    ]
    if (
        qualification["profile"]["id"] != ISA_PROFILE_ID
        or qualification["classifier_sha256"]
        != inventory["classifier_sha256"]
        or qualification["profile"]["architecture"] != "x86"
        or qualification["profile"]["cpu"] != "i686"
        or qualification["profile"]["execution_mode"] != "protected-32"
        or qualification["profile"]["environment"] != "pe32"
        or qualification["semantic_kernel"]["id"] != kernel.get("id")
        or qualification["semantic_kernel"]["decoder_sha256"]
        != kernel.get("decoder_sha256")
        or qualification["semantic_kernel"]["semantics_sha256"]
        != kernel.get("semantics_sha256")
        or [
            (row["form_id"], row["semantic_form"])
            for row in qualification["forms"]
        ]
        != inventory_forms
    ):
        _fail("shared ISA qualification is not the exact platform campaign")
    qualification_by_id = {
        row["form_id"]: row for row in qualification["forms"]
    }
    expected_forms = [
        {
            **dict(row),
            "lean_decode": {
                "status": "checked",
                "evidence_id": form_replay["replay_sha256"],
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
    if payload.get("isa_form_catalog") != expected_forms:
        _fail("ISA form catalog is not the exact intrinsic inventory projection")
    surface_evidence = [
        row for row in payload.get("evidence", [])
        if isinstance(row, Mapping)
        and row.get("kind")
        == "target_independent_reviewed_isa_form_allowlist"
    ]
    if (
        len(surface_evidence) != 1
        or surface_evidence[0].get("identity")
        != inventory["inventory_sha256"]
        or surface_evidence[0].get("authority") != "finite_exact_allowlist"
        or surface_evidence[0].get("surface_review") != isa_surface_review
    ):
        _fail("reviewed finite ISA classifier surface is stale")
    if payload.get("abi_profiles") != abi_profiles:
        _fail("physical ABI profile catalog is stale")
    if payload.get("native_primitives") != native_primitives:
        _fail("native primitive declaration catalog is stale")
    if any(
        row["qualification"]["status"] != "complete"
        or row["qualification"]["authority"]
        != "reviewed_native_primitive_contract"
        or row["qualification"]["test_results_authorizing"] is not False
        for row in native_primitives
    ):
        _fail("native contract review or veto-only policy is stale")
    holes = payload.get("holes")
    if not isinstance(holes, list):
        _fail("platform holes are malformed")
    return {
        "authority": True,
        "platform_sha256": payload["platform_sha256"],
        "transfer_primitives": len(primitives),
        "runtime_providers": len(providers),
        "isa_forms": len(expected_forms),
        "isa_forms_qualified": qualification["counts"]["qualified"],
        "isa_forms_incomplete": qualification["counts"]["incomplete"],
        "isa_forms_disputed": qualification["counts"]["disputed"],
        "isa_forms_vetoed": qualification["counts"]["vetoed"],
        "behavioral_c_rejections": sum(
            row["behavioral_c_lowering"]["status"] == "rejected"
            for row in primitives
        ),
        "abi_profiles": len(abi_profiles),
        "native_primitives": len(native_primitives),
        "holes": len(holes),
    }


__all__ = ["replay_qualified_platform_v1"]
