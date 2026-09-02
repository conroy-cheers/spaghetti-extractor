"""Closed projection and member validation for semantic-object-v1."""

from __future__ import annotations

from typing import Any, Mapping

from ..external.resolved import ResolvedExternalEnvironmentV1
from ..semantic_objects.object_authority import MachineObjectAuthorityV2
from ..transfer.exception_semantics import CheckedExceptionTransitionV1
from ..util import sha256_bytes
from .semantic_object import (
    _canonical_bytes,
    _definitions_with_evidence_dependencies,
    _effect_index,
    _evidence_inventory,
    _fail,
    _mapping,
    _migration_holes,
    _project_relocations,
    _project_roots,
    _project_symbols,
    _rows,
    _selection_reference,
    _sha256,
    _text,
)

def _validate_bindings(
    payload: Mapping[str, Any], plan: Mapping[str, Any],
    interface: Mapping[str, Any], authority: MachineObjectAuthorityV2,
    selection: Mapping[str, Any] | None,
    requirements: Mapping[str, Any] | None,
    platform: Mapping[str, Any] | None,
    resolved_environment: ResolvedExternalEnvironmentV1 | None,
    environment_content_sha256: str | None,
) -> None:
    bindings = _mapping(payload["bindings"], "semantic-object bindings")
    expected = {
        "pe_sha256", "image_id", "module_interface_sha256",
        "module_interface_content_sha256", "transfer_plan_sha256",
        "transfer_plan_content_sha256", "machine_object_authority_sha256",
        "machine_object_authority_content_sha256", "exact_universe_sha256",
        "operation_registry_sha256", "isa_requirements_sha256",
        "qualified_platform_sha256", "platform_selection_sha256",
        "resolved_external_environment_sha256",
        "resolved_external_environment_content_sha256",
    }
    if set(bindings) != expected:
        _fail("semantic-object binding fields are incomplete")
    for field in expected - {
        "image_id", "isa_requirements_sha256", "qualified_platform_sha256",
        "platform_selection_sha256",
        "resolved_external_environment_sha256",
        "resolved_external_environment_content_sha256",
    }:
        _sha256(bindings[field], f"semantic-object {field}")
    optional = (
        bindings["isa_requirements_sha256"],
        bindings["qualified_platform_sha256"],
        bindings["platform_selection_sha256"],
    )
    if any(value is None for value in optional) != all(
        value is None for value in optional
    ):
        _fail("semantic-object platform bindings are only partially present")
    for index, value in enumerate(optional):
        if value is not None:
            _sha256(value, f"semantic-object platform binding {index}")
    environment_bindings = (
        bindings["resolved_external_environment_sha256"],
        bindings["resolved_external_environment_content_sha256"],
    )
    if any(value is None for value in environment_bindings) != all(
        value is None for value in environment_bindings
    ):
        _fail("semantic-object environment bindings are only partially present")
    for index, value in enumerate(environment_bindings):
        if value is not None:
            _sha256(value, f"semantic-object environment binding {index}")
    _text(bindings["image_id"], "semantic-object image ID")
    observed = {
        "pe_sha256": interface["identity"]["pe_sha256"],
        "image_id": interface["image_id"],
        "module_interface_sha256": interface["interface_sha256"],
        "module_interface_content_sha256": sha256_bytes(_canonical_bytes(interface)),
        "transfer_plan_sha256": plan["plan_sha256"],
        "transfer_plan_content_sha256": sha256_bytes(_canonical_bytes(plan)),
        "machine_object_authority_sha256": authority.authority_sha256,
        "machine_object_authority_content_sha256": sha256_bytes(
            _canonical_bytes(authority.to_payload())
        ),
        "exact_universe_sha256": plan["bindings"]["exact_universe_sha256"],
        "operation_registry_sha256": plan["operation_registry_sha256"],
        "isa_requirements_sha256": (
            None if requirements is None else requirements["requirements_sha256"]
        ),
        "qualified_platform_sha256": (
            None if platform is None else platform["platform_sha256"]
        ),
        "platform_selection_sha256": (
            None if selection is None else selection["selection_sha256"]
        ),
        "resolved_external_environment_sha256": (
            None if resolved_environment is None
            else resolved_environment.identity
        ),
        "resolved_external_environment_content_sha256": (
            environment_content_sha256
        ),
    }
    if dict(bindings) != observed:
        _fail("semantic-object bindings are stale")


def _validate_projection(
    payload: Mapping[str, Any], plan: Mapping[str, Any],
    interface: Mapping[str, Any], authority: MachineObjectAuthorityV2,
    selection: Mapping[str, Any] | None,
    requirements: Mapping[str, Any] | None,
    platform: Mapping[str, Any] | None,
    checked_exceptions: tuple[CheckedExceptionTransitionV1, ...],
    resolved_environment: ResolvedExternalEnvironmentV1 | None,
    environment_content_sha256: str | None,
    transfers: tuple[Any, ...],
) -> None:
    symbols = _rows(payload["symbols"], "semantic-object symbols")
    definitions = _rows(payload["definitions"], "semantic-object definitions")
    relocations = _rows(payload["relocations"], "semantic-object relocations")
    roots = _rows(payload["roots"], "semantic-object roots")
    expected_symbols, expected_definitions, declaration_holes = _project_symbols(
        plan, interface, checked_exceptions, resolved_environment
    )
    expected_evidence = _evidence_inventory(
        plan=plan,
        plan_content_sha256=sha256_bytes(_canonical_bytes(plan)),
        interface=interface,
        interface_content_sha256=sha256_bytes(_canonical_bytes(interface)),
        authority=authority,
        authority_content_sha256=sha256_bytes(
            _canonical_bytes(authority.to_payload())
        ),
        selection=selection,
        requirements=requirements,
        requirements_content_sha256=(
            None if requirements is None
            else sha256_bytes(_canonical_bytes(requirements))
        ),
        platform=platform,
        resolved_environment=resolved_environment,
        environment_content_sha256=environment_content_sha256,
    )
    expected_definitions = _definitions_with_evidence_dependencies(
        expected_definitions, expected_evidence, selection, checked_exceptions
    )
    if symbols != expected_symbols or definitions != expected_definitions:
        _fail("semantic-object declarations do not replay from their bound inputs")
    expected_relocations, relocation_holes = _project_relocations(
        plan, interface, checked_exceptions
    )
    if relocations != expected_relocations:
        _fail("semantic-object relocations do not replay from the module interface")
    expected_roots, root_holes = _project_roots(plan, interface)
    if roots != expected_roots:
        _fail("semantic-object roots do not replay from the bound entry surfaces")
    if payload["effect_index"] != _effect_index(
        plan, transfers, authority, expected_symbols, checked_exceptions,
    ):
        _fail("semantic-object effect index is stale")
    if payload["platform_selection"] != _selection_reference(selection):
        _fail("semantic-object qualified-platform selection is stale")
    holes = _rows(payload["holes"], "semantic-object holes")
    if holes != _migration_holes(
        plan, interface, [*root_holes, *declaration_holes], relocation_holes,
        expected_relocations, selection, checked_exceptions
    ):
        _fail("semantic-object holes are stale or were silently removed")
    evidence = _rows(payload["evidence"], "semantic-object evidence")
    if evidence != expected_evidence:
        _fail("semantic-object evidence bindings are stale")


def _validate_members(
    payload: Mapping[str, Any], plan: Mapping[str, Any],
    interface: Mapping[str, Any], authority: MachineObjectAuthorityV2,
    selection: Mapping[str, Any] | None,
    requirements: Mapping[str, Any] | None,
    platform: Mapping[str, Any] | None,
    resolved_environment: ResolvedExternalEnvironmentV1 | None,
    environment_content_sha256: str | None,
) -> None:
    expected = {
        "module_interface": {
            "path": "module-interface.json",
            "identity": interface["interface_sha256"],
            "content_sha256": sha256_bytes(_canonical_bytes(interface)),
        },
        "transfer_plan": {
            "path": "executable-transfer-plan.json",
            "identity": plan["plan_sha256"],
            "content_sha256": sha256_bytes(_canonical_bytes(plan)),
        },
        "machine_object_authority": {
            "path": "machine-object-authority.json",
            "identity": authority.authority_sha256,
            "content_sha256": sha256_bytes(
                _canonical_bytes(authority.to_payload())
            ),
        },
    }
    if selection is not None:
        assert requirements is not None
        assert platform is not None
        expected.update({
            "isa_requirements": {
                "path": "isa-requirements.json",
                "identity": requirements["requirements_sha256"],
                "content_sha256": sha256_bytes(_canonical_bytes(requirements)),
            },
            "qualified_platform": {
                "path": "qualified-platform.json",
                "identity": platform["platform_sha256"],
                "content_sha256": selection["bindings"][
                    "platform_content_sha256"
                ],
            },
            "qualified_platform_isa_certificate": {
                "path": "isa-form-qualification-certificate.json",
                "identity": selection["bindings"]["certificate_sha256"],
                "content_sha256": platform["members"][
                    "isa_form_qualification_certificate"
                ]["content_sha256"],
            },
            "platform_selection": {
                "path": "qualified-platform-selection.json",
                "identity": selection["selection_sha256"],
                "content_sha256": sha256_bytes(_canonical_bytes(selection)),
            },
        })
    if resolved_environment is not None:
        assert environment_content_sha256 is not None
        expected["resolved_external_environment"] = {
            "path": "resolved-external-environment.json",
            "identity": resolved_environment.identity,
            "content_sha256": environment_content_sha256,
        }
    if payload["members"] != expected:
        _fail("semantic-object package members are stale")
