"""Common implementation authority for every universal component.

Implementation provenance is intentionally separate from the component
contract.  Consumers depend on the contract hash; candidate closure depends on
the selected implementation receipt.  This is the cache boundary that permits
a pinned binary or machine-IR implementation to be replaced by portable C
without rechecking consumers.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .activation_receipt import ActivationReceiptV1
from .formats import COMPONENT_IMPLEMENTATION_V3_FORMAT
from .source import load_component_source_package
from .universal_contract import ComponentContractV3, read_component_contract_v3
from .universal_binding import (
    ComponentMachineBindingV3,
    read_component_machine_binding_v3,
)


IMPLEMENTATION_KINDS = frozenset(
    {
        "portable_c",
        "pinned_binary",
        "machine_ir",
        "external_environment",
        "blocked",
    }
)
PORTABILITY_CLASSES = frozenset({"portable", "conditional", "pinned", "none"})
REALIZATION_KIND_BY_IMPLEMENTATION = {
    "portable_c": "native_component_runtime",
    "pinned_binary": "pinned_binary_runtime",
    "machine_ir": "machine_ir_interpreter",
    "external_environment": "external_environment",
    "blocked": "none",
}


class ComponentImplementationError(ValueError):
    """A component implementation record is malformed or stale."""


@dataclass(frozen=True)
class ComponentImplementationV3:
    implementation_id: str
    component_id: str
    contract_sha256: str
    kind: str
    status: str
    artifact_kind: str
    artifact_sha256: str | None
    authority_kind: str
    authority_sha256: str | None
    portability: str
    dependency_contract_ids: tuple[str, ...]
    realization: Mapping[str, object]
    issues: tuple[Mapping[str, object], ...]
    implementation_sha256: str

    @property
    def authorizing(self) -> bool:
        return self.status == "checked" and self.kind != "blocked"

    @classmethod
    def parse(cls, value: object) -> "ComponentImplementationV3":
        row = _object(value, "component implementation V3")
        _exact(
            row,
            {
                "format",
                "id",
                "component_id",
                "contract_sha256",
                "kind",
                "status",
                "artifact",
                "authority",
                "portability",
                "dependency_contract_ids",
                "realization",
                "issues",
                "policy",
                "implementation_sha256",
            },
            "component implementation V3",
        )
        if row["format"] != COMPONENT_IMPLEMENTATION_V3_FORMAT:
            raise ComponentImplementationError(
                "unsupported component implementation format"
            )
        kind = _choice(row["kind"], IMPLEMENTATION_KINDS, "implementation kind")
        status = _choice(
            row["status"], {"checked", "incomplete", "violated"},
            "implementation status",
        )
        artifact = _object(row["artifact"], "implementation artifact")
        _exact(artifact, {"kind", "sha256"}, "implementation artifact")
        authority = _object(row["authority"], "implementation authority")
        _exact(authority, {"kind", "sha256"}, "implementation authority")
        portability = _object(row["portability"], "implementation portability")
        _exact(portability, {"class", "reason"}, "implementation portability")
        portability_class = _choice(
            portability["class"], PORTABILITY_CLASSES, "portability class"
        )
        _text(portability["reason"], "portability reason")
        expected_portability = {
            "portable_c": "portable",
            "pinned_binary": "pinned",
            "machine_ir": "pinned",
            "external_environment": "conditional",
            "blocked": "none",
        }[kind]
        if portability_class != expected_portability:
            raise ComponentImplementationError(
                "implementation kind contradicts its portability class"
            )
        artifact_digest = _optional_digest(
            artifact["sha256"], "implementation artifact digest"
        )
        authority_digest = _optional_digest(
            authority["sha256"], "implementation authority digest"
        )
        if kind == "blocked":
            if status == "checked" or artifact_digest is not None or authority_digest is not None:
                raise ComponentImplementationError(
                    "blocked implementation cannot carry checked authority"
                )
        elif status == "checked" and (
            artifact_digest is None or authority_digest is None
        ):
            raise ComponentImplementationError(
                "checked implementation requires artifact and authority digests"
            )
        realization = _canonical_object(
            row["realization"], "implementation realization"
        )
        realization_kind = _identifier(
            realization.get("kind"), "implementation realization kind"
        )
        if realization_kind != REALIZATION_KIND_BY_IMPLEMENTATION[kind]:
            raise ComponentImplementationError(
                "implementation kind contradicts its realization kind"
            )
        issues = tuple(
            _canonical_object(item, "implementation issue")
            for item in _array(row["issues"], "implementation issues")
        )
        if status == "checked" and issues:
            raise ComponentImplementationError(
                "checked implementation may not contain issues"
            )
        if status != "checked" and not issues:
            raise ComponentImplementationError(
                "non-checked implementation requires an issue"
            )
        dependencies = _identifiers(
            row["dependency_contract_ids"], "implementation dependency contracts"
        )
        policy = _object(row["policy"], "implementation policy")
        _exact(
            policy,
            {
                "contract_is_authoritative",
                "implementation_may_not_change_contract",
                "consumer_qualification_depends_only_on_contract",
                "unchecked_implementation_may_not_execute",
                "original_binary_executed",
            },
            "implementation policy",
        )
        if policy != _policy():
            raise ComponentImplementationError(
                "component implementation policy weakens authority separation"
            )
        core = dict(row)
        observed = _digest(
            core.pop("implementation_sha256"), "component implementation digest"
        )
        if observed != canonical_sha256_v3(core):
            raise ComponentImplementationError(
                "component implementation digest is stale"
            )
        return cls(
            implementation_id=_identifier(row["id"], "implementation id"),
            component_id=_identifier(row["component_id"], "component id"),
            contract_sha256=_digest(row["contract_sha256"], "component contract digest"),
            kind=kind,
            status=status,
            artifact_kind=_identifier(artifact["kind"], "artifact kind"),
            artifact_sha256=artifact_digest,
            authority_kind=_identifier(authority["kind"], "authority kind"),
            authority_sha256=authority_digest,
            portability=portability_class,
            dependency_contract_ids=dependencies,
            realization=realization,
            issues=issues,
            implementation_sha256=observed,
        )

    def to_payload(self) -> dict[str, object]:
        core = {
            "format": COMPONENT_IMPLEMENTATION_V3_FORMAT,
            "id": self.implementation_id,
            "component_id": self.component_id,
            "contract_sha256": self.contract_sha256,
            "kind": self.kind,
            "status": self.status,
            "artifact": {
                "kind": self.artifact_kind,
                "sha256": self.artifact_sha256,
            },
            "authority": {
                "kind": self.authority_kind,
                "sha256": self.authority_sha256,
            },
            "portability": {
                "class": self.portability,
                "reason": _portability_reason(self.kind),
            },
            "dependency_contract_ids": list(self.dependency_contract_ids),
            "realization": dict(self.realization),
            "issues": [dict(item) for item in self.issues],
            "policy": _policy(),
        }
        return {**core, "implementation_sha256": self.implementation_sha256}


def create_component_implementation_v3(
    *,
    implementation_id: str,
    contract: ComponentContractV3 | Path | str | Mapping[str, object],
    kind: str,
    artifact_kind: str,
    artifact_sha256: str | None,
    authority_kind: str,
    authority_sha256: str | None,
    realization: Mapping[str, object],
    dependency_contract_ids: Sequence[str] = (),
    issues: Sequence[Mapping[str, object]] = (),
    _allow_blocked: bool = False,
    out: Path | str | None = None,
) -> ComponentImplementationV3:
    checked_contract = (
        contract
        if isinstance(contract, ComponentContractV3)
        else read_component_contract_v3(contract)
    )
    if kind not in IMPLEMENTATION_KINDS:
        raise ComponentImplementationError(
            f"unsupported component implementation kind {kind!r}"
        )
    if kind == "blocked" and not _allow_blocked:
        raise ComponentImplementationError(
            "blocked implementations are configuration-reducer output, not authored input"
        )
    normalized_issues = [dict(item) for item in issues]
    if checked_contract.status != "checked":
        normalized_issues.append(
            {
                "status": (
                    "violated"
                    if checked_contract.status == "violated"
                    else "incomplete"
                ),
                "code": "component_contract_not_checked",
            }
        )
    if kind == "blocked" and not normalized_issues:
        normalized_issues.append(
            {"status": "incomplete", "code": "component_implementation_missing"}
        )
    status = (
        "violated"
        if any(item.get("status") == "violated" for item in normalized_issues)
        else "incomplete"
        if normalized_issues
        else "checked"
    )
    core: dict[str, object] = {
        "format": COMPONENT_IMPLEMENTATION_V3_FORMAT,
        "id": implementation_id,
        "component_id": checked_contract.component_id,
        "contract_sha256": checked_contract.contract_sha256,
        "kind": kind,
        "status": status,
        "artifact": {"kind": artifact_kind, "sha256": artifact_sha256},
        "authority": {"kind": authority_kind, "sha256": authority_sha256},
        "portability": {
            "class": {
                "portable_c": "portable",
                "pinned_binary": "pinned",
                "machine_ir": "pinned",
                "external_environment": "conditional",
                "blocked": "none",
            }.get(kind, "none"),
            "reason": _portability_reason(kind),
        },
        "dependency_contract_ids": sorted(set(dependency_contract_ids)),
        "realization": json.loads(json.dumps(realization)),
        "issues": sorted(
            normalized_issues,
            key=lambda item: (
                str(item.get("status", "")), str(item.get("code", ""))
            ),
        ),
        "policy": _policy(),
    }
    result = ComponentImplementationV3.parse(
        {**core, "implementation_sha256": canonical_sha256_v3(core)}
    )
    if out is not None:
        _write(Path(out), result.to_payload())
    return result


def adapt_portable_c_implementation_v3(
    *,
    implementation_id: str,
    contract: ComponentContractV3 | Path | str | Mapping[str, object],
    machine_binding: ComponentMachineBindingV3 | Path | str | Mapping[str, object],
    source_package: Path | str,
    activation_receipt: Path | str | Mapping[str, object],
    out: Path | str | None = None,
) -> ComponentImplementationV3:
    checked_contract = (
        contract
        if isinstance(contract, ComponentContractV3)
        else read_component_contract_v3(contract)
    )
    binding = (
        machine_binding
        if isinstance(machine_binding, ComponentMachineBindingV3)
        else read_component_machine_binding_v3(machine_binding)
    )
    source = load_component_source_package(source_package)
    receipt_payload = _load_receipt(
        activation_receipt, "component activation receipt", "activation-receipt.json"
    )
    receipt = ActivationReceiptV1.parse(receipt_payload)
    issues: list[dict[str, object]] = []
    if receipt.component_id != checked_contract.component_id:
        issues.append(
            {"status": "violated", "code": "activation_component_mismatch"}
        )
    if receipt.bindings.get("interface_sha256") != checked_contract.interface_sha256:
        issues.append(
            {"status": "violated", "code": "activation_interface_binding_stale"}
        )
    if binding.contract_sha256 != checked_contract.contract_sha256:
        issues.append(
            {"status": "violated", "code": "activation_machine_contract_stale"}
        )
    if not binding.authorizing:
        issues.append(
            {"status": "incomplete", "code": "activation_machine_binding_not_checked"}
        )
    if (
        receipt.bindings.get("semantic_contract_sha256")
        != binding.semantic_contract_sha256
    ):
        issues.append(
            {"status": "violated", "code": "activation_semantic_binding_stale"}
        )
    source_sha256 = source.get("implementation_sha256")
    if receipt.bindings.get("implementation_sha256") != source_sha256:
        issues.append(
            {"status": "violated", "code": "activation_source_binding_stale"}
        )
    if not receipt.activation_authorized or receipt.status != "checked":
        issues.append(
            {"status": "incomplete", "code": "activation_receipt_not_checked"}
        )
    if not isinstance(source_sha256, str):
        raise ComponentImplementationError(
            "portable source package has no implementation digest"
        )
    return create_component_implementation_v3(
        implementation_id=implementation_id,
        contract=checked_contract,
        kind="portable_c",
        artifact_kind="component_source_package",
        artifact_sha256=source_sha256,
        authority_kind="component_activation_receipt_v2",
        authority_sha256=receipt.receipt_sha256,
        realization={"kind": "native_component_runtime", "symbol_set": checked_contract.component_id},
        issues=issues,
        out=out,
    )


def create_blocked_component_implementation_v3(
    *,
    implementation_id: str,
    contract: ComponentContractV3 | Path | str | Mapping[str, object],
    issues: Sequence[Mapping[str, object]],
    out: Path | str | None = None,
) -> ComponentImplementationV3:
    """Create the fail-closed reducer result for an unavailable implementation."""

    return create_component_implementation_v3(
        implementation_id=implementation_id,
        contract=contract,
        kind="blocked",
        artifact_kind="none",
        artifact_sha256=None,
        authority_kind="none",
        authority_sha256=None,
        realization={"kind": "none"},
        issues=issues,
        _allow_blocked=True,
        out=out,
    )


def adapt_machine_ir_implementation_v3(
    *,
    implementation_id: str,
    contract: ComponentContractV3 | Path | str | Mapping[str, object],
    machine_binding: ComponentMachineBindingV3 | Path | str | Mapping[str, object],
    out: Path | str | None = None,
) -> ComponentImplementationV3:
    checked_contract = (
        contract
        if isinstance(contract, ComponentContractV3)
        else read_component_contract_v3(contract)
    )
    binding = (
        machine_binding
        if isinstance(machine_binding, ComponentMachineBindingV3)
        else read_component_machine_binding_v3(machine_binding)
    )
    issues: list[dict[str, object]] = []
    if binding.contract_sha256 != checked_contract.contract_sha256:
        issues.append(
            {"status": "violated", "code": "machine_binding_contract_stale"}
        )
    if not binding.authorizing:
        issues.append(
            {"status": "incomplete", "code": "machine_binding_not_checked"}
        )
    return create_component_implementation_v3(
        implementation_id=implementation_id,
        contract=checked_contract,
        kind="machine_ir",
        artifact_kind="machine_ir",
        artifact_sha256=binding.machine_ir_sha256,
        authority_kind="component_machine_binding_v3",
        authority_sha256=binding.binding_sha256,
        realization={"kind": "machine_ir_interpreter"},
        issues=issues,
        out=out,
    )


def read_component_implementation_v3(
    value: Path | str | Mapping[str, object],
) -> ComponentImplementationV3:
    return ComponentImplementationV3.parse(
        _load_receipt(value, "component implementation V3", "implementation-v3.json")
    )


def _policy() -> dict[str, bool]:
    return {
        "contract_is_authoritative": True,
        "implementation_may_not_change_contract": True,
        "consumer_qualification_depends_only_on_contract": True,
        "unchecked_implementation_may_not_execute": True,
        "original_binary_executed": False,
    }


def _portability_reason(kind: str) -> str:
    return {
        "portable_c": "portable source implements the machine-independent contract",
        "pinned_binary": "implementation is bound to one exact binary release",
        "machine_ir": "implementation depends on the selected machine ISA and interpreter",
        "external_environment": "portability depends on the selected environment profile",
        "blocked": "no qualified implementation is selected",
    }.get(kind, "unknown implementation kind")


def _load_receipt(
    value: Path | str | Mapping[str, object], description: str, filename: str
) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return json.loads(json.dumps(value))
    path = Path(value)
    if path.is_dir():
        path = path / filename
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentImplementationError(f"cannot read {description}: {exc}") from exc
    return _object(payload, description)


def _write(path: Path, payload: Mapping[str, object]) -> None:
    if path.suffix != ".json":
        path.mkdir(parents=True, exist_ok=True)
        path = path / "implementation-v3.json"
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _object(value: object, description: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentImplementationError(f"{description} must be an object")
    return value


def _canonical_object(value: object, description: str) -> Mapping[str, object]:
    return json.loads(json.dumps(_object(value, description)))


def _array(value: object, description: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise ComponentImplementationError(f"{description} must be an array")
    return value


def _exact(value: Mapping[str, object], fields: set[str], description: str) -> None:
    if set(value) != fields:
        raise ComponentImplementationError(
            f"{description} must contain exactly {sorted(fields)!r}"
        )


def _text(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentImplementationError(f"{description} must be a nonempty string")
    return value


def _identifier(value: object, description: str) -> str:
    result = _text(value, description)
    if not result[0].isalnum() or any(
        not (character.isalnum() or character in "._-:") for character in result
    ):
        raise ComponentImplementationError(f"{description} is invalid")
    return result


def _choice(value: object, choices: set[str] | frozenset[str], description: str) -> str:
    result = _text(value, description)
    if result not in choices:
        raise ComponentImplementationError(f"{description} is unsupported")
    return result


def _digest(value: object, description: str) -> str:
    result = _text(value, description)
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise ComponentImplementationError(f"{description} is not a SHA-256 digest")
    return result


def _optional_digest(value: object, description: str) -> str | None:
    return None if value is None else _digest(value, description)


def _identifiers(value: object, description: str) -> tuple[str, ...]:
    result = tuple(_identifier(item, description) for item in _array(value, description))
    if result != tuple(sorted(set(result))):
        raise ComponentImplementationError(
            f"{description} must be unique and canonically ordered"
        )
    return result


__all__ = [
    "ComponentImplementationError",
    "ComponentImplementationV3",
    "IMPLEMENTATION_KINDS",
    "adapt_machine_ir_implementation_v3",
    "adapt_portable_c_implementation_v3",
    "create_blocked_component_implementation_v3",
    "create_component_implementation_v3",
    "read_component_implementation_v3",
]
