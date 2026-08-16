"""Checked island, reusable implementation, and adoption-intent records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from ..artifacts.formats import (
    CHECKED_LIBRARY_ISLAND_V1_FORMAT,
    LIBRARY_ADOPTION_INTENT_V1_FORMAT,
    REUSABLE_LIBRARY_IMPLEMENTATION_V1_FORMAT,
)
from .v4_identity_records import LibraryIslandIssueV4
from .v4_record_support import (
    ISSUE_FAMILIES,
    STATUSES,
    StrictCodec,
    array,
    canonical_sha256,
    choice,
    fail,
    optional_text,
    sha256_text,
    stable_id,
    status_from,
    strict_object,
    text,
    text_tuple,
    validate_text_tuple,
)

_ADOPTION_MODES = frozenset({"adopt", "draft"})


def _canonical_issues(
    issues: Iterable[LibraryIslandIssueV4],
) -> tuple[LibraryIslandIssueV4, ...]:
    return tuple(sorted(set(issues), key=lambda issue: issue.issue_id))


def _validate_issues(
    issues: tuple[LibraryIslandIssueV4, ...], location: str
) -> None:
    ids = tuple(issue.issue_id for issue in issues)
    if tuple(sorted(set(ids))) != ids:
        fail(
            "record_order_invalid",
            "issues must have unique, canonically sorted IDs",
            location,
        )


def _family_status(
    issues: Iterable[LibraryIslandIssueV4], family: str
) -> str:
    return status_from(issue.status for issue in issues if issue.family == family)


@dataclass(frozen=True)
class CheckedLibraryIslandV1:
    checked_island_id: str
    target_id: str
    target_binary_sha256: str
    machine_ir_sha256: str
    island_id: str
    hypotheses_sha256: str
    implementation_id: str
    implementation_sha256: str
    checker_id: str
    checked_unit_ids: tuple[str, ...]
    checked_operation_ids: tuple[str, ...]
    checked_boundary_edge_ids: tuple[str, ...]
    dependency_sha256s: tuple[str, ...]
    identity_status: str
    boundary_status: str
    implementation_status: str
    status: str
    issues: tuple[LibraryIslandIssueV4, ...]
    receipt_sha256: str

    @property
    def identity_payload(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "target_binary_sha256": self.target_binary_sha256,
            "machine_ir_sha256": self.machine_ir_sha256,
            "island_id": self.island_id,
            "hypotheses_sha256": self.hypotheses_sha256,
            "implementation_id": self.implementation_id,
            "implementation_sha256": self.implementation_sha256,
            "checker_id": self.checker_id,
            "checked_unit_ids": list(self.checked_unit_ids),
            "checked_operation_ids": list(self.checked_operation_ids),
            "checked_boundary_edge_ids": list(self.checked_boundary_edge_ids),
            "dependency_sha256s": list(self.dependency_sha256s),
        }

    @property
    def core_payload(self) -> dict[str, Any]:
        return {
            "format": CHECKED_LIBRARY_ISLAND_V1_FORMAT,
            "id": self.checked_island_id,
            **self.identity_payload,
            "identity_status": self.identity_status,
            "boundary_status": self.boundary_status,
            "implementation_status": self.implementation_status,
            "status": self.status,
            "issues": [issue.to_payload() for issue in self.issues],
        }

    def __post_init__(self) -> None:
        for name, value in (
            ("target_id", self.target_id),
            ("island_id", self.island_id),
            ("implementation_id", self.implementation_id),
            ("checker_id", self.checker_id),
        ):
            text(value, f"checked island.{name}")
        sha256_text(
            self.target_binary_sha256,
            "checked island.target_binary_sha256",
        )
        sha256_text(self.machine_ir_sha256, "checked island.machine_ir_sha256")
        sha256_text(self.hypotheses_sha256, "checked island.hypotheses_sha256")
        sha256_text(
            self.implementation_sha256,
            "checked island.implementation_sha256",
        )
        for name, values, nonempty in (
            ("checked_unit_ids", self.checked_unit_ids, True),
            ("checked_operation_ids", self.checked_operation_ids, True),
            ("checked_boundary_edge_ids", self.checked_boundary_edge_ids, False),
            ("dependency_sha256s", self.dependency_sha256s, False),
        ):
            validate_text_tuple(values, f"checked island.{name}", nonempty=nonempty)
        for index, dependency in enumerate(self.dependency_sha256s):
            sha256_text(dependency, f"checked island.dependency_sha256s[{index}]")
        _validate_issues(self.issues, "checked island.issues")
        for family, actual in (
            ("identity", self.identity_status),
            ("boundary", self.boundary_status),
            ("implementation", self.implementation_status),
        ):
            choice(actual, STATUSES, f"checked island.{family}_status")
            expected = _family_status(self.issues, family)
            if actual != expected:
                fail(
                    "status_evidence_mismatch",
                    f"{family} status must equal {expected!r} from local issues",
                    f"checked island.{family}_status",
                )
        expected_status = status_from(
            (self.identity_status, self.boundary_status, self.implementation_status)
        )
        choice(self.status, STATUSES, "checked island.status")
        if self.status != expected_status:
            fail(
                "status_evidence_mismatch",
                f"overall status must equal {expected_status!r}",
                "checked island.status",
            )
        if self.checked_island_id != stable_id(
            "checked-library-island-v1", self.identity_payload
        ):
            fail(
                "stale_checked_island_id",
                "checked island ID does not bind its inputs",
                "checked island.id",
            )
        sha256_text(self.receipt_sha256, "checked island.receipt_sha256")
        if self.receipt_sha256 != canonical_sha256(self.core_payload):
            fail(
                "stale_checked_island_hash",
                "checked island hash does not bind its contents",
                "checked island.receipt_sha256",
            )

    @classmethod
    def create(
        cls,
        *,
        target_id: str,
        target_binary_sha256: str,
        machine_ir_sha256: str,
        island_id: str,
        hypotheses_sha256: str,
        implementation_id: str,
        implementation_sha256: str,
        checker_id: str,
        checked_unit_ids: Iterable[str],
        checked_operation_ids: Iterable[str],
        checked_boundary_edge_ids: Iterable[str] = (),
        dependency_sha256s: Iterable[str] = (),
        issues: Iterable[LibraryIslandIssueV4] = (),
    ) -> "CheckedLibraryIslandV1":
        units = tuple(sorted(set(checked_unit_ids)))
        operations = tuple(sorted(set(checked_operation_ids)))
        boundaries = tuple(sorted(set(checked_boundary_edge_ids)))
        dependencies = tuple(sorted(set(dependency_sha256s)))
        canonical_issues = _canonical_issues(issues)
        identity = {
            "target_id": target_id,
            "target_binary_sha256": target_binary_sha256,
            "machine_ir_sha256": machine_ir_sha256,
            "island_id": island_id,
            "hypotheses_sha256": hypotheses_sha256,
            "implementation_id": implementation_id,
            "implementation_sha256": implementation_sha256,
            "checker_id": checker_id,
            "checked_unit_ids": list(units),
            "checked_operation_ids": list(operations),
            "checked_boundary_edge_ids": list(boundaries),
            "dependency_sha256s": list(dependencies),
        }
        checked_id = stable_id("checked-library-island-v1", identity)
        statuses = {
            family: _family_status(canonical_issues, family)
            for family in ISSUE_FAMILIES
        }
        status = status_from(statuses.values())
        core = {
            "format": CHECKED_LIBRARY_ISLAND_V1_FORMAT,
            "id": checked_id,
            **identity,
            "identity_status": statuses["identity"],
            "boundary_status": statuses["boundary"],
            "implementation_status": statuses["implementation"],
            "status": status,
            "issues": [issue.to_payload() for issue in canonical_issues],
        }
        return cls(
            checked_island_id=checked_id,
            target_id=target_id,
            target_binary_sha256=target_binary_sha256,
            machine_ir_sha256=machine_ir_sha256,
            island_id=island_id,
            hypotheses_sha256=hypotheses_sha256,
            implementation_id=implementation_id,
            implementation_sha256=implementation_sha256,
            checker_id=checker_id,
            checked_unit_ids=units,
            checked_operation_ids=operations,
            checked_boundary_edge_ids=boundaries,
            dependency_sha256s=dependencies,
            identity_status=statuses["identity"],
            boundary_status=statuses["boundary"],
            implementation_status=statuses["implementation"],
            status=status,
            issues=canonical_issues,
            receipt_sha256=canonical_sha256(core),
        )

    def to_payload(self) -> dict[str, Any]:
        return {**self.core_payload, "receipt_sha256": self.receipt_sha256}

    @classmethod
    def from_payload(cls, value: object, location: str) -> "CheckedLibraryIslandV1":
        fields = {
            "format",
            "id",
            "target_id",
            "target_binary_sha256",
            "machine_ir_sha256",
            "island_id",
            "hypotheses_sha256",
            "implementation_id",
            "implementation_sha256",
            "checker_id",
            "checked_unit_ids",
            "checked_operation_ids",
            "checked_boundary_edge_ids",
            "dependency_sha256s",
            "identity_status",
            "boundary_status",
            "implementation_status",
            "status",
            "issues",
            "receipt_sha256",
        }
        row = strict_object(value, fields, location)
        if row["format"] != CHECKED_LIBRARY_ISLAND_V1_FORMAT:
            fail(
                "wrong_artifact_format",
                "not a checked library island V1 artifact",
                f"{location}.format",
            )
        return cls(
            checked_island_id=text(row["id"], f"{location}.id"),
            target_id=text(row["target_id"], f"{location}.target_id"),
            target_binary_sha256=sha256_text(
                row["target_binary_sha256"],
                f"{location}.target_binary_sha256",
            ),
            machine_ir_sha256=sha256_text(
                row["machine_ir_sha256"], f"{location}.machine_ir_sha256"
            ),
            island_id=text(row["island_id"], f"{location}.island_id"),
            hypotheses_sha256=sha256_text(
                row["hypotheses_sha256"], f"{location}.hypotheses_sha256"
            ),
            implementation_id=text(
                row["implementation_id"], f"{location}.implementation_id"
            ),
            implementation_sha256=sha256_text(
                row["implementation_sha256"],
                f"{location}.implementation_sha256",
            ),
            checker_id=text(row["checker_id"], f"{location}.checker_id"),
            checked_unit_ids=text_tuple(
                row["checked_unit_ids"],
                f"{location}.checked_unit_ids",
                nonempty=True,
            ),
            checked_operation_ids=text_tuple(
                row["checked_operation_ids"],
                f"{location}.checked_operation_ids",
                nonempty=True,
            ),
            checked_boundary_edge_ids=text_tuple(
                row["checked_boundary_edge_ids"],
                f"{location}.checked_boundary_edge_ids",
            ),
            dependency_sha256s=text_tuple(
                row["dependency_sha256s"], f"{location}.dependency_sha256s"
            ),
            identity_status=choice(
                row["identity_status"], STATUSES, f"{location}.identity_status"
            ),
            boundary_status=choice(
                row["boundary_status"], STATUSES, f"{location}.boundary_status"
            ),
            implementation_status=choice(
                row["implementation_status"],
                STATUSES,
                f"{location}.implementation_status",
            ),
            status=choice(row["status"], STATUSES, f"{location}.status"),
            issues=tuple(
                LibraryIslandIssueV4.from_payload(
                    item, f"{location}.issues[{index}]"
                )
                for index, item in enumerate(array(row["issues"], f"{location}.issues"))
            ),
            receipt_sha256=sha256_text(
                row["receipt_sha256"], f"{location}.receipt_sha256"
            ),
        )


@dataclass(frozen=True, order=True)
class LibraryOperationSourceMappingV1:
    mapping_id: str
    operation_id: str
    source_id: str
    source_symbol: str
    source_sha256: str

    @property
    def identity_payload(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "source_id": self.source_id,
            "source_symbol": self.source_symbol,
            "source_sha256": self.source_sha256,
        }

    def __post_init__(self) -> None:
        text(self.operation_id, "operation source mapping.operation_id")
        text(self.source_id, "operation source mapping.source_id")
        text(self.source_symbol, "operation source mapping.source_symbol")
        sha256_text(self.source_sha256, "operation source mapping.source_sha256")
        if self.mapping_id != stable_id(
            "library-operation-source-v1", self.identity_payload
        ):
            fail(
                "stale_mapping_id",
                "mapping ID does not bind its contents",
                "operation source mapping.id",
            )

    @classmethod
    def create(
        cls,
        *,
        operation_id: str,
        source_id: str,
        source_symbol: str,
        source_sha256: str,
    ) -> "LibraryOperationSourceMappingV1":
        identity = {
            "operation_id": operation_id,
            "source_id": source_id,
            "source_symbol": source_symbol,
            "source_sha256": source_sha256,
        }
        return cls(
            mapping_id=stable_id("library-operation-source-v1", identity),
            operation_id=operation_id,
            source_id=source_id,
            source_symbol=source_symbol,
            source_sha256=source_sha256,
        )

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.mapping_id, **self.identity_payload}

    @classmethod
    def from_payload(
        cls, value: object, location: str
    ) -> "LibraryOperationSourceMappingV1":
        row = strict_object(
            value,
            {"id", "operation_id", "source_id", "source_symbol", "source_sha256"},
            location,
        )
        return cls(
            mapping_id=text(row["id"], f"{location}.id"),
            operation_id=text(row["operation_id"], f"{location}.operation_id"),
            source_id=text(row["source_id"], f"{location}.source_id"),
            source_symbol=text(row["source_symbol"], f"{location}.source_symbol"),
            source_sha256=sha256_text(
                row["source_sha256"], f"{location}.source_sha256"
            ),
        )


@dataclass(frozen=True)
class ReusableLibraryImplementationV1:
    implementation_id: str
    family_id: str
    recipe_id: str
    compatible_release_ids: tuple[str, ...]
    operation_source_mappings: tuple[LibraryOperationSourceMappingV1, ...]
    interface_contract_ids: tuple[str, ...]
    effect_contract_ids: tuple[str, ...]
    compile_profile_id: str | None
    qualification_checker_id: str | None
    qualification_receipt_sha256: str | None
    status: str
    issues: tuple[LibraryIslandIssueV4, ...]
    implementation_sha256: str

    @property
    def identity_payload(self) -> dict[str, Any]:
        return {
            "family_id": self.family_id,
            "recipe_id": self.recipe_id,
            "compatible_release_ids": list(self.compatible_release_ids),
            "mapping_ids": [item.mapping_id for item in self.operation_source_mappings],
            "interface_contract_ids": list(self.interface_contract_ids),
            "effect_contract_ids": list(self.effect_contract_ids),
            "compile_profile_id": self.compile_profile_id,
            "qualification_checker_id": self.qualification_checker_id,
            "qualification_receipt_sha256": self.qualification_receipt_sha256,
        }

    @property
    def core_payload(self) -> dict[str, Any]:
        return {
            "format": REUSABLE_LIBRARY_IMPLEMENTATION_V1_FORMAT,
            "id": self.implementation_id,
            "family_id": self.family_id,
            "recipe_id": self.recipe_id,
            "compatible_release_ids": list(self.compatible_release_ids),
            "operation_source_mappings": [
                item.to_payload() for item in self.operation_source_mappings
            ],
            "interface_contract_ids": list(self.interface_contract_ids),
            "effect_contract_ids": list(self.effect_contract_ids),
            "compile_profile_id": self.compile_profile_id,
            "qualification_checker_id": self.qualification_checker_id,
            "qualification_receipt_sha256": self.qualification_receipt_sha256,
            "status": self.status,
            "issues": [issue.to_payload() for issue in self.issues],
        }

    def __post_init__(self) -> None:
        text(self.family_id, "reusable implementation.family_id")
        text(self.recipe_id, "reusable implementation.recipe_id")
        validate_text_tuple(
            self.compatible_release_ids,
            "reusable implementation.compatible_release_ids",
            nonempty=True,
        )
        mapping_ids = tuple(item.mapping_id for item in self.operation_source_mappings)
        if not mapping_ids or tuple(sorted(set(mapping_ids))) != mapping_ids:
            fail(
                "record_order_invalid",
                "operation/source mappings must be nonempty with sorted unique IDs",
                "reusable implementation.operation_source_mappings",
            )
        operation_ids = [item.operation_id for item in self.operation_source_mappings]
        if len(set(operation_ids)) != len(operation_ids):
            fail(
                "duplicate_operation_mapping",
                "each operation must map to exactly one source",
                "reusable implementation.operation_source_mappings",
            )
        validate_text_tuple(
            self.interface_contract_ids,
            "reusable implementation.interface_contract_ids",
        )
        validate_text_tuple(
            self.effect_contract_ids,
            "reusable implementation.effect_contract_ids",
        )
        if self.compile_profile_id is not None:
            text(
                self.compile_profile_id,
                "reusable implementation.compile_profile_id",
            )
        if self.qualification_checker_id is not None:
            text(
                self.qualification_checker_id,
                "reusable implementation.qualification_checker_id",
            )
        if self.qualification_receipt_sha256 is not None:
            sha256_text(
                self.qualification_receipt_sha256,
                "reusable implementation.qualification_receipt_sha256",
            )
        if (self.qualification_checker_id is None) != (
            self.qualification_receipt_sha256 is None
        ):
            fail(
                "implementation_qualification_invalid",
                "qualification checker and receipt hash must be supplied together",
                "reusable implementation.qualification",
            )
        _validate_issues(self.issues, "reusable implementation.issues")
        if any(issue.family != "implementation" for issue in self.issues):
            fail(
                "issue_scope_mismatch",
                "implementation issues must use the implementation family",
                "reusable implementation.issues",
            )
        expected_status = status_from(issue.status for issue in self.issues)
        choice(self.status, STATUSES, "reusable implementation.status")
        if self.status != expected_status:
            fail(
                "status_evidence_mismatch",
                f"implementation status must equal {expected_status!r}",
                "reusable implementation.status",
            )
        if self.status == "complete" and (
            not self.interface_contract_ids
            or self.compile_profile_id is None
            or self.qualification_checker_id is None
            or self.qualification_receipt_sha256 is None
        ):
            fail(
                "implementation_qualification_missing",
                "complete implementation requires an interface contract, "
                "a compile profile, and a checked qualification receipt",
                "reusable implementation",
            )
        if self.implementation_id != stable_id(
            "reusable-library-implementation-v1", self.identity_payload
        ):
            fail(
                "stale_implementation_id",
                "implementation ID does not bind its mappings",
                "reusable implementation.id",
            )
        sha256_text(
            self.implementation_sha256,
            "reusable implementation.implementation_sha256",
        )
        if self.implementation_sha256 != canonical_sha256(self.core_payload):
            fail(
                "stale_implementation_hash",
                "implementation SHA-256 does not bind its contents",
                "reusable implementation.implementation_sha256",
            )

    @classmethod
    def create(
        cls,
        *,
        family_id: str,
        recipe_id: str,
        compatible_release_ids: Iterable[str],
        operation_source_mappings: Iterable[LibraryOperationSourceMappingV1],
        interface_contract_ids: Iterable[str] = (),
        effect_contract_ids: Iterable[str] = (),
        compile_profile_id: str | None = None,
        qualification_checker_id: str | None = None,
        qualification_receipt_sha256: str | None = None,
        issues: Iterable[LibraryIslandIssueV4] = (),
    ) -> "ReusableLibraryImplementationV1":
        releases = tuple(sorted(set(compatible_release_ids)))
        mappings = tuple(
            sorted(set(operation_source_mappings), key=lambda item: item.mapping_id)
        )
        interfaces = tuple(sorted(set(interface_contract_ids)))
        effects = tuple(sorted(set(effect_contract_ids)))
        canonical_issues = _canonical_issues(issues)
        identity = {
            "family_id": family_id,
            "recipe_id": recipe_id,
            "compatible_release_ids": list(releases),
            "mapping_ids": [item.mapping_id for item in mappings],
            "interface_contract_ids": list(interfaces),
            "effect_contract_ids": list(effects),
            "compile_profile_id": compile_profile_id,
            "qualification_checker_id": qualification_checker_id,
            "qualification_receipt_sha256": qualification_receipt_sha256,
        }
        implementation_id = stable_id(
            "reusable-library-implementation-v1", identity
        )
        status = status_from(issue.status for issue in canonical_issues)
        core = {
            "format": REUSABLE_LIBRARY_IMPLEMENTATION_V1_FORMAT,
            "id": implementation_id,
            "family_id": family_id,
            "recipe_id": recipe_id,
            "compatible_release_ids": list(releases),
            "operation_source_mappings": [item.to_payload() for item in mappings],
            "interface_contract_ids": list(interfaces),
            "effect_contract_ids": list(effects),
            "compile_profile_id": compile_profile_id,
            "qualification_checker_id": qualification_checker_id,
            "qualification_receipt_sha256": qualification_receipt_sha256,
            "status": status,
            "issues": [issue.to_payload() for issue in canonical_issues],
        }
        return cls(
            implementation_id=implementation_id,
            family_id=family_id,
            recipe_id=recipe_id,
            compatible_release_ids=releases,
            operation_source_mappings=mappings,
            interface_contract_ids=interfaces,
            effect_contract_ids=effects,
            compile_profile_id=compile_profile_id,
            qualification_checker_id=qualification_checker_id,
            qualification_receipt_sha256=qualification_receipt_sha256,
            status=status,
            issues=canonical_issues,
            implementation_sha256=canonical_sha256(core),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            **self.core_payload,
            "implementation_sha256": self.implementation_sha256,
        }

    @classmethod
    def from_payload(
        cls, value: object, location: str
    ) -> "ReusableLibraryImplementationV1":
        fields = {
            "format",
            "id",
            "family_id",
            "recipe_id",
            "compatible_release_ids",
            "operation_source_mappings",
            "interface_contract_ids",
            "effect_contract_ids",
            "compile_profile_id",
            "qualification_checker_id",
            "qualification_receipt_sha256",
            "status",
            "issues",
            "implementation_sha256",
        }
        row = strict_object(value, fields, location)
        if row["format"] != REUSABLE_LIBRARY_IMPLEMENTATION_V1_FORMAT:
            fail(
                "wrong_artifact_format",
                "not a reusable implementation V1 artifact",
                f"{location}.format",
            )
        return cls(
            implementation_id=text(row["id"], f"{location}.id"),
            family_id=text(row["family_id"], f"{location}.family_id"),
            recipe_id=text(row["recipe_id"], f"{location}.recipe_id"),
            compatible_release_ids=text_tuple(
                row["compatible_release_ids"],
                f"{location}.compatible_release_ids",
                nonempty=True,
            ),
            operation_source_mappings=tuple(
                LibraryOperationSourceMappingV1.from_payload(
                    item, f"{location}.operation_source_mappings[{index}]"
                )
                for index, item in enumerate(
                    array(
                        row["operation_source_mappings"],
                        f"{location}.operation_source_mappings",
                    )
                )
            ),
            interface_contract_ids=text_tuple(
                row["interface_contract_ids"],
                f"{location}.interface_contract_ids",
            ),
            effect_contract_ids=text_tuple(
                row["effect_contract_ids"], f"{location}.effect_contract_ids"
            ),
            compile_profile_id=optional_text(
                row["compile_profile_id"], f"{location}.compile_profile_id"
            ),
            qualification_checker_id=optional_text(
                row["qualification_checker_id"],
                f"{location}.qualification_checker_id",
            ),
            qualification_receipt_sha256=(
                None
                if row["qualification_receipt_sha256"] is None
                else sha256_text(
                    row["qualification_receipt_sha256"],
                    f"{location}.qualification_receipt_sha256",
                )
            ),
            status=choice(row["status"], STATUSES, f"{location}.status"),
            issues=tuple(
                LibraryIslandIssueV4.from_payload(
                    item, f"{location}.issues[{index}]"
                )
                for index, item in enumerate(array(row["issues"], f"{location}.issues"))
            ),
            implementation_sha256=sha256_text(
                row["implementation_sha256"],
                f"{location}.implementation_sha256",
            ),
        )


@dataclass(frozen=True)
class LibraryAdoptionIntentV1:
    intent_id: str
    target_id: str
    island_id: str
    hypotheses_sha256: str
    implementation_id: str | None
    recipe_id: str | None
    mode: str
    intent_sha256: str

    @property
    def identity_payload(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "island_id": self.island_id,
            "hypotheses_sha256": self.hypotheses_sha256,
            "implementation_id": self.implementation_id,
            "recipe_id": self.recipe_id,
            "mode": self.mode,
        }

    @property
    def core_payload(self) -> dict[str, Any]:
        return {
            "format": LIBRARY_ADOPTION_INTENT_V1_FORMAT,
            "id": self.intent_id,
            **self.identity_payload,
        }

    def __post_init__(self) -> None:
        text(self.target_id, "adoption intent.target_id")
        text(self.island_id, "adoption intent.island_id")
        sha256_text(self.hypotheses_sha256, "adoption intent.hypotheses_sha256")
        if self.implementation_id is not None:
            text(self.implementation_id, "adoption intent.implementation_id")
        if self.recipe_id is not None:
            text(self.recipe_id, "adoption intent.recipe_id")
        if (self.implementation_id is None) == (self.recipe_id is None):
            fail(
                "adoption_selection_invalid",
                "exactly one implementation ID or recipe ID is required",
                "adoption intent",
            )
        choice(self.mode, _ADOPTION_MODES, "adoption intent.mode")
        if self.mode == "adopt" and self.implementation_id is None:
            fail(
                "adoption_selection_invalid",
                "adopt mode requires a checked implementation ID",
                "adoption intent.implementation_id",
            )
        if self.intent_id != stable_id(
            "library-adoption-intent-v1", self.identity_payload
        ):
            fail(
                "stale_adoption_intent_id",
                "intent ID does not bind its selection",
                "adoption intent.id",
            )
        sha256_text(self.intent_sha256, "adoption intent.intent_sha256")
        if self.intent_sha256 != canonical_sha256(self.core_payload):
            fail(
                "stale_adoption_intent_hash",
                "intent SHA-256 does not bind its contents",
                "adoption intent.intent_sha256",
            )

    @classmethod
    def create(
        cls,
        *,
        target_id: str,
        island_id: str,
        hypotheses_sha256: str,
        implementation_id: str | None = None,
        recipe_id: str | None = None,
        mode: str,
    ) -> "LibraryAdoptionIntentV1":
        identity = {
            "target_id": target_id,
            "island_id": island_id,
            "hypotheses_sha256": hypotheses_sha256,
            "implementation_id": implementation_id,
            "recipe_id": recipe_id,
            "mode": mode,
        }
        intent_id = stable_id("library-adoption-intent-v1", identity)
        core = {
            "format": LIBRARY_ADOPTION_INTENT_V1_FORMAT,
            "id": intent_id,
            **identity,
        }
        return cls(
            intent_id=intent_id,
            target_id=target_id,
            island_id=island_id,
            hypotheses_sha256=hypotheses_sha256,
            implementation_id=implementation_id,
            recipe_id=recipe_id,
            mode=mode,
            intent_sha256=canonical_sha256(core),
        )

    def to_payload(self) -> dict[str, Any]:
        return {**self.core_payload, "intent_sha256": self.intent_sha256}

    @classmethod
    def from_payload(cls, value: object, location: str) -> "LibraryAdoptionIntentV1":
        fields = {
            "format",
            "id",
            "target_id",
            "island_id",
            "hypotheses_sha256",
            "implementation_id",
            "recipe_id",
            "mode",
            "intent_sha256",
        }
        row = strict_object(value, fields, location)
        if row["format"] != LIBRARY_ADOPTION_INTENT_V1_FORMAT:
            fail(
                "wrong_artifact_format",
                "not a library adoption intent V1 artifact",
                f"{location}.format",
            )
        return cls(
            intent_id=text(row["id"], f"{location}.id"),
            target_id=text(row["target_id"], f"{location}.target_id"),
            island_id=text(row["island_id"], f"{location}.island_id"),
            hypotheses_sha256=sha256_text(
                row["hypotheses_sha256"], f"{location}.hypotheses_sha256"
            ),
            implementation_id=optional_text(
                row["implementation_id"], f"{location}.implementation_id"
            ),
            recipe_id=optional_text(row["recipe_id"], f"{location}.recipe_id"),
            mode=choice(row["mode"], _ADOPTION_MODES, f"{location}.mode"),
            intent_sha256=sha256_text(
                row["intent_sha256"], f"{location}.intent_sha256"
            ),
        )


CHECKED_LIBRARY_ISLAND_CODEC_V1 = StrictCodec(
    lambda value: value.to_payload(), CheckedLibraryIslandV1.from_payload
)
REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1 = StrictCodec(
    lambda value: value.to_payload(), ReusableLibraryImplementationV1.from_payload
)
LIBRARY_ADOPTION_INTENT_CODEC_V1 = StrictCodec(
    lambda value: value.to_payload(), LibraryAdoptionIntentV1.from_payload
)


__all__ = [
    "CHECKED_LIBRARY_ISLAND_CODEC_V1",
    "CHECKED_LIBRARY_ISLAND_V1_FORMAT",
    "LIBRARY_ADOPTION_INTENT_CODEC_V1",
    "LIBRARY_ADOPTION_INTENT_V1_FORMAT",
    "REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1",
    "REUSABLE_LIBRARY_IMPLEMENTATION_V1_FORMAT",
    "CheckedLibraryIslandV1",
    "LibraryAdoptionIntentV1",
    "LibraryOperationSourceMappingV1",
    "ReusableLibraryImplementationV1",
]
