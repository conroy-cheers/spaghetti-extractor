"""Strict codec for the pure operator discovery index."""

from __future__ import annotations

import copy
import re
from typing import Any, Mapping

from ..errors import ToolkitInputError
from .formats import OPERATOR_INDEX_FORMAT


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_INDEX_FIELDS = {
    "format", "targetId", "defaultConfiguration", "project", "components",
    "boundaries", "libraries", "candidate",
}
_PROJECT_PRODUCTS = {
    "analysis", "status", "semanticModule", "regressionCheck", "acceptanceCheck",
}
_COMPONENT_PRODUCTS = {
    "interface", "bindingIntent", "sourcePackage", "semanticSlice",
    "workPackage", "qualification", "sourceCheck", "sourceContractCheck", "sourceEditCheck", "conditionalCheck", "conditionalCheckFor",
}
_BOUNDARY_PRODUCTS = {"source", "intent", "check"}
_BOUNDARY_KINDS = {"checked_protocol", "checked_schema", "component"}
_LIBRARY_PRODUCTS = {
    "status", "check", "catalogSearchIndex", "targetSignatureGraph",
    "releaseHypotheses",
}
_CANDIDATE_PRODUCTS = {"selection", "realization"}
_CANDIDATE_MODES = {"faithful", "hybrid", "portable"}


def _object(value: object, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ToolkitInputError(f"{context} must be an object")
    return copy.deepcopy(dict(value))


def _exact(row: Mapping[str, Any], fields: set[str], context: str) -> None:
    if set(row) != fields:
        raise ToolkitInputError(f"{context} fields are incomplete")


def _identifier(value: object, context: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ToolkitInputError(f"{context} must be an identifier")
    return value


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ToolkitInputError(f"{context} must be a nonempty string")
    return value


def _products(value: object, allowed: set[str], context: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ToolkitInputError(f"{context} products must be an array of strings")
    if value != sorted(set(value)):
        raise ToolkitInputError(f"{context} products must be sorted and unique")
    unsupported = set(value) - allowed
    if unsupported:
        raise ToolkitInputError(
            f"{context} products are unsupported: {sorted(unsupported)!r}"
        )
    return list(value)


def _identifier_map(value: object, context: str) -> dict[str, dict[str, Any]]:
    row = _object(value, context)
    return {
        _identifier(key, f"{context} key"): _object(item, f"{context} {key}")
        for key, item in row.items()
    }


def parse_operator_index_v1(value: object) -> dict[str, Any]:
    """Validate and return an isolated operator index V1 payload."""

    payload = _object(value, "operator index")
    _exact(payload, _INDEX_FIELDS, "operator index")
    if payload["format"] != OPERATOR_INDEX_FORMAT:
        raise ToolkitInputError("operator index format is unsupported")
    _identifier(payload["targetId"], "operator index target ID")

    project = _object(payload["project"], "operator project index")
    _exact(project, {"products"}, "operator project index")
    _products(project["products"], _PROJECT_PRODUCTS, "operator project index")

    components = _object(payload["components"], "operator component index")
    _exact(components, {"products", "units"}, "operator component index")
    _products(components["products"], {"proposals"}, "operator component index")
    units = _identifier_map(components["units"], "operator component units")
    rva_owners: dict[int, str] = {}
    for identity, unit in units.items():
        _exact(unit, {"label", "entryRvas", "products"}, f"component {identity}")
        _string(unit["label"], f"component {identity} label")
        entry_rvas = unit["entryRvas"]
        if (
            not isinstance(entry_rvas, list)
            or any(not isinstance(rva, int) or isinstance(rva, bool) or rva < 0 or rva > 0xFFFFFFFF for rva in entry_rvas)
            or entry_rvas != sorted(set(entry_rvas))
        ):
            raise ToolkitInputError(
                f"component {identity} entry RVAs must be sorted unique PE32 values"
            )
        for rva in entry_rvas:
            owner = rva_owners.get(rva)
            if owner is not None:
                raise ToolkitInputError(
                    f"component entry RVA {rva:#x} is shared by {owner} and {identity}"
                )
            rva_owners[rva] = identity
        _products(unit["products"], _COMPONENT_PRODUCTS, f"component {identity}")

    boundaries = _object(payload["boundaries"], "operator boundary index")
    _exact(boundaries, {"products", "subjects"}, "operator boundary index")
    _products(boundaries["products"], {"status", "check"}, "operator boundary index")
    boundary_subjects = _object(boundaries["subjects"], "operator boundary subjects")
    for subject, raw in boundary_subjects.items():
        _string(subject, "operator boundary subject")
        if ":" not in subject or subject.startswith(":") or subject.endswith(":"):
            raise ToolkitInputError(f"operator boundary subject {subject!r} is malformed")
        row = _object(raw, f"boundary subject {subject}")
        _exact(row, {"kind", "products"}, f"boundary subject {subject}")
        if row["kind"] not in _BOUNDARY_KINDS:
            raise ToolkitInputError(f"boundary subject {subject} kind is unsupported")
        _products(row["products"], _BOUNDARY_PRODUCTS, f"boundary subject {subject}")
        if row["kind"] == "component":
            component_id = subject.removeprefix("component:")
            if subject != f"component:{component_id}" or component_id not in units:
                raise ToolkitInputError(
                    f"boundary component subject {subject} is not an indexed unit"
                )

    libraries = payload["libraries"]
    if libraries is not None:
        library = _object(libraries, "operator library index")
        _exact(library, {"products", "selections"}, "operator library index")
        _products(library["products"], _LIBRARY_PRODUCTS, "operator library index")
        selections = _identifier_map(library["selections"], "operator library selections")
        for identity, selection in selections.items():
            _exact(selection, {"products"}, f"library selection {identity}")
            _products(selection["products"], {"check"}, f"library selection {identity}")

    candidate = _object(payload["candidate"], "operator candidate index")
    _exact(candidate, {"products", "configurations", "testSuites"}, "operator candidate index")
    _products(candidate["products"], {"allTests"}, "operator candidate index")
    configurations = _identifier_map(
        candidate["configurations"], "operator candidate configurations"
    )
    for identity, configuration in configurations.items():
        _exact(
            configuration,
            {"label", "mode", "selectedComponentIds", "products"},
            f"candidate configuration {identity}",
        )
        _string(configuration["label"], f"candidate configuration {identity} label")
        if configuration["mode"] not in _CANDIDATE_MODES:
            raise ToolkitInputError(f"candidate configuration {identity} mode is unsupported")
        selected = configuration["selectedComponentIds"]
        if (
            not isinstance(selected, list)
            or any(not isinstance(item, str) or item not in units for item in selected)
            or selected != sorted(set(selected))
        ):
            raise ToolkitInputError(
                f"candidate configuration {identity} selected components are malformed"
            )
        _products(
            configuration["products"], _CANDIDATE_PRODUCTS,
            f"candidate configuration {identity}",
        )
    default = _identifier(payload["defaultConfiguration"], "default configuration")
    if default not in configurations:
        raise ToolkitInputError("default configuration is not indexed")

    suites = _identifier_map(candidate["testSuites"], "operator candidate test suites")
    for identity, suite in suites.items():
        _exact(suite, {"configurationId", "caseIds"}, f"candidate test suite {identity}")
        configuration_id = _identifier(
            suite["configurationId"], f"candidate test suite {identity} configuration"
        )
        if configuration_id not in configurations:
            raise ToolkitInputError(
                f"candidate test suite {identity} references an unknown configuration"
            )
        cases = suite["caseIds"]
        if (
            not isinstance(cases, list)
            or any(not isinstance(item, str) or not item for item in cases)
            or len(cases) != len(set(cases))
        ):
            raise ToolkitInputError(
                f"candidate test suite {identity} cases are malformed"
            )
    if bool(suites) != ("allTests" in candidate["products"]):
        raise ToolkitInputError("candidate allTests capability disagrees with test suites")
    return payload


__all__ = ["parse_operator_index_v1"]
