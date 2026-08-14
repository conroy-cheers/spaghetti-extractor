"""Pinned XED catalog parsing and canonicalization."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import Any

from . import catalog as _catalog_api
from .catalog import (
    DispositionReason,
    ISAFormCatalog,
    ISA_PROFILE_ID,
    ProfileDisposition,
    XEDCatalogGenerator,
    XEDCatalogProfile,
    XEDInstructionCatalog,
    XEDInstructionTemplate,
    XEDOperandTemplate,
    XED_INSTRUCTION_CATALOG_FORMAT,
    _exact_fields,
    _object,
    _objects,
    _possibly_empty_string,
    _small_count,
    _string,
    _uint,
    parse_isa_form_catalog,
)
from .conformance import ISAConformanceError

def _parse_xed_operand(value: Any, context: str) -> XEDOperandTemplate:
    payload = _object(value, context)
    fields = {
        "name",
        "visibility",
        "action",
        "width",
        "xtype",
        "type",
        "nonterminal",
        "register",
        "immediate",
    }
    _exact_fields(payload, fields, context)
    immediate = payload.get("immediate")
    return XEDOperandTemplate(
        name=_string(payload.get("name"), f"{context}.name"),
        visibility=_string(payload.get("visibility"), f"{context}.visibility"),
        action=_string(payload.get("action"), f"{context}.action"),
        width=_string(payload.get("width"), f"{context}.width"),
        xtype=_string(payload.get("xtype"), f"{context}.xtype"),
        type=_string(payload.get("type"), f"{context}.type"),
        nonterminal=_possibly_empty_string(
            payload.get("nonterminal"), f"{context}.nonterminal"
        ),
        register=_possibly_empty_string(
            payload.get("register"), f"{context}.register"
        ),
        immediate=(
            None
            if immediate is None
            else _uint(immediate, 64, f"{context}.immediate")
        ),
    )


def _xed_operand_payload(operand: XEDOperandTemplate) -> dict[str, Any]:
    return {
        "name": operand.name,
        "visibility": operand.visibility,
        "action": operand.action,
        "width": operand.width,
        "xtype": operand.xtype,
        "type": operand.type,
        "nonterminal": operand.nonterminal,
        "register": operand.register,
        "immediate": operand.immediate,
    }


def _xed_semantic_payload(
    *,
    iform: str,
    iclass: str,
    category: str,
    extension: str,
    isa_set: str,
    cpl: int,
    exception: str,
    flag_info_index: int,
    flag_complex: bool,
    attributes: tuple[str, ...],
    operands: tuple[XEDOperandTemplate, ...],
) -> dict[str, Any]:
    """Return stable semantic fields, deliberately excluding the table index."""
    return {
        "iform": iform,
        "iclass": iclass,
        "category": category,
        "extension": extension,
        "isa_set": isa_set,
        "cpl": cpl,
        "exception": exception,
        "flag_info_index": flag_info_index,
        "flag_complex": flag_complex,
        "attributes": sorted(attributes),
        "operands": [_xed_operand_payload(operand) for operand in operands],
    }


_EXTERNAL_PLATFORM_CATEGORIES = frozenset({"SYSCALL", "SYSRET", "INTERRUPT"})
_UNSUPPORTED_SYSTEM_CATEGORIES = frozenset({"SYSTEM", "IO", "IOSTRINGOP"})
_SEPARATELY_QUALIFIED_CATEGORIES = frozenset(
    {"FLAGOP", "MISC", "PREFETCH", "SEGOP"}
)
_PRIVILEGED_ATTRIBUTE_MARKERS = frozenset(
    {"PRIVILEGED", "RING0", "PROTECTED_MODE_ONLY_PRIVILEGED"}
)
_PRIVILEGED_REGISTER_PREFIXES = ("CR", "DR", "TR", "MSR")


def _has_x87_state(
    *,
    category: str,
    exception: str,
    operands: tuple[XEDOperandTemplate, ...],
) -> bool:
    fields = [category, exception]
    for operand in operands:
        fields.extend(
            (
                operand.width,
                operand.xtype,
                operand.type,
                operand.nonterminal,
                operand.register,
            )
        )
    return any("X87" in field.upper() or "FPU" in field.upper() for field in fields)


def _has_privileged_operand_class(
    operands: tuple[XEDOperandTemplate, ...],
) -> bool:
    for operand in operands:
        fields = (operand.nonterminal, operand.register)
        for field in fields:
            normalized = field.upper().removeprefix("XED_REG_")
            if normalized.startswith(_PRIVILEGED_REGISTER_PREFIXES):
                return True
    return False


def derive_xed_profile_disposition(
    *,
    category: str,
    exception: str,
    flag_complex: bool,
    attributes: tuple[str, ...],
    operands: tuple[XEDOperandTemplate, ...],
) -> tuple[ProfileDisposition, tuple[DispositionReason, ...]]:
    """Classify state requirements without inspecting instruction identities."""
    normalized_category = category.upper()
    normalized_attributes = {attribute.upper() for attribute in attributes}
    if normalized_attributes & _PRIVILEGED_ATTRIBUTE_MARKERS:
        return (
            ProfileDisposition.EXCLUDED_UNSUPPORTED,
            (DispositionReason.PRIVILEGED_ATTRIBUTE,),
        )
    if _has_privileged_operand_class(operands):
        return (
            ProfileDisposition.EXCLUDED_UNSUPPORTED,
            (DispositionReason.PRIVILEGED_OPERAND_CLASS,),
        )
    if normalized_category in _UNSUPPORTED_SYSTEM_CATEGORIES:
        return (
            ProfileDisposition.EXCLUDED_UNSUPPORTED,
            (DispositionReason.UNSUPPORTED_SYSTEM_CATEGORY,),
        )
    if normalized_category in _EXTERNAL_PLATFORM_CATEGORIES:
        return (
            ProfileDisposition.EXTERNAL_PLATFORM,
            (DispositionReason.EXTERNAL_EVENT_CATEGORY,),
        )
    separate_reasons: list[DispositionReason] = []
    if normalized_category in _SEPARATELY_QUALIFIED_CATEGORIES:
        separate_reasons.append(DispositionReason.AMBIGUOUS_SPECIAL_STATE_CATEGORY)
    if _has_x87_state(
        category=category,
        exception=exception,
        operands=operands,
    ):
        separate_reasons.append(DispositionReason.X87_STATE)
    if flag_complex:
        separate_reasons.append(DispositionReason.COMPLEX_FLAG_STATE)
    if separate_reasons:
        return ProfileDisposition.SEPARATELY_QUALIFIED, tuple(separate_reasons)
    return ProfileDisposition.CORE, (DispositionReason.CORE_STATE,)


def xed_template_form_id_from_fields(
    *,
    iform: str,
    iclass: str,
    category: str,
    extension: str,
    isa_set: str,
    cpl: int,
    exception: str,
    flag_info_index: int,
    flag_complex: bool,
    attributes: tuple[str, ...],
    operands: tuple[XEDOperandTemplate, ...],
) -> str:
    payload = _xed_semantic_payload(
        iform=iform,
        iclass=iclass,
        category=category,
        extension=extension,
        isa_set=isa_set,
        cpl=cpl,
        exception=exception,
        flag_info_index=flag_info_index,
        flag_complex=flag_complex,
        attributes=attributes,
        operands=operands,
    )
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return "xed-" + hashlib.sha256(encoded).hexdigest()


def _parse_xed_template(value: Any, context: str) -> XEDInstructionTemplate:
    payload = _object(value, context)
    fields = {
        "table_index",
        "iform",
        "iclass",
        "category",
        "extension",
        "isa_set",
        "cpl",
        "exception",
        "flag_info_index",
        "flag_complex",
        "attributes",
        "operands",
    }
    _exact_fields(payload, fields, context)
    attributes_value = payload.get("attributes")
    if not isinstance(attributes_value, list):
        raise ISAConformanceError(f"{context}.attributes must be a list")
    attributes = tuple(
        sorted(
            _string(item, f"{context}.attributes[{index}]")
            for index, item in enumerate(attributes_value)
        )
    )
    if len(attributes) != len(set(attributes)):
        raise ISAConformanceError(f"{context}.attributes must be unique")
    operands = tuple(
        _parse_xed_operand(row, f"{context}.operands[{index}]")
        for index, row in enumerate(
            _objects(payload.get("operands"), f"{context}.operands")
        )
    )
    flag_complex = payload.get("flag_complex")
    if not isinstance(flag_complex, bool):
        raise ISAConformanceError(f"{context}.flag_complex must be a boolean")
    semantic_fields = {
        "iform": _string(payload.get("iform"), f"{context}.iform"),
        "iclass": _string(payload.get("iclass"), f"{context}.iclass"),
        "category": _string(payload.get("category"), f"{context}.category"),
        "extension": _string(payload.get("extension"), f"{context}.extension"),
        "isa_set": _string(payload.get("isa_set"), f"{context}.isa_set"),
        "cpl": _small_count(payload.get("cpl"), f"{context}.cpl", 3),
        "exception": _string(payload.get("exception"), f"{context}.exception"),
        "flag_info_index": _uint(
            payload.get("flag_info_index"), 32, f"{context}.flag_info_index"
        ),
        "flag_complex": flag_complex,
        "attributes": attributes,
        "operands": operands,
    }
    disposition, disposition_reasons = derive_xed_profile_disposition(
        category=semantic_fields["category"],
        exception=semantic_fields["exception"],
        flag_complex=semantic_fields["flag_complex"],
        attributes=semantic_fields["attributes"],
        operands=semantic_fields["operands"],
    )
    return XEDInstructionTemplate(
        table_indices=(
            _uint(payload.get("table_index"), 32, f"{context}.table_index"),
        ),
        form_id=_catalog_api.xed_template_form_id_from_fields(**semantic_fields),
        disposition=disposition,
        disposition_reasons=disposition_reasons,
        **semantic_fields,
    )


def parse_xed_instruction_catalog(value: Any) -> XEDInstructionCatalog:
    """Parse the pinned XED table emitter without assigning it proof authority."""
    payload = _object(value, "XED instruction catalog")
    _exact_fields(
        payload,
        {"format", "generator", "profile", "templates"},
        "XED instruction catalog",
    )
    if payload.get("format") != XED_INSTRUCTION_CATALOG_FORMAT:
        raise ISAConformanceError("unsupported XED instruction catalog format")
    generator_payload = _object(
        payload.get("generator"), "XED instruction catalog.generator"
    )
    _exact_fields(
        generator_payload,
        {"name", "xed_version"},
        "XED instruction catalog.generator",
    )
    profile_payload = _object(
        payload.get("profile"), "XED instruction catalog.profile"
    )
    _exact_fields(
        profile_payload,
        {"id", "chip", "machine_mode", "stack_address_width", "privilege"},
        "XED instruction catalog.profile",
    )
    profile = XEDCatalogProfile(
        id=_string(profile_payload.get("id"), "XED instruction catalog.profile.id"),
        chip=_string(
            profile_payload.get("chip"), "XED instruction catalog.profile.chip"
        ),
        machine_mode=_string(
            profile_payload.get("machine_mode"),
            "XED instruction catalog.profile.machine_mode",
        ),
        stack_address_width=_uint(
            profile_payload.get("stack_address_width"),
            8,
            "XED instruction catalog.profile.stack_address_width",
        ),
        privilege=_string(
            profile_payload.get("privilege"),
            "XED instruction catalog.profile.privilege",
        ),
    )
    if profile != XEDCatalogProfile(
        id=ISA_PROFILE_ID,
        chip="PENTIUMPRO",
        machine_mode="LEGACY_32",
        stack_address_width=32,
        privilege="ring3",
    ):
        raise ISAConformanceError(
            "XED instruction catalog.profile is not the exact pe32-i686-v1 profile"
        )
    source_templates = tuple(
        _parse_xed_template(row, f"XED instruction catalog.templates[{index}]")
        for index, row in enumerate(
            _objects(payload.get("templates"), "XED instruction catalog.templates")
        )
    )
    if not source_templates:
        raise ISAConformanceError(
            "XED instruction catalog.templates must not be empty"
        )
    table_indices = [template.table_index for template in source_templates]
    if table_indices != sorted(set(table_indices)):
        raise ISAConformanceError(
            "XED instruction catalog templates must have unique ascending table indices"
        )
    grouped: dict[str, XEDInstructionTemplate] = {}
    semantic_payloads: dict[str, dict[str, Any]] = {}
    for template in source_templates:
        semantic_payload = _xed_template_payload(template, table_index=None)
        prior = grouped.get(template.form_id)
        if prior is None:
            grouped[template.form_id] = template
            semantic_payloads[template.form_id] = semantic_payload
            continue
        if semantic_payloads[template.form_id] != semantic_payload:
            raise ISAConformanceError(
                "XED instruction catalog semantic identity has conflicting fields"
            )
        grouped[template.form_id] = replace(
            prior,
            table_indices=tuple(
                sorted((*prior.table_indices, *template.table_indices))
            ),
        )
    templates = tuple(
        sorted(grouped.values(), key=lambda template: template.table_indices)
    )
    return XEDInstructionCatalog(
        generator=XEDCatalogGenerator(
            name=_string(
                generator_payload.get("name"),
                "XED instruction catalog.generator.name",
            ),
            xed_version=_string(
                generator_payload.get("xed_version"),
                "XED instruction catalog.generator.xed_version",
            ),
        ),
        profile=profile,
        templates=templates,
    )


def parse_isa_catalog(value: Any) -> ISAFormCatalog | XEDInstructionCatalog:
    """Parse either raw XED templates or an enriched executable form catalog."""
    payload = _object(value, "ISA catalog")
    if payload.get("format") == XED_INSTRUCTION_CATALOG_FORMAT:
        return parse_xed_instruction_catalog(payload)
    return parse_isa_form_catalog(payload)


def _xed_template_payload(
    template: XEDInstructionTemplate,
    *,
    table_index: int | None,
) -> dict[str, Any]:
    semantic = _xed_semantic_payload(
        iform=template.iform,
        iclass=template.iclass,
        category=template.category,
        extension=template.extension,
        isa_set=template.isa_set,
        cpl=template.cpl,
        exception=template.exception,
        flag_info_index=template.flag_info_index,
        flag_complex=template.flag_complex,
        attributes=template.attributes,
        operands=template.operands,
    )
    return ({} if table_index is None else {"table_index": table_index}) | semantic


def serialize_xed_instruction_catalog(
    catalog: XEDInstructionCatalog,
) -> dict[str, Any]:
    if not isinstance(catalog, XEDInstructionCatalog):
        raise ISAConformanceError("catalog must be an XEDInstructionCatalog")
    template_rows = [
        _xed_template_payload(template, table_index=table_index)
        for template in catalog.templates
        for table_index in template.table_indices
    ]
    template_rows.sort(key=lambda row: int(row["table_index"]))
    payload = {
        "format": catalog.format,
        "generator": {
            "name": catalog.generator.name,
            "xed_version": catalog.generator.xed_version,
        },
        "profile": {
            "id": catalog.profile.id,
            "chip": catalog.profile.chip,
            "machine_mode": catalog.profile.machine_mode,
            "stack_address_width": catalog.profile.stack_address_width,
            "privilege": catalog.profile.privilege,
        },
        "templates": template_rows,
    }
    if parse_xed_instruction_catalog(payload) != catalog:
        raise ISAConformanceError("XED catalog is not a valid typed instance")
    return payload


def canonical_xed_instruction_catalog_input(
    catalog: XEDInstructionCatalog,
) -> bytes:
    return (
        json.dumps(
            serialize_xed_instruction_catalog(catalog),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        + b"\n"
    )


def xed_instruction_catalog_sha256(catalog: XEDInstructionCatalog) -> str:
    return hashlib.sha256(canonical_xed_instruction_catalog_input(catalog)).hexdigest()
