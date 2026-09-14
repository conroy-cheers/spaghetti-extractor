"""Unowned exact semantic context required by a conditional portable proof."""

from typing import Mapping, Sequence

from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from .slices_v2 import SemanticSliceV2, SemanticSliceV2Error, build_semantic_slice_v2


def validate_exact_context(value: object, owned: SemanticSliceV2) -> SemanticSliceV2:
    context = SemanticSliceV2.parse(value)
    owned_ids = {row["definition_id"] for row in owned.payload["definitions"]}
    if context.payload["obligations"] or any(
        row["definition_kind"] != "transfer_v2"
        or not isinstance(row["symbol_id"], str)
        or not row["symbol_id"].startswith("original:function:")
        or "generated_behavioral_c" not in row["allowed_provider_kinds"]
        or row["definition_id"] in owned_ids
        for row in context.payload["definitions"]
    ):
        raise SemanticSliceV2Error("exact context must contain unowned generated transfer definitions")
    return context


def validate_proof_exact_context(*, proof_plan: Mapping, qualification) -> None:
    symbols = {
        f"original:function:{unit}" for operation in proof_plan["operations"]
        if operation.get("continuation") is not None
        for unit in operation["continuation"]["unit_ids"]
    }
    declared = qualification.payload.get("exact_context")
    if not symbols:
        if declared is not None:
            raise SemanticSliceV2Error("provider declares exact context absent from its proof")
        return
    if declared is None:
        raise SemanticSliceV2Error("provider omits its proof's exact context requirement")
    context = validate_exact_context(declared, qualification.semantic_slice)
    rows = context.payload["definitions"]
    if len(rows) != len(symbols) or {row["symbol_id"] for row in rows} != symbols:
        raise SemanticSliceV2Error("provider exact context differs from its proof's continuation units")


def build_exact_context(
    *, proof_plan: Mapping, linked: LinkedSemanticModuleV2 | None,
    owned: SemanticSliceV2,
) -> dict | None:
    units = {
        unit for operation in proof_plan["operations"]
        if operation.get("continuation") is not None
        for unit in operation["continuation"]["unit_ids"]
    }
    if not units:
        return None
    if linked is None:
        raise SemanticSliceV2Error("continuation selection requires the linked semantic module")
    symbols = {f"original:function:{unit}" for unit in units}
    definitions = [row for row in linked.payload["definitions"] if row["symbol_id"] in symbols]
    if len(definitions) != len(symbols) or {row["symbol_id"] for row in definitions} != symbols:
        raise SemanticSliceV2Error("continuation selection definitions are missing or ambiguous")
    context = build_semantic_slice_v2(
        linked_semantic_module=linked,
        definition_ids=[row["definition_id"] for row in definitions],
    )
    return dict(validate_exact_context(context, owned).payload)


def exact_context_blockers(
    *, qualifications: Sequence, definition_selections: Sequence[Mapping],
    obligation_selections: Sequence[Mapping] = (),
    linked: LinkedSemanticModuleV2 | None = None,
) -> list[dict]:
    """Check the final choices, including providers selected by other overlays.

    Matching the selected generated provider's complete definition row binds
    semantics and their dependency contracts without pinning unrelated units.
    Object membership and strong dispatch are still checked at native linking.
    """
    choices = {row["definition_id"]: row for row in definition_selections}
    by_digest = {item.identity: item for item in qualifications}
    selected = {row["qualification_sha256"] for row in [*definition_selections, *obligation_selections]}
    blockers = []
    for digest in sorted(selected):
        qualification = by_digest.get(digest)
        if qualification is None or "exact_context" not in qualification.payload:
            continue  # Missing qualifications have their own admission blocker.
        context = validate_exact_context(qualification.payload["exact_context"], qualification.semantic_slice)
        common = {"provider_id": qualification.provider_id, "qualification_sha256": digest}
        if linked is not None:
            try:
                current = build_semantic_slice_v2(
                    linked_semantic_module=linked,
                    definition_ids=[row["definition_id"] for row in context.payload["definitions"]],
                )
            except SemanticSliceV2Error:
                current = None
            if current != context.payload:
                blockers.append({**common, "code": "provider_exact_context_stale"})
        for definition in context.payload["definitions"]:
            identity = definition["definition_id"]
            choice = choices.get(identity)
            if choice is None:
                code = "provider_exact_context_selection_missing"
            elif choice["provider_kind"] != "generated_behavioral_c":
                code = "provider_exact_context_replaced"
            else:
                provider = by_digest.get(choice["qualification_sha256"])
                if (
                    provider is not None
                    and provider.provider_id == choice["provider_id"]
                    and provider.provider_kind == "generated_behavioral_c"
                    and provider.payload["status"] == "complete"
                    and definition in provider.semantic_slice.payload["definitions"]
                    and any(row["definition_id"] == identity and row["native_symbol"] == choice["native_symbol"]
                            for row in provider.payload["definition_materializations"])
                ):
                    continue
                code = "provider_exact_context_qualification_mismatch"
            blockers.append({**common, "code": code, "definition_id": identity})
    return blockers
