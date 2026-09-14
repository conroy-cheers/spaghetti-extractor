"""Bind logical parameter captures to actual compiler-resolved C arguments."""

from __future__ import annotations

from typing import Mapping, Sequence

from .bisimulation import BisimulationOperationV1
from .bisimulation_support import BisimulationRefinementError


def check_parameter_bindings(*, symbols: Mapping, instructions: Sequence[Mapping],
                             function: str, parameter_ids: Sequence[str],
                             operation: BisimulationOperationV1) -> dict:
    parameters = symbols[function]["type"]["namedSub"]["parameters"]["sub"]
    if len(parameters) != len(parameter_ids) + 1:
        raise BisimulationRefinementError("source cut C argument inventory disagrees with the interface")
    identities = [row["namedSub"]["#identifier"]["id"] for row in parameters]
    if len(set(identities)) != len(identities) or any(
        symbols[identity].get("isParameter") is not True
        or symbols[identity].get("location", {}).get("function") != function
        for identity in identities
    ):
        raise BisimulationRefinementError("source cut C argument identities are ambiguous")
    expected = dict(zip(parameter_ids, identities[1:], strict=True))
    declarations = {
        row["code"]["sub"][0]["namedSub"]["identifier"]["id"]: index
        for index, row in enumerate(instructions) if row.get("instructionId") == "DECL"
    }
    cuts, omitted = {}, {}
    for sync in operation.syncs:
        missing = set(expected) - {capture.identity for capture in sync.captures if capture.kind == "parameter"}
        for identity in sorted(missing):
            typ = symbols[expected[identity]].get("type", {})
            if (typ.get("id") not in {"signedbv", "unsignedbv"}
                    or typ.get("namedSub", {}).get("width", {}).get("id") not in {"8", "16", "32"}):
                raise BisimulationRefinementError(
                    f"sync {sync.identity!r} cannot reconstruct parameter {identity!r}: "
                    "only integer arguments up to 32 bits may be omitted and overapproximated"
                )
        omitted[sync.identity] = [expected[identity] for identity in sorted(missing)]
        anchors = [identity for identity in declarations
                   if symbols[identity].get("baseName") == "__CPROVER_spx_local_sync_" + sync.identity]
        if len(anchors) != 1:
            raise BisimulationRefinementError("source cut parameter scope is absent or ambiguous")
        anchor = anchors[0]
        scope = anchor.rsplit("::", 1)[0] + "::"
        bindings = []
        for capture, argument in zip(sync.captures, sync.source_arguments(), strict=True):
            if capture.kind != "parameter":
                continue
            parameter = expected.get(capture.identity)
            if (parameter is None or argument != symbols[parameter].get("baseName")
                    or any(symbols[identity].get("baseName") == argument
                           and scope.startswith(identity.rsplit("::", 1)[0] + "::")
                           and index < declarations[anchor]
                           for identity, index in declarations.items())):
                raise BisimulationRefinementError(
                    f"source cut {function}:{sync.identity} parameter {capture.identity!r} "
                    "must bind its actual C argument without shadowing"
                )
            bindings.append({"parameter_id": capture.identity, "source_argument": argument,
                             "compiler_symbol": parameter})
        cuts[sync.identity] = bindings
    return {"function": function, "context_parameter": identities[0],
            "parameters": expected, "cuts": cuts, "omitted_scalar_parameters": omitted}
