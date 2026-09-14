"""Physical direct-call and external-tail classification for canonical transfers."""

from .model import TransferPlanError


def external_tail_call(transfer):
    """Identify the one call route whose saved caller continuation survives JMP."""
    if not transfer.actions or transfer.actions[-1].op != "outcome_external":
        return None
    routes = [call for call in transfer.calls if call.kind in {"external_call", "indirect_call"}]
    if len(routes) > 1:
        raise TransferPlanError("external-tail transfer has more than one native route")
    return routes[0] if routes else None
