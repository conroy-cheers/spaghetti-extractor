from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from math import gcd
from typing import Any, Callable

from .dataflow import strongly_connected_components


RuntimeFrameLocation = tuple[str, int, str, int]
RuntimeFrameAliasState = tuple[int, RuntimeFrameLocation]
RuntimeFrameRegisterShape = tuple[int, str, str]

_FRAME_OFFSET_MODULUS = 2**32


@dataclass(frozen=True)
class RuntimeFrameAliasViability:
    viable: frozenset[RuntimeFrameAliasState]
    explored: frozenset[RuntimeFrameAliasState]
    budget_exceeded: bool


@dataclass(frozen=True)
class RuntimeFrameAffineFamily:
    """An exact common-translation coset of paired 32-bit frame offsets."""

    original_register: str
    original_base: int
    candidate_register: str
    candidate_base: int
    translation_stride: int

    def __post_init__(self) -> None:
        if (
            self.translation_stride <= 0
            or _FRAME_OFFSET_MODULUS % self.translation_stride != 0
        ):
            raise ValueError("frame translation stride must divide 2^32")
        if not 0 <= self.original_base < self.translation_stride:
            raise ValueError("frame family original base is not canonical")
        if not 0 <= self.candidate_base < _FRAME_OFFSET_MODULUS:
            raise ValueError("frame family candidate base is outside uint32")

    @property
    def cardinality(self) -> int:
        return _FRAME_OFFSET_MODULUS // self.translation_stride

    @property
    def representative(self) -> RuntimeFrameLocation:
        return (
            self.original_register,
            self.original_base,
            self.candidate_register,
            self.candidate_base,
        )

    def contains(self, location: RuntimeFrameLocation) -> bool:
        if (
            location[0] != self.original_register
            or location[2] != self.candidate_register
        ):
            return False
        translation = (int(location[1]) - self.original_base) % (
            _FRAME_OFFSET_MODULUS
        )
        return (
            translation % self.translation_stride == 0
            and int(location[3]) % _FRAME_OFFSET_MODULUS
            == (self.candidate_base + translation) % _FRAME_OFFSET_MODULUS
        )


RuntimeFrameAffineState = tuple[int, RuntimeFrameAffineFamily]


@dataclass(frozen=True)
class RuntimeFrameAffineTransfer:
    """A translation-equivariant transfer supplied by checked affine analysis."""

    target_node: int
    original_register: str
    original_delta: int
    candidate_register: str
    candidate_delta: int


@dataclass(frozen=True)
class RuntimeFrameAffineViability:
    viable: frozenset[RuntimeFrameAffineState]
    explored: frozenset[RuntimeFrameAffineState]
    unsupported_cycle_shapes: frozenset[RuntimeFrameRegisterShape]
    budget_exceeded: bool
    budget_kind: str | None = None
    transitions: frozenset[
        tuple[
            RuntimeFrameAffineState,
            int,
            RuntimeFrameAffineTransfer,
            RuntimeFrameAffineState,
        ]
    ] = frozenset()

    @property
    def complete(self) -> bool:
        return not self.unsupported_cycle_shapes and not self.budget_exceeded


def _runtime_frame_affine_family(
    location: RuntimeFrameLocation,
    translation_stride: int,
) -> RuntimeFrameAffineFamily:
    if (
        translation_stride <= 0
        or _FRAME_OFFSET_MODULUS % translation_stride != 0
    ):
        raise ValueError("frame translation stride must divide 2^32")
    original = int(location[1]) % _FRAME_OFFSET_MODULUS
    candidate = int(location[3]) % _FRAME_OFFSET_MODULUS
    original_base = original % translation_stride
    translation = (original - original_base) % _FRAME_OFFSET_MODULUS
    return RuntimeFrameAffineFamily(
        original_register=str(location[0]),
        original_base=original_base,
        candidate_register=str(location[2]),
        candidate_base=(candidate - translation) % _FRAME_OFFSET_MODULUS,
        translation_stride=translation_stride,
    )


def runtime_frame_affine_viability(
    seeds: tuple[RuntimeFrameAliasState, ...],
    *,
    memory_ready: Callable[[int, RuntimeFrameAffineFamily], bool],
    required_edges: Callable[[int], tuple[int, ...]],
    affine_transfers: Callable[
        [int, str, str, int], tuple[RuntimeFrameAffineTransfer, ...]
    ],
    max_shapes: int = 4096,
    max_families: int = 4096,
) -> RuntimeFrameAffineViability:
    """Compute successor viability over exact modular affine frame families.

    Transfer rules are required to apply uniformly to every offset with the
    selected source register pair. ``memory_ready`` must likewise certify every
    member of the supplied family. These universal contracts let a paired
    common-translation cycle be represented by its exact modular coset instead
    of enumerating offsets or widening a finite stack window.

    A cycle whose original and candidate net translations differ cannot use
    this one-parameter representation. The entire result then fails closed;
    callers must supply a richer relational invariant rather than silently
    dropping one side's drift.
    """
    if max_shapes <= 0:
        raise ValueError("runtime frame affine shape budget must be positive")
    if max_families <= 0:
        raise ValueError("runtime frame affine family budget must be positive")

    seed_shapes = tuple(dict.fromkeys(
        (node_id, location[0], location[2]) for node_id, location in seeds
    ))
    pending_shapes = deque(seed_shapes)
    shapes: set[RuntimeFrameRegisterShape] = set()
    shape_transitions: dict[
        RuntimeFrameRegisterShape,
        tuple[tuple[int, tuple[RuntimeFrameAffineTransfer, ...]], ...],
    ] = {}
    while pending_shapes:
        shape = pending_shapes.popleft()
        if shape in shapes:
            continue
        if len(shapes) >= max_shapes:
            return RuntimeFrameAffineViability(
                viable=frozenset(),
                explored=frozenset(),
                unsupported_cycle_shapes=frozenset(),
                budget_exceeded=True,
                budget_kind="shapes",
            )
        shapes.add(shape)
        node_id, original_register, candidate_register = shape
        outgoing = tuple(
            (
                edge_id,
                tuple(dict.fromkeys(affine_transfers(
                    node_id, original_register, candidate_register, edge_id
                ))),
            )
            for edge_id in required_edges(node_id)
        )
        shape_transitions[shape] = outgoing
        for _, transfers in outgoing:
            for transfer in transfers:
                if transfer.target_node < 0:
                    raise ValueError(
                        "runtime frame transfer target must be nonnegative"
                    )
                target_shape = (
                    transfer.target_node,
                    transfer.original_register,
                    transfer.candidate_register,
                )
                if target_shape not in shapes:
                    pending_shapes.append(target_shape)

    if not shapes:
        return RuntimeFrameAffineViability(
            viable=frozenset(),
            explored=frozenset(),
            unsupported_cycle_shapes=frozenset(),
            budget_exceeded=False,
        )

    ordered_shapes = tuple(sorted(shapes))
    shape_index = {shape: index for index, shape in enumerate(ordered_shapes)}
    weighted_successors: list[
        list[tuple[int, int, int]]
    ] = [[] for _ in ordered_shapes]
    for shape, outgoing in shape_transitions.items():
        source_index = shape_index[shape]
        for _, transfers in outgoing:
            for transfer in transfers:
                target_shape = (
                    transfer.target_node,
                    transfer.original_register,
                    transfer.candidate_register,
                )
                weighted_successors[source_index].append((
                    shape_index[target_shape],
                    int(transfer.original_delta) % _FRAME_OFFSET_MODULUS,
                    int(transfer.candidate_delta) % _FRAME_OFFSET_MODULUS,
                ))

    partition = strongly_connected_components(tuple(
        tuple(
            target for target, _, _ in successors
        )
        for successors in weighted_successors
    ))
    component_strides = [_FRAME_OFFSET_MODULUS] * len(partition.components)
    unsupported_components: set[int] = set()
    for component_id, component in enumerate(partition.components):
        members = set(component)
        root = component[0]
        potentials: dict[int, tuple[int, int]] = {root: (0, 0)}
        pending = [root]
        while pending:
            source_index = pending.pop()
            source_original, source_candidate = potentials[source_index]
            for target_index, original_delta, candidate_delta in (
                weighted_successors[source_index]
            ):
                if target_index not in members or target_index in potentials:
                    continue
                potentials[target_index] = (
                    (source_original + original_delta) % _FRAME_OFFSET_MODULUS,
                    (source_candidate + candidate_delta) % _FRAME_OFFSET_MODULUS,
                )
                pending.append(target_index)
        if len(potentials) != len(component):
            raise AssertionError("frame SCC root did not reach every member")

        stride = _FRAME_OFFSET_MODULUS
        for source_index in component:
            source_original, source_candidate = potentials[source_index]
            for target_index, original_delta, candidate_delta in (
                weighted_successors[source_index]
            ):
                if target_index not in members:
                    continue
                target_original, target_candidate = potentials[target_index]
                original_discrepancy = (
                    source_original + original_delta - target_original
                ) % _FRAME_OFFSET_MODULUS
                candidate_discrepancy = (
                    source_candidate + candidate_delta - target_candidate
                ) % _FRAME_OFFSET_MODULUS
                if original_discrepancy != candidate_discrepancy:
                    unsupported_components.add(component_id)
                stride = gcd(stride, original_discrepancy)
        component_strides[component_id] = stride

    if unsupported_components:
        return RuntimeFrameAffineViability(
            viable=frozenset(),
            explored=frozenset(),
            unsupported_cycle_shapes=frozenset(
                ordered_shapes[index]
                for component_id in unsupported_components
                for index in partition.components[component_id]
            ),
            budget_exceeded=False,
        )

    def saturated_state(
        node_id: int,
        family: RuntimeFrameAffineFamily,
    ) -> RuntimeFrameAffineState:
        shape = (node_id, family.original_register, family.candidate_register)
        component_id = partition.component_by_region[shape_index[shape]]
        stride = gcd(
            family.translation_stride, component_strides[component_id]
        )
        return node_id, _runtime_frame_affine_family(
            family.representative, stride
        )

    def transfer_state(
        family: RuntimeFrameAffineFamily,
        transfer: RuntimeFrameAffineTransfer,
    ) -> RuntimeFrameAffineState:
        location = (
            transfer.original_register,
            (family.original_base + int(transfer.original_delta))
            % _FRAME_OFFSET_MODULUS,
            transfer.candidate_register,
            (family.candidate_base + int(transfer.candidate_delta))
            % _FRAME_OFFSET_MODULUS,
        )
        target_family = _runtime_frame_affine_family(
            location, family.translation_stride
        )
        return saturated_state(transfer.target_node, target_family)

    pending_states = deque(
        saturated_state(
            node_id,
            _runtime_frame_affine_family(location, _FRAME_OFFSET_MODULUS),
        )
        for node_id, location in seeds
    )
    explored: set[RuntimeFrameAffineState] = set()
    transition_facts: set[
        tuple[
            RuntimeFrameAffineState,
            int,
            RuntimeFrameAffineTransfer,
            RuntimeFrameAffineState,
        ]
    ] = set()
    transitions: dict[
        RuntimeFrameAffineState,
        tuple[tuple[int, tuple[RuntimeFrameAffineState, ...]], ...],
    ] = {}
    while pending_states:
        state = pending_states.popleft()
        if state in explored:
            continue
        if len(explored) >= max_families:
            return RuntimeFrameAffineViability(
                viable=frozenset(),
                explored=frozenset(explored),
                unsupported_cycle_shapes=frozenset(),
                budget_exceeded=True,
                budget_kind="families",
            )
        explored.add(state)
        node_id, family = state
        shape = (node_id, family.original_register, family.candidate_register)
        outgoing_rows = []
        for edge_id, transfers in shape_transitions[shape]:
            targets = []
            for transfer in transfers:
                target = transfer_state(family, transfer)
                targets.append(target)
                transition_facts.add((state, edge_id, transfer, target))
            outgoing_rows.append((edge_id, tuple(dict.fromkeys(targets))))
        outgoing = tuple(outgoing_rows)
        transitions[state] = outgoing
        for _, targets in outgoing:
            for target in targets:
                if target not in explored:
                    pending_states.append(target)

    viable = {
        state for state in explored if memory_ready(state[0], state[1])
    }
    changed = True
    while changed:
        changed = False
        for state in tuple(viable):
            if any(
                not any(target in viable for target in targets)
                for _, targets in transitions[state]
            ):
                viable.remove(state)
                changed = True

    return RuntimeFrameAffineViability(
        viable=frozenset(viable),
        explored=frozenset(explored),
        unsupported_cycle_shapes=frozenset(),
        budget_exceeded=False,
        transitions=frozenset(transition_facts),
    )


def runtime_frame_alias_viability(
    seeds: tuple[RuntimeFrameAliasState, ...],
    *,
    memory_ready: Callable[[int, RuntimeFrameLocation], bool],
    required_edges: Callable[[int], tuple[int, ...]],
    transfer_targets: Callable[
        [int, RuntimeFrameLocation, int], tuple[RuntimeFrameAliasState, ...]
    ],
    max_states: int = 4096,
) -> RuntimeFrameAliasViability:
    """Compute the greatest finite successor-viable alias fixed point.

    This is proposal analysis only.  The generated Lean proof still checks
    every selected transfer.  A changing-offset cycle that exceeds the finite
    state budget therefore fails closed instead of being widened.
    """
    if max_states <= 0:
        raise ValueError("runtime frame alias state budget must be positive")

    pending = deque(dict.fromkeys(seeds))
    explored: set[RuntimeFrameAliasState] = set()
    transitions: dict[
        RuntimeFrameAliasState,
        tuple[tuple[int, tuple[RuntimeFrameAliasState, ...]], ...],
    ] = {}
    budget_exceeded = False
    while pending:
        state = pending.popleft()
        if state in explored:
            continue
        if len(explored) >= max_states:
            budget_exceeded = True
            break
        explored.add(state)
        node_id, location = state
        outgoing = tuple(
            (
                edge_id,
                tuple(dict.fromkeys(
                    transfer_targets(node_id, location, edge_id)
                )),
            )
            for edge_id in required_edges(node_id)
        )
        transitions[state] = outgoing
        for _, targets in outgoing:
            for target in targets:
                if target not in explored:
                    pending.append(target)

    if budget_exceeded:
        return RuntimeFrameAliasViability(
            viable=frozenset(),
            explored=frozenset(explored),
            budget_exceeded=True,
        )

    viable = {
        state for state in explored
        if memory_ready(state[0], state[1])
    }
    changed = True
    while changed:
        changed = False
        for state in tuple(viable):
            if any(
                not any(target in viable for target in targets)
                for _, targets in transitions.get(state, ())
            ):
                viable.remove(state)
                changed = True

    return RuntimeFrameAliasViability(
        viable=frozenset(viable),
        explored=frozenset(explored),
        budget_exceeded=False,
    )


def runtime_frame_location_key(location: dict[str, Any]) -> RuntimeFrameLocation:
    return (
        str(location.get("original_register", "esp")),
        int(location["original"]),
        str(location.get("candidate_register", "esp")),
        int(location["candidate"]),
    )


def runtime_frame_location_payload(
    location: RuntimeFrameLocation,
) -> dict[str, Any]:
    return {
        "original_register": location[0],
        "original": location[1],
        "candidate_register": location[2],
        "candidate": location[3],
    }


def runtime_frame_affine_family_payload(
    family: RuntimeFrameAffineFamily,
) -> dict[str, Any]:
    return {
        "original_register": family.original_register,
        "original_base": family.original_base,
        "candidate_register": family.candidate_register,
        "candidate_base": family.candidate_base,
        "translation_stride": family.translation_stride,
        "cardinality": family.cardinality,
        "representative": runtime_frame_location_payload(
            family.representative
        ),
    }


def return_frame_claim_for_location(
    relation_row: dict[str, Any],
    location: RuntimeFrameLocation,
) -> dict[str, Any] | None:
    for claim in relation_row.get("return_pop_frame_claims", []):
        if runtime_frame_location_key(claim["offsets"]) == location:
            return claim
    return_claim = relation_row.get("return_pop_claim") or {}
    if (
        location[0] != "esp"
        or location[2] != "esp"
        or location[1] != int(return_claim.get("original_stack_offset", -1))
        or location[3] != int(return_claim.get("candidate_stack_offset", -1))
        or return_claim.get("original_stack_witness") is None
        or return_claim.get("candidate_stack_witness") is None
    ):
        return None
    return {
        "profile": "return_pop_runtime_frame_v1",
        "offsets": runtime_frame_location_payload(location),
        "original_slot_witness": return_claim["original_stack_witness"],
        "candidate_slot_witness": return_claim["candidate_stack_witness"],
    }
