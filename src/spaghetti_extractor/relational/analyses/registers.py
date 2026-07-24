from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Literal

from ...errors import StageAInputError
from ...stage_binary import StageABinary
from ...util import sha256_bytes
from ..callsite_preservation import (
    CALLSITE_PRESERVATION_ARTIFACT_FORMAT,
    parse_callsite_preservation_artifact,
    serialize_callsite_preservation_artifact,
)
from ..contract import _semantic_expr_is_pure
from ..extraction import (
    _semantic_exact_memory_inputs,
)
from ..model import _semantic_constant_bool
from ..register_dataflow_artifact import (
    register_transfer_observation_sha256,
    register_transfer_semantics_sha256,
)
from ..register_transfer_ir import (
    RegisterTransferIncomplete,
    compile_register_transfer_program,
    evaluate_register_transfer_program,
    parse_register_transfer_context,
    register_transfer_context_payload,
    register_transfer_programs_payload,
)
from ..schema import STAGE_A_RELATIONAL_MODEL_ID
from .callsite import (
    CALLSITE_PRESERVATION_ANALYSIS_FORMAT,
    propose_callsite_preserved_register_summary,
)
from .control import _constant_read32_address
from .dataflow import stable_dataflow_graph, strongly_connected_components
from .external import _semantic_external_target_identity
from .fixedpoint import solve_monotone_fixed_point_by_scc
from .semantic_control import _semantic_edges
from .region_local import (
    _attach_assembled_immutable_read_address_separations,
    _attach_import_seed_address_separations,
    _exact_index_expression,
    _iat_import_register_seed_candidates,
    _iat_seed_read,
    _refine_contract_bounds,
    _semantic_index_from_address,
    _semantic_read_addresses,
)
from .register_static import (
    _immutable_image_u32_value,
    _immutable_image_word_read,
    _paired_constant_relation,
)
from .register_lattice import (
    RegisterRelation,
    _REGISTER_CODE_POINTER_DISJUNCTION_BUDGET,
    _REGISTER_RELATION_KINDS,
    _register_code_pointer_producer_relation,
    _register_code_pointer_provenance_payload,
    _register_relation_implies,
    _register_relation_implies_exact,
    _register_relation_join,
    _register_relation_key,
    _register_relation_kind,
    _register_relation_payload,
)
from .segments import _semantic_expr_registers
from .stack import (
    _attach_return_slot_contracts,
    _direct_call_push_claim,
    _discover_static_call_return_summaries,
    _indirect_call_push_claim,
    _return_pop_claim,
)


_X86_GENERAL_REGISTERS = frozenset({
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
})
_PE32_EXTERNAL_REGISTER_POLICY_ID = "win32-cdecl-stdcall-registers-v1"
_PE32_EXTERNAL_PRESERVED_REGISTERS = frozenset({
    "ebx", "esi", "edi", "ebp", "esp",
})


RegisterControlAtomKind = Literal[
    "exact_code_pointer", "static_code_pointer", "import_return",
]
RegisterControlEdgeKind = Literal["direct", "call_return"]

REGISTER_CONTROL_UNKNOWN_CALL = "register_control_unknown_call"
REGISTER_CONTROL_AMBIGUOUS_WRITABLE_LOAD = (
    "register_control_ambiguous_writable_load"
)
REGISTER_CONTROL_DISJUNCTION_BUDGET_EXCEEDED = (
    "register_control_finite_disjunction_budget_exceeded"
)
REGISTER_CONTROL_UNKNOWN_OR_CLOBBERED = (
    "register_control_unknown_or_clobbered"
)
REGISTER_CONTROL_PAIR_MISMATCH = "register_control_register_pair_mismatch"
REGISTER_CONTROL_FIXED_POINT_INCOMPLETE = (
    "register_control_fixed_point_not_converged"
)
REGISTER_CONTROL_INVALID_CONTROL_ATOM = (
    "register_control_invalid_indirect_control_atom"
)


def _checked_register_name(register: str) -> str:
    value = str(register).lower()
    if value not in _X86_GENERAL_REGISTERS:
        raise ValueError(f"unsupported x86 register: {register!r}")
    return value


@dataclass(frozen=True)
class RegisterControlRegisterPair:
    original: str
    candidate: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "original", _checked_register_name(self.original))
        object.__setattr__(self, "candidate", _checked_register_name(self.candidate))

    def to_payload(self) -> dict[str, str]:
        return {"original": self.original, "candidate": self.candidate}


@dataclass(frozen=True)
class RegisterControlProvenanceAtom:
    """Finite, auditable origin for a register value used by control analysis."""

    kind: RegisterControlAtomKind
    producer_region_index: int
    register_pair: RegisterControlRegisterPair
    target_id: int | None = None
    claim_kind: str | None = None
    machine_contract_id: int | None = None
    import_identity: tuple[str, str, str | int] | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.producer_region_index, int)
            or isinstance(self.producer_region_index, bool)
            or self.producer_region_index < 0
        ):
            raise ValueError("producer region index must be non-negative")
        if self.kind in {"exact_code_pointer", "static_code_pointer"}:
            if (
                not isinstance(self.target_id, int)
                or isinstance(self.target_id, bool)
                or self.target_id < 0
                or not isinstance(self.claim_kind, str)
                or not self.claim_kind
                or self.machine_contract_id is not None
                or self.import_identity is not None
            ):
                raise ValueError("code-pointer atom is not exact and canonical")
            return
        if self.kind != "import_return":
            raise ValueError(f"unsupported register-control atom kind: {self.kind!r}")
        identity = self.import_identity
        if (
            self.target_id is not None
            or self.claim_kind is not None
            or not isinstance(self.machine_contract_id, int)
            or isinstance(self.machine_contract_id, bool)
            or self.machine_contract_id < 0
            or not isinstance(identity, tuple)
            or len(identity) != 3
            or not isinstance(identity[0], str)
            or not identity[0]
            or identity[1] not in {"symbol", "ordinal"}
            or (
                identity[1] == "symbol"
                and (not isinstance(identity[2], str) or not identity[2])
            )
            or (
                identity[1] == "ordinal"
                and (
                    not isinstance(identity[2], int)
                    or isinstance(identity[2], bool)
                    or identity[2] < 0
                )
            )
        ):
            raise ValueError("import-return atom is not exact and canonical")
        object.__setattr__(
            self, "import_identity",
            (identity[0].lower(), identity[1], identity[2]),
        )

    def sort_key(self) -> tuple[Any, ...]:
        return (
            self.kind,
            -1 if self.target_id is None else self.target_id,
            -1 if self.machine_contract_id is None else self.machine_contract_id,
            self.import_identity or ("", "", ""),
            self.producer_region_index,
            self.register_pair.original,
            self.register_pair.candidate,
            self.claim_kind or "",
        )

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": self.kind,
            "producer_region_index": self.producer_region_index,
            "register_pair": self.register_pair.to_payload(),
        }
        if self.kind in {"exact_code_pointer", "static_code_pointer"}:
            payload.update({
                "target_id": self.target_id,
                "claim_kind": self.claim_kind,
            })
        else:
            assert self.import_identity is not None
            imported: dict[str, Any] = {"dll": self.import_identity[0]}
            imported[self.import_identity[1]] = self.import_identity[2]
            payload.update({
                "machine_contract_id": self.machine_contract_id,
                "import": imported,
            })
        payload["atom_id"] = sha256_bytes(json.dumps(
            payload, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode())
        return payload


@dataclass(frozen=True)
class RegisterControlCopy:
    output: RegisterControlRegisterPair
    source: RegisterControlRegisterPair


@dataclass(frozen=True)
class RegisterControlBlockedOutput:
    output: RegisterControlRegisterPair
    reason_code: str

    def __post_init__(self) -> None:
        if self.reason_code != REGISTER_CONTROL_AMBIGUOUS_WRITABLE_LOAD:
            raise ValueError("blocked output must use a checked fail-closed reason")


@dataclass(frozen=True)
class RegisterControlRegionTransfer:
    region_index: int
    copies: tuple[RegisterControlCopy, ...] = ()
    producers: tuple[RegisterControlProvenanceAtom, ...] = ()
    blocked_outputs: tuple[RegisterControlBlockedOutput, ...] = ()
    preserve_unmentioned: bool = False


@dataclass(frozen=True)
class RegisterControlImportResult:
    register_pair: RegisterControlRegisterPair
    import_identity: tuple[str, str, str | int]

    def __post_init__(self) -> None:
        identity = self.import_identity
        if (
            not isinstance(identity, tuple)
            or len(identity) != 3
            or not isinstance(identity[0], str)
            or not identity[0]
            or identity[1] not in {"symbol", "ordinal"}
            or (
                identity[1] == "symbol"
                and (not isinstance(identity[2], str) or not identity[2])
            )
            or (
                identity[1] == "ordinal"
                and (
                    not isinstance(identity[2], int)
                    or isinstance(identity[2], bool)
                    or identity[2] < 0
                )
            )
        ):
            raise ValueError("import result identity is not exact and canonical")
        object.__setattr__(
            self, "import_identity",
            (identity[0].lower(), identity[1], identity[2]),
        )

    def to_payload(self) -> dict[str, Any]:
        imported: dict[str, Any] = {"dll": self.import_identity[0]}
        imported[self.import_identity[1]] = self.import_identity[2]
        return {
            "register_pair": self.register_pair.to_payload(),
            "import": imported,
        }


@dataclass(frozen=True)
class RegisterControlCallContract:
    contract_id: int
    preserved_registers: tuple[RegisterControlRegisterPair, ...] = ()
    import_results: tuple[RegisterControlImportResult, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.contract_id, int)
            or isinstance(self.contract_id, bool)
            or self.contract_id < 0
        ):
            raise ValueError("machine call contract id must be non-negative")
        if len(set(self.preserved_registers)) != len(self.preserved_registers):
            raise ValueError("call contract has duplicate preserved registers")
        result_pairs = [result.register_pair for result in self.import_results]
        if len(set(result_pairs)) != len(result_pairs):
            raise ValueError("call contract has ambiguous import results")


@dataclass(frozen=True)
class RegisterControlEdge:
    source_region_index: int
    target_region_index: int
    kind: RegisterControlEdgeKind = "direct"
    machine_contract_id: int | None = None


@dataclass(frozen=True)
class RegisterControlUse:
    region_index: int
    register_pair: RegisterControlRegisterPair
    purpose: Literal["register_state", "indirect_control"] = "register_state"


@dataclass(frozen=True)
class _RegisterControlValue:
    atoms: tuple[RegisterControlProvenanceAtom, ...] = ()
    blockers: tuple[str, ...] = ()

    def to_payload(self) -> dict[str, Any]:
        return {
            "atoms": [atom.to_payload() for atom in self.atoms],
            "blockers": list(self.blockers),
        }


@dataclass(frozen=True)
class RegisterControlProvenanceWitness:
    payload: dict[str, Any]

    @property
    def status(self) -> str:
        return str(self.payload["status"])

    @property
    def blockers(self) -> tuple[dict[str, Any], ...]:
        return tuple(self.payload["blockers"])

    def to_payload(self) -> dict[str, Any]:
        return json.loads(json.dumps(self.payload))


def build_register_control_provenance_witness(
    *,
    region_count: int,
    register_pairs: tuple[RegisterControlRegisterPair, ...],
    entry_region_indices: tuple[int, ...],
    transfers: tuple[RegisterControlRegionTransfer, ...],
    edges: tuple[RegisterControlEdge, ...],
    call_contracts: tuple[RegisterControlCallContract, ...] = (),
    uses: tuple[RegisterControlUse, ...] = (),
    finite_disjunction_budget: int = _REGISTER_CODE_POINTER_DISJUNCTION_BUDGET,
) -> RegisterControlProvenanceWitness:
    """Build a fail-closed register-control witness over a finite product graph.

    The result is proposal evidence only. A later planner may serialize it into
    proof IR, but Lean must replay the transfer, call contracts, SCC closure,
    and control-use checks before any acceptance claim can depend on it.
    """
    if (
        not isinstance(region_count, int)
        or isinstance(region_count, bool)
        or region_count <= 0
    ):
        raise ValueError("register-control region count must be positive")
    if (
        not isinstance(finite_disjunction_budget, int)
        or isinstance(finite_disjunction_budget, bool)
        or finite_disjunction_budget <= 0
    ):
        raise ValueError("register-control disjunction budget must be positive")
    if not register_pairs or len(set(register_pairs)) != len(register_pairs):
        raise ValueError("register-control register pairs must be unique")
    if len({pair.original for pair in register_pairs}) != len(register_pairs):
        raise ValueError("original register mapping is ambiguous")
    if len({pair.candidate for pair in register_pairs}) != len(register_pairs):
        raise ValueError("candidate register mapping is ambiguous")
    register_pairs = tuple(sorted(
        register_pairs, key=lambda pair: (pair.original, pair.candidate),
    ))
    pair_set = frozenset(register_pairs)

    def checked_region(index: int, label: str) -> int:
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or not 0 <= index < region_count
        ):
            raise ValueError(f"{label} is outside the region inventory")
        return index

    entry_regions = frozenset(
        checked_region(index, "entry region") for index in entry_region_indices
    )
    transfer_by_region: dict[int, RegisterControlRegionTransfer] = {}
    for transfer in transfers:
        region_index = checked_region(transfer.region_index, "transfer region")
        if region_index in transfer_by_region:
            raise ValueError("duplicate register-control region transfer")
        if not isinstance(transfer.preserve_unmentioned, bool):
            raise ValueError("preserve-unmentioned must be Boolean")
        mentioned: set[RegisterControlRegisterPair] = set()
        for copy in transfer.copies:
            if copy.output not in pair_set or copy.source not in pair_set:
                raise ValueError("register-control copy uses an unknown register pair")
            if copy.output in mentioned:
                raise ValueError("register-control output transfer is ambiguous")
            mentioned.add(copy.output)
        producer_outputs: set[RegisterControlRegisterPair] = set()
        for atom in transfer.producers:
            if atom.producer_region_index != region_index:
                raise ValueError("producer atom names the wrong region")
            if atom.register_pair not in pair_set:
                raise ValueError("producer atom uses an unknown register pair")
            producer_outputs.add(atom.register_pair)
        if mentioned & producer_outputs:
            raise ValueError("register-control output has copy and producer rules")
        mentioned.update(producer_outputs)
        for blocked in transfer.blocked_outputs:
            if blocked.output not in pair_set:
                raise ValueError("blocked output uses an unknown register pair")
            if blocked.output in mentioned:
                raise ValueError("register-control output has conflicting rules")
            mentioned.add(blocked.output)
        transfer_by_region[region_index] = transfer
    for region_index in range(region_count):
        transfer_by_region.setdefault(
            region_index, RegisterControlRegionTransfer(region_index),
        )

    contracts_by_id: dict[int, RegisterControlCallContract] = {}
    for contract in call_contracts:
        if contract.contract_id in contracts_by_id:
            raise ValueError("duplicate register-control machine contract id")
        if any(pair not in pair_set for pair in contract.preserved_registers):
            raise ValueError("call contract preserves an unknown register pair")
        if any(
            result.register_pair not in pair_set
            for result in contract.import_results
        ):
            raise ValueError("call contract returns an unknown register pair")
        contracts_by_id[contract.contract_id] = contract

    incoming: list[list[tuple[int, RegisterControlEdge]]] = [
        [] for _ in range(region_count)
    ]
    successors: list[set[int]] = [set() for _ in range(region_count)]
    normalized_edges: list[RegisterControlEdge] = []
    for edge_index, edge in enumerate(edges):
        source = checked_region(edge.source_region_index, "edge source")
        target = checked_region(edge.target_region_index, "edge target")
        if edge.kind not in {"direct", "call_return"}:
            raise ValueError("unsupported register-control edge kind")
        if edge.kind == "direct" and edge.machine_contract_id is not None:
            raise ValueError("direct register-control edge cannot name a call contract")
        incoming[target].append((edge_index, edge))
        successors[source].add(target)
        normalized_edges.append(edge)

    unknown = _RegisterControlValue(
        blockers=(REGISTER_CONTROL_UNKNOWN_OR_CLOBBERED,),
    )

    def atom_value(atoms: list[RegisterControlProvenanceAtom]) -> _RegisterControlValue:
        unique = {atom.sort_key(): atom for atom in atoms}
        ordered = tuple(unique[key] for key in sorted(unique))
        if len(ordered) > finite_disjunction_budget:
            return _RegisterControlValue(
                blockers=(REGISTER_CONTROL_DISJUNCTION_BUDGET_EXCEEDED,),
            )
        return _RegisterControlValue(atoms=ordered)

    def join_values(values: list[_RegisterControlValue]) -> _RegisterControlValue:
        if not values:
            return unknown
        blockers = sorted({code for value in values for code in value.blockers})
        if blockers:
            return _RegisterControlValue(blockers=tuple(blockers))
        return atom_value([atom for value in values for atom in value.atoms])

    def transfer_output(
        region_index: int,
        input_state: dict[RegisterControlRegisterPair, _RegisterControlValue],
    ) -> dict[RegisterControlRegisterPair, _RegisterControlValue]:
        transfer = transfer_by_region[region_index]
        copies = {copy.output: copy.source for copy in transfer.copies}
        producers: dict[
            RegisterControlRegisterPair, list[RegisterControlProvenanceAtom]
        ] = {}
        for atom in transfer.producers:
            producers.setdefault(atom.register_pair, []).append(atom)
        blocked = {
            item.output: item.reason_code for item in transfer.blocked_outputs
        }
        result = {}
        for pair in register_pairs:
            if pair in copies:
                result[pair] = input_state[copies[pair]]
            elif pair in producers:
                result[pair] = atom_value(producers[pair])
            elif pair in blocked:
                result[pair] = _RegisterControlValue(
                    blockers=(blocked[pair],),
                )
            elif transfer.preserve_unmentioned:
                result[pair] = input_state[pair]
            else:
                result[pair] = unknown
        return result

    def edge_value(
        edge: RegisterControlEdge,
        pair: RegisterControlRegisterPair,
        source_state: dict[
            RegisterControlRegisterPair, _RegisterControlValue
        ],
    ) -> _RegisterControlValue:
        if edge.kind == "direct":
            return source_state[pair]
        contract = contracts_by_id.get(edge.machine_contract_id)
        if contract is None:
            return _RegisterControlValue(blockers=(REGISTER_CONTROL_UNKNOWN_CALL,))
        import_results = [
            result for result in contract.import_results
            if result.register_pair == pair
        ]
        if import_results:
            return atom_value([
                RegisterControlProvenanceAtom(
                    kind="import_return",
                    producer_region_index=edge.source_region_index,
                    register_pair=pair,
                    machine_contract_id=contract.contract_id,
                    import_identity=import_results[0].import_identity,
                )
            ])
        if pair in contract.preserved_registers:
            return source_state[pair]
        return unknown

    initial_inputs: list[
        dict[RegisterControlRegisterPair, _RegisterControlValue] | None
    ] = [
        ({pair: unknown for pair in register_pairs}
         if region_index in entry_regions else None)
        for region_index in range(region_count)
    ]
    initial_outputs: list[
        dict[RegisterControlRegisterPair, _RegisterControlValue] | None
    ] = [None] * region_count

    def evaluate_output(
        region_index: int,
        input_state: dict[RegisterControlRegisterPair, _RegisterControlValue],
        previous_output: dict[
            RegisterControlRegisterPair, _RegisterControlValue
        ] | None,
    ) -> tuple[
        dict[RegisterControlRegisterPair, _RegisterControlValue],
        dict[RegisterControlRegisterPair, tuple[str, ...]],
    ]:
        proposed = transfer_output(region_index, input_state)
        if previous_output is not None:
            proposed = {
                pair: join_values([previous_output[pair], proposed[pair]])
                for pair in register_pairs
            }
        return proposed, {
            pair: proposed[pair].blockers for pair in register_pairs
        }

    def recompute_input(
        region_index: int,
        outputs: list[
            dict[RegisterControlRegisterPair, _RegisterControlValue] | None
        ] | tuple[
            dict[RegisterControlRegisterPair, _RegisterControlValue] | None, ...
        ],
    ) -> dict[RegisterControlRegisterPair, _RegisterControlValue] | None:
        available = [
            (edge, outputs[edge.source_region_index])
            for _edge_index, edge in incoming[region_index]
            if outputs[edge.source_region_index] is not None
        ]
        if not available and region_index not in entry_regions:
            return None
        result = {}
        for pair in register_pairs:
            values = [
                edge_value(edge, pair, source_state)
                for edge, source_state in available
                if source_state is not None
            ]
            if region_index in entry_regions:
                values.append(unknown)
            result[pair] = join_values(values)
        return result

    fixed_point = solve_monotone_fixed_point_by_scc(
        initial_input_states=initial_inputs,
        initial_output_states=initial_outputs,
        initial_output_reason_states=[None] * region_count,
        successors=[tuple(sorted(items)) for items in successors],
        evaluate_output=evaluate_output,
        recompute_input=recompute_input,
        max_iterations=(
            region_count * len(register_pairs)
            * (finite_disjunction_budget + 2) + 1
        ),
    )

    blockers: dict[tuple[Any, ...], dict[str, Any]] = {}

    def add_blocker(
        code: str,
        *,
        region_index: int,
        direction: str,
        pair: RegisterControlRegisterPair | None = None,
        edge_index: int | None = None,
    ) -> None:
        row = {
            "code": code,
            "region_index": region_index,
            "direction": direction,
        }
        if pair is not None:
            row["register_pair"] = pair.to_payload()
        if edge_index is not None:
            row["edge_index"] = edge_index
        key = (
            code, region_index, direction,
            pair.original if pair is not None else "",
            pair.candidate if pair is not None else "",
            -1 if edge_index is None else edge_index,
        )
        blockers[key] = row

    for region_index, transfer in sorted(transfer_by_region.items()):
        for blocked in transfer.blocked_outputs:
            add_blocker(
                blocked.reason_code,
                region_index=region_index,
                direction="output",
                pair=blocked.output,
            )
    for edge_index, edge in enumerate(normalized_edges):
        if edge.kind == "call_return" and (
            edge.machine_contract_id not in contracts_by_id
        ):
            add_blocker(
                REGISTER_CONTROL_UNKNOWN_CALL,
                region_index=edge.target_region_index,
                direction="edge",
                edge_index=edge_index,
            )
    if not fixed_point.converged:
        add_blocker(
            REGISTER_CONTROL_FIXED_POINT_INCOMPLETE,
            region_index=min(entry_regions, default=0),
            direction="graph",
        )

    def state_payload(
        state: dict[
            RegisterControlRegisterPair, _RegisterControlValue
        ] | None,
    ) -> list[dict[str, Any]]:
        if state is None:
            return []
        return [
            {
                "register_pair": pair.to_payload(),
                **state[pair].to_payload(),
            }
            for pair in register_pairs
        ]

    use_rows = []
    for use_index, use in enumerate(uses):
        region_index = checked_region(use.region_index, "control-use region")
        if use.purpose not in {"register_state", "indirect_control"}:
            raise ValueError("unsupported register-control use purpose")
        if use.register_pair not in pair_set:
            add_blocker(
                REGISTER_CONTROL_PAIR_MISMATCH,
                region_index=region_index,
                direction="use",
            )
            continue
        state = fixed_point.input_states[region_index]
        value = state.get(use.register_pair, unknown) if state is not None else unknown
        use_blockers = list(value.blockers)
        if (
            not use_blockers
            and use.purpose == "indirect_control"
            and any(atom.kind == "import_return" for atom in value.atoms)
        ):
            use_blockers.append(REGISTER_CONTROL_INVALID_CONTROL_ATOM)
        for code in use_blockers:
            add_blocker(
                code,
                region_index=region_index,
                direction="use",
                pair=use.register_pair,
            )
        use_rows.append({
            "use_index": use_index,
            "region_index": region_index,
            "register_pair": use.register_pair.to_payload(),
            "purpose": use.purpose,
            "status": "resolved" if not use_blockers else "incomplete",
            **value.to_payload(),
        })

    partition = strongly_connected_components(
        [tuple(sorted(items)) for items in successors]
    )
    scc_rows = []
    for component_id, members in enumerate(partition.components):
        local_edges = [
            index for index, edge in enumerate(normalized_edges)
            if edge.source_region_index in members
            and edge.target_region_index in members
        ]
        local_payload = {
            "component_id": component_id,
            "region_indices": list(members),
            "predecessor_component_ids": list(
                partition.predecessor_component_ids[component_id]
            ),
            "successor_component_ids": list(
                partition.successor_component_ids[component_id]
            ),
            "edge_indices": local_edges,
            "cyclic": (
                len(members) > 1
                or any(
                    normalized_edges[index].source_region_index
                    == normalized_edges[index].target_region_index
                    for index in local_edges
                )
            ),
            "input_states": [
                {
                    "region_index": region_index,
                    "registers": state_payload(
                        fixed_point.input_states[region_index]
                    ),
                }
                for region_index in members
            ],
            "output_states": [
                {
                    "region_index": region_index,
                    "registers": state_payload(
                        fixed_point.output_states[region_index]
                    ),
                }
                for region_index in members
            ],
        }
        local_payload["evidence_sha256"] = sha256_bytes(json.dumps(
            local_payload, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode())
        scc_rows.append(local_payload)

    blocker_rows = [blockers[key] for key in sorted(blockers)]
    body: dict[str, Any] = {
        "format": "stage-a-register-control-provenance-witness-v1",
        "status": (
            "proposal_requires_generated_lean_replay"
            if fixed_point.converged and not blocker_rows else "incomplete"
        ),
        "acceptance_authority": False,
        "finite_disjunction_budget": finite_disjunction_budget,
        "fixed_point": {
            "solver": "scc_monotone_fixed_point_v1",
            "converged": fixed_point.converged,
            "iterations": fixed_point.iterations,
            "transfer_evaluations": fixed_point.transfer_evaluations,
            "component_order": list(partition.topological_component_ids),
        },
        "register_pairs": [pair.to_payload() for pair in register_pairs],
        "entry_region_indices": sorted(entry_regions),
        "transfers": [
            {
                "region_index": region_index,
                "copies": [
                    {
                        "output": copy.output.to_payload(),
                        "source": copy.source.to_payload(),
                    }
                    for copy in sorted(
                        transfer_by_region[region_index].copies,
                        key=lambda item: (
                            item.output.original, item.output.candidate,
                            item.source.original, item.source.candidate,
                        ),
                    )
                ],
                "producers": [
                    atom.to_payload() for atom in sorted(
                        transfer_by_region[region_index].producers,
                        key=RegisterControlProvenanceAtom.sort_key,
                    )
                ],
                "blocked_outputs": [
                    {
                        "output": item.output.to_payload(),
                        "reason_code": item.reason_code,
                    }
                    for item in sorted(
                        transfer_by_region[region_index].blocked_outputs,
                        key=lambda blocked: (
                            blocked.output.original,
                            blocked.output.candidate,
                            blocked.reason_code,
                        ),
                    )
                ],
                "preserve_unmentioned": (
                    transfer_by_region[region_index].preserve_unmentioned
                ),
            }
            for region_index in range(region_count)
        ],
        "call_contracts": [
            {
                "contract_id": contract_id,
                "preserved_registers": [
                    pair.to_payload()
                    for pair in sorted(
                        contracts_by_id[contract_id].preserved_registers,
                        key=lambda item: (item.original, item.candidate),
                    )
                ],
                "import_results": [
                    result.to_payload()
                    for result in sorted(
                        contracts_by_id[contract_id].import_results,
                        key=lambda item: (
                            item.register_pair.original,
                            item.register_pair.candidate,
                            item.import_identity,
                        ),
                    )
                ],
            }
            for contract_id in sorted(contracts_by_id)
        ],
        "edges": [
            {
                "edge_index": edge_index,
                "source_region_index": edge.source_region_index,
                "target_region_index": edge.target_region_index,
                "kind": edge.kind,
                "machine_contract_id": edge.machine_contract_id,
                "contract_status": (
                    "not_applicable" if edge.kind == "direct"
                    else "checked" if edge.machine_contract_id in contracts_by_id
                    else "missing"
                ),
            }
            for edge_index, edge in enumerate(normalized_edges)
        ],
        "regions": [
            {
                "region_index": region_index,
                "inputs": state_payload(fixed_point.input_states[region_index]),
                "outputs": state_payload(fixed_point.output_states[region_index]),
            }
            for region_index in range(region_count)
        ],
        "sccs": scc_rows,
        "uses": use_rows,
        "blockers": blocker_rows,
    }
    body["witness_sha256"] = sha256_bytes(json.dumps(
        body, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode())
    return RegisterControlProvenanceWitness(body)


def _machine_result_invariant_relation(relation: dict[str, Any]) -> str:
    return "exact" if relation.get("relation") == "exact" else "related_word"


def _fixed_register_values(
    input_relations: dict[str, RegisterRelation],
    candidate_registers: dict[str, str] | None,
) -> tuple[dict[str, int], dict[str, int]]:
    """Return unambiguous fixed scalar inputs for each binary side."""
    original_values: dict[str, int] = {}
    candidate_rows: dict[str, list[int]] = {}
    for original_register, relation in input_relations.items():
        payload = _register_relation_payload(relation)
        if payload["relation"] != "fixed_word":
            continue
        value = int(payload["value"]) & 0xFFFFFFFF
        original_values[str(original_register)] = value
        candidate_register = str(
            (candidate_registers or {}).get(
                str(original_register), str(original_register),
            )
        )
        candidate_rows.setdefault(candidate_register, []).append(value)
    candidate_values = {
        register: values[0]
        for register, values in candidate_rows.items()
        if len(values) == 1
    }
    return original_values, candidate_values


def _fixed_immutable_expr_value(
    expression: Any,
    binary: StageABinary,
    fixed_registers: dict[str, int],
) -> int | None:
    """Propose a value for the fragment replayed by Lean.

    This result never serves as proof evidence.  The generated claim includes
    only the proposed scalar; Lean reevaluates the decoded expression from the
    exact PE bytes and checked source invariant.
    """
    if not isinstance(expression, dict):
        return None
    operation = str(expression.get("op", ""))
    mask = 0xFFFFFFFF

    if operation == "input_reg":
        value = fixed_registers.get(str(expression.get("reg", "")))
        return None if value is None else value & mask
    if operation == "constant":
        value = expression.get("value")
        if not isinstance(value, int) or isinstance(value, bool):
            return None
        return value & mask

    if operation in {
        "add", "sub", "bit_and", "bit_xor", "bit_or", "multiply",
        "multiply_high_unsigned", "multiply_high_signed",
        "shift_left_by", "shift_right_by", "shift_arithmetic_right_by",
        "unsigned_less_value",
    }:
        left = _fixed_immutable_expr_value(
            expression.get("left"), binary, fixed_registers,
        )
        right = _fixed_immutable_expr_value(
            expression.get("right"), binary, fixed_registers,
        )
        if left is None or right is None:
            return None
        if operation == "add":
            return (left + right) & mask
        if operation == "sub":
            return (left - right) & mask
        if operation == "bit_and":
            return left & right
        if operation == "bit_xor":
            return left ^ right
        if operation == "bit_or":
            return left | right
        if operation == "multiply":
            return (left * right) & mask
        if operation == "multiply_high_unsigned":
            return ((left * right) >> 32) & mask
        if operation == "multiply_high_signed":
            signed_left = left if left < 0x80000000 else left - 0x100000000
            signed_right = right if right < 0x80000000 else right - 0x100000000
            return ((signed_left * signed_right) >> 32) & mask
        if operation == "shift_left_by":
            return (left << (right % 32)) & mask
        if operation == "shift_right_by":
            return left >> (right % 32)
        if operation == "shift_arithmetic_right_by":
            signed = left if left < 0x80000000 else left - 0x100000000
            return (signed >> (right % 32)) & mask
        return 1 if left < right else 0

    if operation in {"bit_not", "lowest_set_bit", "highest_set_bit"}:
        value = _fixed_immutable_expr_value(
            expression.get("value"), binary, fixed_registers,
        )
        if value is None:
            return None
        if operation == "bit_not":
            return (~value) & mask
        if operation == "lowest_set_bit":
            return 32 if value == 0 else (value & -value).bit_length() - 1
        return 0 if value == 0 else value.bit_length() - 1

    if operation in {"shift_left", "shift_right"}:
        value = _fixed_immutable_expr_value(
            expression.get("value"), binary, fixed_registers,
        )
        amount = expression.get("amount")
        if (
            value is None
            or not isinstance(amount, int)
            or isinstance(amount, bool)
            or amount < 0
        ):
            return None
        if operation == "shift_left":
            return (value << amount) & mask if amount < 32 else 0
        return value >> amount if amount < 32 else 0

    if operation in {"extract_byte", "bit_value"}:
        value = _fixed_immutable_expr_value(
            expression.get("value"), binary, fixed_registers,
        )
        index = expression.get("index")
        if (
            value is None
            or not isinstance(index, int)
            or isinstance(index, bool)
            or index < 0
        ):
            return None
        if operation == "extract_byte":
            return (value >> (index * 8)) & 0xFF if index < 4 else 0
        return (value >> index) & 1 if index < 32 else 0

    if operation in {"read8", "read32"}:
        address = _fixed_immutable_expr_value(
            expression.get("address"), binary, fixed_registers,
        )
        if address is None:
            return None
        word = _immutable_image_u32_value(binary, address)
        if word is None:
            return None
        return word & 0xFF if operation == "read8" else word

    if operation == "if_equal":
        left = _fixed_immutable_expr_value(
            expression.get("left"), binary, fixed_registers,
        )
        right = _fixed_immutable_expr_value(
            expression.get("right"), binary, fixed_registers,
        )
        if left is None or right is None:
            return None
        branch = expression.get("then" if left == right else "else")
        return _fixed_immutable_expr_value(branch, binary, fixed_registers)

    return None

def _infer_register_output_relation(
    original_expression: dict[str, Any],
    candidate_expression: dict[str, Any],
    input_relations: dict[str, RegisterRelation],
    contract: dict[str, Any],
    original_image_base: int,
    candidate_image_base: int,
    global_values_empty: bool,
    original_bin: StageABinary | None = None,
    candidate_bin: StageABinary | None = None,
    candidate_input_registers: dict[str, str] | None = None,
) -> tuple[RegisterRelation, str]:
    constant_relation = _paired_constant_relation(
        original_expression,
        candidate_expression,
        contract,
        original_image_base,
        candidate_image_base,
    )
    if constant_relation is not None:
        return constant_relation, "paired_constant"
    static_slot = _matching_static_word_relation_slot(
        original_expression, candidate_expression, contract,
    )
    if static_slot is not None:
        relation = str(static_slot["relation"])
        if relation == "fixed_code_pointer":
            relation = {
                "relation": "fixed_code_pointer",
                "target_id": int(static_slot["target_id"]),
            }
        return relation, "static_word_slot"
    if (
        original_bin is not None
        and candidate_bin is not None
    ):
        original_read = _immutable_image_word_read(
            original_expression, original_bin,
        )
        candidate_read = _immutable_image_word_read(
            candidate_expression, candidate_bin,
        )
        if original_read is not None and candidate_read is not None:
            _, original_writes, original_assembled, original_value = original_read
            _, candidate_writes, candidate_assembled, candidate_value = candidate_read
            immutable_relation = _paired_constant_relation(
                {"op": "constant", "value": original_value},
                {"op": "constant", "value": candidate_value},
                contract,
                original_image_base,
                candidate_image_base,
            )
            if immutable_relation is not None:
                if not original_assembled and not candidate_assembled:
                    return immutable_relation, "immutable_image_word"
                if (
                    original_assembled == candidate_assembled
                    and len(original_writes) == len(candidate_writes)
                ):
                    return immutable_relation, "assembled_immutable_image_word"
    if (
        original_expression.get("op") == "input_reg"
        and candidate_expression.get("op") == "input_reg"
    ):
        register = str(original_expression.get("reg"))
        candidate_register = str(candidate_expression.get("reg"))
        expected_candidate = (candidate_input_registers or {}).get(
            register, register,
        )
        if candidate_register == expected_candidate:
            return (
                input_relations.get(register, "related_word"),
                "identity_transfer",
            )
    if original_bin is not None and candidate_bin is not None:
        original_fixed, candidate_fixed = _fixed_register_values(
            input_relations, candidate_input_registers,
        )
        original_value = _fixed_immutable_expr_value(
            original_expression, original_bin, original_fixed,
        )
        candidate_value = _fixed_immutable_expr_value(
            candidate_expression, candidate_bin, candidate_fixed,
        )
        if original_value is not None and candidate_value is not None:
            fixed_relation = _paired_constant_relation(
                {"op": "constant", "value": original_value},
                {"op": "constant", "value": candidate_value},
                contract,
                original_image_base,
                candidate_image_base,
            )
            if fixed_relation is not None:
                return fixed_relation, "fixed_immutable_expression"
    if original_expression == candidate_expression:
        dependencies = _semantic_expr_registers(original_expression)
        if _semantic_expr_is_pure(original_expression) and all(
            _register_relation_implies_exact(
                input_relations.get(register, "related_word")
            )
            for register in dependencies
        ):
            return "exact", "lean_exact_memory_free_expression"
        if global_values_empty and _semantic_exact_memory_inputs(
            original_expression,
            {
                register for register, relation in input_relations.items()
                if _register_relation_implies_exact(relation)
            },
        ):
            return "exact", "lean_exact_memory_expression"
    return "related_word", "unsupported_or_mixed_relation"


def _matching_static_word_relation_slot(
    original_expression: dict[str, Any],
    candidate_expression: dict[str, Any],
    contract: dict[str, Any],
) -> dict[str, Any] | None:
    original_address = _constant_read32_address(original_expression)
    candidate_address = _constant_read32_address(candidate_expression)
    if original_address is None or candidate_address is None:
        return None
    code_targets = contract.get("code_targets", [])
    matches = []
    for slot in contract.get("static_word_relation_slots", []):
        if not isinstance(slot, dict):
            continue
        relation = str(slot.get("relation"))
        valid_fixed_target = False
        if relation == "fixed_code_pointer":
            target_id = slot.get("target_id")
            valid_fixed_target = (
                isinstance(target_id, int)
                and not isinstance(target_id, bool)
                and target_id >= 0
                and isinstance(code_targets, list)
                and target_id < len(code_targets)
                and isinstance(code_targets[target_id], dict)
                and code_targets[target_id].get("id") == target_id
            )
        if (
            int(slot.get("original_address", -1)) == original_address
            and int(slot.get("candidate_address", -1)) == candidate_address
            and (
                relation in _REGISTER_RELATION_KINDS - {"fixed_code_pointer"}
                or valid_fixed_target
            )
        ):
            matches.append(slot)
    return dict(matches[0]) if len(matches) == 1 else None


def _paired_code_target_id(
    original_value: int,
    candidate_value: int,
    contract: dict[str, Any],
    original_image_base: int,
    candidate_image_base: int,
) -> int | None:
    """Return the unique canonical target for a concrete address pair."""
    matches = []
    for target_id, target in enumerate(contract.get("code_targets", [])):
        if not (
            isinstance(target, dict)
            and target.get("id") == target_id
        ):
            continue
        original_rvas = [
            target.get("original_rva"),
            *target.get("original_aliases", []),
        ]
        candidate_rvas = [
            target.get("candidate_rva"),
            *target.get("candidate_aliases", []),
        ]
        if (
            (original_value & 0xFFFFFFFF) in {
                (original_image_base + int(rva)) & 0xFFFFFFFF
                for rva in original_rvas
                if isinstance(rva, int) and not isinstance(rva, bool)
            }
            and (candidate_value & 0xFFFFFFFF) in {
                (candidate_image_base + int(rva)) & 0xFFFFFFFF
                for rva in candidate_rvas
                if isinstance(rva, int) and not isinstance(rva, bool)
            }
        ):
            matches.append(target_id)
    return matches[0] if len(matches) == 1 else None


def _register_transfer_region_context_sha256(
    *,
    behavior_pair: dict[str, Any],
    input_pairs: dict[str, str],
    output_pairs: dict[str, str],
    contract: dict[str, Any],
    original_image_base: int,
    candidate_image_base: int,
    original_bin: StageABinary | None,
    candidate_bin: StageABinary | None,
    register_order: tuple[str, ...],
) -> str:
    """Hash only static facts that can affect one region transfer."""
    original_registers = behavior_pair["original_ir"]["registers"]
    candidate_registers = behavior_pair["candidate_ir"]["registers"]
    rows = []
    for register in register_order:
        candidate_register = output_pairs.get(register)
        if (
            register not in original_registers
            or candidate_register is None
            or candidate_register not in candidate_registers
        ):
            rows.append({
                "register": register,
                "candidate_register": candidate_register,
                "status": "output_pair_missing",
            })
            continue
        original_expression = original_registers[register]
        candidate_expression = candidate_registers[candidate_register]
        rows.append({
            "register": register,
            "candidate_register": candidate_register,
            "original_expression": original_expression,
            "candidate_expression": candidate_expression,
            "paired_constant_relation": _paired_constant_relation(
                original_expression,
                candidate_expression,
                contract,
                original_image_base,
                candidate_image_base,
            ),
            "static_word_relation_slot": _matching_static_word_relation_slot(
                original_expression,
                candidate_expression,
                contract,
            ),
            "original_immutable_word_read": (
                _immutable_image_word_read(original_expression, original_bin)
                if original_bin is not None else None
            ),
            "candidate_immutable_word_read": (
                _immutable_image_word_read(candidate_expression, candidate_bin)
                if candidate_bin is not None else None
            ),
        })
    return sha256_bytes(
        json.dumps(
            {
                "format": "stage-a-register-transfer-region-context-v2",
                "original_image_base": original_image_base,
                "candidate_image_base": candidate_image_base,
                "global_values_empty": not contract.get("value_targets"),
                "input_pairs": input_pairs,
                "output_pairs": output_pairs,
                "outputs": rows,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _fixed_immutable_transfer_probe(
    *,
    behavior_pair: dict[str, Any],
    input_relations: dict[str, RegisterRelation],
    input_pairs: dict[str, str],
    output_pairs: dict[str, str],
    original_bin: StageABinary | None,
    candidate_bin: StageABinary | None,
    register_order: tuple[str, ...],
) -> list[dict[str, Any]]:
    if original_bin is None or candidate_bin is None:
        return []
    original_fixed, candidate_fixed = _fixed_register_values(
        input_relations, input_pairs,
    )
    original_registers = behavior_pair["original_ir"]["registers"]
    candidate_registers = behavior_pair["candidate_ir"]["registers"]
    rows = []
    for register in register_order:
        candidate_register = output_pairs.get(register)
        if (
            register not in original_registers
            or candidate_register is None
            or candidate_register not in candidate_registers
        ):
            continue
        original_value = _fixed_immutable_expr_value(
            original_registers[register], original_bin, original_fixed,
        )
        candidate_value = _fixed_immutable_expr_value(
            candidate_registers[candidate_register],
            candidate_bin,
            candidate_fixed,
        )
        if original_value is not None or candidate_value is not None:
            rows.append({
                "register": register,
                "candidate_register": candidate_register,
                "original_value": original_value,
                "candidate_value": candidate_value,
            })
    return rows

def _callsite_generation_incomplete(
    callsite: int,
    code: str,
    *,
    node_id: int | None = None,
    reference: Any = None,
    nested_reason_codes: list[str] | None = None,
) -> dict[str, Any]:
    issue: dict[str, Any] = {"code": code}
    if node_id is not None:
        issue["node_id"] = int(node_id)
    if reference is not None:
        issue["reference"] = reference
    if nested_reason_codes:
        issue["nested_reason_codes"] = sorted(set(nested_reason_codes))
    return {
        "format": CALLSITE_PRESERVATION_ANALYSIS_FORMAT,
        "status": "incomplete",
        "callsite_id": int(callsite),
        "reason_codes": [code],
        "issues": [issue],
        "certificate": None,
    }


def _translate_callsite_behavior(
    behavior: dict[str, Any],
    region_by_target_id: dict[int, int],
) -> tuple[dict[str, Any], list[str]]:
    # Only control targets are rewritten.  Keep the large normalized register
    # and memory trees shared and copy the path that this function mutates.
    translated = dict(behavior)
    source_outcome = behavior.get("outcome")
    outcome = dict(source_outcome) if isinstance(source_outcome, dict) else None
    if not isinstance(outcome, dict):
        return translated, ["normalized_outcome_missing"]
    translated["outcome"] = outcome
    operation = outcome.get("op")
    target_fields: tuple[str, ...]
    if operation == "jump":
        target_fields = ("target",)
    elif operation == "branch":
        target_fields = ("taken", "fallthrough")
    elif operation == "call":
        target_fields = ("target", "continuation")
    elif operation == "call_unmapped_return":
        target_fields = ("target",)
    elif operation == "external_call":
        target_fields = ("continuation",)
    elif operation == "indirect_call":
        target_fields = ("continuation",)
    else:
        target_fields = ()
    issues: list[str] = []
    for field in target_fields:
        target_id = outcome.get(field)
        if (
            not isinstance(target_id, int)
            or isinstance(target_id, bool)
            or int(target_id) not in region_by_target_id
        ):
            issues.append(f"{field}_target_unmapped")
            continue
        outcome[field] = region_by_target_id[int(target_id)]
    return translated, sorted(set(issues))


def _propose_internal_callsite_preservation_summaries(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    import_register_analysis: dict[str, Any],
    register_relations: dict[str, Any],
) -> dict[str, Any]:
    """Propose callsite-local preservation without granting proof authority.

    Static return summaries delimit each callee and its exact return inventory.
    Normalized control targets are converted to paired region indices, then the
    standalone analyzer checks syntactic register preservation over that finite
    graph.  Every result remains untrusted until generated Lean replays it.
    """
    regions = contract.get("regions", [])
    duplicate_target_ids: set[int] = set()
    region_by_target_id: dict[int, int] = {}
    for region_index, region in enumerate(regions):
        target_id = region.get("numeric_id")
        if not isinstance(target_id, int) or isinstance(target_id, bool):
            continue
        if int(target_id) in region_by_target_id:
            duplicate_target_ids.add(int(target_id))
            continue
        region_by_target_id[int(target_id)] = region_index
    for target_id in duplicate_target_ids:
        region_by_target_id.pop(target_id, None)

    relations_by_callsite: dict[int, list[dict[str, Any]]] = {}
    for inventory in ("relations", "callsite_candidate_relations"):
        for row in import_register_analysis.get(inventory, []):
            try:
                callsite = int(row["region_index"])
                relation = {
                    "original": str(row["original_register"]),
                    "candidate": str(row["candidate_register"]),
                    "import": json.loads(json.dumps(row["import"])),
                }
            except (KeyError, TypeError, ValueError):
                continue
            if not 0 <= callsite < len(behaviors):
                continue
            relations_by_callsite.setdefault(callsite, []).append(relation)
    for callsite, relations in relations_by_callsite.items():
        relations_by_callsite[callsite] = sorted(
            {
                json.dumps(relation, sort_keys=True, separators=(",", ":")):
                    relation
                for relation in relations
            }.values(),
            key=lambda relation: json.dumps(
                relation, sort_keys=True, separators=(",", ":")
            ),
        )

    register_relations_by_callsite: dict[int, list[dict[str, Any]]] = {}
    relation_rows = register_relations.get("regions", [])
    for callsite, row in enumerate(relation_rows):
        if not isinstance(row, dict):
            continue
        for claim_index, claim in enumerate(row.get("output_claims", [])):
            if not isinstance(claim, dict) or not isinstance(claim.get("output"), dict):
                continue
            output = claim["output"]
            relation_kind = output.get("relation")
            if relation_kind not in {
                "fixed_word", "code_pointer", "fixed_code_pointer", "data_pointer",
            }:
                continue
            pair = (str(output.get("original")), str(output.get("candidate")))
            if pair[0] not in _X86_GENERAL_REGISTERS or pair[1] not in (
                _X86_GENERAL_REGISTERS
            ):
                continue
            relation = json.loads(json.dumps(output))
            relation["origin"] = {
                "kind": "region_output_claim",
                "region_index": callsite,
                "claim_index": claim_index,
                "claim_hash": sha256_bytes(json.dumps(
                    claim, sort_keys=True, separators=(",", ":"), allow_nan=False,
                ).encode()),
            }
            register_relations_by_callsite.setdefault(callsite, []).append(relation)
    for callsite, relations in register_relations_by_callsite.items():
        register_relations_by_callsite[callsite] = sorted(
            {
                json.dumps(relation, sort_keys=True, separators=(",", ":")):
                    relation
                for relation in relations
            }.values(),
            key=lambda relation: json.dumps(
                relation, sort_keys=True, separators=(",", ":")
            ),
        )

    raw_summaries = (
        register_relations.get("return_slot_analysis", {})
        .get("call_summary_analysis", {})
        .get("summaries", [])
    )
    summaries_by_callsite: dict[int, list[dict[str, Any]]] = {}
    duplicate_callsites: set[int] = set()
    for summary in raw_summaries:
        if not isinstance(summary, dict):
            continue
        try:
            callsite = int(summary["callsite_region_index"])
        except (KeyError, TypeError, ValueError):
            continue
        summaries_by_callsite.setdefault(callsite, []).append(summary)
    summary_by_callsite = {
        callsite: sorted(
            summaries,
            key=lambda summary: json.dumps(
                summary, sort_keys=True, separators=(",", ":")
            ),
        )[0]
        for callsite, summaries in summaries_by_callsite.items()
    }
    duplicate_callsites.update(
        callsite for callsite, summaries in summaries_by_callsite.items()
        if len(summaries) != 1
    )

    translated_behaviors: list[dict[str, Any]] = []
    translation_issues: dict[int, list[str]] = {}
    for region_index, behavior_pair in enumerate(behaviors):
        original, original_issues = _translate_callsite_behavior(
            behavior_pair.get("original_ir") or {}, region_by_target_id
        )
        candidate, candidate_issues = _translate_callsite_behavior(
            behavior_pair.get("candidate_ir") or {}, region_by_target_id
        )
        translated_behaviors.append({
            "node_id": region_index,
            "original_ir": original,
            "candidate_ir": candidate,
        })
        issues = sorted(set(original_issues + candidate_issues))
        if issues:
            translation_issues[region_index] = issues

    base_control: list[dict[str, Any]] = []
    returning_external_contracts: dict[tuple[int, int], dict[str, Any]] = {}
    direct_external_contracts: dict[int, dict[str, Any]] = {}
    ambiguous_direct_external_sources: set[int] = set()
    known_indirect_calls: dict[int, tuple[int, int]] = {}
    contracts_by_id = {
        int(item["id"]): item
        for item in contract.get("machine_import_call_contracts", [])
        if isinstance(item, dict)
        and isinstance(item.get("id"), int)
        and not isinstance(item.get("id"), bool)
    }
    for edge in register_relations.get("edges", []):
        if not isinstance(edge, dict):
            continue
        direct_contract_id = edge.get("machine_contract_id")
        direct_source = edge.get("source_region_index")
        if (
            edge.get("kind") == "external_call"
            and isinstance(direct_contract_id, int)
            and not isinstance(direct_contract_id, bool)
            and isinstance(direct_source, int)
            and not isinstance(direct_source, bool)
            and int(direct_contract_id) in contracts_by_id
        ):
            source_id = int(direct_source)
            contract_row = contracts_by_id[int(direct_contract_id)]
            existing = direct_external_contracts.get(source_id)
            if existing is not None and existing != contract_row:
                ambiguous_direct_external_sources.add(source_id)
                direct_external_contracts.pop(source_id, None)
            elif source_id not in ambiguous_direct_external_sources:
                direct_external_contracts[source_id] = contract_row
        indirect_claim = edge.get("indirect_target_claim")
        if (
            edge.get("kind") == "call"
            and isinstance(indirect_claim, dict)
            and isinstance(edge.get("source_region_index"), int)
            and isinstance(edge.get("target_region_index"), int)
            and isinstance(indirect_claim.get("continuation_region_index"), int)
        ):
            known_indirect_calls[int(edge["source_region_index"])] = (
                int(edge["target_region_index"]),
                int(indirect_claim["continuation_region_index"]),
            )
        contract_id = edge.get("returning_external_thunk_contract_id")
        if not isinstance(contract_id, int) or isinstance(contract_id, bool):
            continue
        machine_contract = contracts_by_id.get(int(contract_id))
        if machine_contract is None:
            continue
        returning_external_contracts[(
            int(edge["source_region_index"]),
            int(edge["target_region_index"]),
        )] = machine_contract
    for region_index, behavior_pair in enumerate(translated_behaviors):
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        original_op = original_outcome.get("op")
        candidate_op = candidate_outcome.get("op")
        successors: list[int] = []
        exit_row: dict[str, Any]
        if original_op != candidate_op:
            exit_row = {"kind": "unsupported"}
        elif original_op == "jump" and isinstance(original_outcome.get("target"), int):
            successors = [int(original_outcome["target"])]
            exit_row = {"kind": "direct"}
        elif original_op == "branch" and all(
            isinstance(original_outcome.get(field), int)
            for field in ("taken", "fallthrough")
        ):
            successors = [
                int(original_outcome["taken"]),
                int(original_outcome["fallthrough"]),
            ]
            exit_row = {"kind": "direct"}
        elif original_op == "returned":
            exit_row = {"kind": "return"}
        elif original_op == "call" and all(
            isinstance(original_outcome.get(field), int)
            for field in ("target", "continuation")
        ):
            successors = [int(original_outcome["continuation"])]
            machine_contract = returning_external_contracts.get((
                region_index, int(original_outcome["target"]),
            ))
            if machine_contract is None:
                exit_row = {"kind": "nested_call"}
            else:
                preserved = sorted({
                    str(register)
                    for register in machine_contract.get("preserved_registers", [])
                    if str(register) in _X86_GENERAL_REGISTERS
                })
                exit_row = {
                    "kind": "external_call",
                    "machine_contract_id": int(machine_contract["id"]),
                    "original_preserved_registers": preserved,
                    "candidate_preserved_registers": preserved,
                }
        elif original_op == "external_call" and all(
            isinstance(original_outcome.get(field), int)
            and isinstance(candidate_outcome.get(field), int)
            for field in ("continuation",)
        ):
            machine_contract = direct_external_contracts.get(region_index)
            if (
                machine_contract is None
                or machine_contract.get("disposition") != "returns"
                or original_outcome.get("continuation")
                    != candidate_outcome.get("continuation")
                or _semantic_external_target_identity(
                    original_outcome.get("import")
                ) != _semantic_external_target_identity(
                    candidate_outcome.get("import")
                )
            ):
                exit_row = {"kind": "unsupported"}
            else:
                preserved = sorted({
                    str(register)
                    for register in machine_contract.get(
                        "preserved_registers", []
                    )
                    if str(register) in _X86_GENERAL_REGISTERS
                })
                successors = [int(original_outcome["continuation"])]
                exit_row = {
                    "kind": "external_call",
                    "machine_contract_id": int(machine_contract["id"]),
                    "original_preserved_registers": preserved,
                    "candidate_preserved_registers": preserved,
                }
        elif original_op in {"indirect_call", "indirect_jump"}:
            exit_row = {"kind": "unresolved_indirect"}
        else:
            exit_row = {"kind": "unsupported"}
        base_control.append({
            "node_id": region_index,
            "successors": successors,
            "exit": exit_row,
        })

    analysis_cache: dict[tuple[int, str, str], dict[str, Any]] = {}

    def relation_key(relations: list[dict[str, Any]]) -> str:
        return json.dumps(relations, sort_keys=True, separators=(",", ":"))

    def summary_shape(
        callsite: int,
    ) -> tuple[int, int, list[int]] | None:
        summary = summary_by_callsite.get(callsite)
        if summary is None:
            return None
        try:
            callee = int(summary["callee_region_index"])
            continuation = int(summary["continuation_region_index"])
            returns = sorted({
                int(item) for item in summary["return_region_indices"]
            })
        except (KeyError, TypeError, ValueError):
            return None
        if not (
            0 <= callsite < len(behaviors)
            and 0 <= callee < len(behaviors)
            and 0 <= continuation < len(behaviors)
            and returns
            and all(0 <= item < len(behaviors) for item in returns)
        ):
            return None
        return callee, continuation, returns

    def reachable_nested_calls(
        callee: int,
    ) -> tuple[list[int], dict[str, Any] | None]:
        pending = [callee]
        visited: set[int] = set()
        nested: set[int] = set()
        while pending:
            node = pending.pop()
            if node in visited:
                continue
            if not 0 <= node < len(base_control):
                return [], _callsite_generation_incomplete(
                    node, "reachable_control_node_missing", node_id=node
                )
            visited.add(node)
            if node in translation_issues:
                return [], _callsite_generation_incomplete(
                    node,
                    "control_target_unmapped",
                    node_id=node,
                    reference=translation_issues[node],
                )
            control = base_control[node]
            exit_kind = control["exit"]["kind"]
            if exit_kind == "nested_call":
                nested.add(node)
            for successor in reversed(control["successors"]):
                if successor not in visited:
                    pending.append(successor)
        return sorted(nested), None

    def build_analysis(
        callsite: int,
        requested_relations: list[dict[str, Any]],
        requested_register_relations: list[dict[str, Any]],
        active: tuple[int, ...] = (),
    ) -> dict[str, Any]:
        key = (
            callsite,
            relation_key(requested_relations),
            relation_key(requested_register_relations),
        )
        if callsite in active:
            return _callsite_generation_incomplete(
                callsite,
                "recursive_callsite_summary_dependency",
                node_id=callsite,
                reference=list(active) + [callsite],
            )
        if key in analysis_cache:
            return analysis_cache[key]
        if callsite in duplicate_callsites:
            result = _callsite_generation_incomplete(
                callsite, "call_summary_duplicate", node_id=callsite
            )
            analysis_cache[key] = result
            return result
        summary = summary_by_callsite.get(callsite)
        if summary is None:
            result = _callsite_generation_incomplete(
                callsite, "nested_call_summary_missing", node_id=callsite
            )
            analysis_cache[key] = result
            return result
        if not summary.get("closed"):
            result = _callsite_generation_incomplete(
                callsite, "call_summary_not_closed", node_id=callsite
            )
            analysis_cache[key] = result
            return result
        shape = summary_shape(callsite)
        if shape is None:
            result = _callsite_generation_incomplete(
                callsite, "call_summary_inventory_invalid", node_id=callsite
            )
            analysis_cache[key] = result
            return result
        callee, continuation, returns = shape
        original_call = translated_behaviors[callsite]["original_ir"].get("outcome") or {}
        candidate_call = translated_behaviors[callsite]["candidate_ir"].get("outcome") or {}
        known_indirect = known_indirect_calls.get(callsite)
        direct_shape = all(
            outcome.get(field) == expected
            for outcome in (original_call, candidate_call)
            for field, expected in (
                ("op", "call"), ("target", callee),
                ("continuation", continuation),
            )
        )
        indirect_shape = (
            known_indirect == (callee, continuation)
            and all(
                outcome.get("op") == "indirect_call"
                and outcome.get("continuation") == continuation
                for outcome in (original_call, candidate_call)
            )
        )
        if not direct_shape and not indirect_shape:
            result = _callsite_generation_incomplete(
                callsite, "call_summary_behavior_mismatch", node_id=callsite
            )
            analysis_cache[key] = result
            return result

        dependencies, dependency_issue = reachable_nested_calls(callee)
        if dependency_issue is not None:
            result = dict(dependency_issue)
            result["callsite_id"] = callsite
            analysis_cache[key] = result
            return result
        child_analyses: dict[int, dict[str, Any]] = {}
        for dependency in dependencies:
            child = build_analysis(
                dependency, requested_relations, requested_register_relations,
                active + (callsite,)
            )
            child_analyses[dependency] = child
            if child.get("status") != "satisfied":
                result = _callsite_generation_incomplete(
                    callsite,
                    "nested_callsite_summary_incomplete",
                    node_id=dependency,
                    reference=dependency,
                    nested_reason_codes=list(child.get("reason_codes", [])),
                )
                analysis_cache[key] = result
                return result

        control = json.loads(json.dumps(base_control))
        for dependency, child in child_analyses.items():
            control[dependency]["exit"]["summary_id"] = child[
                "certificate"
            ]["id"]
        result = propose_callsite_preserved_register_summary(
            callsite_id=callsite,
            callee_entry=callee,
            return_inventory=[{
                "return_node_id": return_node,
                "continuation_id": continuation,
            } for return_node in returns],
            requested_relations=requested_relations,
            requested_register_relations=requested_register_relations,
            behaviors=translated_behaviors,
            control=control,
            nested_summaries=[
                child_analyses[dependency]
                for dependency in sorted(child_analyses)
            ],
        )
        analysis_cache[key] = result
        return result

    internal_callsite_node_ids = set(summary_by_callsite)
    for region_index, behavior_pair in enumerate(translated_behaviors):
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        if (
            original_outcome.get("op") in {"call", "indirect_call"}
            and candidate_outcome.get("op") == original_outcome.get("op")
        ):
            internal_callsite_node_ids.add(region_index)

    rows: list[dict[str, Any]] = []
    proposal_edges: list[dict[str, Any]] = []
    for callsite in sorted(internal_callsite_node_ids):
        relations = relations_by_callsite.get(callsite, [])
        preserved_register_relations = register_relations_by_callsite.get(
            callsite, [],
        )
        shape = summary_shape(callsite)
        metadata = {
            "callsite_region_index": callsite,
            "callee_region_index": shape[0] if shape is not None else None,
            "continuation_region_index": shape[1] if shape is not None else None,
            "return_region_indices": shape[2] if shape is not None else [],
            "requested_relations": relations,
            "requested_register_relations": preserved_register_relations,
        }
        if not relations and not preserved_register_relations:
            rows.append({
                **metadata,
                "status": "not_applicable",
                "reason_codes": ["no_preservable_relations_at_callsite"],
                "analysis": None,
            })
            continue
        analysis = build_analysis(
            callsite, relations, preserved_register_relations,
        )
        rows.append({
            **metadata,
            "status": analysis["status"],
            "reason_codes": analysis["reason_codes"],
            "analysis": analysis,
        })
        if analysis.get("status") != "satisfied" or shape is None:
            continue
        certificate = analysis["certificate"]
        proposal_edges.append({
            "source_region_index": callsite,
            "target_region_index": shape[1],
            "kind": "internal_callsite_preservation_summary",
            "environment_barrier": False,
            "proposal_only": True,
            "certificate_id": certificate["id"],
            "certificate_hash": certificate["certificate_hash"],
            "preserved_import_relations": certificate["requested_relations"],
            "preserved_register_relations": certificate[
                "requested_register_relations"
            ],
            "return_region_indices": shape[2],
        })

    all_certificates = {
        analysis["certificate"]["id"]: analysis["certificate"]
        for analysis in analysis_cache.values()
        if analysis.get("status") == "satisfied"
    }
    payload = {
        "format": CALLSITE_PRESERVATION_ARTIFACT_FORMAT,
        "status": "proposal_requires_generated_lean_replay",
        "summaries": rows,
        "certificates": [
            all_certificates[certificate_id]
            for certificate_id in sorted(all_certificates)
        ],
        "proposal_edges": proposal_edges,
        "counts": {
            "call_summaries": len(rows),
            "satisfied": sum(row["status"] == "satisfied" for row in rows),
            "incomplete": sum(row["status"] == "incomplete" for row in rows),
            "not_applicable": sum(
                row["status"] == "not_applicable" for row in rows
            ),
            "proposal_edges": len(proposal_edges),
            "certificates": len(all_certificates),
        },
        "trust": {
            "role": "analysis_and_certificate_proposal_only",
            "acceptance_authority": False,
            "required_replay": (
                "Lean must replay every normalized behavior, control edge, "
                "return inventory, nested dependency, and preserved relation"
            ),
        },
    }
    return serialize_callsite_preservation_artifact(
        parse_callsite_preservation_artifact(
            payload,
            region_count=len(behaviors),
        )
    )


def _infer_import_register_invariants(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    seeds: list[dict[str, Any]],
    *,
    internal_return_predecessors: list[dict[str, Any]] | None = None,
    callsite_summary_predecessors: list[dict[str, Any]] | None = None,
    returning_external_thunk_predecessors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    region_by_numeric_id = {
        int(region["numeric_id"]): index
        for index, region in enumerate(contract.get("regions", []))
    }
    nonvolatile = {"ebx", "esi", "edi", "ebp"}

    def identity_key(imported: dict[str, Any]) -> tuple[str, str, str | int]:
        if "symbol" in imported:
            return (str(imported["dll"]).lower(), "symbol", str(imported["symbol"]))
        return (str(imported["dll"]).lower(), "ordinal", int(imported["ordinal"]))

    identities = {
        identity_key(seed["import"]): seed["import"] for seed in seeds
    }
    seed_facts: dict[int, set[tuple[str, str, tuple[str, str, str | int]]]] = {}
    for seed in seeds:
        seed_facts.setdefault(int(seed["region_index"]), set()).add((
            str(seed["original_register"]),
            str(seed["candidate_register"]),
            identity_key(seed["import"]),
        ))

    edges: list[dict[str, Any]] = []
    incoming: list[list[int]] = [[] for _ in behaviors]
    for source_index, behavior_pair in enumerate(behaviors):
        original_edges = _semantic_edges(behavior_pair["original_ir"])
        candidate_edges = _semantic_edges(behavior_pair["candidate_ir"])
        if len(original_edges) == len(candidate_edges):
            for original_edge, candidate_edge in zip(
                original_edges, candidate_edges, strict=True
            ):
                if (
                    int(original_edge["target"]) != int(candidate_edge["target"])
                    or str(original_edge["kind"]) != str(candidate_edge["kind"])
                ):
                    continue
                target_index = region_by_numeric_id.get(int(original_edge["target"]))
                if target_index is None:
                    continue
                if (
                    _semantic_constant_bool(original_edge["guard"]) is False
                    and _semantic_constant_bool(candidate_edge["guard"]) is False
                ):
                    continue
                edge = {
                    "source_region_index": source_index,
                    "target_region_index": target_index,
                    "kind": str(original_edge["kind"]),
                    "environment_barrier": bool(
                        original_edge.get("environment_barrier")
                        or candidate_edge.get("environment_barrier")
                    ),
                }
                incoming[target_index].append(len(edges))
                edges.append(edge)
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        if (
            original_outcome.get("op") == "indirect_call"
            and candidate_outcome.get("op") == "indirect_call"
            and int(original_outcome.get("continuation", -1))
                == int(candidate_outcome.get("continuation", -2))
        ):
            target_index = region_by_numeric_id.get(
                int(original_outcome["continuation"])
            )
            if target_index is not None:
                incoming[target_index].append(len(edges))
                edges.append({
                    "source_region_index": source_index,
                    "target_region_index": target_index,
                    "kind": "indirect_external_call_continuation",
                    "environment_barrier": True,
                })

    # Preserve the ordinary decoded predecessor graph separately.  A relation
    # can reach an internal callsite before it is known to be inductive across
    # a surrounding loop: the missing loop edge may itself depend on a
    # callsite-local preservation summary.  These base predecessors support
    # proposal discovery only.  Return and summary edges below remain required
    # to close the authoritative must-hold fixed point.
    base_incoming = [list(edge_indices) for edge_indices in incoming]

    existing_edges = {
        (
            int(edge["source_region_index"]),
            int(edge["target_region_index"]),
            str(edge["kind"]),
        )
        for edge in edges
    }
    callsite_summary_return_pairs: set[tuple[int, int]] = set()
    for predecessor in callsite_summary_predecessors or []:
        if not isinstance(predecessor, dict):
            continue
        target_index = predecessor.get("target_region_index")
        returns = predecessor.get("return_region_indices")
        if not (
            isinstance(target_index, int)
            and not isinstance(target_index, bool)
            and isinstance(returns, list)
            and predecessor.get("proposal_only") is True
            and isinstance(predecessor.get("certificate_id"), str)
            and isinstance(predecessor.get("certificate_hash"), str)
            and isinstance(predecessor.get("preserved_import_relations"), list)
            and predecessor.get("preserved_import_relations")
        ):
            continue
        callsite_summary_return_pairs.update(
            (return_index, target_index)
            for return_index in returns
            if isinstance(return_index, int) and not isinstance(return_index, bool)
        )
    accepted_return_predecessors = 0
    superseded_return_predecessors = 0
    for predecessor in internal_return_predecessors or []:
        source_index = int(predecessor.get("source_region_index", -1))
        target_index = int(predecessor.get("target_region_index", -1))
        key = (source_index, target_index, "internal_return")
        if (
            not 0 <= source_index < len(behaviors)
            or not 0 <= target_index < len(behaviors)
            or key in existing_edges
        ):
            continue
        edge = {
            "source_region_index": source_index,
            "target_region_index": target_index,
            "kind": "internal_return",
            "environment_barrier": False,
        }
        if (source_index, target_index) in callsite_summary_return_pairs:
            edge["superseded_by_callsite_summary"] = True
            superseded_return_predecessors += 1
        else:
            incoming[target_index].append(len(edges))
        edges.append(edge)
        existing_edges.add(key)
        accepted_return_predecessors += 1

    accepted_callsite_summary_predecessors = 0
    for predecessor in callsite_summary_predecessors or []:
        if not isinstance(predecessor, dict):
            continue
        source_value = predecessor.get("source_region_index")
        target_value = predecessor.get("target_region_index")
        if not (
            isinstance(source_value, int)
            and not isinstance(source_value, bool)
            and isinstance(target_value, int)
            and not isinstance(target_value, bool)
        ):
            continue
        source_index = int(source_value)
        target_index = int(target_value)
        key = (
            source_index, target_index,
            "internal_callsite_preservation_summary",
        )
        relations = predecessor.get("preserved_import_relations")
        if (
            not 0 <= source_index < len(behaviors)
            or not 0 <= target_index < len(behaviors)
            or key in existing_edges
            or not isinstance(relations, list)
            or not relations
            or not isinstance(predecessor.get("certificate_id"), str)
            or not isinstance(predecessor.get("certificate_hash"), str)
            or predecessor.get("proposal_only") is not True
        ):
            continue
        allowed_relations: set[
            tuple[str, str, tuple[str, str, str | int]]
        ] = set()
        try:
            for relation in relations:
                imported = identity_key(relation["import"])
                if imported not in identities:
                    raise ValueError
                allowed_relations.add((
                    str(relation["original"]),
                    str(relation["candidate"]),
                    imported,
                ))
        except (KeyError, TypeError, ValueError):
            continue
        incoming[target_index].append(len(edges))
        edges.append({
            "source_region_index": source_index,
            "target_region_index": target_index,
            "kind": "internal_callsite_preservation_summary",
            "environment_barrier": False,
            "proposal_only": True,
            "certificate_id": predecessor["certificate_id"],
            "certificate_hash": predecessor["certificate_hash"],
            "preserved_import_relation_keys": sorted(allowed_relations),
        })
        existing_edges.add(key)
        accepted_callsite_summary_predecessors += 1

    accepted_returning_external_thunk_predecessors = 0
    for predecessor in returning_external_thunk_predecessors or []:
        if not isinstance(predecessor, dict):
            continue
        source_value = predecessor.get("source_region_index")
        target_value = predecessor.get("target_region_index")
        contract_id = predecessor.get("machine_contract_id")
        preserved = predecessor.get("preserved_registers")
        if not (
            isinstance(source_value, int)
            and not isinstance(source_value, bool)
            and isinstance(target_value, int)
            and not isinstance(target_value, bool)
            and isinstance(contract_id, int)
            and not isinstance(contract_id, bool)
            and isinstance(preserved, list)
            and all(
                isinstance(register, str) and register in _X86_GENERAL_REGISTERS
                for register in preserved
            )
            and predecessor.get("proposal_only") is True
        ):
            continue
        source_index = int(source_value)
        target_index = int(target_value)
        key = (source_index, target_index, "returning_external_thunk")
        if (
            not 0 <= source_index < len(behaviors)
            or not 0 <= target_index < len(behaviors)
            or key in existing_edges
        ):
            continue
        incoming[target_index].append(len(edges))
        edges.append({
            "source_region_index": source_index,
            "target_region_index": target_index,
            "kind": "returning_external_thunk",
            "environment_barrier": True,
            "proposal_only": True,
            "machine_contract_id": int(contract_id),
            "preserved_registers": sorted(set(preserved)),
        })
        existing_edges.add(key)
        accepted_returning_external_thunk_predecessors += 1

    def transferred_source_fact(
        edge: dict[str, Any],
        target_fact: tuple[str, str, tuple[str, str, str | int]],
    ) -> tuple[str, str, tuple[str, str, str | int]] | None:
        source_index = int(edge["source_region_index"])
        original_register, candidate_register, imported = target_fact
        if (
            edge["kind"] == "internal_callsite_preservation_summary"
            and target_fact not in set(edge["preserved_import_relation_keys"])
        ):
            return None
        if edge["kind"] == "returning_external_thunk":
            preserved_registers = set(edge["preserved_registers"])
            if (
                original_register not in preserved_registers
                or candidate_register not in preserved_registers
            ):
                return None
        original_expression = (
            behaviors[source_index]["original_ir"].get("registers") or {}
        ).get(original_register) or {}
        candidate_expression = (
            behaviors[source_index]["candidate_ir"].get("registers") or {}
        ).get(candidate_register) or {}
        if (
            original_expression.get("op") != "input_reg"
            or candidate_expression.get("op") != "input_reg"
        ):
            return None
        if edge["environment_barrier"] and (
            original_register not in nonvolatile
            or candidate_register not in nonvolatile
        ):
            return None
        return (
            str(original_expression["reg"]),
            str(candidate_expression["reg"]),
            imported,
        )

    def edge_supports(
        edge: dict[str, Any],
        target_fact: tuple[str, str, tuple[str, str, str | int]],
        facts: set[tuple[int, str, str, tuple[str, str, str | int]]],
    ) -> bool:
        source_index = int(edge["source_region_index"])
        if target_fact in seed_facts.get(source_index, set()):
            return True
        source_fact = transferred_source_fact(edge, target_fact)
        return source_fact is not None and (source_index, *source_fact) in facts

    def grow_facts(
        predecessor_inventory: list[list[int]],
    ) -> set[tuple[int, str, str, tuple[str, str, str | int]]]:
        result: set[
            tuple[int, str, str, tuple[str, str, str | int]]
        ] = set()
        changed = True
        while changed:
            changed = False
            for target_index, edge_indices in enumerate(predecessor_inventory):
                for edge_index in edge_indices:
                    source_index = int(
                        edges[edge_index]["source_region_index"]
                    )
                    target_facts = set(seed_facts.get(source_index, set()))
                    original_outputs = (
                        behaviors[source_index]["original_ir"].get(
                            "registers"
                        ) or {}
                    )
                    candidate_outputs = (
                        behaviors[source_index]["candidate_ir"].get(
                            "registers"
                        ) or {}
                    )
                    source_facts = [
                        (
                            original_register,
                            candidate_register,
                            imported,
                        )
                        for (
                            region_index,
                            original_register,
                            candidate_register,
                            imported,
                        ) in result
                        if region_index == source_index
                    ]
                    for source_fact in source_facts:
                        imported = source_fact[2]
                        for original_target in original_outputs:
                            for candidate_target in candidate_outputs:
                                target_fact = (
                                    str(original_target),
                                    str(candidate_target),
                                    imported,
                                )
                                if transferred_source_fact(
                                    edges[edge_index], target_fact
                                ) == source_fact:
                                    target_facts.add(target_fact)
                    for target_fact in target_facts:
                        fact = (target_index, *target_fact)
                        if fact not in result and edge_supports(
                            edges[edge_index], target_fact, result
                        ):
                            result.add(fact)
                            changed = True
        return result

    callsite_candidate_facts = grow_facts(base_incoming)
    facts = grow_facts(incoming)

    changed = True
    while changed:
        changed = False
        for fact in list(facts):
            target_index, original_register, candidate_register, imported = fact
            edge_indices = incoming[target_index]
            target_fact = (original_register, candidate_register, imported)
            if not edge_indices or not all(
                edge_supports(edges[edge_index], target_fact, facts)
                for edge_index in edge_indices
            ):
                facts.remove(fact)
                changed = True

    relation_rows = []
    for region_index, original_register, candidate_register, imported in sorted(facts):
        relation_rows.append({
            "region_index": region_index,
            "original_register": original_register,
            "candidate_register": candidate_register,
            "import": identities[imported],
            "incoming_edge_indices": incoming[region_index],
            "incoming_edges": [edges[index] for index in incoming[region_index]],
        })

    internal_callsites = {
        region_index
        for region_index, behavior_pair in enumerate(behaviors)
        if (
            (behavior_pair["original_ir"].get("outcome") or {}).get("op")
                == "call"
            and
            (behavior_pair["candidate_ir"].get("outcome") or {}).get("op")
                == "call"
        )
    }
    callsite_candidate_rows = [
        {
            "region_index": region_index,
            "original_register": original_register,
            "candidate_register": candidate_register,
            "import": identities[imported],
            "status": "proposal_requires_strict_fixed_point_and_lean_replay",
        }
        for region_index, original_register, candidate_register, imported
        in sorted(callsite_candidate_facts)
        if region_index in internal_callsites
    ]

    call_rows = []
    facts_by_region: dict[int, list[dict[str, Any]]] = {}
    for row in relation_rows:
        facts_by_region.setdefault(int(row["region_index"]), []).append(row)
    for source_index, behavior_pair in enumerate(behaviors):
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        original_target = original_outcome.get("target") or {}
        candidate_target = candidate_outcome.get("target") or {}
        if (
            original_outcome.get("op") != "indirect_call"
            or candidate_outcome.get("op") != "indirect_call"
            or original_target.get("op") != "input_reg"
            or candidate_target.get("op") != "input_reg"
        ):
            continue
        matches = [
            row for row in facts_by_region.get(source_index, [])
            if row["original_register"] == original_target.get("reg")
            and row["candidate_register"] == candidate_target.get("reg")
        ]
        if len(matches) != 1:
            continue
        continuation = int(original_outcome.get("continuation", -1))
        if continuation != int(candidate_outcome.get("continuation", -2)):
            continue
        continuation_index = region_by_numeric_id.get(continuation)
        if continuation_index is None:
            continue
        call_rows.append({
            "profile": "inductive_iat_register_call_v1",
            "source_region_index": source_index,
            "continuation_region_index": continuation_index,
            "original_register": str(original_target["reg"]),
            "candidate_register": str(candidate_target["reg"]),
            "import": matches[0]["import"],
        })

    # A region may load an IAT entry and dispatch through that value before the
    # next cutpoint.  Such a call does not require an inductive entry relation:
    # the existing import-register seed certificate proves the output value
    # directly from the loader-populated IAT word.  Keep this proposal exact and
    # unambiguous; Lean independently replays the seed and call-target equality.
    call_sources = {int(row["source_region_index"]) for row in call_rows}
    seeds_by_region: dict[int, list[dict[str, Any]]] = {}
    for seed in seeds:
        seeds_by_region.setdefault(int(seed["region_index"]), []).append(seed)
    for source_index, behavior_pair in enumerate(behaviors):
        if source_index in call_sources:
            continue
        original_behavior = behavior_pair["original_ir"]
        candidate_behavior = behavior_pair["candidate_ir"]
        original_outcome = original_behavior.get("outcome") or {}
        candidate_outcome = candidate_behavior.get("outcome") or {}
        if (
            original_outcome.get("op") != "indirect_call"
            or candidate_outcome.get("op") != "indirect_call"
        ):
            continue
        continuation = int(original_outcome.get("continuation", -1))
        if continuation != int(candidate_outcome.get("continuation", -2)):
            continue
        continuation_index = region_by_numeric_id.get(continuation)
        if continuation_index is None:
            continue
        original_registers = original_behavior.get("registers") or {}
        candidate_registers = candidate_behavior.get("registers") or {}
        matches = [
            seed for seed in seeds_by_region.get(source_index, [])
            if original_outcome.get("target")
                == original_registers.get(str(seed["original_register"]))
            and candidate_outcome.get("target")
                == candidate_registers.get(str(seed["candidate_register"]))
        ]
        if len(matches) != 1:
            continue
        seed = matches[0]
        call_rows.append({
            "profile": "seeded_iat_register_call_v1",
            "source_region_index": source_index,
            "continuation_region_index": continuation_index,
            "original_register": str(seed["original_register"]),
            "candidate_register": str(seed["candidate_register"]),
            "import": seed["import"],
            "seed": json.loads(json.dumps(seed)),
        })

    call_rows.sort(key=lambda row: (
        int(row["source_region_index"]),
        int(row["continuation_region_index"]),
        str(row["profile"]),
    ))

    return {
        "format": "stage-a-relational-import-register-invariants-v1",
        "status": "proposal_requires_edge_and_scc_lean_replay",
        "abi_profile": "pe32-win32-nonvolatile-registers-v1",
        "nonvolatile_registers": sorted(nonvolatile),
        "relations": relation_rows,
        "callsite_candidate_relations": callsite_candidate_rows,
        "indirect_import_calls": call_rows,
        "counts": {
            "seeds": len(seeds),
            "relations": len(relation_rows),
            "callsite_candidate_relations": len(callsite_candidate_rows),
            "indirect_import_calls": len(call_rows),
            "internal_return_predecessors": accepted_return_predecessors,
            "superseded_internal_return_predecessors": (
                superseded_return_predecessors
            ),
            "callsite_summary_predecessors": (
                accepted_callsite_summary_predecessors
            ),
            "returning_external_thunk_predecessors": (
                accepted_returning_external_thunk_predecessors
            ),
        },
    }


def _closed_internal_return_predecessors(
    register_relations: dict[str, Any],
) -> list[dict[str, int]]:
    summaries = (
        register_relations.get("return_slot_analysis", {})
        .get("call_summary_analysis", {})
        .get("summaries", [])
    )
    result: set[tuple[int, int]] = set()
    for summary in summaries:
        if not summary.get("closed"):
            continue
        continuation = int(summary.get("continuation_region_index", -1))
        for return_index in summary.get("return_region_indices", []):
            result.add((int(return_index), continuation))
    return [
        {
            "source_region_index": source_index,
            "target_region_index": target_index,
        }
        for source_index, target_index in sorted(result)
    ]


def _returning_external_thunk_predecessors(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    register_relations: dict[str, Any],
) -> list[dict[str, Any]]:
    """Propose caller-specific successors for checked returning import thunks.

    The edge is intentionally not treated as an ordinary decoded predecessor.
    Its import facts are carried by the active runtime frame and must be replayed
    through the exact machine contract by Lean before acceptance.
    """
    region_by_numeric_id = {
        int(region["numeric_id"]): index
        for index, region in enumerate(contract.get("regions", []))
    }
    contracts_by_id = {
        int(item["id"]): item
        for item in contract.get("machine_import_call_contracts", [])
        if isinstance(item, dict)
        and isinstance(item.get("id"), int)
        and not isinstance(item.get("id"), bool)
    }
    rows: dict[tuple[int, int, int], dict[str, Any]] = {}
    for edge in register_relations.get("edges", []):
        if not isinstance(edge, dict) or edge.get("kind") != "call":
            continue
        contract_id = edge.get("returning_external_thunk_contract_id")
        source_value = edge.get("source_region_index")
        if not (
            isinstance(contract_id, int)
            and not isinstance(contract_id, bool)
            and isinstance(source_value, int)
            and not isinstance(source_value, bool)
            and 0 <= int(source_value) < len(behaviors)
        ):
            continue
        machine_contract = contracts_by_id.get(int(contract_id))
        if machine_contract is None or machine_contract.get("disposition") != "returns":
            continue
        source_index = int(source_value)
        original_outcome = behaviors[source_index].get("original_ir", {}).get(
            "outcome"
        ) or {}
        candidate_outcome = behaviors[source_index].get("candidate_ir", {}).get(
            "outcome"
        ) or {}
        continuation = original_outcome.get("continuation")
        if (
            original_outcome.get("op") != "call"
            or candidate_outcome.get("op") != "call"
            or continuation != candidate_outcome.get("continuation")
            or not isinstance(continuation, int)
            or isinstance(continuation, bool)
        ):
            continue
        target_index = region_by_numeric_id.get(int(continuation))
        if target_index is None:
            continue
        key = (source_index, target_index, int(contract_id))
        rows[key] = {
            "source_region_index": source_index,
            "target_region_index": target_index,
            "machine_contract_id": int(contract_id),
            "preserved_registers": sorted({
                str(register)
                for register in machine_contract.get("preserved_registers", [])
                if str(register) in _X86_GENERAL_REGISTERS
            }),
            "proposal_only": True,
        }
    return [rows[key] for key in sorted(rows)]

def _attach_import_register_invariants(
    contract: dict[str, Any], analysis: dict[str, Any],
) -> dict[str, Any]:
    refined = json.loads(json.dumps(contract))
    relations_by_region: dict[int, list[dict[str, Any]]] = {}
    for relation in analysis.get("relations", []):
        relations_by_region.setdefault(int(relation["region_index"]), []).append({
            "original": str(relation["original_register"]),
            "candidate": str(relation["candidate_register"]),
            "import": relation["import"],
        })
    for region_index, region in enumerate(refined.get("regions", [])):
        region["input_import_relations"] = sorted(
            relations_by_region.get(region_index, []),
            key=lambda item: (
                item["original"], item["candidate"],
                json.dumps(item["import"], sort_keys=True),
            ),
        )
        region["output_import_relations"] = []
    return refined


def _indirect_fixed_code_pointer_register_calls(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    relation_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Propose register-indirect calls justified by a fixed target invariant.

    This inventory is diagnostic/proof-input data only. Product-graph creation
    must replay the relation and decoded outcomes independently before adding
    any control edge.
    """
    regions = contract.get("regions", [])
    code_targets = contract.get("code_targets", [])
    region_by_numeric_id = {
        int(region["numeric_id"]): region_index
        for region_index, region in enumerate(regions)
        if isinstance(region, dict)
        and isinstance(region.get("numeric_id"), int)
        and not isinstance(region.get("numeric_id"), bool)
    }
    target_ids_by_region_index: dict[int, list[int]] = {}
    for target_id, target in enumerate(code_targets):
        if not (
            isinstance(target, dict)
            and target.get("id") == target_id
            and isinstance(target.get("region_index"), int)
            and not isinstance(target.get("region_index"), bool)
        ):
            continue
        target_ids_by_region_index.setdefault(
            int(target["region_index"]), []
        ).append(target_id)
    result: list[dict[str, Any]] = []
    for source_index, (behavior_pair, relation_row) in enumerate(zip(
        behaviors, relation_rows, strict=True,
    )):
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        original_target = original_outcome.get("target") or {}
        candidate_target = candidate_outcome.get("target") or {}
        original_continuation = original_outcome.get("continuation")
        candidate_continuation = candidate_outcome.get("continuation")
        if not (
            original_outcome.get("op") == "indirect_call"
            and candidate_outcome.get("op") == "indirect_call"
            and isinstance(original_target, dict)
            and isinstance(candidate_target, dict)
            and original_target.get("op") == "input_reg"
            and candidate_target.get("op") == "input_reg"
            and isinstance(original_continuation, int)
            and not isinstance(original_continuation, bool)
            and original_continuation == candidate_continuation
        ):
            continue
        continuation_index = region_by_numeric_id.get(original_continuation)
        if continuation_index is None:
            continue
        continuation_target_ids = target_ids_by_region_index.get(
            continuation_index, []
        )
        if len(continuation_target_ids) != 1:
            continue
        continuation_target_id = continuation_target_ids[0]
        original_register = str(original_target.get("reg"))
        candidate_register = str(candidate_target.get("reg"))
        matches = [
            relation
            for relation in relation_row.get("inputs", [])
            if relation.get("original") == original_register
            and relation.get("candidate") == candidate_register
            and relation.get("relation") == "fixed_code_pointer"
            and isinstance(relation.get("target_id"), int)
            and not isinstance(relation.get("target_id"), bool)
        ]
        if len(matches) != 1:
            continue
        target_id = int(matches[0]["target_id"])
        if not (
            isinstance(code_targets, list)
            and 0 <= target_id < len(code_targets)
            and isinstance(code_targets[target_id], dict)
            and code_targets[target_id].get("id") == target_id
        ):
            continue
        target = code_targets[target_id]
        mapped_region_index = target.get("region_index")
        if "region_index" in target:
            if not (
                isinstance(mapped_region_index, int)
                and not isinstance(mapped_region_index, bool)
                and 0 <= mapped_region_index < len(regions)
            ):
                continue
            target_region_index = int(mapped_region_index)
        else:
            target_region_index = region_by_numeric_id.get(target_id)
        if target_region_index is None:
            continue
        result.append({
            "profile": "inductive_fixed_code_pointer_register_call_v1",
            "source_region_index": source_index,
            "target_region_index": target_region_index,
            "continuation_region_index": continuation_index,
            "continuation_target_id": continuation_target_id,
            "target_id": target_id,
            "original_register": original_register,
            "candidate_register": candidate_register,
        })
    return sorted(
        result,
        key=lambda row: (
            row["source_region_index"], row["target_id"],
            row["continuation_region_index"], row["original_register"],
            row["candidate_register"],
        ),
    )


def _bounded_register_code_pointer_provenance(
    *,
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    relation_rows: list[dict[str, Any]],
    predecessors: list[list[tuple[Any, ...]]],
    register_order: tuple[str, ...],
    input_pair_candidates: list[dict[str, str]],
    output_pair_candidates: list[dict[str, str]],
    output_reasons: list[dict[str, str]],
    launch_root_region_indices: set[int],
    protocol_callback_region_indices: set[int],
    conservative_entry_regions: set[int],
    stack_window_input_pairs: list[set[tuple[str, str]]],
    original_image_base: int,
    candidate_image_base: int,
    disjunction_budget: int,
) -> dict[str, Any]:
    """Track finite register-held code targets without granting authority.

    This side lattice deliberately does not alter the semantic register
    relations consumed by Lean. It records only unambiguous fixed-target
    producers, exact register copies, and graph-edge preservation. Any unknown
    contribution dominates a join, and an over-budget union is discarded.
    """
    if (
        not isinstance(disjunction_budget, int)
        or isinstance(disjunction_budget, bool)
        or disjunction_budget <= 0
    ):
        raise ValueError("register code-pointer disjunction budget must be positive")

    region_count = len(relation_rows)
    unknown: RegisterRelation = "related_word"
    producer_reasons = frozenset({
        "paired_constant",
        "static_word_slot",
        "immutable_image_word",
        "assembled_immutable_image_word",
        "fixed_immutable_expression",
    })
    overflow_locations: set[tuple[str, int, str]] = set()

    def joined(
        relations: list[RegisterRelation],
        *,
        direction: str,
        region_index: int,
        register: str,
    ) -> RegisterRelation:
        provenance = [
            _register_code_pointer_provenance_payload(relation)
            for relation in relations
        ]
        if provenance and all(payload is not None for payload in provenance):
            target_ids = {
                int(alternative["target_id"])
                for payload in provenance
                if payload is not None
                for alternative in payload["target_alternatives"]
            }
            if len(target_ids) > disjunction_budget:
                overflow_locations.add((direction, region_index, register))
        return _register_relation_join(
            relations,
            finite_code_pointer_budget=disjunction_budget,
        )

    output_relations_by_register = [
        {
            str(relation["original"]): relation
            for relation in row.get("outputs", [])
            if isinstance(relation, dict)
        }
        for row in relation_rows
    ]
    output_claims_by_register = []
    for row in relation_rows:
        claims: dict[str, list[dict[str, Any]]] = {}
        for claim in row.get("output_claims", []):
            if not isinstance(claim, dict):
                continue
            output = claim.get("output")
            if not isinstance(output, dict):
                continue
            original_register = output.get("original")
            if isinstance(original_register, str):
                claims.setdefault(original_register, []).append(claim)
        output_claims_by_register.append(claims)

    def transfer_output(
        region_index: int,
        register: str,
        input_state: dict[str, RegisterRelation],
    ) -> RegisterRelation:
        original_registers = behaviors[region_index]["original_ir"]["registers"]
        candidate_registers = behaviors[region_index]["candidate_ir"]["registers"]
        candidate_register = output_pair_candidates[region_index].get(register)
        if (
            register not in original_registers
            or candidate_register is None
            or candidate_register not in candidate_registers
        ):
            return unknown
        original_expression = original_registers[register]
        candidate_expression = candidate_registers[candidate_register]
        if (
            isinstance(original_expression, dict)
            and isinstance(candidate_expression, dict)
            and original_expression.get("op") == "input_reg"
            and candidate_expression.get("op") == "input_reg"
        ):
            source_register = str(original_expression.get("reg"))
            expected_candidate = input_pair_candidates[region_index].get(
                source_register, source_register,
            )
            if str(candidate_expression.get("reg")) == expected_candidate:
                return input_state.get(source_register, unknown)

        semantic_relation = output_relations_by_register[region_index].get(register)
        reason = output_reasons[region_index].get(register, "")
        target_id = (
            semantic_relation.get("target_id")
            if isinstance(semantic_relation, dict)
            and semantic_relation.get("relation") == "fixed_code_pointer"
            else None
        )
        if target_id is None and reason in producer_reasons:
            claim_targets = []
            for claim in output_claims_by_register[region_index].get(register, []):
                output = claim.get("output")
                original_value = claim.get("original_value")
                candidate_value = claim.get("candidate_value")
                if not (
                    isinstance(output, dict)
                    and output.get("candidate") == candidate_register
                    and isinstance(original_value, int)
                    and not isinstance(original_value, bool)
                    and isinstance(candidate_value, int)
                    and not isinstance(candidate_value, bool)
                ):
                    continue
                claim_target = _paired_code_target_id(
                    original_value,
                    candidate_value,
                    contract,
                    original_image_base,
                    candidate_image_base,
                )
                if claim_target is not None:
                    claim_targets.append(claim_target)
            unique_claim_targets = sorted(set(claim_targets))
            target_id = (
                unique_claim_targets[0]
                if len(unique_claim_targets) == 1 else None
            )
        if (
            reason not in producer_reasons
            or not isinstance(target_id, int)
            or isinstance(target_id, bool)
            or target_id < 0
        ):
            return unknown
        return _register_code_pointer_producer_relation(
            target_id=target_id,
            region_id=str(relation_rows[region_index]["region_id"]),
            region_index=region_index,
            claim_kind=reason,
            original_register=register,
            candidate_register=candidate_register,
        )

    seed_regions = (
        launch_root_region_indices
        | protocol_callback_region_indices
        | conservative_entry_regions
    )
    input_states: list[dict[str, RegisterRelation] | None] = [
        ({register: unknown for register in register_order}
         if region_index in seed_regions else None)
        for region_index in range(region_count)
    ]
    output_states: list[dict[str, RegisterRelation] | None] = [
        None for _ in range(region_count)
    ]
    output_reason_states: list[dict[str, str] | None] = [
        None for _ in range(region_count)
    ]
    successors: list[set[int]] = [set() for _ in range(region_count)]
    for target_index, incoming in enumerate(predecessors):
        for source_index, _barrier, _kind, _preserved, _results in incoming:
            successors[int(source_index)].add(target_index)

    def evaluate_output(
        region_index: int,
        input_state: dict[str, RegisterRelation],
        previous_output: dict[str, RegisterRelation] | None,
    ) -> tuple[dict[str, RegisterRelation], dict[str, str]]:
        proposed = {
            register: transfer_output(region_index, register, input_state)
            for register in register_order
        }
        reasons = {
            register: (
                "finite_code_pointer"
                if _register_code_pointer_provenance_payload(relation) is not None
                else "unknown_or_clobbered"
            )
            for register, relation in proposed.items()
        }
        if previous_output is None:
            return proposed, reasons
        stable = {
            register: joined(
                [previous_output[register], proposed[register]],
                direction="output",
                region_index=region_index,
                register=register,
            )
            for register in register_order
        }
        return stable, reasons

    def recompute_input(
        region_index: int,
        next_outputs: list[dict[str, RegisterRelation] | None]
        | tuple[dict[str, RegisterRelation] | None, ...],
    ) -> dict[str, RegisterRelation] | None:
        result: dict[str, RegisterRelation] = {}
        any_candidates = False
        for register in register_order:
            candidates: list[RegisterRelation] = []
            if region_index in seed_regions:
                candidates.append(unknown)
            for source_index, barrier, kind, preserved, edge_results in (
                predecessors[region_index]
            ):
                source_output = next_outputs[int(source_index)]
                if source_output is None:
                    continue
                any_candidates = True
                if kind == "internal_callsite_preservation_summary":
                    result_relation = edge_results.get(register)
                    source_targets = _register_code_pointer_provenance_payload(
                        source_output[register]
                    )
                    result_target = (
                        _register_relation_payload(result_relation).get("target_id")
                        if result_relation is not None else None
                    )
                    contribution = (
                        source_output[register]
                        if register in preserved
                        and source_targets is not None
                        and {
                            alternative["target_id"]
                            for alternative in source_targets["target_alternatives"]
                        } == {result_target}
                        else unknown
                    )
                elif not barrier:
                    contribution = source_output[register]
                elif register in edge_results:
                    contribution = unknown
                elif register in preserved:
                    contribution = source_output[register]
                else:
                    contribution = unknown
                candidates.append(contribution)
            if not candidates:
                continue
            any_candidates = True
            result[register] = joined(
                candidates,
                direction="input",
                region_index=region_index,
                register=register,
            )
            candidate_register = input_pair_candidates[region_index].get(register)
            if (
                candidate_register is not None
                and (register, candidate_register)
                    in stack_window_input_pairs[region_index]
            ):
                result[register] = unknown
        if not any_candidates:
            return None
        if len(result) != len(register_order):
            raise AssertionError("reachable code-pointer provenance state is incomplete")
        return result

    fixed_point = solve_monotone_fixed_point_by_scc(
        initial_input_states=input_states,
        initial_output_states=output_states,
        initial_output_reason_states=output_reason_states,
        successors=[tuple(sorted(items)) for items in successors],
        evaluate_output=evaluate_output,
        recompute_input=recompute_input,
        max_iterations=max(
            1, region_count * len(register_order) * (disjunction_budget + 1) + 1,
        ),
    )

    def relation_rows_for_state(
        region_index: int,
        state: dict[str, RegisterRelation] | None,
        pairs: dict[str, str],
    ) -> list[dict[str, Any]]:
        if state is None:
            return []
        rows = []
        for register in register_order:
            payload = _register_code_pointer_provenance_payload(state[register])
            candidate_register = pairs.get(register)
            if payload is None or candidate_register is None:
                continue
            rows.append({
                "original": register,
                "candidate": candidate_register,
                **payload,
            })
        return rows

    provenance_regions = []
    for region_index in range(region_count):
        inputs = relation_rows_for_state(
            region_index,
            fixed_point.input_states[region_index],
            input_pair_candidates[region_index],
        )
        outputs = relation_rows_for_state(
            region_index,
            fixed_point.output_states[region_index],
            output_pair_candidates[region_index],
        )
        if inputs or outputs:
            provenance_regions.append({
                "region_id": str(relation_rows[region_index]["region_id"]),
                "region_index": region_index,
                "inputs": inputs,
                "outputs": outputs,
            })

    regions = contract.get("regions", [])
    code_targets = contract.get("code_targets", [])
    region_by_numeric_id = {
        int(region["numeric_id"]): region_index
        for region_index, region in enumerate(regions)
        if isinstance(region, dict)
        and isinstance(region.get("numeric_id"), int)
        and not isinstance(region.get("numeric_id"), bool)
    }
    target_ids_by_region_index: dict[int, list[int]] = {}
    for target_id, target in enumerate(code_targets):
        if not (
            isinstance(target, dict)
            and target.get("id") == target_id
        ):
            continue
        mapped = target.get("region_index")
        target_region = (
            int(mapped)
            if isinstance(mapped, int)
            and not isinstance(mapped, bool)
            and 0 <= mapped < region_count
            else region_by_numeric_id.get(target_id)
        )
        if target_region is not None:
            target_ids_by_region_index.setdefault(target_region, []).append(target_id)

    controls = []
    incomplete_controls = []
    for source_index, behavior_pair in enumerate(behaviors):
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        operation = original_outcome.get("op")
        original_target = original_outcome.get("target") or {}
        candidate_target = candidate_outcome.get("target") or {}
        if not (
            operation in {"indirect_call", "indirect_jump"}
            and candidate_outcome.get("op") == operation
            and isinstance(original_target, dict)
            and isinstance(candidate_target, dict)
            and original_target.get("op") == "input_reg"
            and candidate_target.get("op") == "input_reg"
        ):
            continue
        original_register = str(original_target.get("reg"))
        candidate_register = str(candidate_target.get("reg"))
        expected_candidate = input_pair_candidates[source_index].get(
            original_register
        )
        state = fixed_point.input_states[source_index]
        payload = (
            _register_code_pointer_provenance_payload(
                state.get(original_register, unknown)
            )
            if state is not None else None
        )
        blocker = None
        if candidate_register != expected_candidate:
            blocker = "ambiguous_register_pair"
        elif ("input", source_index, original_register) in overflow_locations:
            blocker = "finite_disjunction_budget_overflow"
        elif payload is None:
            blocker = "unknown_or_clobbered_provenance"

        target_alternatives = []
        if blocker is None and payload is not None:
            for alternative in payload["target_alternatives"]:
                target_id = int(alternative["target_id"])
                target = (
                    code_targets[target_id]
                    if isinstance(code_targets, list)
                    and 0 <= target_id < len(code_targets)
                    and isinstance(code_targets[target_id], dict)
                    and code_targets[target_id].get("id") == target_id
                    else None
                )
                mapped = target.get("region_index") if target is not None else None
                target_region_index = (
                    int(mapped)
                    if isinstance(mapped, int)
                    and not isinstance(mapped, bool)
                    and 0 <= mapped < region_count
                    else region_by_numeric_id.get(target_id)
                )
                if target_region_index is None:
                    blocker = "canonical_target_region_missing"
                    target_alternatives = []
                    break
                target_alternatives.append({
                    "target_id": target_id,
                    "target_region_index": target_region_index,
                    "producer_witnesses": alternative["producer_witnesses"],
                })

        continuation = {}
        if blocker is None and operation == "indirect_call":
            original_continuation = original_outcome.get("continuation")
            candidate_continuation = candidate_outcome.get("continuation")
            continuation_region_index = (
                region_by_numeric_id.get(original_continuation)
                if isinstance(original_continuation, int)
                and not isinstance(original_continuation, bool)
                and original_continuation == candidate_continuation
                else None
            )
            continuation_target_ids = target_ids_by_region_index.get(
                continuation_region_index, []
            ) if continuation_region_index is not None else []
            if len(continuation_target_ids) != 1:
                blocker = "canonical_continuation_missing_or_ambiguous"
            else:
                continuation = {
                    "continuation_region_index": continuation_region_index,
                    "continuation_target_id": continuation_target_ids[0],
                }

        common = {
            "source_region_index": source_index,
            "operation": operation,
            "original_register": original_register,
            "candidate_register": candidate_register,
        }
        if blocker is not None:
            incomplete_controls.append({**common, "blocker": blocker})
            continue
        controls.append({
            "profile": "inductive_finite_code_pointer_register_control_v1",
            **common,
            **continuation,
            "target_alternatives": target_alternatives,
        })

    finite_inputs = sum(len(region["inputs"]) for region in provenance_regions)
    finite_outputs = sum(len(region["outputs"]) for region in provenance_regions)
    multi_target_inputs = sum(
        len(relation["target_alternatives"]) > 1
        for region in provenance_regions for relation in region["inputs"]
    )
    multi_target_outputs = sum(
        len(relation["target_alternatives"]) > 1
        for region in provenance_regions for relation in region["outputs"]
    )
    return {
        "profile": "bounded_register_code_pointer_provenance_v1",
        "status": (
            "proposal_requires_generated_lean_replay"
            if fixed_point.converged else "incomplete"
        ),
        "acceptance_authority": False,
        "finite_disjunction_budget": disjunction_budget,
        "converged": fixed_point.converged,
        "iterations": fixed_point.iterations,
        "overflow_locations": [
            {"direction": direction, "region_index": region_index,
             "register": register}
            for direction, region_index, register in sorted(overflow_locations)
        ],
        "controls": controls,
        "incomplete_controls": incomplete_controls,
        "counts": {
            "regions_with_provenance": len(provenance_regions),
            "finite_input_relations": finite_inputs,
            "finite_output_relations": finite_outputs,
            "multi_target_input_relations": multi_target_inputs,
            "multi_target_output_relations": multi_target_outputs,
            "indirect_controls": len(controls),
            "indirect_calls": sum(
                control["operation"] == "indirect_call" for control in controls
            ),
            "indirect_jumps": sum(
                control["operation"] == "indirect_jump" for control in controls
            ),
            "multi_target_indirect_controls": sum(
                len(control["target_alternatives"]) > 1 for control in controls
            ),
            "incomplete_indirect_controls": len(incomplete_controls),
            "overflow_locations": len(overflow_locations),
        },
        "regions": provenance_regions,
    }


def _register_transfer_propagation(
    *,
    regions: list[dict[str, Any]],
    predecessors: list[
        list[
            tuple[
                int, bool, str, frozenset[str],
                dict[str, RegisterRelation],
            ]
        ]
    ],
    register_order: tuple[str, ...],
    launch_root_region_indices: set[int],
    protocol_callback_region_indices: set[int],
    conservative_entry_regions: set[int],
    input_pair_candidates: list[dict[str, str]],
    stack_window_input_pairs: list[set[tuple[str, str]]],
) -> dict[str, Any]:
    propagation_edges = {
        json.dumps(edge, sort_keys=True, separators=(",", ":")): edge
        for target_index, incoming in enumerate(predecessors)
        for source_index, barrier, kind, preserved, results in incoming
        for edge in [{
            "source_id": str(regions[source_index]["id"]),
            "target_id": str(regions[target_index]["id"]),
            "environment_barrier": bool(barrier),
            "kind": str(kind),
            "preserved_registers": sorted(preserved),
            "result_relations": [
                {
                    "register": register,
                    **_register_relation_payload(results[register]),
                }
                for register in register_order
                if register in results
            ],
        }]
    }
    return {
        "regions": [
            {
                "id": str(region["id"]),
                "seed_relation": (
                    _register_relation_join([
                        *(
                            ["exact"]
                            if region_index in launch_root_region_indices
                            else []
                        ),
                        *(
                            ["related_word"]
                            if region_index in protocol_callback_region_indices
                            or region_index in conservative_entry_regions
                            else []
                        ),
                    ])
                    if region_index in launch_root_region_indices
                    or region_index in protocol_callback_region_indices
                    or region_index in conservative_entry_regions
                    else None
                ),
                "stack_window_registers": sorted(
                    register
                    for register in register_order
                    if (
                        input_pair_candidates[region_index].get(register)
                        is not None
                        and (
                            register,
                            input_pair_candidates[region_index][register],
                        ) in stack_window_input_pairs[region_index]
                    )
                ),
            }
            for region_index, region in enumerate(regions)
        ],
        "edges": sorted(
            propagation_edges.values(),
            key=lambda edge: (
                edge["target_id"],
                edge["source_id"],
                edge["kind"],
                json.dumps(edge, sort_keys=True, separators=(",", ":")),
            ),
        ),
    }


def _synthesize_register_relations(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    *,
    original_image_base: int,
    candidate_image_base: int,
    indirect_call_candidates: list[dict[str, Any]] | None = None,
    import_call_candidates: list[dict[str, Any]] | None = None,
    callsite_summary_predecessors: list[dict[str, Any]] | None = None,
    original_bin: StageABinary | None = None,
    candidate_bin: StageABinary | None = None,
    _solver_metrics: dict[str, int] | None = None,
    _transfer_cache: dict[
        str, tuple[dict[str, RegisterRelation], dict[str, str]]
    ] | None = None,
    _transfer_table_out: dict[str, Any] | None = None,
    _transfer_programs_out: dict[str, Any] | None = None,
    _transfer_program_cache: dict[str, tuple[dict[str, Any], list[dict[str, Any]]]]
    | None = None,
    _dataflow_aggregate: dict[str, Any] | None = None,
    _compiled_problem_out: dict[str, Any] | None = None,
    code_pointer_disjunction_budget: int = (
        _REGISTER_CODE_POINTER_DISJUNCTION_BUDGET
    ),
) -> tuple[dict[str, Any], dict[str, Any]]:
    refined = json.loads(json.dumps(contract))
    regions = refined["regions"]
    region_by_id = {int(region["numeric_id"]): index for index, region in enumerate(regions)}
    launch_root_region_indices = {
        index for index, region in enumerate(regions) if bool(region.get("root"))
    }

    def region_index_for_target_id(target_id: int) -> int | None:
        matching_targets = [
            target for target in refined.get("code_targets", [])
            if int(target["id"]) == target_id
        ]
        if len(matching_targets) != 1:
            return None
        mapped_region_index = matching_targets[0].get("region_index")
        return (
            int(mapped_region_index)
            if isinstance(mapped_region_index, int)
            and not isinstance(mapped_region_index, bool)
            and 0 <= mapped_region_index < len(regions)
            else region_by_id.get(target_id)
        )

    for target_id_value in (refined.get("launch") or {}).get(
        "tls_callback_target_ids", []
    ):
        target_id = int(target_id_value)
        region_index = region_index_for_target_id(target_id)
        if region_index is not None:
            launch_root_region_indices.add(region_index)
    protocol_callback_region_indices = {
        region_index
        for state in (refined.get("protocol_callback_control") or {}).get(
            "states", []
        )
        if isinstance(state, dict)
        and isinstance(state.get("target_id"), int)
        and not isinstance(state.get("target_id"), bool)
        for region_index in [region_index_for_target_id(int(state["target_id"]))]
        if region_index is not None
    }
    predecessors: list[
        list[
            tuple[
                int, bool, str, frozenset[str],
                dict[str, RegisterRelation],
            ]
        ]
    ] = [[] for _ in regions]
    edges: list[dict[str, Any]] = []
    pending_indirect_edges: list[dict[str, Any]] = []
    pending_indirect_jump_edges: list[dict[str, Any]] = []
    pending_import_edges: list[dict[str, Any]] = []
    indirect_by_source = {
        int(candidate["source_region_index"]): candidate
        for candidate in (indirect_call_candidates or [])
    }
    import_call_by_source = {
        int(candidate["source_region_index"]): candidate
        for candidate in (import_call_candidates or [])
    }
    contracts_by_target: dict[
        tuple[str, str, str | int], list[dict[str, Any]]
    ] = {}
    for item in refined.get("machine_import_call_contracts", []):
        imported = item.get("import") or {}
        identity = (
            str(imported.get("dll", "")).lower(),
            "symbol" if "symbol" in imported else "ordinal",
            imported.get("symbol", imported.get("ordinal")),
        )
        contracts_by_target.setdefault(identity, []).append(item)

    def paired_machine_contract(
        original_outcome: dict[str, Any], candidate_outcome: dict[str, Any],
    ) -> dict[str, Any] | None:
        original_identity = _semantic_external_target_identity(
            original_outcome.get("import")
        )
        candidate_identity = _semantic_external_target_identity(
            candidate_outcome.get("import")
        )
        contracts = (
            contracts_by_target.get(original_identity, [])
            if original_identity is not None
            and original_identity == candidate_identity else []
        )
        if len(contracts) != 1:
            return None
        return contracts[0]

    def machine_preserved_registers(
        contract: dict[str, Any] | None,
    ) -> frozenset[str]:
        if contract is None:
            return frozenset()
        preserved = {
            str(register)
            for register in contract.get("preserved_registers", [])
            if str(register) in _X86_GENERAL_REGISTERS
        }
        if isinstance(contract.get("stack_result_delta"), int):
            preserved.add("esp")
        return frozenset(preserved)

    for source_index, behavior_pair in enumerate(behaviors):
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        original_edges = _semantic_edges(behavior_pair["original_ir"])
        candidate_edges = _semantic_edges(behavior_pair["candidate_ir"])
        if len(original_edges) != len(candidate_edges):
            continue
        candidate_by_target: dict[int, list[dict[str, Any]]] = {}
        for candidate_edge in candidate_edges:
            candidate_by_target.setdefault(
                int(candidate_edge["target"]), []
            ).append(candidate_edge)
        paired_edges: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for original_edge in original_edges:
            matches = candidate_by_target.get(int(original_edge["target"]), [])
            if len(matches) != 1:
                paired_edges = []
                break
            candidate_edge = matches[0]
            original_kind = str(original_edge["kind"])
            candidate_kind = str(candidate_edge["kind"])
            branch_kinds = {"branch_taken", "branch_fallthrough"}
            if (
                original_kind != candidate_kind
                and {original_kind, candidate_kind} != branch_kinds
            ) or bool(original_edge.get("environment_barrier")) != bool(
                candidate_edge.get("environment_barrier")
            ):
                paired_edges = []
                break
            paired_edges.append((original_edge, candidate_edge))
        if len(paired_edges) != len(original_edges):
            continue
        for original_edge, candidate_edge in paired_edges:
            target_index = region_by_id.get(int(original_edge["target"]))
            if target_index is None:
                continue
            barrier = bool(original_edge.get("environment_barrier"))
            machine_contract = (
                paired_machine_contract(original_outcome, candidate_outcome)
                if barrier else None
            )
            result_relations = (
                {
                    str(relation["register"]):
                        _machine_result_invariant_relation(relation)
                    for relation in machine_contract.get(
                        "result_register_relations", []
                    )
                }
                if machine_contract is not None else {}
            )
            predecessors[target_index].append(
                (
                    source_index, barrier, str(original_edge["kind"]),
                    (
                        machine_preserved_registers(machine_contract)
                        if barrier else _PE32_EXTERNAL_PRESERVED_REGISTERS
                    ),
                    result_relations,
                )
            )
            edges.append({
                "source_region_index": source_index,
                "target_region_index": target_index,
                "kind": str(original_edge["kind"]),
                "candidate_kind": str(candidate_edge["kind"]),
                "original_guard": original_edge["guard"],
                "candidate_guard": candidate_edge["guard"],
                "environment_barrier": barrier,
                "requires_call_stack_proof": False,
                "machine_contract_id": (
                    int(machine_contract["id"])
                    if machine_contract is not None else None
                ),
            })
        indirect_candidate = indirect_by_source.get(source_index)
        if indirect_candidate is not None:
            target_index = int(indirect_candidate["target_region_index"])
            indirect_kind = (
                "jump"
                if indirect_candidate["profile"] in {
                    "immutable_relocated_function_pointer_jump_v1",
                    "fixed_static_function_pointer_jump_v1",
                    "fixed_code_address_indirect_jump_v1",
                }
                else "call"
            )
            predecessors[target_index].append(
                (
                    source_index, False, indirect_kind,
                    _PE32_EXTERNAL_PRESERVED_REGISTERS,
                    {},
                )
            )
            pending_edge = {
                "source_region_index": source_index,
                "target_region_index": target_index,
                "kind": indirect_kind,
                "original_guard": {"op": "bool_constant", "value": True},
                "candidate_guard": {"op": "bool_constant", "value": True},
                "environment_barrier": False,
                "requires_call_stack_proof": False,
                "indirect_target_profile": indirect_candidate["profile"],
                "indirect_target_claim": indirect_candidate,
            }
            if indirect_kind == "jump":
                pending_indirect_jump_edges.append(pending_edge)
            else:
                pending_indirect_edges.append(pending_edge)
        import_call_candidate = import_call_by_source.get(source_index)
        if import_call_candidate is not None:
            target_index = int(import_call_candidate["continuation_region_index"])
            import_outcome = {"import": import_call_candidate["import"]}
            machine_contract = paired_machine_contract(
                import_outcome, import_outcome
            )
            result_relations = (
                {
                    str(relation["register"]):
                        _machine_result_invariant_relation(relation)
                    for relation in machine_contract.get(
                        "result_register_relations", []
                    )
                }
                if machine_contract is not None else {}
            )
            predecessors[target_index].append(
                (
                    source_index, True, "external_call",
                    machine_preserved_registers(machine_contract),
                    result_relations,
                )
            )
            pending_import_edges.append({
                "source_region_index": source_index,
                "target_region_index": target_index,
                "kind": "external_call",
                "original_guard": {"op": "bool_constant", "value": True},
                "candidate_guard": {"op": "bool_constant", "value": True},
                "environment_barrier": True,
                "requires_call_stack_proof": False,
                "indirect_target_profile": import_call_candidate["profile"],
                "import": import_call_candidate["import"],
                "machine_contract_id": (
                    int(machine_contract["id"])
                    if machine_contract is not None else None
                ),
            })
    for edge in edges:
        if edge.get("kind") != "call":
            continue
        caller_index = int(edge["source_region_index"])
        thunk_index = int(edge["target_region_index"])
        caller_outcome = behaviors[caller_index]["original_ir"].get("outcome") or {}
        candidate_caller_outcome = (
            behaviors[caller_index]["candidate_ir"].get("outcome") or {}
        )
        thunk_outcome = behaviors[thunk_index]["original_ir"].get("outcome") or {}
        candidate_thunk_outcome = (
            behaviors[thunk_index]["candidate_ir"].get("outcome") or {}
        )
        if (
            caller_outcome.get("op") != "call"
            or candidate_caller_outcome.get("op") != "call"
            or caller_outcome.get("continuation")
                != candidate_caller_outcome.get("continuation")
            or thunk_outcome.get("op") != "external_jump"
            or candidate_thunk_outcome.get("op") != "external_jump"
        ):
            continue
        original_identity = _semantic_external_target_identity(
            thunk_outcome.get("import")
        )
        candidate_identity = _semantic_external_target_identity(
            candidate_thunk_outcome.get("import")
        )
        contracts = (
            contracts_by_target.get(original_identity, [])
            if original_identity is not None
            and original_identity == candidate_identity else []
        )
        continuation = caller_outcome.get("continuation")
        continuation_index = (
            region_by_id.get(int(continuation))
            if isinstance(continuation, int) else None
        )
        if len(contracts) != 1 or continuation_index is None:
            continue
        contract = contracts[0]
        if contract.get("disposition") != "returns":
            # A terminal or protocol import has no ordinary successor state.
            # Recording it as a returning thunk invents a continuation and can
            # make runtime-frame propagation reject an otherwise valid terminal
            # edge (or worse, relate unreachable code after the call).
            continue
        edge["returning_external_thunk_contract_id"] = int(contract["id"])
        predecessors[continuation_index].append((
            caller_index,
            True,
            "external_jump_return",
            frozenset(
                {str(item) for item in contract["preserved_registers"]}
                | {"esp"}
            ),
            {
                str(relation["register"]):
                    _machine_result_invariant_relation(relation)
                for relation in contract.get(
                    "result_register_relations", []
                )
            },
        ))

    # A return destination is selected by the checked runtime call frame, not by
    # untrusted function recovery. Return continuations therefore participate
    # in rooted reachability but remain absent from decoded predecessor edges;
    # Lean checks the concrete runtime frame at composition time.

    # Keep existing direct edge IDs stable when a new checked indirect-target
    # profile becomes available. Product-graph arrays remain contiguous, while
    # an added indirect edge only changes the tail chunk and its source node's
    # outgoing inventory.
    edges.extend(pending_indirect_edges)
    edges.extend(pending_import_edges)
    edges.extend(pending_indirect_jump_edges)
    for edge in edges:
        edge["direct_call_push_claim"] = _direct_call_push_claim(
            regions[int(edge["source_region_index"])],
            behaviors[int(edge["source_region_index"])],
            original_image_base=original_image_base,
            candidate_image_base=candidate_image_base,
        ) if edge["kind"] == "call" else None
        edge["indirect_call_push_claim"] = _indirect_call_push_claim(
            regions[int(edge["source_region_index"])],
            behaviors[int(edge["source_region_index"])],
            original_image_base=original_image_base,
            candidate_image_base=candidate_image_base,
        ) if (
            edge["kind"] == "call"
            and edge.get("indirect_target_profile") in {
                "immutable_relocated_function_pointer_call_v1",
                "fixed_static_function_pointer_call_v1",
                "inductive_fixed_code_pointer_register_call_v1",
            }
        ) else None

    return_summary_analysis = _discover_static_call_return_summaries(
        [
            {
                "is_return": (
                    (behavior["original_ir"].get("outcome") or {}).get("op")
                        == "returned"
                    and
                    (behavior["candidate_ir"].get("outcome") or {}).get("op")
                        == "returned"
                ),
            }
            for behavior in behaviors
        ],
        edges,
    )
    callsite_summary_rows = [
        row for row in (callsite_summary_predecessors or [])
        if isinstance(row, dict)
        and row.get("kind") == "internal_callsite_preservation_summary"
    ]
    covered_return_predecessors = {
        (int(return_index), int(row["target_region_index"]))
        for row in callsite_summary_rows
        for return_index in row.get("return_region_indices", [])
        if isinstance(return_index, int) and not isinstance(return_index, bool)
        if isinstance(row.get("preserved_register_relations"), list)
        if any(
            isinstance(relation, dict)
            and str(relation.get("original")) in _X86_GENERAL_REGISTERS
            and relation.get("candidate") == relation.get("original")
            for relation in row.get("preserved_register_relations", [])
        )
    }
    return_predecessors: set[tuple[int, int]] = set()
    for summary in return_summary_analysis["summaries"]:
        if not summary["closed"]:
            continue
        continuation = int(summary["continuation_region_index"])
        for return_index_value in summary["return_region_indices"]:
            return_index = int(return_index_value)
            key = (return_index, continuation)
            if key in covered_return_predecessors:
                continue
            if key in return_predecessors:
                continue
            return_predecessors.add(key)
            predecessors[continuation].append((
                return_index,
                False,
                "internal_return",
                frozenset(),
                {},
            ))
    for summary in callsite_summary_rows:
        try:
            source_index = int(summary["source_region_index"])
            target_index = int(summary["target_region_index"])
        except (KeyError, TypeError, ValueError):
            continue
        if not (
            0 <= source_index < len(regions)
            and 0 <= target_index < len(regions)
        ):
            continue
        preserved_relations: dict[str, RegisterRelation] = {}
        for relation in summary.get("preserved_register_relations", []):
            if not isinstance(relation, dict):
                continue
            original_register = str(relation.get("original"))
            candidate_register = str(relation.get("candidate"))
            if (
                original_register not in _X86_GENERAL_REGISTERS
                or candidate_register != original_register
            ):
                continue
            preserved_relations[original_register] = _register_relation_payload(
                relation
            )
        if not preserved_relations:
            continue
        predecessors[target_index].append((
            source_index,
            False,
            "internal_callsite_preservation_summary",
            frozenset(preserved_relations),
            preserved_relations,
        ))

    successor_regions: list[set[int]] = [set() for _ in regions]
    for target_index, incoming in enumerate(predecessors):
        for source_index, _barrier, _kind, _preserved, _results in incoming:
            successor_regions[source_index].add(target_index)
    components = strongly_connected_components(successor_regions)
    declared_entry_regions = (
        launch_root_region_indices | protocol_callback_region_indices
    )
    conservative_entry_regions = {
        region
        for component_id in components.source_component_ids
        for component in [components.components[component_id]]
        if declared_entry_regions.isdisjoint(component)
        for region in component
    }
    rooted_reachable_regions = set(declared_entry_regions)
    reachability_worklist = list(sorted(declared_entry_regions, reverse=True))
    while reachability_worklist:
        source = reachability_worklist.pop()
        for target in sorted(successor_regions[source]):
            if target in rooted_reachable_regions:
                continue
            rooted_reachable_regions.add(target)
            reachability_worklist.append(target)

    register_order = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    stack_window_input_pairs = [
        {
            (str(window["original_register"]), str(window["candidate_register"]))
            for window in region.get("stack_windows", [])
        }
        for region in regions
    ]
    input_pair_candidates = [
        {
            str(pair["original"]): str(pair["candidate"])
            for pair in region.get("inputs", [])
        }
        for region in regions
    ]
    output_pair_candidates = [
        {
            str(pair["original"]): str(pair["candidate"])
            for pair in region.get("outputs", [])
        }
        for region in regions
    ]
    related_seed = {register: "related_word" for register in register_order}
    input_states: list[dict[str, RegisterRelation] | None] = []
    for region_index in range(len(regions)):
        seeds: list[RegisterRelation] = []
        if region_index in launch_root_region_indices:
            seeds.append("exact")
        if (
            region_index in protocol_callback_region_indices
            or region_index in conservative_entry_regions
        ):
            seeds.append("related_word")
        input_states.append(
            {
                register: _register_relation_join(seeds)
                for register in register_order
            }
            if seeds else None
        )
    output_states: list[dict[str, RegisterRelation] | None] = [
        None for _ in regions
    ]
    output_reason_states: list[dict[str, str] | None] = [
        None for _ in regions
    ]
    max_iterations = max(1, len(regions) * len(register_order) + 1)
    transfer_cache_hits = 0
    transfer_cache_misses = 0
    if _dataflow_aggregate is not None and _transfer_table_out is not None:
        raise StageAInputError(
            "precomputed register dataflow cannot emit observation tables"
        )
    transfer_region_contexts = [
        _register_transfer_region_context_sha256(
            behavior_pair=behavior_pair,
            input_pairs=input_pair_candidates[region_index],
            output_pairs=output_pair_candidates[region_index],
            contract=refined,
            original_image_base=original_image_base,
            candidate_image_base=candidate_image_base,
            original_bin=original_bin,
            candidate_bin=candidate_bin,
            register_order=register_order,
        )
        for region_index, behavior_pair in enumerate(behaviors)
    ]
    need_transfer_programs = (
        _transfer_programs_out is not None
        or _dataflow_aggregate is not None
        or _compiled_problem_out is not None
    )
    transfer_context = (
        register_transfer_context_payload(
            contract=refined,
            original_bin=original_bin,
            candidate_bin=candidate_bin,
        )
        if need_transfer_programs
        and original_bin is not None
        and candidate_bin is not None
        and hasattr(original_bin, "pe")
        and hasattr(candidate_bin, "pe")
        else None
    )
    transfer_program_cache_key = (
        sha256_bytes(json.dumps({
            "format": "stage-a-register-transfer-program-set-v1",
            "context_sha256": transfer_context["context_sha256"],
            "region_contexts": transfer_region_contexts,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        if transfer_context is not None else None
    )
    cached_program_set = (
        _transfer_program_cache.get(transfer_program_cache_key)
        if _transfer_program_cache is not None
        and transfer_program_cache_key is not None
        else None
    )
    if cached_program_set is not None:
        transfer_context, transfer_programs = cached_program_set
    elif transfer_context is not None:
        transfer_programs = [
            compile_register_transfer_program(
                region_id=str(regions[region_index]["id"]),
                behavior_pair=behavior_pair,
                input_pairs=input_pair_candidates[region_index],
                output_pairs=output_pair_candidates[region_index],
                contract=refined,
                original_image_base=original_image_base,
                candidate_image_base=candidate_image_base,
                original_bin=original_bin,
                candidate_bin=candidate_bin,
                context_sha256=str(transfer_context["context_sha256"]),
                register_order=register_order,
            )
            for region_index, behavior_pair in enumerate(behaviors)
        ]
        if (
            _transfer_program_cache is not None
            and transfer_program_cache_key is not None
        ):
            _transfer_program_cache[transfer_program_cache_key] = (
                transfer_context, transfer_programs,
            )
    else:
        transfer_programs = []
    parsed_transfer_context = (
        parse_register_transfer_context(transfer_context)
        if transfer_context is not None else None
    )
    transfer_propagation = (
        _register_transfer_propagation(
            regions=regions,
            predecessors=predecessors,
            register_order=register_order,
            launch_root_region_indices=launch_root_region_indices,
            protocol_callback_region_indices=protocol_callback_region_indices,
            conservative_entry_regions=conservative_entry_regions,
            input_pair_candidates=input_pair_candidates,
            stack_window_input_pairs=stack_window_input_pairs,
        )
        if need_transfer_programs or _transfer_table_out is not None else None
    )
    program_dataflow_graph = (
        stable_dataflow_graph(
            successor_regions,
            region_ids=[str(region["id"]) for region in regions],
            transfer_semantics_sha256=[
                str(program["program_sha256"])
                for program in transfer_programs
            ],
        )
        if transfer_context is not None else None
    )
    transfer_program_artifact = (
        register_transfer_programs_payload(
            original_sha256=str(original_bin.sha256),
            candidate_sha256=str(candidate_bin.sha256),
            graph_sha256=str(program_dataflow_graph.graph_sha256),
            context=transfer_context,
            programs=transfer_programs,
            propagation=transfer_propagation,
        )
        if transfer_context is not None
        and program_dataflow_graph is not None
        and transfer_propagation is not None
        and original_bin is not None
        and candidate_bin is not None
        else None
    )
    if _compiled_problem_out is not None:
        if _dataflow_aggregate is not None:
            raise StageAInputError(
                "register dataflow compilation cannot also consume a solution"
            )
        if transfer_program_artifact is None or program_dataflow_graph is None:
            raise StageAInputError(
                "register dataflow compilation requires exact PE transfer programs"
            )
        _compiled_problem_out.clear()
        _compiled_problem_out.update({
            "graph": program_dataflow_graph.to_payload(),
            "transfer_programs": transfer_program_artifact,
        })
        return refined, {
            "format": "stage-a-register-dataflow-compile-only-v1",
            "status": "compiled",
            "acceptance_authority": False,
        }
    transfer_observation_hashes: list[set[str]] = [set() for _ in regions]
    transfer_observation_rows: list[dict[str, dict[str, Any]]] = [
        {} for _ in regions
    ]
    def evaluate_output(
        region_index: int,
        input_kinds: dict[str, RegisterRelation],
        previous_output: dict[str, RegisterRelation] | None,
    ) -> tuple[dict[str, RegisterRelation], dict[str, str]]:
        nonlocal transfer_cache_hits, transfer_cache_misses
        behavior_pair = behaviors[region_index]
        original_registers = behavior_pair["original_ir"]["registers"]
        candidate_registers = behavior_pair["candidate_ir"]["registers"]
        fixed_immutable_probe = _fixed_immutable_transfer_probe(
            behavior_pair=behavior_pair,
            input_relations=input_kinds,
            input_pairs=input_pair_candidates[region_index],
            output_pairs=output_pair_candidates[region_index],
            original_bin=original_bin,
            candidate_bin=candidate_bin,
            register_order=register_order,
        )
        input_relation_payloads = [
            {
                "register": register,
                **_register_relation_payload(input_kinds[register]),
            }
            for register in register_order
        ]
        transfer_observation = register_transfer_observation_sha256(
            input_relations=input_relation_payloads,
            fixed_immutable_probe=fixed_immutable_probe,
        )
        transfer_observation_hashes[region_index].add(transfer_observation)
        transfer_cache_key = (
            transfer_region_contexts[region_index]
            + ":"
            + transfer_observation
        )
        cached_transfer = (
            _transfer_cache.get(transfer_cache_key)
            if _transfer_cache is not None else None
        )
        if cached_transfer is not None:
            transfer_cache_hits += 1
            cached_kinds, cached_reasons = cached_transfer
            kinds = {
                register: (
                    dict(relation) if isinstance(relation, dict) else relation
                )
                for register, relation in cached_kinds.items()
            }
            reasons = dict(cached_reasons)
        else:
            transfer_cache_misses += 1
            if parsed_transfer_context is not None:
                try:
                    transfer_result = evaluate_register_transfer_program(
                        transfer_programs[region_index],
                        input_kinds,
                        context_payload=parsed_transfer_context,
                        validate=False,
                        validate_context=False,
                    )
                except RegisterTransferIncomplete as exc:
                    raise AssertionError(
                        "compiled register transfer program is incomplete: "
                        + exc.code
                    ) from exc
                kinds = transfer_result.relations
                reasons = transfer_result.reasons
            else:
                kinds = {}
                reasons = {}
                for register in register_order:
                    candidate_register = output_pair_candidates[
                        region_index
                    ].get(register)
                    if (
                        register not in original_registers
                        or candidate_register is None
                        or candidate_register not in candidate_registers
                    ):
                        kinds[register] = "related_word"
                        reasons[register] = "output_register_pair_missing"
                        continue
                    kinds[register], reasons[register] = (
                        _infer_register_output_relation(
                            original_registers[register],
                            candidate_registers[candidate_register],
                            input_kinds,
                            refined,
                            original_image_base,
                            candidate_image_base,
                            not refined.get("value_targets"),
                            original_bin,
                            candidate_bin,
                            input_pair_candidates[region_index],
                        )
                    )
            if _transfer_cache is not None:
                _transfer_cache[transfer_cache_key] = (
                    {
                        register: (
                            dict(relation)
                            if isinstance(relation, dict) else relation
                        )
                        for register, relation in kinds.items()
                    },
                    dict(reasons),
                )
        observation_row = {
            "sha256": transfer_observation,
            "input_relations": input_relation_payloads,
            "fixed_immutable_probe": fixed_immutable_probe,
            "output_relations": [
                {
                    "register": register,
                    **_register_relation_payload(kinds[register]),
                }
                for register in register_order
            ],
            "reasons": dict(reasons),
        }
        prior_observation = transfer_observation_rows[region_index].get(
            transfer_observation
        )
        if prior_observation is not None and prior_observation != observation_row:
            raise AssertionError("register transfer observation is nondeterministic")
        transfer_observation_rows[region_index][transfer_observation] = (
            observation_row
        )
        if previous_output is not None:
            joined_kinds = {
                register: _register_relation_join([
                    previous_output[register], kinds[register],
                ])
                for register in register_order
            }
            for register in register_order:
                if joined_kinds[register] != kinds[register]:
                    reasons[register] = "monotone_transfer_widening"
            kinds = joined_kinds
        return kinds, reasons

    def recompute_input(
        region_index: int,
        next_outputs: list[dict[str, RegisterRelation] | None]
        | tuple[dict[str, RegisterRelation] | None, ...],
    ) -> dict[str, RegisterRelation] | None:
        incoming = predecessors[region_index]
        kinds: dict[str, RegisterRelation] | None = None
        for register in register_order:
            candidates: list[RegisterRelation] = []
            if region_index in launch_root_region_indices:
                candidates.append("exact")
            if region_index in protocol_callback_region_indices:
                candidates.append("related_word")
            if region_index in conservative_entry_regions:
                candidates.append("related_word")
            for source_index, barrier, kind, preserved, results in incoming:
                source_output = next_outputs[source_index]
                if source_output is None:
                    continue
                candidates.append(
                    source_output[register]
                    if kind == "internal_callsite_preservation_summary"
                    and register in preserved
                    and register in results
                    and _register_relation_key(
                        source_output[register]
                    ) == _register_relation_key(results[register])
                    else "related_word"
                    if kind == "internal_callsite_preservation_summary"
                    else source_output[register]
                    if not barrier
                    else results[register]
                    if register in results
                    else source_output[register]
                    if register in preserved
                    else "related_word"
                )
            if not candidates:
                continue
            if kinds is None:
                kinds = {}
            kinds[register] = _register_relation_join(candidates)
            candidate_register = input_pair_candidates[region_index].get(register)
            if (
                candidate_register is not None
                and (register, candidate_register)
                    in stack_window_input_pairs[region_index]
            ):
                # A stack window relates offsets inside paired concrete ranges;
                # it does not imply literal register equality.
                kinds[register] = "related_word"
        if kinds is not None and len(kinds) != len(register_order):
            raise AssertionError("reachable register state is incomplete")
        return kinds

    if _dataflow_aggregate is not None:
        # Keep distributed-solution replay outside the proposal producer's
        # import closure. Proposal discovery does not consume an aggregate, so
        # checker-only changes must not invalidate that expensive phase.
        from ..register_dataflow_solution import (
            validate_register_dataflow_solution,
        )

        if (
            transfer_program_artifact is None
            or program_dataflow_graph is None
            or original_bin is None
            or candidate_bin is None
        ):
            raise StageAInputError(
                "precomputed register dataflow requires exact PE transfer programs"
            )
        solution = validate_register_dataflow_solution(
            aggregate_payload=_dataflow_aggregate,
            transfer_programs_payload=transfer_program_artifact,
            expected_original_sha256=original_bin.sha256,
            expected_candidate_sha256=candidate_bin.sha256,
            expected_graph_sha256=program_dataflow_graph.graph_sha256,
        )
        input_states = [dict(state) for state in solution.input_states]
        output_states = [dict(state) for state in solution.output_states]
        output_reason_states = [
            dict(reasons) for reasons in solution.output_reasons
        ]
        converged = True
        fixed_point_iterations = 0
        transfer_evaluations = 0
    else:
        fixed_point = solve_monotone_fixed_point_by_scc(
            initial_input_states=input_states,
            initial_output_states=output_states,
            initial_output_reason_states=output_reason_states,
            successors=[tuple(sorted(targets)) for targets in successor_regions],
            evaluate_output=evaluate_output,
            recompute_input=recompute_input,
            max_iterations=max_iterations,
        )
        input_states = list(fixed_point.input_states)
        output_states = list(fixed_point.output_states)
        output_reason_states = list(fixed_point.output_reason_states)
        converged = fixed_point.converged
        fixed_point_iterations = fixed_point.iterations
        transfer_evaluations = fixed_point.transfer_evaluations
    transfer_semantics_sha256 = [
        register_transfer_semantics_sha256(
            context_sha256=transfer_region_contexts[region_index],
            observation_sha256=sorted(
                transfer_observation_hashes[region_index]
            ),
        )
        for region_index in range(len(regions))
    ]
    observation_dataflow_graph = stable_dataflow_graph(
        successor_regions,
        region_ids=[str(region["id"]) for region in regions],
        transfer_semantics_sha256=transfer_semantics_sha256,
    )
    dataflow_graph = program_dataflow_graph or observation_dataflow_graph
    if _transfer_table_out is not None:
        assert transfer_propagation is not None
        _transfer_table_out.clear()
        _transfer_table_out.update({
            "graph": observation_dataflow_graph.to_payload(),
            "graph_sha256": observation_dataflow_graph.graph_sha256,
            "regions": [
                {
                    "id": str(region["id"]),
                    "context_sha256": transfer_region_contexts[region_index],
                    "transfer_semantics_sha256": transfer_semantics_sha256[
                        region_index
                    ],
                    "observations": [
                        transfer_observation_rows[region_index][digest]
                        for digest in sorted(
                            transfer_observation_rows[region_index]
                        )
                    ],
                }
                for region_index, region in enumerate(regions)
            ],
            "propagation": transfer_propagation,
        })
    if _transfer_programs_out is not None and transfer_context is not None:
        assert transfer_propagation is not None
        assert program_dataflow_graph is not None
        _transfer_programs_out.clear()
        _transfer_programs_out.update({
            "graph": program_dataflow_graph.to_payload(),
            "graph_sha256": program_dataflow_graph.graph_sha256,
            "context": transfer_context,
            "programs": transfer_programs,
            "propagation": transfer_propagation,
        })
    if _solver_metrics is not None:
        _solver_metrics.clear()
        _solver_metrics.update({
            "iterations": fixed_point_iterations,
            "transfer_evaluations": transfer_evaluations,
            "transfer_cache_hits": transfer_cache_hits,
            "transfer_cache_misses": transfer_cache_misses,
        })

    analyzed_regions = {
        region_index
        for region_index, state in enumerate(input_states)
        if state is not None
    }
    input_kinds = [
        dict(state) if state is not None else dict(related_seed)
        for state in input_states
    ]
    output_kinds = [
        dict(state) if state is not None else dict(related_seed)
        for state in output_states
    ]
    output_reasons = [
        dict(reasons) if reasons is not None else {
            register: "unreachable_from_declared_roots"
            for register in register_order
        }
        for reasons in output_reason_states
    ]

    relation_rows: list[dict[str, Any]] = []
    exact_claims = 0
    input_import_pairs = [
        {
            (str(relation["original"]), str(relation["candidate"]))
            for relation in region.get("input_import_relations", [])
        }
        for region in regions
    ]
    output_import_pairs: list[set[tuple[str, str]]] = [set() for _ in regions]
    for edge in edges:
        if not edge["environment_barrier"] and not edge["requires_call_stack_proof"]:
            output_import_pairs[int(edge["source_region_index"])].update(
                input_import_pairs[int(edge["target_region_index"])]
            )
    for region_index, region in enumerate(regions):
        input_pairs = {pair["original"]: pair for pair in region["inputs"]}
        output_pairs = {pair["original"]: pair for pair in region["outputs"]}
        region["input_relations"] = [
            {
                "original": input_pairs[register]["original"],
                "candidate": input_pairs[register]["candidate"],
                **_register_relation_payload(
                    input_kinds[region_index][register]
                ),
            }
            for register in register_order
            if register in input_pairs
            and (
                input_pairs[register]["original"],
                input_pairs[register]["candidate"],
            ) not in input_import_pairs[region_index]
        ]
        region["output_relations"] = [
            {
                "original": output_pairs[register]["original"],
                "candidate": output_pairs[register]["candidate"],
                **_register_relation_payload(
                    output_kinds[region_index][register]
                ),
            }
            for register in register_order
            if register in output_pairs
            and (
                output_pairs[register]["original"],
                output_pairs[register]["candidate"],
            ) not in output_import_pairs[region_index]
        ]
        claims = []
        output_claims = []
        input_relation_by_original = {
            relation["original"]: relation for relation in region["input_relations"]
        }
        for relation in region["output_relations"]:
            register = relation["original"]
            original_expression = behaviors[region_index]["original_ir"]["registers"][register]
            candidate_expression = behaviors[region_index]["candidate_ir"]["registers"][
                relation["candidate"]
            ]
            reason = output_reasons[region_index][register]
            if (
                _register_relation_implies_exact(relation)
                and relation["original"] == relation["candidate"]
                and original_expression == candidate_expression
                and reason not in {
                    "lean_exact_memory_expression", "immutable_image_word",
                    "assembled_immutable_image_word", "static_word_slot",
                    "fixed_immutable_expression",
                }
            ):
                claims.append({
                    "register": register,
                    "relation": "exact",
                    "reason": reason,
                    "expression": original_expression,
                })
            if reason == "identity_transfer":
                input_register = str(original_expression["reg"])
                input_relation = input_relation_by_original.get(input_register)
                if (
                    input_relation is not None
                    and candidate_expression.get("op") == "input_reg"
                    and str(candidate_expression["reg"]) == input_relation["candidate"]
                    and input_relation["relation"] == relation["relation"]
                ):
                    output_claims.append({
                        "kind": "identity",
                        "input": input_relation,
                        "output": relation,
                    })
            elif reason == "paired_constant":
                output_claims.append({
                    "kind": "constant",
                    "output": relation,
                    "original_value": int(original_expression["value"]),
                    "candidate_value": int(candidate_expression["value"]),
                })
            elif reason == "lean_exact_memory_expression":
                output_claims.append({
                    "kind": "exact_memory",
                    "output": relation,
                    "expression": original_expression,
                })
            elif reason in {
                "immutable_image_word", "assembled_immutable_image_word",
            }:
                original_read = (
                    _immutable_image_word_read(original_expression, original_bin)
                    if original_bin is not None else None
                )
                candidate_read = (
                    _immutable_image_word_read(candidate_expression, candidate_bin)
                    if candidate_bin is not None else None
                )
                if (
                    original_read is not None
                    and candidate_read is not None
                ):
                    (
                        original_address, original_writes,
                        original_assembled, original_value,
                    ) = original_read
                    (
                        candidate_address, candidate_writes,
                        candidate_assembled, candidate_value,
                    ) = candidate_read
                    output_claims.append({
                        "kind": "immutable_image_word",
                        "output": relation,
                        "original_address": original_address,
                        "candidate_address": candidate_address,
                        "original_value": original_value,
                        "candidate_value": candidate_value,
                        "original_assembled_read": original_assembled,
                        "candidate_assembled_read": candidate_assembled,
                        "original_writes": original_writes,
                        "candidate_writes": candidate_writes,
                    })
            elif reason == "fixed_immutable_expression":
                if original_bin is not None and candidate_bin is not None:
                    original_fixed, candidate_fixed = _fixed_register_values(
                        input_kinds[region_index],
                        input_pair_candidates[region_index],
                    )
                    original_value = _fixed_immutable_expr_value(
                        original_expression, original_bin, original_fixed,
                    )
                    candidate_value = _fixed_immutable_expr_value(
                        candidate_expression, candidate_bin, candidate_fixed,
                    )
                    if original_value is not None and candidate_value is not None:
                        output_claims.append({
                            "kind": "fixed_immutable_expression",
                            "output": relation,
                            "original_value": original_value,
                            "candidate_value": candidate_value,
                        })
            elif relation["relation"] == "exact" and any(
                claim["register"] == register for claim in claims
            ):
                output_claims.append({
                    "kind": "exact_expression",
                    "output": relation,
                    "expression": original_expression,
                })
        exact_claims += len(claims)
        relation_rows.append({
            "region_id": region["id"],
            "region_index": region_index,
            "analysis_reachable": region_index in analyzed_regions,
            "register_graph_rooted_reachable": (
                region_index in rooted_reachable_regions
            ),
            "inputs": region["input_relations"],
            "outputs": region["output_relations"],
            "runtime_frame_inputs": json.loads(json.dumps(
                region["input_relations"]
            )),
            "runtime_frame_outputs": json.loads(json.dumps(
                region["output_relations"]
            )),
            "exact_output_claims": claims,
            "output_claims": output_claims,
            "return_pop_claim": _return_pop_claim(
                behaviors[region_index], region=region
            ),
            "is_return": (
                (behaviors[region_index]["original_ir"].get("outcome") or {}).get("op")
                    == "returned"
                and (behaviors[region_index]["candidate_ir"].get("outcome") or {}).get("op")
                    == "returned"
            ),
            "fully_exact_output_transfer": (
                len(claims) == len(region["output_relations"])
                and bool(region["output_relations"])
                and all(
                    relation["relation"] == "exact"
                    for relation in region["output_relations"]
                )
            ),
            "fully_supported_output_transfer": (
                len(output_claims) == len(region["output_relations"])
                and bool(region["output_relations"])
            ),
            "predecessor_count": len(predecessors[region_index]),
            "environment_barrier": any(
                barrier for _, barrier, _, _, _ in predecessors[region_index]
            ),
        })

    # Proposal-only inventory. Unlike the legacy indirect candidates accepted
    # as inputs above, these rows do not create predecessors or graph edges.
    indirect_fixed_code_pointer_calls = (
        _indirect_fixed_code_pointer_register_calls(
            refined, behaviors, relation_rows,
        )
    )
    register_code_pointer_provenance = (
        _bounded_register_code_pointer_provenance(
            contract=refined,
            behaviors=behaviors,
            relation_rows=relation_rows,
            predecessors=predecessors,
            register_order=register_order,
            input_pair_candidates=input_pair_candidates,
            output_pair_candidates=output_pair_candidates,
            output_reasons=output_reasons,
            launch_root_region_indices=launch_root_region_indices,
            protocol_callback_region_indices=protocol_callback_region_indices,
            conservative_entry_regions=conservative_entry_regions,
            stack_window_input_pairs=stack_window_input_pairs,
            original_image_base=original_image_base,
            candidate_image_base=candidate_image_base,
            disjunction_budget=code_pointer_disjunction_budget,
        )
    )

    unsupported_edges = 0
    fully_exact_edges = 0
    exact_pair_edge_claims = 0
    edges_with_exact_pair_claims = 0
    for edge in edges:
        source = edge["source_region_index"]
        target = edge["target_region_index"]
        indirect_control = bool(edge.get("indirect_target_profile"))
        immutable_indirect_jump = (
            edge.get("indirect_target_profile") in {
                "immutable_relocated_function_pointer_jump_v1",
                "fixed_static_function_pointer_jump_v1",
                "fixed_code_address_indirect_jump_v1",
            }
        )
        checked_single_target_indirect = (
            immutable_indirect_jump
            or edge.get("indirect_target_profile") in {
                "immutable_relocated_function_pointer_call_v1",
                "fixed_static_function_pointer_call_v1",
                "inductive_fixed_code_pointer_register_call_v1",
            }
        )
        source_claims = {
            claim["register"]: claim
            for claim in relation_rows[source]["exact_output_claims"]
        }
        source_outputs = {
            relation["original"]: relation
            for relation in relation_rows[source]["outputs"]
        }
        pair_claims = [] if (
            edge["environment_barrier"] or edge["requires_call_stack_proof"]
            or indirect_control
        ) else [
            {
                "register": target_relation["original"],
                "target_relation": target_relation["relation"],
                "expression": source_claims[target_relation["original"]]["expression"],
            }
            for target_relation in relation_rows[target]["inputs"]
            if target_relation["relation"] in {"exact", "related_word"}
            and target_relation["original"] in source_claims
            and source_outputs[target_relation["original"]]["candidate"]
                == target_relation["candidate"]
        ]
        edge["exact_output_pair_claims"] = pair_claims
        supported = (
            not edge["environment_barrier"]
            and not edge["requires_call_stack_proof"]
            and (not indirect_control or checked_single_target_indirect)
            and all(
            _register_relation_implies(
                output_kinds[source][register], input_kinds[target][register]
            )
            for register in register_order
            )
        )
        edge["relation_preservation_proposed"] = supported
        edge["environment_register_policy"] = (
            {
                "id": _PE32_EXTERNAL_REGISTER_POLICY_ID,
                "preserved": sorted(_PE32_EXTERNAL_PRESERVED_REGISTERS),
                "clobbered": sorted(
                    set(register_order) - _PE32_EXTERNAL_PRESERVED_REGISTERS
                ),
                "status": "requires_relational_environment_compatibility",
            }
            if edge["environment_barrier"]
            else None
        )
        edge["fully_exact_edge_proposed"] = (
            not edge["environment_barrier"]
            and not edge["requires_call_stack_proof"]
            and not indirect_control
            and relation_rows[source]["fully_exact_output_transfer"]
            and all(
                relation["relation"] == "exact"
                for relation in relation_rows[target]["inputs"]
            )
            and relation_rows[source]["outputs"] == relation_rows[target]["inputs"]
        )
        unsupported_edges += not supported
        fully_exact_edges += edge["fully_exact_edge_proposed"]
        exact_pair_edge_claims += len(pair_claims)
        edges_with_exact_pair_claims += bool(pair_claims)
    return_slot_analysis = _attach_return_slot_contracts(
        behaviors, relation_rows, edges,
        machine_import_call_contracts=refined.get(
            "machine_import_call_contracts", []
        ),
    )
    counts = {
        "regions": len(regions),
        "dataflow_sccs": len(components.components),
        "dataflow_source_sccs": len(components.source_component_ids),
        "conservative_entry_regions": len(conservative_entry_regions),
        "analyzed_regions": len(analyzed_regions),
        "register_graph_rooted_reachable_regions": len(
            rooted_reachable_regions
        ),
        "register_graph_rooted_reachable_edges": sum(
            int(edge["source_region_index"]) in rooted_reachable_regions
            for edge in edges
        ),
        "direct_edges": len(edges),
        "exact_input_relations": sum(
            _register_relation_kind(kind) == "exact"
            for kinds in input_kinds for kind in kinds.values()
        ),
        "exact_output_relations": sum(
            _register_relation_kind(kind) == "exact"
            for kinds in output_kinds for kind in kinds.values()
        ),
        "code_pointer_output_relations": sum(
            _register_relation_kind(kind) == "code_pointer"
            for kinds in output_kinds for kind in kinds.values()
        ),
        "fixed_code_pointer_output_relations": sum(
            _register_relation_kind(kind) == "fixed_code_pointer"
            for kinds in output_kinds for kind in kinds.values()
        ),
        "fixed_word_input_relations": sum(
            _register_relation_kind(kind) == "fixed_word"
            for kinds in input_kinds for kind in kinds.values()
        ),
        "fixed_word_output_relations": sum(
            _register_relation_kind(kind) == "fixed_word"
            for kinds in output_kinds for kind in kinds.values()
        ),
        "indirect_fixed_code_pointer_calls": len(
            indirect_fixed_code_pointer_calls
        ),
        "finite_code_pointer_indirect_controls": int(
            register_code_pointer_provenance["counts"]["indirect_controls"]
        ),
        "finite_code_pointer_multi_target_controls": int(
            register_code_pointer_provenance["counts"]
            ["multi_target_indirect_controls"]
        ),
        "finite_code_pointer_provenance_overflows": int(
            register_code_pointer_provenance["counts"]["overflow_locations"]
        ),
        "data_pointer_output_relations": sum(
            _register_relation_kind(kind) == "data_pointer"
            for kinds in output_kinds for kind in kinds.values()
        ),
        "lean_exact_output_claims": exact_claims,
        "fully_exact_output_regions": sum(
            row["fully_exact_output_transfer"] for row in relation_rows
        ),
        "register_output_claims": sum(
            len(row["output_claims"]) for row in relation_rows
        ),
        "fully_supported_output_regions": sum(
            row["fully_supported_output_transfer"] for row in relation_rows
        ),
        "environment_barrier_edges": sum(edge["environment_barrier"] for edge in edges),
        "environment_register_policy_edges": sum(
            edge["environment_register_policy"] is not None for edge in edges
        ),
        "call_return_edges": sum(
            edge["requires_call_stack_proof"] for edge in edges
        ),
        "direct_call_edges": sum(
            edge["kind"] == "call" and not edge.get("indirect_target_profile")
            for edge in edges
        ),
        "checked_direct_call_pushes": sum(
            edge["direct_call_push_claim"] is not None for edge in edges
        ),
        "checked_indirect_call_pushes": sum(
            edge.get("indirect_call_push_claim") is not None for edge in edges
        ),
        "return_regions": sum(
            (behavior["original_ir"].get("outcome") or {}).get("op") == "returned"
            and (behavior["candidate_ir"].get("outcome") or {}).get("op") == "returned"
            for behavior in behaviors
        ),
        "checked_return_pops": sum(
            row["return_pop_claim"] is not None for row in relation_rows
        ),
        "return_slot_seed_edges": int(return_slot_analysis["seed_edges"]),
        "return_slot_transfer_claims": int(return_slot_analysis["transfer_claims"]),
        "return_slot_transfer_rules": int(return_slot_analysis["transfer_rules"]),
        "return_slot_return_transfer_claims": int(
            return_slot_analysis["return_transfer_claims"]
        ),
        "return_slot_return_transfer_rules": int(
            return_slot_analysis["return_transfer_rules"]
        ),
        "return_slot_call_summary_claims": int(
            return_slot_analysis["call_summary_claims"]
        ),
        "replayable_return_slot_call_summaries": int(
            return_slot_analysis["replayable_call_summaries"]
        ),
        "regions_with_return_slot_offsets": int(
            return_slot_analysis["regions_with_offsets"]
        ),
        "return_regions_with_aligned_runtime_frame": int(
            return_slot_analysis["aligned_returns"]
        ),
        "return_slot_overflow_regions": len(return_slot_analysis["overflow_regions"]),
        "unsupported_edge_proposals": unsupported_edges,
        "fully_exact_edge_proposals": fully_exact_edges,
        "exact_pair_edge_claims": exact_pair_edge_claims,
        "edges_with_exact_pair_claims": edges_with_exact_pair_claims,
    }
    dataflow_complete = converged and len(analyzed_regions) == len(regions)
    artifact = {
        "format": "stage-a-relational-register-relations-v1",
        "status": (
            "proposal_requires_generated_lean_replay"
            if dataflow_complete
            else "incomplete"
        ),
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "converged": converged,
        "dataflow_complete": dataflow_complete,
        "iterations": None,
        "relation_kinds": sorted(_REGISTER_RELATION_KINDS),
        "trust": {
            "role": "analysis_and_proof_proposal_only",
            "acceptance_rule": (
                "exact output claims and every direct-edge implication must be reconstructed "
                "from decoded behavior and checked by Lean"
            ),
        },
        "dataflow_graph": dataflow_graph.to_payload(),
        "return_slot_analysis": return_slot_analysis,
        "indirect_fixed_code_pointer_calls": indirect_fixed_code_pointer_calls,
        "register_code_pointer_provenance": register_code_pointer_provenance,
        "counts": counts,
        "regions": relation_rows,
        "edges": edges,
    }
    return refined, artifact
