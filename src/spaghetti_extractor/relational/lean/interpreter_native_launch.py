"""Generate exact native launch-wrapper certificates for interpreter candidates.

Python supplies only finite RVA routes and exact candidate bytes.  The emitted
Lean module re-parses the PE and imports, re-decodes every instruction, checks
the canonical entry/TLS inventory, and derives semantic paths by replaying the
candidate native transition system.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping

import capstone
from capstone import x86_const

from ...errors import StageAInputError
from ...stage_binary import (
    StageABinary,
    _parse_linker_map_symbol_line,
    _parse_stage_a_pe,
)
from ...util import sha256_bytes, write_json
from .common import (
    _lean_byte_tree_definitions,
    _lean_import_certificate,
    _lean_pe,
)


INTERPRETER_NATIVE_LAUNCH_MODULE = (
    "GeneratedRelationalInterpreterNativeLaunch"
)
INTERPRETER_NATIVE_LAUNCH_GRAPH_MODULE = (
    "GeneratedRelationalInterpreterNativeLaunchGraph"
)
INTERPRETER_NATIVE_LAUNCH_GRAPH_PLAN_FILENAME = (
    "interpreter-native-launch-graph-plan.json"
)
NATIVE_ENGINE_PLAN_FORMAT = "stage-b-native-engine-plan-v1"

_LOCAL_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*\Z")
_NAMESPACE = re.compile(
    r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*\Z"
)
_U32_LIMIT = 1 << 32

CutpointKind = Literal["dispatch", "return_wrapper", "termination_wrapper"]
SourceKind = Literal["entry", "tls_callback", "stable_cutpoint"]
DestinationKind = Literal["stable_cutpoint", "returned", "terminated"]
GraphDestinationKind = Literal["dispatch", "returned", "terminated"]
GraphInstructionKind = Literal["ordinary", "x87_fnsave", "x87_frstor"]


class RelationalInterpreterNativeLaunchGenerationError(StageAInputError):
    """A native launch route is stale, incomplete, or malformed."""


@dataclass(frozen=True)
class NativeLaunchGraphArtifactBinding:
    """Untrusted route proposal recovered from versioned Stage B artifacts."""

    spec: NativeLaunchGraphSpec
    symbol_rvas: tuple[tuple[str, int], ...]
    tls_callback_rvas: tuple[int, ...]

    def payload(self) -> dict[str, object]:
        return {
            "format": "stage-a-native-launch-graph-artifact-binding-v1",
            "acceptance_authority": False,
            "tls_callback_rvas": list(self.tls_callback_rvas),
            "symbol_rvas": [
                {"symbol": symbol, "rva": rva}
                for symbol, rva in self.symbol_rvas
            ],
            "routes": [
                {
                    "source_kind": route.source_kind,
                    "source_index": route.source_index,
                    "source_rva": route.source_rva,
                    "destination_kind": route.destination_kind,
                    "destination_rva": route.destination_rva,
                }
                for route in self.spec.routes
            ],
        }


@dataclass(frozen=True)
class NativeLaunchGraphRouteSpec:
    """One exact root/wrapper route to a semantic launch boundary.

    Root RVAs are always parsed from the PE.  ``source_rva`` is accepted only
    for return and termination wrappers because those are candidate-private
    cutpoints rather than loader-selected roots.
    """

    source_kind: SourceKind
    destination_kind: GraphDestinationKind
    destination_rva: int | None = None
    source_index: int | None = None
    source_rva: int | None = None


@dataclass(frozen=True)
class NativeLaunchGraphSpec:
    routes: tuple[NativeLaunchGraphRouteSpec, ...]
    module_name: str = INTERPRETER_NATIVE_LAUNCH_GRAPH_MODULE
    namespace: str = "StageA.GeneratedRelational.InterpreterNativeLaunchGraph"


def native_launch_graph_spec_from_engine_artifacts(
    *,
    candidate_pe: Path | str,
    linker_map: Path | str,
    native_engine_plan: Path | str,
    module_name: str = INTERPRETER_NATIVE_LAUNCH_GRAPH_MODULE,
    namespace: str = (
        "StageA.GeneratedRelational.InterpreterNativeLaunchGraph"
    ),
) -> NativeLaunchGraphArtifactBinding:
    """Derive exact wrapper routes from the stable Stage B native ABI.

    The returned routes remain untrusted proposal data.  The graph writer and
    reviewed Lean checker independently decode the exact candidate bytes.  PE
    root order is authoritative: engine metadata may identify a callback, but
    cannot reorder or introduce loader-selected TLS roots.
    """

    candidate_path = Path(candidate_pe)
    engine_path = Path(native_engine_plan)
    try:
        engine = json.loads(engine_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"cannot read native-engine plan: {exc}"
        ) from exc
    if not isinstance(engine, Mapping):
        raise RelationalInterpreterNativeLaunchGenerationError(
            "native-engine plan must be a JSON object"
        )
    if engine.get("format") != NATIVE_ENGINE_PLAN_FORMAT:
        raise RelationalInterpreterNativeLaunchGenerationError(
            "unsupported native-engine plan format"
        )
    blockers = engine.get("blockers")
    if engine.get("status") != "ready" or blockers != []:
        raise RelationalInterpreterNativeLaunchGenerationError(
            "native-engine plan is not ready and blocker-free"
        )

    wrappers = engine.get("launch_wrapper_symbols")
    if not isinstance(wrappers, Mapping):
        raise RelationalInterpreterNativeLaunchGenerationError(
            "native-engine plan has no launch-wrapper symbol inventory"
        )
    entry_return = _required_symbol_name(
        wrappers.get("entry_return"), "entry return"
    )
    termination = _required_symbol_name(
        wrappers.get("termination"), "termination"
    )
    listed_callback_returns = wrappers.get("callback_dispatch_returns")
    if not isinstance(listed_callback_returns, list) or not all(
        isinstance(value, str) and value for value in listed_callback_returns
    ):
        raise RelationalInterpreterNativeLaunchGenerationError(
            "callback return symbol inventory is malformed"
        )
    if len(set(listed_callback_returns)) != len(listed_callback_returns):
        raise RelationalInterpreterNativeLaunchGenerationError(
            "callback return symbol inventory contains duplicates"
        )

    callbacks = engine.get("callback_abis")
    if not isinstance(callbacks, list):
        raise RelationalInterpreterNativeLaunchGenerationError(
            "native-engine callback ABI inventory is malformed"
        )
    callback_returns: dict[int, str] = {}
    callback_inventory_returns: list[str] = []
    for index, raw in enumerate(callbacks):
        if not isinstance(raw, Mapping):
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"native-engine callback ABI {index} is not an object"
            )
        rva = _required_u32(raw.get("rva"), f"callback ABI {index} RVA")
        symbol = _required_symbol_name(
            raw.get("dispatch_return_symbol"),
            f"callback ABI {index} dispatch return",
        )
        if rva in callback_returns:
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"native-engine callback ABI inventory duplicates RVA {rva:#x}"
            )
        callback_returns[rva] = symbol
        callback_inventory_returns.append(symbol)
    if callback_inventory_returns != listed_callback_returns:
        raise RelationalInterpreterNativeLaunchGenerationError(
            "launch-wrapper callback symbols disagree with callback ABIs"
        )

    binary = _parse_stage_a_pe(candidate_path)
    try:
        if binary.bitness != 32 or binary.machine != "i386":
            raise RelationalInterpreterNativeLaunchGenerationError(
                "native launch artifact binding requires an x86 PE32 candidate"
            )
        if binary.tls_callback_rvas is None:
            detail = binary.tls_callback_parse_error or "unknown parse error"
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"candidate TLS callbacks are not exactly parseable: {detail}"
            )
        if binary.tls_callback_array_immutable is not True:
            raise RelationalInterpreterNativeLaunchGenerationError(
                "candidate TLS callback array is not immutable"
            )
        tls_callback_rvas = tuple(binary.tls_callback_rvas)
        missing = [
            rva for rva in tls_callback_rvas if rva not in callback_returns
        ]
        if missing:
            raise RelationalInterpreterNativeLaunchGenerationError(
                "native-engine plan omits candidate TLS callback ABIs: "
                + ", ".join(f"{rva:#x}" for rva in missing)
            )

        # Dispatch function names are part of the reviewed native-engine ABI.
        # Return and termination names are generated per plan and therefore
        # come from the versioned role inventory above.
        entry_dispatch = "stage_b_native_run_entry"
        callback_dispatch = "stage_b_native_run_callback"
        requested = [entry_dispatch, entry_return]
        if tls_callback_rvas:
            requested.append(callback_dispatch)
        requested.extend(callback_returns[rva] for rva in tls_callback_rvas)
        requested.append(termination)
        symbol_rvas = _resolve_executable_linker_symbols(
            Path(linker_map), binary, tuple(requested)
        )

        routes: list[NativeLaunchGraphRouteSpec] = [
            NativeLaunchGraphRouteSpec(
                "entry", "dispatch", symbol_rvas[entry_dispatch]
            )
        ]
        routes.extend(
            NativeLaunchGraphRouteSpec(
                "tls_callback",
                "dispatch",
                symbol_rvas[callback_dispatch],
                source_index=index,
            )
            for index, _ in enumerate(tls_callback_rvas)
        )
        routes.append(
            NativeLaunchGraphRouteSpec(
                "stable_cutpoint",
                "returned",
                source_rva=symbol_rvas[entry_return],
            )
        )
        routes.extend(
            NativeLaunchGraphRouteSpec(
                "stable_cutpoint",
                "returned",
                source_rva=symbol_rvas[callback_returns[rva]],
            )
            for rva in tls_callback_rvas
        )
        routes.append(
            NativeLaunchGraphRouteSpec(
                "stable_cutpoint",
                "terminated",
                source_rva=symbol_rvas[termination],
            )
        )
        spec = NativeLaunchGraphSpec(
            routes=tuple(routes),
            module_name=module_name,
            namespace=namespace,
        )
        _validate_graph_names(spec)
        bindings = tuple((name, symbol_rvas[name]) for name in requested)
        return NativeLaunchGraphArtifactBinding(
            spec=spec,
            symbol_rvas=bindings,
            tls_callback_rvas=tls_callback_rvas,
        )
    finally:
        binary.pe.close()


@dataclass(frozen=True)
class NativeLaunchGraphNode:
    instruction: NativeLaunchInstruction
    instruction_kind: GraphInstructionKind
    successors: tuple[int, ...]
    rank: int
    terminal: GraphDestinationKind | None = None


@dataclass(frozen=True)
class NativeLaunchGraphRoute:
    spec: NativeLaunchGraphRouteSpec
    source_rva: int
    nodes: tuple[NativeLaunchGraphNode, ...]


@dataclass(frozen=True)
class RelationalInterpreterNativeLaunchGraphPlan:
    candidate_bytes: bytes
    candidate_sha256: str
    engine_segments_sha256: str
    pe_literal: str
    import_certificate_literal: str
    entrypoint_rva: int
    tls_callback_rvas: tuple[int, ...]
    cutpoints: tuple[tuple[CutpointKind, int], ...]
    spec: NativeLaunchGraphSpec
    routes: tuple[NativeLaunchGraphRoute, ...]

    def payload(self) -> dict[str, object]:
        return {
            "format": "stage-a-relational-interpreter-native-launch-graph-v1",
            "acceptance_authority": False,
            "candidate_sha256": self.candidate_sha256,
            "engine_segments_sha256": self.engine_segments_sha256,
            "canonical_roots": {
                "entrypoint_rva": self.entrypoint_rva,
                "tls_callback_rvas": list(self.tls_callback_rvas),
            },
            "lean_module": self.spec.module_name,
            "lean_namespace": self.spec.namespace,
            "lean_terms": {
                "checked_graph": "generatedCheckedNativeLaunchGraph",
                "static_graph": "generatedNativeLaunchGraphStaticChecked",
            },
            "cutpoints": [
                {"kind": kind, "rva": rva} for kind, rva in self.cutpoints
            ],
            "routes": [
                {
                    "source_kind": route.spec.source_kind,
                    "source_index": route.spec.source_index,
                    "source_rva": route.source_rva,
                    "destination_kind": route.spec.destination_kind,
                    "destination_rva": route.spec.destination_rva,
                    "nodes": [
                        {
                            "rva": node.instruction.rva,
                            "bytes": node.instruction.data.hex(),
                            "instruction_kind": node.instruction_kind,
                            "successors": list(node.successors),
                            "rank": node.rank,
                            "terminal": node.terminal,
                        }
                        for node in route.nodes
                    ],
                }
                for route in self.routes
            ],
        }


@dataclass(frozen=True)
class NativeLaunchCutpointSpec:
    kind: CutpointKind
    rva: int


@dataclass(frozen=True)
class NativeLaunchPathSpec:
    source_kind: SourceKind
    destination_kind: DestinationKind
    instruction_rvas: tuple[int, ...]
    source_index: int | None = None
    destination_index: int | None = None


@dataclass(frozen=True)
class NativeLaunchCertificateSpec:
    cutpoints: tuple[NativeLaunchCutpointSpec, ...]
    paths: tuple[NativeLaunchPathSpec, ...]
    module_name: str = INTERPRETER_NATIVE_LAUNCH_MODULE
    namespace: str = "StageA.GeneratedRelational.InterpreterNativeLaunch"


@dataclass(frozen=True)
class NativeLaunchInstruction:
    rva: int
    data: bytes

    def lean(self) -> str:
        values = ", ".join(str(byte) for byte in self.data)
        return f"{{ rva := {self.rva}, bytes := [{values}] }}"


@dataclass(frozen=True)
class NativeLaunchResolvedPath:
    spec: NativeLaunchPathSpec
    instructions: tuple[NativeLaunchInstruction, ...]


@dataclass(frozen=True)
class RelationalInterpreterNativeLaunchPlan:
    candidate_bytes: bytes
    candidate_sha256: str
    pe_literal: str
    import_certificate_literal: str
    entrypoint_rva: int
    tls_callback_rvas: tuple[int, ...]
    spec: NativeLaunchCertificateSpec
    paths: tuple[NativeLaunchResolvedPath, ...]

    def payload(self) -> dict[str, object]:
        return {
            "format": "stage-a-relational-interpreter-native-launch-v1",
            "acceptance_authority": False,
            "candidate_sha256": self.candidate_sha256,
            "canonical_roots": {
                "entrypoint_rva": self.entrypoint_rva,
                "tls_callback_rvas": list(self.tls_callback_rvas),
            },
            "cutpoints": [
                {"kind": cutpoint.kind, "rva": cutpoint.rva}
                for cutpoint in self.spec.cutpoints
            ],
            "paths": [
                {
                    "source_kind": path.spec.source_kind,
                    "source_index": path.spec.source_index,
                    "destination_kind": path.spec.destination_kind,
                    "destination_index": path.spec.destination_index,
                    "instruction_rvas": [
                        instruction.rva for instruction in path.instructions
                    ],
                    "instruction_bytes": [
                        instruction.data.hex() for instruction in path.instructions
                    ],
                }
                for path in self.paths
            ],
        }


def build_relational_interpreter_native_launch_plan(
    *,
    candidate_pe: Path | str,
    spec: NativeLaunchCertificateSpec,
) -> RelationalInterpreterNativeLaunchPlan:
    """Bind a generic finite launch-route specification to one exact PE32."""

    _validate_names(spec)
    path = Path(candidate_pe)
    try:
        candidate_bytes = path.read_bytes()
    except OSError as exc:
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"cannot read candidate PE: {exc}"
        ) from exc

    binary = _parse_stage_a_pe(path)
    try:
        if binary.bitness != 32 or binary.machine != "i386":
            raise RelationalInterpreterNativeLaunchGenerationError(
                "native launch certificates require an x86 PE32 candidate"
            )
        if binary.entrypoint_rva <= 0:
            raise RelationalInterpreterNativeLaunchGenerationError(
                "candidate PE has no canonical entrypoint RVA"
            )
        if binary.tls_callback_rvas is None:
            detail = binary.tls_callback_parse_error or "unknown parse error"
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"candidate TLS callbacks are not exactly parseable: {detail}"
            )
        if binary.tls_callback_array_immutable is not True:
            raise RelationalInterpreterNativeLaunchGenerationError(
                "candidate TLS callback array is not immutable"
            )

        _validate_cutpoints(binary, spec.cutpoints)
        expected_sources = _expected_sources(binary, spec.cutpoints)
        actual_sources = tuple(
            (path_spec.source_kind, path_spec.source_index)
            for path_spec in spec.paths
        )
        if actual_sources != expected_sources:
            raise RelationalInterpreterNativeLaunchGenerationError(
                "paths must cover entry, TLS callbacks, return wrappers, and "
                "termination wrappers exactly once in canonical order"
            )

        resolved: list[NativeLaunchResolvedPath] = []
        for ordinal, path_spec in enumerate(spec.paths):
            _validate_path_shape(binary, spec.cutpoints, path_spec, ordinal)
            instructions = tuple(
                NativeLaunchInstruction(rva, _instruction_bytes(binary, rva))
                for rva in path_spec.instruction_rvas
            )
            expected_start = _source_rva(binary, spec.cutpoints, path_spec)
            if instructions[0].rva != expected_start:
                raise RelationalInterpreterNativeLaunchGenerationError(
                    f"path {ordinal} starts at 0x{instructions[0].rva:x}, "
                    f"expected 0x{expected_start:x}"
                )
            resolved.append(NativeLaunchResolvedPath(path_spec, instructions))

        return RelationalInterpreterNativeLaunchPlan(
            candidate_bytes=candidate_bytes,
            candidate_sha256=sha256_bytes(candidate_bytes),
            pe_literal=_lean_pe(binary, "generatedNativeLaunchCandidateBytes"),
            import_certificate_literal=_lean_import_certificate(binary),
            entrypoint_rva=binary.entrypoint_rva,
            tls_callback_rvas=tuple(binary.tls_callback_rvas),
            spec=spec,
            paths=tuple(resolved),
        )
    finally:
        binary.pe.close()


def build_relational_interpreter_native_launch_graph_plan(
    *,
    candidate_pe: Path | str,
    engine_segments: Path | str,
    spec: NativeLaunchGraphSpec,
) -> RelationalInterpreterNativeLaunchGraphPlan:
    """Recover a complete finite wrapper CFG from exact candidate bytes.

    The engine-segment artifact is an untrusted proposal input.  Its candidate
    hash and any overlapping diagnostics/control sites are checked here; Lean
    must still re-check the emitted graph against the embedded PE bytes before
    it can carry proof authority.
    """

    _validate_graph_names(spec)
    candidate_path = Path(candidate_pe)
    engine_path = Path(engine_segments)
    try:
        candidate_bytes = candidate_path.read_bytes()
    except OSError as exc:
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"cannot read candidate PE: {exc}"
        ) from exc
    try:
        engine_bytes = engine_path.read_bytes()
        report = json.loads(engine_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"cannot read engine-segment evidence: {exc}"
        ) from exc
    if not isinstance(report, Mapping):
        raise RelationalInterpreterNativeLaunchGenerationError(
            "engine-segment evidence must be a JSON object"
        )

    candidate_sha256 = sha256_bytes(candidate_bytes)
    _validate_engine_segment_binding(report, candidate_sha256)
    binary = _parse_stage_a_pe(candidate_path)
    try:
        if binary.bitness != 32 or binary.machine != "i386":
            raise RelationalInterpreterNativeLaunchGenerationError(
                "native launch CFG certificates require an x86 PE32 candidate"
            )
        if binary.entrypoint_rva <= 0:
            raise RelationalInterpreterNativeLaunchGenerationError(
                "candidate PE has no canonical entrypoint RVA"
            )
        if binary.tls_callback_rvas is None:
            detail = binary.tls_callback_parse_error or "unknown parse error"
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"candidate TLS callbacks are not exactly parseable: {detail}"
            )
        if binary.tls_callback_array_immutable is not True:
            raise RelationalInterpreterNativeLaunchGenerationError(
                "candidate TLS callback array is not immutable"
            )

        _validate_graph_route_inventory(binary, spec.routes)
        routes = tuple(
            _build_native_launch_graph_route(binary, route, report)
            for route in spec.routes
        )
        _reject_overlapping_engine_segment_issues(report, routes)
        cutpoints = _native_launch_graph_cutpoints(routes)
        return RelationalInterpreterNativeLaunchGraphPlan(
            candidate_bytes=candidate_bytes,
            candidate_sha256=candidate_sha256,
            engine_segments_sha256=sha256_bytes(engine_bytes),
            pe_literal=_lean_pe(
                binary, "generatedNativeLaunchGraphCandidateBytes"
            ),
            import_certificate_literal=_lean_import_certificate(binary),
            entrypoint_rva=binary.entrypoint_rva,
            tls_callback_rvas=tuple(binary.tls_callback_rvas),
            cutpoints=cutpoints,
            spec=spec,
            routes=routes,
        )
    finally:
        binary.pe.close()


def relational_interpreter_native_launch_source(
    plan: RelationalInterpreterNativeLaunchPlan,
) -> str:
    """Emit the self-contained reflected Lean certificate module."""

    spec = plan.spec
    cutpoints = ",\n  ".join(_lean_cutpoint(value) for value in spec.cutpoints)
    path_definitions = "\n\n".join(
        _lean_path(index, path) for index, path in enumerate(plan.paths)
    )
    path_names = ", ".join(
        f"generatedNativeLaunchPath{index:04d}"
        for index in range(len(plan.paths))
    )
    byte_tree = _lean_byte_tree_definitions(
        "generatedNativeLaunchCandidateBytes", plan.candidate_bytes
    )

    return f"""import StageA.RelationalInterpreterNativeLaunch

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

{byte_tree}

def generatedNativeLaunchCandidatePe : PE32 :=
  {plan.pe_literal}

def generatedNativeLaunchImportCertificate : ImportTableCertificate :=
  {plan.import_certificate_literal}

def generatedNativeLaunchImports : List PEImport :=
  generatedNativeLaunchImportCertificate.imports

theorem generatedNativeLaunchCandidateParsed :
    parsePE32Tree generatedNativeLaunchCandidateBytes =
      some generatedNativeLaunchCandidatePe := by
  decide +kernel

theorem generatedNativeLaunchImportsParsed :
    parseImports generatedNativeLaunchCandidatePe =
      some generatedNativeLaunchImports := by
  decide +kernel

def generatedNativeLaunchCutpoints : List StableInterpreterCutpoint := [
  {cutpoints}
]

{path_definitions}

def generatedNativeLaunchCertificate : ExactNativeLaunchWrapperCertificate := {{
  cutpoints := generatedNativeLaunchCutpoints
  paths := [{path_names}]
}}

theorem generatedNativeLaunchCertificateStaticChecked :
    generatedNativeLaunchCertificate.staticChecked
      generatedNativeLaunchCandidatePe generatedNativeLaunchImports = true := by
  decide +kernel

theorem generatedNativeLaunchCertificateSemanticSound
    (environment : NativeWorldEnvironment) :
    generatedNativeLaunchCertificate.SemanticallySound {{
      pe := generatedNativeLaunchCandidatePe
      imports := generatedNativeLaunchImports
      environment := environment
    }} :=
  generatedNativeLaunchCertificate.semanticSound _

#print axioms generatedNativeLaunchCertificateStaticChecked
#print axioms generatedNativeLaunchCertificateSemanticSound

end {spec.namespace}
"""


def write_relational_interpreter_native_launch(
    out: Path | str,
    *,
    candidate_pe: Path | str,
    spec: NativeLaunchCertificateSpec,
) -> Path:
    """Write one generated module beneath an output ``StageA`` directory."""

    plan = build_relational_interpreter_native_launch_plan(
        candidate_pe=candidate_pe, spec=spec
    )
    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    destination = stage_a / f"{spec.module_name}.lean"
    destination.write_text(
        relational_interpreter_native_launch_source(plan), encoding="utf-8"
    )
    return destination


def relational_interpreter_native_launch_graph_source(
    plan: RelationalInterpreterNativeLaunchGraphPlan,
) -> str:
    """Emit exact graph data and its reviewed Lean checks.

    The generated module contains no semantic acceptance claim.  It embeds the
    candidate bytes, re-parses the PE and imports, and asks the reviewed graph
    checker to validate every decoded node, successor, root, cutpoint, and
    well-founded rank.
    """

    node_definitions: list[str] = []
    route_definitions: list[str] = []
    replay_theorems: list[str] = []
    route_names: list[str] = []
    for route_index, route in enumerate(plan.routes):
        node_names: list[str] = []
        for node_index, node in enumerate(route.nodes):
            node_name = _native_launch_graph_node_name(route_index, node_index)
            node_names.append(node_name)
            node_definitions.append(
                _lean_native_launch_graph_node(node_name, node)
            )
        route_name = _native_launch_graph_route_name(route_index)
        route_names.append(route_name)
        route_definitions.append(
            _lean_native_launch_graph_route(
                plan, route_name, route, node_names
            )
        )
        replay_theorems.append(
            _lean_native_launch_graph_replay_theorem(route_name)
        )

    byte_tree = _lean_byte_tree_definitions(
        "generatedNativeLaunchGraphCandidateBytes", plan.candidate_bytes
    )
    cutpoints = ",\n  ".join(
        f"{{ kind := .{_lean_graph_cutpoint_kind(kind)}, rva := {rva} }}"
        for kind, rva in plan.cutpoints
    )
    nodes = "\n\n".join(node_definitions)
    routes = "\n\n".join(route_definitions)
    replay = "\n\n".join(replay_theorems)
    certificate_routes = ", ".join(route_names)

    return f"""import StageA.RelationalInterpreterMixedLaunchRefinement

namespace {plan.spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedLaunchRefinement
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

{byte_tree}

def generatedNativeLaunchGraphCandidatePe : PE32 :=
  {plan.pe_literal}

def generatedNativeLaunchGraphImportCertificate : ImportTableCertificate :=
  {plan.import_certificate_literal}

def generatedNativeLaunchGraphImports : List PEImport :=
  generatedNativeLaunchGraphImportCertificate.imports

theorem generatedNativeLaunchGraphCandidateParsed :
    parsePE32Tree generatedNativeLaunchGraphCandidateBytes =
      some generatedNativeLaunchGraphCandidatePe := by
  decide +kernel

theorem generatedNativeLaunchGraphImportsParsed :
    parseImports generatedNativeLaunchGraphCandidatePe =
      some generatedNativeLaunchGraphImports := by
  decide +kernel

def generatedNativeLaunchGraphCutpoints : List StableInterpreterCutpoint := [
  {cutpoints}
]

{nodes}

{routes}

def generatedNativeLaunchGraphCertificate :
    ExactNativeLaunchGraphCertificate := {{
  cutpoints := generatedNativeLaunchGraphCutpoints
  routes := [{certificate_routes}]
}}

theorem generatedNativeLaunchGraphStaticChecked :
    generatedNativeLaunchGraphCertificate.staticChecked
      generatedNativeLaunchGraphCandidatePe
      generatedNativeLaunchGraphImports = true := by
  decide +kernel

def generatedCheckedNativeLaunchGraph : CheckedExactNativeLaunchGraph := {{
  candidatePe := generatedNativeLaunchGraphCandidatePe
  candidateImports := generatedNativeLaunchGraphImports
  certificate := generatedNativeLaunchGraphCertificate
  staticChecked := generatedNativeLaunchGraphStaticChecked
}}

{replay}

#print axioms generatedNativeLaunchGraphStaticChecked
#print axioms ReflectedNativeLaunchGraphRoute.replay?_sound

end {plan.spec.namespace}
"""


def write_relational_interpreter_native_launch_graph(
    out: Path | str,
    *,
    candidate_pe: Path | str,
    engine_segments: Path | str,
    spec: NativeLaunchGraphSpec,
) -> RelationalInterpreterNativeLaunchGraphPlan:
    """Write deterministic graph-plan JSON and generated Lean source."""

    plan = build_relational_interpreter_native_launch_graph_plan(
        candidate_pe=candidate_pe,
        engine_segments=engine_segments,
        spec=spec,
    )
    output = Path(out)
    stage_a = output / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    (stage_a / f"{spec.module_name}.lean").write_text(
        relational_interpreter_native_launch_graph_source(plan),
        encoding="utf-8",
    )
    write_json(
        output / INTERPRETER_NATIVE_LAUNCH_GRAPH_PLAN_FILENAME,
        plan.payload(),
    )
    return plan


def _validate_names(spec: NativeLaunchCertificateSpec) -> None:
    if _LOCAL_NAME.fullmatch(spec.module_name) is None:
        raise RelationalInterpreterNativeLaunchGenerationError(
            "module_name must be a local Lean module name"
        )
    if _NAMESPACE.fullmatch(spec.namespace) is None:
        raise RelationalInterpreterNativeLaunchGenerationError(
            "namespace must be a canonical Lean namespace"
        )


def _required_symbol_name(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"{label} symbol is missing or malformed"
        )
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) is None:
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"{label} symbol is not a portable linker symbol"
        )
    return value


def _required_u32(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"{label} must be an unsigned 32-bit integer"
        )
    if not 0 <= value < _U32_LIMIT:
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"{label} lies outside the unsigned 32-bit range"
        )
    return value


def _resolve_executable_linker_symbols(
    linker_map: Path,
    binary: StageABinary,
    requested: tuple[str, ...],
) -> dict[str, int]:
    if len(set(requested)) != len(requested):
        raise RelationalInterpreterNativeLaunchGenerationError(
            "native launch roles resolve to duplicate symbol names"
        )
    try:
        lines = linker_map.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"cannot read candidate linker map: {exc}"
        ) from exc
    wanted = set(requested)
    found: dict[str, int] = {}
    for line in lines:
        parsed = _parse_linker_map_symbol_line(line, binary)
        if parsed is None:
            continue
        rva, raw_name = parsed
        aliases = (raw_name, raw_name.removeprefix("_"))
        for name in aliases:
            if name not in wanted:
                continue
            previous = found.setdefault(name, rva)
            if previous != rva:
                raise RelationalInterpreterNativeLaunchGenerationError(
                    f"candidate linker map gives ambiguous RVAs for {name}"
                )
    missing = [name for name in requested if name not in found]
    if missing:
        raise RelationalInterpreterNativeLaunchGenerationError(
            "candidate linker map omits native launch symbols: "
            + ", ".join(missing)
        )
    for name, rva in found.items():
        if not any(
            section.executable and section.rva_start <= rva < section.rva_end
            for section in binary.sections
        ):
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"native launch symbol {name} at {rva:#x} is not executable"
            )
    return found


def _validate_graph_names(spec: NativeLaunchGraphSpec) -> None:
    if _LOCAL_NAME.fullmatch(spec.module_name) is None:
        raise RelationalInterpreterNativeLaunchGenerationError(
            "module_name must be a local Lean module name"
        )
    if _NAMESPACE.fullmatch(spec.namespace) is None:
        raise RelationalInterpreterNativeLaunchGenerationError(
            "namespace must be a canonical Lean namespace"
        )


def _native_launch_graph_cutpoints(
    routes: tuple[NativeLaunchGraphRoute, ...],
) -> tuple[tuple[CutpointKind, int], ...]:
    dispatch = tuple(
        dict.fromkeys(
            route.spec.destination_rva
            for route in routes
            if route.spec.destination_kind == "dispatch"
        )
    )
    returned = tuple(
        route.source_rva
        for route in routes
        if route.spec.source_kind == "stable_cutpoint"
        and route.spec.destination_kind == "returned"
    )
    terminated = tuple(
        route.source_rva
        for route in routes
        if route.spec.source_kind == "stable_cutpoint"
        and route.spec.destination_kind == "terminated"
    )
    values: tuple[tuple[CutpointKind, int], ...] = (
        tuple(("dispatch", value) for value in dispatch if value is not None)
        + tuple(("return_wrapper", value) for value in returned)
        + tuple(("termination_wrapper", value) for value in terminated)
    )
    rvas = tuple(rva for _, rva in values)
    if len(set(rvas)) != len(rvas):
        raise RelationalInterpreterNativeLaunchGenerationError(
            "launch graph cutpoint RVAs must be globally unique"
        )
    return values


def _native_launch_graph_node_name(route_index: int, node_index: int) -> str:
    return (
        f"generatedNativeLaunchGraphRoute{route_index:04d}"
        f"Node{node_index:04d}"
    )


def _native_launch_graph_route_name(route_index: int) -> str:
    return f"generatedNativeLaunchGraphRoute{route_index:04d}"


def _lean_graph_cutpoint_kind(kind: CutpointKind) -> str:
    return {
        "dispatch": "dispatch",
        "return_wrapper": "returnWrapper",
        "termination_wrapper": "terminationWrapper",
    }[kind]


def _lean_native_launch_graph_instruction_kind(
    node: NativeLaunchGraphNode,
) -> str:
    return {
        "ordinary": ".ordinary",
        "x87_fnsave": ".x87Frame .fnSave",
        "x87_frstor": ".x87Frame .frStor",
    }[node.instruction_kind]


def _lean_native_launch_graph_terminal(
    node: NativeLaunchGraphNode,
) -> str:
    return "none" if node.terminal is None else f"some .{node.terminal}"


def _lean_native_launch_graph_node(
    name: str, node: NativeLaunchGraphNode
) -> str:
    successors = ", ".join(str(value) for value in node.successors)
    return f"""def {name} : ReflectedNativeLaunchGraphNode := {{
  instruction := {node.instruction.lean()}
  kind := {_lean_native_launch_graph_instruction_kind(node)}
  successors := [{successors}]
  rank := {node.rank}
  terminal := {_lean_native_launch_graph_terminal(node)}
}}"""


def _native_launch_graph_source(
    plan: RelationalInterpreterNativeLaunchGraphPlan,
    route: NativeLaunchGraphRoute,
) -> str:
    if route.spec.source_kind == "entry":
        return ".canonicalRoot .entry"
    if route.spec.source_kind == "tls_callback":
        assert route.spec.source_index is not None
        return f".canonicalRoot (.tlsCallback {route.spec.source_index})"
    kind: CutpointKind = (
        "return_wrapper"
        if route.spec.destination_kind == "returned"
        else "termination_wrapper"
    )
    return f".stableCutpoint {plan.cutpoints.index((kind, route.source_rva))}"


def _native_launch_graph_destination(
    plan: RelationalInterpreterNativeLaunchGraphPlan,
    route: NativeLaunchGraphRoute,
) -> str:
    if route.spec.destination_kind == "returned":
        return ".returned"
    if route.spec.destination_kind == "terminated":
        return ".terminated"
    assert route.spec.destination_rva is not None
    index = plan.cutpoints.index(("dispatch", route.spec.destination_rva))
    return f".stableCutpoint {index}"


def _lean_native_launch_graph_route(
    plan: RelationalInterpreterNativeLaunchGraphPlan,
    name: str,
    route: NativeLaunchGraphRoute,
    node_names: list[str],
) -> str:
    nodes = ",\n    ".join(node_names)
    return f"""def {name} : ReflectedNativeLaunchGraphRoute := {{
  source := {_native_launch_graph_source(plan, route)}
  destination := {_native_launch_graph_destination(plan, route)}
  nodes := [
    {nodes}
  ]
}}"""


def _lean_native_launch_graph_replay_theorem(route_name: str) -> str:
    return f"""theorem {route_name}ReplaySound
    (program : ExactNativeWorldProgram)
    (before : NativeWorldExecution)
    (result : NativeLaunchGraphReplay)
    (replayed :
      {route_name}.replay? program generatedNativeLaunchGraphCutpoints before =
        some result) :
    {route_name}.source.matches program.pe
        generatedNativeLaunchGraphCutpoints before = true /\\
      {route_name}.destination.matches generatedNativeLaunchGraphCutpoints
        result.after = true /\\
      NonemptyRelatedPath program.transitionSystem before result.observations
        result.after :=
  {route_name}.replay?_sound program
    generatedNativeLaunchGraphCutpoints before result replayed"""


def _validate_engine_segment_binding(
    report: Mapping[str, Any], candidate_sha256: str
) -> None:
    if report.get("format") != "stage-a-engine-segment-evidence-v1":
        raise RelationalInterpreterNativeLaunchGenerationError(
            "unsupported engine-segment evidence format"
        )
    candidate = report.get("candidate")
    if not isinstance(candidate, Mapping):
        raise RelationalInterpreterNativeLaunchGenerationError(
            "engine-segment evidence has no candidate binding"
        )
    if candidate.get("pe_sha256") != candidate_sha256:
        raise RelationalInterpreterNativeLaunchGenerationError(
            "engine-segment evidence is bound to a different candidate PE"
        )
    if candidate.get("bitness") != 32 or candidate.get("machine") != "i386":
        raise RelationalInterpreterNativeLaunchGenerationError(
            "engine-segment evidence is not for x86 PE32"
        )
    if report.get("acceptance_authority") is not False:
        raise RelationalInterpreterNativeLaunchGenerationError(
            "engine-segment evidence must remain a non-authoritative proposal"
        )
    control_sites = report.get("control_sites")
    if not isinstance(control_sites, list) or any(
        not isinstance(row, Mapping)
        or not isinstance(row.get("instruction_rva"), int)
        or not isinstance(row.get("kind"), str)
        or (
            row.get("target_rva") is not None
            and not isinstance(row.get("target_rva"), int)
        )
        for row in control_sites
    ):
        raise RelationalInterpreterNativeLaunchGenerationError(
            "engine-segment control-site inventory is malformed"
        )


def _validate_graph_route_inventory(
    binary: StageABinary, routes: tuple[NativeLaunchGraphRouteSpec, ...]
) -> None:
    assert binary.tls_callback_rvas is not None
    expected_roots = (("entry", None),) + tuple(
        ("tls_callback", index)
        for index in range(len(binary.tls_callback_rvas))
    )
    actual_roots = tuple(
        (route.source_kind, route.source_index)
        for route in routes
        if route.source_kind != "stable_cutpoint"
    )
    if actual_roots != expected_roots:
        raise RelationalInterpreterNativeLaunchGenerationError(
            "launch graph routes must cover entry and parsed TLS callbacks "
            "exactly once in canonical order"
        )
    root_prefix = tuple(
        (route.source_kind, route.source_index)
        for route in routes[: len(expected_roots)]
    )
    if root_prefix != expected_roots or any(
        route.source_kind != "stable_cutpoint"
        for route in routes[len(expected_roots) :]
    ):
        raise RelationalInterpreterNativeLaunchGenerationError(
            "launch graph routes must list canonical roots before wrapper "
            "sources"
        )
    if not routes:
        raise RelationalInterpreterNativeLaunchGenerationError(
            "at least one launch graph route is required"
        )

    seen_sources: set[tuple[str, int | None, int | None]] = set()
    for index, route in enumerate(routes):
        key = (route.source_kind, route.source_index, route.source_rva)
        if key in seen_sources:
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"launch graph route {index} duplicates a source"
            )
        seen_sources.add(key)
        if route.source_kind == "entry":
            if route.source_index is not None or route.source_rva is not None:
                raise RelationalInterpreterNativeLaunchGenerationError(
                    f"launch graph route {index} entry source is not canonical"
                )
            if route.destination_kind != "dispatch":
                raise RelationalInterpreterNativeLaunchGenerationError(
                    f"launch graph route {index} entry must reach dispatch"
                )
        elif route.source_kind == "tls_callback":
            if (
                route.source_index is None
                or not 0 <= route.source_index < len(binary.tls_callback_rvas)
                or route.source_rva is not None
            ):
                raise RelationalInterpreterNativeLaunchGenerationError(
                    f"launch graph route {index} TLS source is not canonical"
                )
            if route.destination_kind != "dispatch":
                raise RelationalInterpreterNativeLaunchGenerationError(
                    f"launch graph route {index} TLS source must reach dispatch"
                )
        elif route.source_kind == "stable_cutpoint":
            if route.source_index is not None or route.source_rva is None:
                raise RelationalInterpreterNativeLaunchGenerationError(
                    f"launch graph route {index} wrapper source needs an exact RVA"
                )
            _require_u32(route.source_rva, f"launch graph route {index} source RVA")
            _require_executable_rva(binary, route.source_rva, f"route {index} source")
            if route.destination_kind not in {"returned", "terminated"}:
                raise RelationalInterpreterNativeLaunchGenerationError(
                    f"launch graph route {index} wrapper has invalid destination"
                )
        else:
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"launch graph route {index} has unsupported source kind"
            )

        if route.destination_kind == "dispatch":
            if route.destination_rva is None:
                raise RelationalInterpreterNativeLaunchGenerationError(
                    f"launch graph route {index} dispatch has no exact RVA"
                )
            _require_u32(
                route.destination_rva,
                f"launch graph route {index} destination RVA",
            )
            _require_executable_rva(
                binary, route.destination_rva, f"route {index} destination"
            )
        elif route.destination_rva is not None:
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"launch graph route {index} terminal destination has an RVA"
            )

    wrapper_destinations = tuple(
        route.destination_kind
        for route in routes
        if route.source_kind == "stable_cutpoint"
    )
    canonical_wrapper_destinations = tuple(
        sorted(
            wrapper_destinations,
            key={"returned": 0, "terminated": 1}.__getitem__,
        )
    )
    if wrapper_destinations != canonical_wrapper_destinations:
        raise RelationalInterpreterNativeLaunchGenerationError(
            "launch graph wrapper routes must list returned then terminated "
            "destinations in canonical order"
        )


def _graph_source_rva(
    binary: StageABinary, route: NativeLaunchGraphRouteSpec
) -> int:
    if route.source_kind == "entry":
        return binary.entrypoint_rva
    if route.source_kind == "tls_callback":
        assert binary.tls_callback_rvas is not None
        assert route.source_index is not None
        return binary.tls_callback_rvas[route.source_index]
    assert route.source_rva is not None
    return route.source_rva


def _build_native_launch_graph_route(
    binary: StageABinary,
    route: NativeLaunchGraphRouteSpec,
    report: Mapping[str, Any],
) -> NativeLaunchGraphRoute:
    source_rva = _graph_source_rva(binary, route)
    destination_rva = route.destination_rva
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    pending = [source_rva]
    instructions: dict[int, NativeLaunchInstruction] = {}
    instruction_kinds: dict[int, GraphInstructionKind] = {}
    successors: dict[int, tuple[int, ...]] = {}
    terminals: dict[int, GraphDestinationKind | None] = {}
    occupied: dict[int, int] = {}
    maximum_nodes = 16384

    while pending:
        rva = pending.pop()
        if destination_rva is not None and rva == destination_rva:
            continue
        if rva in instructions:
            continue
        if len(instructions) >= maximum_nodes:
            raise RelationalInterpreterNativeLaunchGenerationError(
                "launch graph exceeds the finite node budget"
            )
        instruction = _decode_exact_instruction(binary, decoder, rva)
        data = bytes(instruction.bytes)
        end = rva + len(data)
        overlap = next(
            (occupied[address] for address in range(rva, end) if address in occupied),
            None,
        )
        if overlap is not None:
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"launch graph has overlapping decodes at 0x{rva:x} and 0x{overlap:x}"
            )
        for address in range(rva, end):
            occupied[address] = rva

        node_successors, terminal = _native_launch_instruction_successors(
            binary, instruction, route
        )
        instructions[rva] = NativeLaunchInstruction(rva, data)
        instruction_kinds[rva] = _native_launch_instruction_kind(instruction)
        successors[rva] = node_successors
        terminals[rva] = terminal
        _check_engine_segment_control_site(
            report, binary, instruction, node_successors
        )
        for successor in reversed(node_successors):
            if destination_rva is not None and successor == destination_rva:
                continue
            _require_executable_rva(
                binary, successor, f"launch graph successor from 0x{rva:x}"
            )
            pending.append(successor)

    ranks = _rank_acyclic_launch_graph(
        source_rva=source_rva,
        destination_rva=destination_rva,
        successors=successors,
        terminals=terminals,
    )
    if destination_rva is not None and not any(
        destination_rva in values for values in successors.values()
    ):
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"launch graph from 0x{source_rva:x} does not reach declared "
            f"dispatch 0x{destination_rva:x}"
        )
    if destination_rva is None and not any(terminals.values()):
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"launch graph from 0x{source_rva:x} has no terminal wrapper exit"
        )
    nodes = tuple(
        NativeLaunchGraphNode(
            instruction=instructions[rva],
            instruction_kind=instruction_kinds[rva],
            successors=successors[rva],
            rank=ranks[rva],
            terminal=terminals[rva],
        )
        for rva in sorted(instructions)
    )
    return NativeLaunchGraphRoute(route, source_rva, nodes)


def _decode_exact_instruction(
    binary: StageABinary, decoder: capstone.Cs, rva: int
) -> Any:
    _require_executable_rva(binary, rva, f"instruction at 0x{rva:x}")
    raw = bytes(binary.pe.get_data(rva, 15))
    rows = list(decoder.disasm(raw, binary.image_base + rva, count=1))
    if len(rows) != 1 or int(rows[0].address) != binary.image_base + rva:
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"instruction at RVA 0x{rva:x} does not decode exactly"
        )
    instruction = rows[0]
    data = bytes(instruction.bytes)
    if not data or bytes(binary.pe.get_data(rva, len(data))) != data:
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"instruction at RVA 0x{rva:x} is not backed by exact PE bytes"
        )
    _require_exact_executable_span(binary, rva, len(data), f"instruction at 0x{rva:x}")
    return instruction


def _native_launch_instruction_successors(
    binary: StageABinary,
    instruction: Any,
    route: NativeLaunchGraphRouteSpec,
) -> tuple[tuple[int, ...], GraphDestinationKind | None]:
    rva = int(instruction.address) - binary.image_base
    fallthrough = rva + int(instruction.size)
    mnemonic = instruction.mnemonic.lower()
    if mnemonic in {
        "hlt",
        "int",
        "int1",
        "int3",
        "into",
        "iret",
        "iretd",
        "syscall",
        "sysenter",
        "ud2",
    }:
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"launch graph reaches faulting or unsupported instruction {mnemonic} "
            f"at 0x{rva:x}"
        )

    if instruction.group(capstone.CS_GRP_RET):
        if route.destination_kind != "returned":
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"launch graph returns before {route.destination_kind} at 0x{rva:x}"
            )
        return (), "returned"

    if instruction.group(capstone.CS_GRP_CALL):
        target = _capstone_direct_target(binary, instruction)
        if target is not None:
            if route.destination_kind == "dispatch" and target == route.destination_rva:
                return (target,), "dispatch"
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"launch graph reaches nested direct call 0x{target:x} at 0x{rva:x}"
            )
        if route.destination_kind == "terminated" and _iat_transfer_rva(
            binary, instruction
        ) is not None:
            return (), "terminated"
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"launch graph reaches indirect call at 0x{rva:x}"
        )

    if instruction.group(capstone.CS_GRP_JUMP):
        target = _capstone_direct_target(binary, instruction)
        if target is None:
            if route.destination_kind == "terminated" and _iat_transfer_rva(
                binary, instruction
            ) is not None:
                return (), "terminated"
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"launch graph reaches indirect jump at 0x{rva:x}"
            )
        if instruction.id == x86_const.X86_INS_JMP:
            return (target,), (
                "dispatch"
                if route.destination_kind == "dispatch"
                and target == route.destination_rva
                else None
            )
        ordered = tuple(dict.fromkeys((target, fallthrough)))
        return ordered, None

    return (fallthrough,), None


def _native_launch_instruction_kind(instruction: Any) -> GraphInstructionKind:
    mnemonic = instruction.mnemonic.lower()
    if mnemonic == "fnsave":
        return "x87_fnsave"
    if mnemonic == "frstor":
        return "x87_frstor"
    return "ordinary"


def _capstone_direct_target(binary: StageABinary, instruction: Any) -> int | None:
    operands = instruction.operands
    if len(operands) != 1 or operands[0].type != x86_const.X86_OP_IMM:
        return None
    absolute = int(operands[0].imm) & (_U32_LIMIT - 1)
    if absolute < binary.image_base:
        return None
    return absolute - binary.image_base


def _iat_transfer_rva(binary: StageABinary, instruction: Any) -> int | None:
    operands = instruction.operands
    if len(operands) != 1 or operands[0].type != x86_const.X86_OP_MEM:
        return None
    memory = operands[0].mem
    if memory.segment != 0 or memory.base != 0 or memory.index != 0:
        return None
    absolute = int(memory.disp) & (_U32_LIMIT - 1)
    if absolute < binary.image_base:
        return None
    rva = absolute - binary.image_base
    return (
        rva
        if any(imported.thunk_rva == rva for imported in binary.imports)
        else None
    )


def _rank_acyclic_launch_graph(
    *,
    source_rva: int,
    destination_rva: int | None,
    successors: Mapping[int, tuple[int, ...]],
    terminals: Mapping[int, GraphDestinationKind | None],
) -> dict[int, int]:
    visiting: set[int] = set()
    ranks: dict[int, int] = {}

    def visit(rva: int) -> int:
        if destination_rva is not None and rva == destination_rva:
            return 0
        if rva in ranks:
            return ranks[rva]
        if rva in visiting:
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"launch graph contains an unranked cycle at 0x{rva:x}"
            )
        if rva not in successors:
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"launch graph successor 0x{rva:x} is absent"
            )
        visiting.add(rva)
        outgoing = successors[rva]
        if not outgoing:
            if terminals.get(rva) is None:
                raise RelationalInterpreterNativeLaunchGenerationError(
                    f"launch graph has an unclassified leaf at 0x{rva:x}"
                )
            rank = 1
        else:
            rank = 1 + max(visit(successor) for successor in outgoing)
        visiting.remove(rva)
        ranks[rva] = rank
        return rank

    visit(source_rva)
    if len(ranks) != len(successors):
        raise RelationalInterpreterNativeLaunchGenerationError(
            "launch graph contains nodes unreachable from its declared source"
        )
    return ranks


def _check_engine_segment_control_site(
    report: Mapping[str, Any],
    binary: StageABinary,
    instruction: Any,
    successors: tuple[int, ...],
) -> None:
    rows = report.get("control_sites")
    if not isinstance(rows, list):
        raise RelationalInterpreterNativeLaunchGenerationError(
            "engine-segment evidence has no control-site inventory"
        )
    rva = int(instruction.address) - binary.image_base
    matching = [
        row
        for row in rows
        if isinstance(row, Mapping)
        and row.get("instruction_rva") == rva
    ]
    # Most launch wrappers are intentionally outside the required kernel
    # closure.  Where the engine report does carry a row, exact target checks
    # happen in `_reject_overlapping_engine_segment_issues`; absence is not
    # promoted to authority here.
    if len(matching) > 1:
        raise RelationalInterpreterNativeLaunchGenerationError(
            "engine-segment control-site inventory is ambiguous"
        )
    if not matching:
        return
    row = matching[0]
    target = _capstone_direct_target(binary, instruction)
    reported_target = row.get("target_rva")
    if reported_target is not None and reported_target != target:
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"engine-segment control target disagrees at 0x{rva:x}"
        )
    if target is not None and target not in successors:
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"launch graph omits engine-segment target at 0x{rva:x}"
        )


def _reject_overlapping_engine_segment_issues(
    report: Mapping[str, Any], routes: tuple[NativeLaunchGraphRoute, ...]
) -> None:
    route_spans = [
        (node.instruction.rva, node.instruction.rva + len(node.instruction.data))
        for route in routes
        for node in route.nodes
    ]
    issues = report.get("issues")
    if not isinstance(issues, list):
        raise RelationalInterpreterNativeLaunchGenerationError(
            "engine-segment evidence has no issue inventory"
        )
    for issue in issues:
        if not isinstance(issue, Mapping):
            raise RelationalInterpreterNativeLaunchGenerationError(
                "engine-segment issue is malformed"
            )
        start = issue.get("rva_start")
        end = issue.get("rva_end")
        if not isinstance(start, int) or not isinstance(end, int) or start >= end:
            raise RelationalInterpreterNativeLaunchGenerationError(
                "engine-segment issue has an invalid RVA span"
            )
        if any(
            start < route_end and route_start < end
            for route_start, route_end in route_spans
        ):
            code = issue.get("code", "unknown")
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"engine-segment issue {code} overlaps the launch graph at 0x{start:x}"
            )


def _validate_cutpoints(
    binary: StageABinary, cutpoints: tuple[NativeLaunchCutpointSpec, ...]
) -> None:
    if not cutpoints:
        raise RelationalInterpreterNativeLaunchGenerationError(
            "at least one stable interpreter cutpoint is required"
        )
    if len({cutpoint.rva for cutpoint in cutpoints}) != len(cutpoints):
        raise RelationalInterpreterNativeLaunchGenerationError(
            "stable interpreter cutpoint RVAs must be unique"
        )
    allowed = {"dispatch", "return_wrapper", "termination_wrapper"}
    for index, cutpoint in enumerate(cutpoints):
        if cutpoint.kind not in allowed:
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"cutpoint {index} has unsupported kind {cutpoint.kind!r}"
            )
        _require_u32(cutpoint.rva, f"cutpoint {index} RVA")
        _require_executable_rva(binary, cutpoint.rva, f"cutpoint {index}")
    if not any(cutpoint.kind == "dispatch" for cutpoint in cutpoints):
        raise RelationalInterpreterNativeLaunchGenerationError(
            "at least one dispatch cutpoint is required"
        )


def _expected_sources(
    binary: StageABinary, cutpoints: tuple[NativeLaunchCutpointSpec, ...]
) -> tuple[tuple[str, int | None], ...]:
    assert binary.tls_callback_rvas is not None
    return (
        (("entry", None),)
        + tuple(
            ("tls_callback", index)
            for index in range(len(binary.tls_callback_rvas))
        )
        + tuple(
            ("stable_cutpoint", index)
            for index, cutpoint in enumerate(cutpoints)
            if cutpoint.kind == "return_wrapper"
        )
        + tuple(
            ("stable_cutpoint", index)
            for index, cutpoint in enumerate(cutpoints)
            if cutpoint.kind == "termination_wrapper"
        )
    )


def _validate_path_shape(
    binary: StageABinary,
    cutpoints: tuple[NativeLaunchCutpointSpec, ...],
    path: NativeLaunchPathSpec,
    ordinal: int,
) -> None:
    if not path.instruction_rvas:
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"path {ordinal} has no reflected instructions"
        )
    for index, rva in enumerate(path.instruction_rvas):
        _require_u32(rva, f"path {ordinal} instruction {index} RVA")

    if path.source_kind == "entry":
        if path.source_index is not None:
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"path {ordinal} entry source must not have an index"
            )
        _require_dispatch_destination(cutpoints, path, ordinal)
        return
    if path.source_kind == "tls_callback":
        callbacks = binary.tls_callback_rvas or ()
        if path.source_index is None or not 0 <= path.source_index < len(callbacks):
            raise RelationalInterpreterNativeLaunchGenerationError(
                f"path {ordinal} TLS source index is out of range"
            )
        _require_dispatch_destination(cutpoints, path, ordinal)
        return
    if path.source_kind != "stable_cutpoint":
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"path {ordinal} has unsupported source kind {path.source_kind!r}"
        )
    source = _cutpoint(cutpoints, path.source_index, ordinal, "source")
    if source.kind == "return_wrapper":
        expected_destination = "returned"
    elif source.kind == "termination_wrapper":
        expected_destination = "terminated"
    else:
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"path {ordinal} cannot start at a dispatch cutpoint"
        )
    if (
        path.destination_kind != expected_destination
        or path.destination_index is not None
    ):
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"path {ordinal} must end at {expected_destination}"
        )


def _require_dispatch_destination(
    cutpoints: tuple[NativeLaunchCutpointSpec, ...],
    path: NativeLaunchPathSpec,
    ordinal: int,
) -> None:
    if path.destination_kind != "stable_cutpoint":
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"path {ordinal} canonical root must end at a dispatch cutpoint"
        )
    destination = _cutpoint(
        cutpoints, path.destination_index, ordinal, "destination"
    )
    if destination.kind != "dispatch":
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"path {ordinal} canonical root destination is not a dispatch cutpoint"
        )


def _cutpoint(
    cutpoints: tuple[NativeLaunchCutpointSpec, ...],
    index: int | None,
    path_ordinal: int,
    role: str,
) -> NativeLaunchCutpointSpec:
    if index is None or not 0 <= index < len(cutpoints):
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"path {path_ordinal} {role} cutpoint index is out of range"
        )
    return cutpoints[index]


def _source_rva(
    binary: StageABinary,
    cutpoints: tuple[NativeLaunchCutpointSpec, ...],
    path: NativeLaunchPathSpec,
) -> int:
    if path.source_kind == "entry":
        return binary.entrypoint_rva
    if path.source_kind == "tls_callback":
        assert binary.tls_callback_rvas is not None
        assert path.source_index is not None
        return binary.tls_callback_rvas[path.source_index]
    assert path.source_index is not None
    return cutpoints[path.source_index].rva


def _instruction_bytes(binary: StageABinary, rva: int) -> bytes:
    _require_executable_rva(binary, rva, f"instruction at 0x{rva:x}")
    raw = bytes(binary.pe.get_data(rva, 15))
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    rows = list(decoder.disasm(raw, binary.image_base + rva, count=1))
    if len(rows) != 1 or rows[0].address != binary.image_base + rva:
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"instruction at RVA 0x{rva:x} does not decode exactly"
        )
    data = bytes(rows[0].bytes)
    if not data or bytes(binary.pe.get_data(rva, len(data))) != data:
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"instruction at RVA 0x{rva:x} is not backed by exact PE bytes"
        )
    _require_exact_executable_span(
        binary, rva, len(data), f"instruction at 0x{rva:x}"
    )
    return data


def _require_executable_rva(binary: StageABinary, rva: int, label: str) -> None:
    _require_exact_executable_span(binary, rva, 1, label)


def _require_exact_executable_span(
    binary: StageABinary, rva: int, size: int, label: str
) -> None:
    if not any(
        section.executable
        and section.rva_start <= rva
        and rva + size <= section.rva_end
        and rva + size <= section.rva_start + section.raw_size
        for section in binary.sections
    ):
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"{label} RVA span 0x{rva:x}..0x{rva + size:x} is not exact "
            "executable image data"
        )


def _require_u32(value: object, label: str) -> None:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value < _U32_LIMIT
    ):
        raise RelationalInterpreterNativeLaunchGenerationError(
            f"{label} must be a 32-bit unsigned integer"
        )


def _lean_cutpoint(cutpoint: NativeLaunchCutpointSpec) -> str:
    kind = {
        "dispatch": "dispatch",
        "return_wrapper": "returnWrapper",
        "termination_wrapper": "terminationWrapper",
    }[cutpoint.kind]
    return f"{{ kind := .{kind}, rva := {cutpoint.rva} }}"


def _lean_path(index: int, path: NativeLaunchResolvedPath) -> str:
    source = _lean_source(path.spec)
    destination = _lean_destination(path.spec)
    instructions = ",\n    ".join(
        instruction.lean() for instruction in path.instructions
    )
    return f"""def generatedNativeLaunchPath{index:04d} :
    ReflectedNativeLaunchPathCertificate := {{
  source := {source}
  destination := {destination}
  steps := [
    {instructions}
  ]
}}"""


def _lean_source(path: NativeLaunchPathSpec) -> str:
    if path.source_kind == "entry":
        return ".canonicalRoot .entry"
    if path.source_kind == "tls_callback":
        return f".canonicalRoot (.tlsCallback {path.source_index})"
    return f".stableCutpoint {path.source_index}"


def _lean_destination(path: NativeLaunchPathSpec) -> str:
    if path.destination_kind == "stable_cutpoint":
        return f".stableCutpoint {path.destination_index}"
    return f".{path.destination_kind}"
