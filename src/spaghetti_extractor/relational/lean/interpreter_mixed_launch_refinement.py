"""Generate guarded native launch graphs for mixed interpreter proofs.

The generator proposes only exact bytes, complete finite successors, and
well-founded ranks.  The generated Lean module re-parses the PE, checks the
graph, and exports the precise mixed refinement obligation.  It never fills
that obligation with a status bit or an unchecked Python claim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ...stage_binary import _parse_stage_a_pe
from .common import (
    _lean_byte_tree_definitions,
    _lean_import_certificate,
    _lean_pe,
)
from .interpreter_native_launch import (
    NativeLaunchGraphNode,
    NativeLaunchGraphRoute,
    NativeLaunchGraphSpec,
    RelationalInterpreterNativeLaunchGraphPlan,
    build_relational_interpreter_native_launch_graph_plan,
)


INTERPRETER_MIXED_LAUNCH_REFINEMENT_MODULE = (
    "GeneratedRelationalInterpreterMixedLaunchRefinement"
)

_LOCAL_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*\Z")
_NAMESPACE = re.compile(
    r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*\Z"
)


@dataclass(frozen=True)
class MixedLaunchRefinementSpec:
    graph: NativeLaunchGraphSpec
    module_name: str = INTERPRETER_MIXED_LAUNCH_REFINEMENT_MODULE
    namespace: str = (
        "StageA.GeneratedRelational.InterpreterMixedLaunchRefinement"
    )
    candidate_binding: "MixedLaunchCandidateLeanBinding | None" = None


@dataclass(frozen=True)
class MixedLaunchCandidateLeanBinding:
    """Existing exact candidate terms used to avoid duplicating PE byte packs."""

    module: str
    namespace: str
    pe: str
    imports: str
    pe_parsed: str
    imports_parsed: str

    def qualified(self, name: str) -> str:
        return f"{self.namespace}.{name}"


@dataclass(frozen=True)
class RelationalInterpreterMixedLaunchRefinementPlan:
    graph: RelationalInterpreterNativeLaunchGraphPlan
    pe_literal: str | None
    import_certificate_literal: str | None
    cutpoints: tuple[tuple[str, int], ...]
    spec: MixedLaunchRefinementSpec

    def payload(self) -> dict[str, object]:
        payload = self.graph.payload()
        payload["format"] = (
            "stage-a-relational-interpreter-mixed-launch-refinement-v1"
        )
        payload["cutpoints"] = [
            {"kind": kind, "rva": rva} for kind, rva in self.cutpoints
        ]
        payload["lean_module"] = self.spec.module_name
        payload["lean_namespace"] = self.spec.namespace
        payload["status"] = "incomplete"
        payload["proof_obligations"] = [
            "static_graph_checked",
            "replay_total_for_all_matching_states",
            "roots_establish_runtime_state_relation",
            "return_wrapper_frame_valid",
            "termination_wrapper_environment_refined",
        ]
        payload["lean_terms"] = {
            "static_graph": "generatedMixedLaunchGraphStaticChecked",
            "required_refinement_type": "GeneratedLaunchWrapperRefinements",
            "launch_wrapper_refinements": None,
        }
        return payload


def build_relational_interpreter_mixed_launch_refinement_plan(
    *,
    candidate_pe: Path | str,
    engine_segments: Path | str,
    spec: MixedLaunchRefinementSpec,
) -> RelationalInterpreterMixedLaunchRefinementPlan:
    """Bind one guarded mixed-launch certificate to exact proposal inputs."""

    _validate_names(spec)
    _validate_complete_wrapper_inventory(spec.graph)
    graph = build_relational_interpreter_native_launch_graph_plan(
        candidate_pe=candidate_pe,
        engine_segments=engine_segments,
        spec=spec.graph,
    )
    binary = _parse_stage_a_pe(Path(candidate_pe))
    try:
        cutpoints = _cutpoint_inventory(graph.routes)
        binding = spec.candidate_binding
        return RelationalInterpreterMixedLaunchRefinementPlan(
            graph=graph,
            pe_literal=(
                None
                if binding is not None
                else _lean_pe(binary, "generatedMixedLaunchCandidateBytes")
            ),
            import_certificate_literal=(
                None if binding is not None else _lean_import_certificate(binary)
            ),
            cutpoints=cutpoints,
            spec=spec,
        )
    finally:
        binary.pe.close()


def relational_interpreter_mixed_launch_refinement_source(
    plan: RelationalInterpreterMixedLaunchRefinementPlan,
) -> str:
    """Emit exact graph data and its Lean-checked mixed proof obligation."""

    binding = plan.spec.candidate_binding
    byte_tree = (
        ""
        if binding is not None
        else _lean_byte_tree_definitions(
            "generatedMixedLaunchCandidateBytes", plan.graph.candidate_bytes
        )
    )
    cutpoints = ",\n  ".join(
        f"{{ kind := .{_lean_cutpoint_kind(kind)}, rva := {rva} }}"
        for kind, rva in plan.cutpoints
    )
    route_definitions = "\n\n".join(
        _lean_route(plan, index, route)
        for index, route in enumerate(plan.graph.routes)
    )
    route_names = ", ".join(
        f"generatedMixedLaunchRoute{index:04d}"
        for index in range(len(plan.graph.routes))
    )
    namespace = plan.spec.namespace

    binding_import = f"\nimport {binding.module}" if binding is not None else ""
    if binding is None:
        assert plan.pe_literal is not None
        assert plan.import_certificate_literal is not None
        candidate_definitions = f"""
def generatedMixedLaunchCandidatePe : PE32 :=
  {plan.pe_literal}

def generatedMixedLaunchImportCertificate : ImportTableCertificate :=
  {plan.import_certificate_literal}

def generatedMixedLaunchImports : List PEImport :=
  generatedMixedLaunchImportCertificate.imports

theorem generatedMixedLaunchCandidateParsed :
    parsePE32Tree generatedMixedLaunchCandidateBytes =
      some generatedMixedLaunchCandidatePe := by
  decide +kernel

theorem generatedMixedLaunchImportsParsed :
    parseImports generatedMixedLaunchCandidatePe =
      some generatedMixedLaunchImports := by
  decide +kernel
"""
    else:
        candidate_definitions = f"""
def generatedMixedLaunchCandidatePe : PE32 :=
  {binding.qualified(binding.pe)}

def generatedMixedLaunchImports : List PEImport :=
  {binding.qualified(binding.imports)}

theorem generatedMixedLaunchCandidateParsed :
    parsePE32Tree generatedMixedLaunchCandidatePe.bytes =
      some generatedMixedLaunchCandidatePe := by
  simpa [generatedMixedLaunchCandidatePe] using
    {binding.qualified(binding.pe_parsed)}

theorem generatedMixedLaunchImportsParsed :
    parseImports generatedMixedLaunchCandidatePe =
      some generatedMixedLaunchImports := by
  simpa [generatedMixedLaunchCandidatePe, generatedMixedLaunchImports] using
    {binding.qualified(binding.imports_parsed)}
"""

    return f"""import StageA.RelationalInterpreterMixedProfile{binding_import}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterMixedLaunchRefinement
open StageA.Relational.InterpreterMixedProfile
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

{byte_tree}

{candidate_definitions}

def generatedMixedLaunchCutpoints : List StableInterpreterCutpoint := [
  {cutpoints}
]

{route_definitions}

def generatedMixedLaunchGraphCertificate :
    ExactNativeLaunchGraphCertificate := {{
  cutpoints := generatedMixedLaunchCutpoints
  routes := [{route_names}]
}}

theorem generatedMixedLaunchGraphStaticChecked :
    generatedMixedLaunchGraphCertificate.staticChecked
      generatedMixedLaunchCandidatePe generatedMixedLaunchImports = true := by
  decide +kernel

/-- This is the exact proof object the mixed binding must provide.  The alias
prevents downstream code from silently substituting the legacy one-linear-path
certificate. -/
abbrev GeneratedLaunchWrapperRefinements
    (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (launch : PE32ConsoleLaunchV2) : Type :=
  CanonicalMixedLaunchWrapperRefinement original candidate contract launch

#print axioms generatedMixedLaunchGraphStaticChecked

end {namespace}
"""


def write_relational_interpreter_mixed_launch_refinement(
    out: Path | str,
    *,
    candidate_pe: Path | str,
    engine_segments: Path | str,
    spec: MixedLaunchRefinementSpec,
) -> Path:
    plan = build_relational_interpreter_mixed_launch_refinement_plan(
        candidate_pe=candidate_pe,
        engine_segments=engine_segments,
        spec=spec,
    )
    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    destination = stage_a / f"{spec.module_name}.lean"
    destination.write_text(
        relational_interpreter_mixed_launch_refinement_source(plan),
        encoding="utf-8",
    )
    return destination


def _validate_names(spec: MixedLaunchRefinementSpec) -> None:
    if _LOCAL_NAME.fullmatch(spec.module_name) is None:
        raise ValueError("module_name must be a local Lean module name")
    if _NAMESPACE.fullmatch(spec.namespace) is None:
        raise ValueError("namespace must be a canonical Lean namespace")
    binding = spec.candidate_binding
    if binding is not None:
        if _NAMESPACE.fullmatch(binding.module) is None:
            raise ValueError("candidate binding module must be canonical")
        if _NAMESPACE.fullmatch(binding.namespace) is None:
            raise ValueError("candidate binding namespace must be canonical")
        for name, value in (
            ("pe", binding.pe),
            ("imports", binding.imports),
            ("pe_parsed", binding.pe_parsed),
            ("imports_parsed", binding.imports_parsed),
        ):
            if _LOCAL_NAME.fullmatch(value) is None:
                raise ValueError(f"candidate binding {name} must be a local name")


def _validate_complete_wrapper_inventory(graph: NativeLaunchGraphSpec) -> None:
    destinations = {
        route.destination_kind
        for route in graph.routes
        if route.source_kind == "stable_cutpoint"
    }
    missing = {"returned", "terminated"} - destinations
    if missing:
        roles = ", ".join(sorted(missing))
        raise ValueError(
            "mixed launch refinement requires declared return and termination "
            f"wrapper routes; missing: {roles}"
        )


def _cutpoint_inventory(
    routes: tuple[NativeLaunchGraphRoute, ...],
) -> tuple[tuple[str, int], ...]:
    values: list[tuple[str, int]] = []
    for route in routes:
        if route.spec.destination_kind == "dispatch":
            assert route.spec.destination_rva is not None
            item = ("dispatch", route.spec.destination_rva)
            if item not in values:
                values.append(item)
        if route.spec.source_kind == "stable_cutpoint":
            assert route.spec.source_rva is not None
            kind = (
                "return_wrapper"
                if route.spec.destination_kind == "returned"
                else "termination_wrapper"
            )
            item = (kind, route.spec.source_rva)
            if item in values:
                raise ValueError("stable launch cutpoints must be unique")
            values.append(item)
    return tuple(values)


def _lean_cutpoint_kind(kind: str) -> str:
    return {
        "dispatch": "dispatch",
        "return_wrapper": "returnWrapper",
        "termination_wrapper": "terminationWrapper",
    }[kind]


def _lean_source(
    plan: RelationalInterpreterMixedLaunchRefinementPlan,
    route: NativeLaunchGraphRoute,
) -> str:
    if route.spec.source_kind == "entry":
        return ".canonicalRoot .entry"
    if route.spec.source_kind == "tls_callback":
        assert route.spec.source_index is not None
        return f".canonicalRoot (.tlsCallback {route.spec.source_index})"
    index = plan.cutpoints.index(
        (
            "return_wrapper"
            if route.spec.destination_kind == "returned"
            else "termination_wrapper",
            route.source_rva,
        )
    )
    return f".stableCutpoint {index}"


def _lean_destination(
    plan: RelationalInterpreterMixedLaunchRefinementPlan,
    route: NativeLaunchGraphRoute,
) -> str:
    if route.spec.destination_kind == "returned":
        return ".returned"
    if route.spec.destination_kind == "terminated":
        return ".terminated"
    assert route.spec.destination_rva is not None
    index = plan.cutpoints.index(("dispatch", route.spec.destination_rva))
    return f".stableCutpoint {index}"


def _lean_instruction_kind(node: NativeLaunchGraphNode) -> str:
    return {
        "ordinary": ".ordinary",
        "x87_fnsave": ".x87Frame .fnSave",
        "x87_frstor": ".x87Frame .frStor",
    }[node.instruction_kind]


def _lean_terminal(node: NativeLaunchGraphNode) -> str:
    if node.terminal is None:
        return "none"
    return f"some .{node.terminal}"


def _lean_node(node: NativeLaunchGraphNode) -> str:
    successors = ", ".join(str(value) for value in node.successors)
    return "{ " + ", ".join(
        (
            f"instruction := {node.instruction.lean()}",
            f"kind := {_lean_instruction_kind(node)}",
            f"successors := [{successors}]",
            f"rank := {node.rank}",
            f"terminal := {_lean_terminal(node)}",
        )
    ) + " }"


def _lean_route(
    plan: RelationalInterpreterMixedLaunchRefinementPlan,
    index: int,
    route: NativeLaunchGraphRoute,
) -> str:
    nodes = ",\n    ".join(_lean_node(node) for node in route.nodes)
    return f"""def generatedMixedLaunchRoute{index:04d} :
    ReflectedNativeLaunchGraphRoute := {{
  source := {_lean_source(plan, route)}
  destination := {_lean_destination(plan, route)}
  nodes := [
    {nodes}
  ]
}}"""
