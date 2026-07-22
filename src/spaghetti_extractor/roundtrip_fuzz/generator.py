from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable

from ..relational.contract import stage_a_generate_relation_contract
from ..relational.mapping import stage_a_generate_map
from ..stage_binary import StageAInputError
from ..util import sha256_file, write_json
from .inventory import write_roundtrip_interface_inventory
from .lowering import (
    AssemblyLoweringVariant,
    LinkedPE32,
    build_gnu_pe32,
    build_llvm_msvc_pe32,
    lower_semantic_program_to_gnu_assembly,
    lower_semantic_program_to_llvm_msvc_assembly,
)
from .model import (
    CaseExpectation,
    CaseManifest,
    CorpusCaseRef,
    CorpusManifest,
    ExpectedCounts,
    ExpectedDisposition,
    NegativeMutation,
    ToolchainIdentity,
    artifact_refs,
    write_case_manifest,
    write_corpus_manifest,
)
from .semantic import (
    AdjustStack,
    AssignRegister,
    Branch,
    CompareRegister,
    InternalCall,
    Jump,
    RegisterArithmetic,
    Return,
    ScalarValue,
    SemanticBlock,
    SemanticProgram,
    StackArithmetic,
    StoreStack,
    ValueKind,
)


SPIKE_GENERATOR_VERSION = "structured-semantic-spike-v1"
SPIKE_CAPABILITY_PROFILE = "x86-pe32-relational-v3"
SPIKE_POSITIVE_CASES = 24
SPIKE_NEGATIVE_CASES = 12
SPIKE_CASES = SPIKE_POSITIVE_CASES + SPIKE_NEGATIVE_CASES
SPIKE_SHARDS = 6

TEMPLATES = (
    "straight-line-arithmetic",
    "guarded-branch",
    "bounded-loop",
    "internal-call-stack",
)

TRANSFORMATIONS = (
    "register-reassignment",
    "temporary-stack-spill",
    "basic-block-split",
    "branch-inversion",
    "equivalent-instruction-selection",
    "function-block-reordering",
    "code-alignment-change",
    "changed-jump-layout",
    "different-prologue-epilogue",
)

_TEMPLATE_TRANSFORMATIONS = {
    "straight-line-arithmetic": (
        "register-reassignment", "temporary-stack-spill", "basic-block-split",
        "equivalent-instruction-selection", "function-block-reordering",
        "code-alignment-change", "changed-jump-layout",
        "different-prologue-epilogue", "register-reassignment",
    ),
    "guarded-branch": (
        "branch-inversion", "temporary-stack-spill", "basic-block-split",
        "function-block-reordering", "code-alignment-change",
        "changed-jump-layout", "different-prologue-epilogue",
        "branch-inversion", "temporary-stack-spill",
    ),
    "bounded-loop": TRANSFORMATIONS,
    "internal-call-stack": (
        "temporary-stack-spill", "basic-block-split",
        "function-block-reordering", "code-alignment-change",
        "changed-jump-layout", "different-prologue-epilogue",
        "temporary-stack-spill", "basic-block-split",
        "function-block-reordering",
    ),
}


@dataclass(frozen=True)
class GeneratedCaseSpec:
    index: int
    seed: int
    template: str
    transformation: str
    negative_ordinal: int | None

    @property
    def case_id(self) -> str:
        polarity = "negative" if self.negative_ordinal is not None else "positive"
        return f"spike-{self.index:03d}-{polarity}-{self.template}"


def spike_case_specs(*, seed: int, count: int = SPIKE_CASES) -> tuple[GeneratedCaseSpec, ...]:
    if seed < 0:
        raise StageAInputError("round-trip seed must be nonnegative")
    if count <= 0:
        raise StageAInputError("round-trip count must be positive")
    specs: list[GeneratedCaseSpec] = []
    negative_ordinal = 0
    for index in range(count):
        # Every third case is negative. The full 36-case spike is exactly 24/12.
        negative = index % 3 == 2
        template = TEMPLATES[index % len(TEMPLATES)]
        template_ordinal = index // len(TEMPLATES)
        transformations = _TEMPLATE_TRANSFORMATIONS[template]
        specs.append(GeneratedCaseSpec(
            index=index,
            seed=seed + index,
            template=template,
            transformation=transformations[template_ordinal % len(transformations)],
            negative_ordinal=negative_ordinal if negative else None,
        ))
        if negative:
            negative_ordinal += 1
    return tuple(specs)


def semantic_program_for_spec(spec: GeneratedCaseSpec) -> SemanticProgram:
    builders: dict[str, Callable[[int], SemanticProgram]] = {
        "straight-line-arithmetic": _straight_line_program,
        "guarded-branch": _guarded_branch_program,
        "bounded-loop": _bounded_loop_program,
        "internal-call-stack": _internal_call_program,
    }
    try:
        return builders[spec.template](spec.seed)
    except KeyError as exc:
        raise StageAInputError(f"unsupported semantic template {spec.template!r}") from exc


def candidate_program_for_spec(
    spec: GeneratedCaseSpec, original: SemanticProgram,
) -> tuple[SemanticProgram, NegativeMutation | None]:
    if spec.negative_ordinal is None:
        return original, None
    mutation_index = spec.negative_ordinal // len(TEMPLATES)
    payload = original.to_payload()
    blocks = {block["id"]: block for block in payload["blocks"]}
    if spec.template == "straight-line-arithmetic":
        operation = blocks["entry"]["operations"][1]
        if mutation_index % 3 == 0:
            operation["immediate"] = (int(operation["immediate"]) + 1) & 0xFFFFFFFF
            mutation = NegativeMutation(
                "wrong-addend", "candidate changes the arithmetic constant", "entry",
            )
        elif mutation_index % 3 == 1:
            operation["operator"] = "sub"
            mutation = NegativeMutation(
                "wrong-operator", "candidate subtracts instead of adding", "entry",
            )
        else:
            blocks["entry"]["operations"][0]["value"]["value"] = "edx"
            mutation = NegativeMutation(
                "wrong-input-register", "candidate reads a different input register", "entry",
            )
    elif spec.template == "guarded-branch":
        if mutation_index % 3 == 0:
            blocks["entry"]["terminator"]["condition"] = "nonzero"
            mutation = NegativeMutation(
                "unswapped-branch-inversion",
                "candidate inverts the guard without swapping successors",
                "entry",
            )
        elif mutation_index % 3 == 1:
            blocks["true-path"]["operations"][0]["value"]["value"] += 1
            mutation = NegativeMutation(
                "wrong-true-result", "candidate changes the true-path result", "true-path",
            )
        else:
            blocks["false-path"]["operations"][0]["value"]["value"] += 1
            mutation = NegativeMutation(
                "wrong-false-result", "candidate changes the false-path result", "false-path",
            )
    elif spec.template == "bounded-loop":
        if mutation_index % 3 == 0:
            blocks["entry"]["operations"][1]["value"]["value"] += 1
            mutation = NegativeMutation(
                "off-by-one-loop-bound", "candidate executes one extra loop iteration", "entry",
            )
        elif mutation_index % 3 == 1:
            blocks["body"]["operations"][0]["immediate"] += 1
            mutation = NegativeMutation(
                "wrong-loop-step", "candidate accumulates a different loop step", "body",
            )
        else:
            blocks["body"]["operations"][1]["immediate"] = 2
            mutation = NegativeMutation(
                "wrong-induction-step", "candidate decrements the induction variable by two", "body",
            )
    else:
        if mutation_index % 3 == 0:
            blocks["callee"]["operations"][0]["offset"] = 8
            mutation = NegativeMutation(
                "wrong-stack-slot", "candidate updates the wrong caller stack slot", "callee",
            )
        elif mutation_index % 3 == 1:
            blocks["callee"]["operations"] = []
            mutation = NegativeMutation(
                "omitted-memory-write", "candidate omits the callee stack update", "callee",
            )
        else:
            blocks["after-call"]["operations"].insert(0, {
                "kind": "assign_register",
                "register": "ebx",
                "value": {"kind": "constant", "width": 32, "value": 0xBAD},
            })
            mutation = NegativeMutation(
                "preserved-register-clobber", "candidate clobbers preserved ebx", "after-call",
            )
    payload["id"] = f"{original.id}-mutated"
    return SemanticProgram.parse(payload), mutation


def lowering_variant_for_spec(
    spec: GeneratedCaseSpec, program: SemanticProgram,
) -> AssemblyLoweringVariant:
    transformation = spec.transformation
    block_ids = tuple(block.id for block in program.blocks)
    arithmetic_block = {
        "straight-line-arithmetic": "entry",
        "guarded-branch": "true-path",
        "bounded-loop": "body",
        "internal-call-stack": "after-call",
    }[spec.template]
    branch_block = {
        "guarded-branch": "entry",
        "bounded-loop": "header",
    }.get(spec.template)
    kwargs: dict[str, Any] = {"id": f"candidate-{transformation}"}
    if transformation == "register-reassignment" and spec.template in {
        "straight-line-arithmetic", "bounded-loop",
    }:
        kwargs["reassign_eax_arithmetic_blocks"] = (arithmetic_block,)
    elif transformation == "temporary-stack-spill":
        kwargs["reversible_spill_blocks"] = (arithmetic_block,)
    elif transformation == "basic-block-split":
        kwargs["split_blocks"] = (arithmetic_block,)
    elif transformation == "branch-inversion" and branch_block is not None:
        kwargs["invert_branch_blocks"] = (branch_block,)
        kwargs["fallthrough_branch_blocks"] = (branch_block,)
        if spec.template == "guarded-branch":
            kwargs["block_order"] = (
                "entry", "true-path", "false-path", "join", "terminal",
            )
        elif spec.template == "bounded-loop":
            kwargs["block_order"] = (
                "entry", "header", "exit", "body", "terminal",
            )
    elif transformation == "equivalent-instruction-selection" and spec.template in {
        "straight-line-arithmetic", "bounded-loop",
    }:
        kwargs["lea_arithmetic_blocks"] = (arithmetic_block,)
    elif transformation == "function-block-reordering":
        kwargs["block_order"] = tuple(reversed(block_ids))
    elif transformation == "code-alignment-change":
        kwargs["align_blocks"] = (block_ids[-1],)
    elif transformation == "changed-jump-layout":
        kwargs["bridge_jump_blocks"] = (arithmetic_block,)
    elif transformation == "different-prologue-epilogue":
        kwargs["reversible_spill_blocks"] = (
            "callee" if spec.template == "internal-call-stack" else arithmetic_block,
        )
    else:
        raise StageAInputError(
            f"transformation {transformation!r} is not valid for template "
            f"{spec.template!r}"
        )
    return AssemblyLoweringVariant(**kwargs)


def original_lowering_variant_for_spec(
    spec: GeneratedCaseSpec,
) -> AssemblyLoweringVariant:
    if spec.transformation != "branch-inversion":
        return AssemblyLoweringVariant("original")
    if spec.template == "guarded-branch":
        order = ("entry", "false-path", "true-path", "join", "terminal")
        branch = "entry"
    elif spec.template == "bounded-loop":
        order = ("entry", "header", "body", "exit", "terminal")
        branch = "header"
    else:
        raise StageAInputError(
            f"branch inversion is not defined for template {spec.template!r}"
        )
    return AssemblyLoweringVariant(
        "original-branch-fallthrough",
        fallthrough_branch_blocks=(branch,),
        block_order=order,
    )


def generate_spike_corpus(
    *,
    out: Path,
    seed: int = 0,
    count: int = SPIKE_CASES,
    toolchain: str = "gnu",
    compiler: str | None = None,
    linker: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    out = Path(out).resolve()
    if out.exists() and any(out.iterdir()):
        if not force:
            raise StageAInputError(
                f"round-trip corpus output is not empty: {out}; use --force to replace it"
            )
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    if toolchain not in {"gnu", "llvm-msvc"}:
        raise StageAInputError(f"unsupported round-trip toolchain {toolchain!r}")

    specs = spike_case_specs(seed=seed, count=count)
    shard_count = min(SPIKE_SHARDS, count)
    references: list[CorpusCaseRef] = []
    observed = {disposition: 0 for disposition in ExpectedDisposition}
    toolchain_identity: ToolchainIdentity | None = None
    for spec in specs:
        case, linked = _generate_spike_case(
            out=out, spec=spec, toolchain=toolchain,
            compiler=compiler, linker=linker, shard_count=shard_count,
        )
        case_path = out / "cases" / spec.case_id / "case.json"
        references.append(CorpusCaseRef(
            id=case.id,
            path=case_path.relative_to(out).as_posix(),
            sha256=sha256_file(case_path),
            shard=case.shard,
        ))
        observed[case.expectation.disposition] += 1
        if toolchain_identity is None:
            toolchain_identity = _toolchain_identity(
                linked, toolchain=toolchain, linker=linker,
            )
    assert toolchain_identity is not None
    corpus = CorpusManifest(
        generator_version=SPIKE_GENERATOR_VERSION,
        root_seed=seed,
        capability_profile=SPIKE_CAPABILITY_PROFILE,
        toolchain=toolchain_identity,
        cases=tuple(references),
        expected_counts=ExpectedCounts(
            observed[ExpectedDisposition.PASS],
            observed[ExpectedDisposition.VIOLATED],
            observed[ExpectedDisposition.INCOMPLETE],
        ),
        shard_count=shard_count,
    )
    corpus_path = out / "corpus.json"
    write_corpus_manifest(corpus_path, corpus)
    write_roundtrip_interface_inventory(out=out / "interface-inventory.json")
    corpus.load_cases(out)
    return {
        "format": "stage-a-roundtrip-generation-v1",
        "status": "generated",
        "corpus": str(corpus_path),
        "corpus_sha256": sha256_file(corpus_path),
        "cases": count,
        "case_ids": [spec.case_id for spec in specs],
        "toolchain": toolchain_identity.to_payload(),
        "expected_counts": corpus.expected_counts.to_payload(),
    }


def _generate_spike_case(
    *, out: Path, spec: GeneratedCaseSpec, toolchain: str,
    compiler: str | None, linker: str | None, shard_count: int,
) -> tuple[CaseManifest, LinkedPE32]:
    case_root = out / "cases" / spec.case_id
    case_root.mkdir(parents=True)
    original_program = semantic_program_for_spec(spec)
    candidate_program, mutation = candidate_program_for_spec(spec, original_program)
    original_semantic = case_root / "semantic-program.json"
    candidate_semantic = case_root / "candidate-semantic-program.json"
    write_json(original_semantic, original_program.to_payload())
    write_json(candidate_semantic, candidate_program.to_payload())
    lower = (
        lower_semantic_program_to_gnu_assembly
        if toolchain == "gnu" else lower_semantic_program_to_llvm_msvc_assembly
    )
    original_source = case_root / "original.S"
    candidate_source = case_root / "candidate.S"
    original_source.write_text(
        lower(original_program, variant=original_lowering_variant_for_spec(spec)),
        encoding="utf-8",
    )
    candidate_source.write_text(
        lower(candidate_program, variant=lowering_variant_for_spec(spec, candidate_program)),
        encoding="utf-8",
    )
    build = _build_function(toolchain=toolchain, compiler=compiler, linker=linker)
    original = build(original_source, case_root / "original.exe", case_root / "original.map")
    candidate = build(candidate_source, case_root / "candidate.exe", case_root / "candidate.map")
    mapping_path = case_root / "relation-proposal.json"
    layout_path = case_root / "layout-contract.json"
    mapping = stage_a_generate_map(
        original=original.binary,
        candidate=candidate.binary,
        linker_map_original=original.linker_map,
        linker_map_candidate=candidate.linker_map,
        out=mapping_path,
        layout_contract_out=layout_path,
        original_flags="semantic-original-v1",
        candidate_flags=f"semantic-candidate-v1 {spec.transformation}",
    )
    if mapping.get("status") != "pass":
        raise StageAInputError(
            f"case {spec.case_id} mapping proposal is incomplete: "
            + json.dumps(mapping.get("issues", [])[:3], sort_keys=True)
        )
    mapping_payload = json.loads(mapping_path.read_text(encoding="utf-8"))
    mapping_payload["original"]["path"] = "original.exe"
    mapping_payload["candidate"]["path"] = "candidate.exe"
    mapping_payload["linker_maps"] = {
        "original": "original.map", "candidate": "candidate.map",
    }
    write_json(mapping_path, mapping_payload)
    relation_path = case_root / "relation-contract.json"
    relation = stage_a_generate_relation_contract(
        original=original.binary,
        candidate=candidate.binary,
        mapping=mapping_path,
        out=relation_path,
    )
    if relation.get("status") != "generated":
        raise StageAInputError(
            f"case {spec.case_id} relation contract is incomplete: "
            + json.dumps(relation.get("issues", [])[:3], sort_keys=True)
        )
    disposition = (
        ExpectedDisposition.PASS if mutation is None else ExpectedDisposition.VIOLATED
    )
    artifacts = artifact_refs(root=case_root, artifacts=(
        ("semantic_program", original_semantic),
        ("candidate_semantic_program", candidate_semantic),
        ("original_source", original_source),
        ("candidate_source", candidate_source),
        ("original_object", original.object),
        ("candidate_object", candidate.object),
        ("original_pe", original.binary),
        ("candidate_pe", candidate.binary),
        ("original_linker_map", original.linker_map),
        ("candidate_linker_map", candidate.linker_map),
        ("relation_proposal", mapping_path),
        ("relation_contract", relation_path),
    ))
    case = CaseManifest(
        id=spec.case_id,
        semantic_program_sha256=sha256_file(original_semantic),
        parent_seed=spec.seed,
        template=spec.template,
        transformations=(spec.transformation,),
        expectation=CaseExpectation(
            disposition,
            "relational-behavior-mismatch-v1" if mutation is not None else None,
            None,
        ),
        mutation=mutation,
        capability_profile=SPIKE_CAPABILITY_PROFILE,
        capabilities=original_program.capabilities,
        proof_families=(
            "static-context", "segment-refinement", "product-composition",
            "launch-realizability", "whole-program-acceptance",
        ),
        artifacts=artifacts,
        replay=(
            "spaghetti-extractor", "stage-a-fuzz-run", "--corpus", "corpus.json",
            "--mode", "proof-core", "--case", spec.case_id, "--out", "run",
        ),
        shard=spec.index % shard_count,
    )
    write_case_manifest(case_root / "case.json", case)
    return case, original


def _build_function(
    *, toolchain: str, compiler: str | None, linker: str | None,
) -> Callable[[Path, Path, Path], LinkedPE32]:
    if toolchain == "gnu":
        return lambda source, binary, linker_map: build_gnu_pe32(
            source=source, binary=binary, linker_map=linker_map,
            compiler=compiler or "i686-w64-mingw32-gcc",
        )
    return lambda source, binary, linker_map: build_llvm_msvc_pe32(
        source=source, binary=binary, linker_map=linker_map,
        clang_cl=compiler or "clang-cl", linker=linker or "lld-link",
    )


def _toolchain_identity(
    linked: LinkedPE32, *, toolchain: str, linker: str | None,
) -> ToolchainIdentity:
    return ToolchainIdentity(
        id=("pinned-mingw32-gnu-v1" if toolchain == "gnu" else "pinned-llvm-msvc-compatible-v1"),
        target=("i686-w64-mingw32" if toolchain == "gnu" else "i686-pc-windows-msvc"),
        compiler=Path(linked.compiler).name,
        compiler_version=linked.compiler_version,
        linker=("gnu-ld-via-gcc" if toolchain == "gnu" else Path(linker or "lld-link").name),
        linker_version=linked.linker_version,
    )


def _word(value: int) -> ScalarValue:
    return ScalarValue(ValueKind.CONSTANT, 32, value & 0xFFFFFFFF)


def _register(name: str) -> ScalarValue:
    return ScalarValue(ValueKind.REGISTER, 32, name)


def _terminal() -> SemanticBlock:
    return SemanticBlock("terminal", (), Jump("terminal"))


def _straight_line_program(seed: int) -> SemanticProgram:
    amount = seed % 13 + 1
    return SemanticProgram.parse({
        "format": "stage-a-roundtrip-semantic-program-v1",
        "id": f"straight-line-{seed}", "entry": "entry",
        "blocks": [
            SemanticBlock("entry", (
                AssignRegister("eax", _register("ecx")),
                RegisterArithmetic("eax", "add", amount),
            ), Jump("terminal")).to_payload(),
            _terminal().to_payload(),
        ],
        "static_objects": [], "observations": ["terminal-state"],
        "capabilities": ["direct-jump", "register-state", "word-arithmetic"],
    })


def _guarded_branch_program(seed: int) -> SemanticProgram:
    true_value = seed % 17 + 3
    false_value = true_value + 9
    return SemanticProgram.parse({
        "format": "stage-a-roundtrip-semantic-program-v1",
        "id": f"guarded-branch-{seed}", "entry": "entry",
        "blocks": [
            SemanticBlock("entry", (CompareRegister("ecx", 0),),
                          Branch("zero", "true-path", "false-path")).to_payload(),
            SemanticBlock("true-path", (AssignRegister("eax", _word(true_value)),),
                          Jump("join")).to_payload(),
            SemanticBlock("false-path", (AssignRegister("eax", _word(false_value)),),
                          Jump("join")).to_payload(),
            SemanticBlock("join", (), Jump("terminal")).to_payload(),
            _terminal().to_payload(),
        ],
        "static_objects": [], "observations": ["terminal-state"],
        "capabilities": ["conditional-branch", "direct-jump", "register-state"],
    })


def _bounded_loop_program(seed: int) -> SemanticProgram:
    bound = seed % 4 + 2
    step = seed % 5 + 1
    return SemanticProgram.parse({
        "format": "stage-a-roundtrip-semantic-program-v1",
        "id": f"bounded-loop-{seed}", "entry": "entry",
        "blocks": [
            SemanticBlock("entry", (
                AssignRegister("eax", _word(0)), AssignRegister("ecx", _word(bound)),
            ), Jump("header")).to_payload(),
            SemanticBlock("header", (CompareRegister("ecx", 0),),
                          Branch("zero", "exit", "body")).to_payload(),
            SemanticBlock("body", (
                RegisterArithmetic("eax", "add", step),
                RegisterArithmetic("ecx", "sub", 1),
            ), Jump("header")).to_payload(),
            SemanticBlock("exit", (), Jump("terminal")).to_payload(),
            _terminal().to_payload(),
        ],
        "static_objects": [], "observations": ["terminal-state"],
        "capabilities": [
            "bounded-loop", "conditional-branch", "direct-jump", "register-state",
            "word-arithmetic",
        ],
    })


def _internal_call_program(seed: int) -> SemanticProgram:
    value = seed % 19 + 1
    amount = seed % 7 + 1
    return SemanticProgram.parse({
        "format": "stage-a-roundtrip-semantic-program-v1",
        "id": f"internal-call-{seed}", "entry": "entry",
        "blocks": [
            SemanticBlock("entry", (
                AdjustStack(8), StoreStack(0, _word(value)), StoreStack(4, _word(0)),
            ), InternalCall("callee", "after-call")).to_payload(),
            SemanticBlock("callee", (StackArithmetic(4, "add", amount),), Return()).to_payload(),
            SemanticBlock("after-call", (AdjustStack(-8),), Jump("terminal")).to_payload(),
            _terminal().to_payload(),
        ],
        "static_objects": [], "observations": ["terminal-state"],
        "capabilities": [
            "direct-jump", "internal-call", "internal-return", "stack-memory",
            "word-arithmetic",
        ],
    })


__all__ = [
    "SPIKE_CASES", "SPIKE_GENERATOR_VERSION", "GeneratedCaseSpec",
    "candidate_program_for_spec", "generate_spike_corpus",
    "lowering_variant_for_spec", "semantic_program_for_spec", "spike_case_specs",
]
