from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from ..relational.contract import stage_a_generate_relation_contract
from ..relational.mapping import stage_a_generate_map
from ..stage_binary import StageAInputError
from ..util import sha256_file, write_json
from .inventory import write_roundtrip_interface_inventory
from .lowering import (
    AssemblyLoweringVariant,
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
    ToolchainIdentity,
    artifact_refs,
    write_case_manifest,
    write_corpus_manifest,
)
from .semantic import (
    AdjustStack,
    Branch,
    CompareRegister,
    ExternalCall,
    InternalCall,
    Jump,
    Return,
    ScalarValue,
    SemanticBlock,
    SemanticProgram,
    StaticObject,
    StoreStack,
    ValueKind,
)


PHASE0_GENERATOR_VERSION = "phase0-winapi-semantic-v3"
PHASE0_CAPABILITY_PROFILE = "x86-pe32-relational-v3"
PHASE0_CASE_ID = "phase0-winapi-lockstep"


def phase0_semantic_program() -> SemanticProgram:
    word = lambda value: ScalarValue(ValueKind.CONSTANT, 32, value & 0xFFFFFFFF)
    register = lambda name: ScalarValue(ValueKind.REGISTER, 32, name)
    address = lambda name: ScalarValue(ValueKind.STATIC_ADDRESS, 32, name)
    return SemanticProgram.parse({
        "format": "stage-a-roundtrip-semantic-program-v1",
        "id": "winapi-console-write",
        "entry": "entry",
        "blocks": [
            SemanticBlock(
                id="entry",
                operations=(AdjustStack(24),),
                terminator=InternalCall("branch-check", "after-helper"),
            ).to_payload(),
            SemanticBlock(
                id="branch-check",
                operations=(CompareRegister("ecx", 0),),
                terminator=Branch("zero", "return-helper", "alternate-path"),
            ).to_payload(),
            SemanticBlock(
                id="alternate-path",
                operations=(),
                terminator=Jump("return-helper"),
            ).to_payload(),
            SemanticBlock(
                id="return-helper",
                operations=(),
                terminator=Return(),
            ).to_payload(),
            SemanticBlock(
                id="after-helper",
                operations=(),
                terminator=Jump("get-handle"),
            ).to_payload(),
            SemanticBlock(
                id="get-handle",
                operations=(StoreStack(0, word(-11)),),
                terminator=ExternalCall(
                    dll="kernel32.dll",
                    symbol="GetStdHandle",
                    decorated_symbol="_GetStdHandle@4",
                    argument_words=1,
                    disposition="returns",
                    continuation="after-get",
                ),
            ).to_payload(),
            SemanticBlock(
                id="after-get",
                operations=(AdjustStack(4),),
                terminator=Jump("write-arguments"),
            ).to_payload(),
            SemanticBlock(
                id="write-arguments",
                operations=(
                    StoreStack(16, word(0)),
                    StoreStack(12, address("written")),
                    StoreStack(8, word(15)),
                    StoreStack(4, address("message")),
                ),
                terminator=Jump("write-call"),
            ).to_payload(),
            SemanticBlock(
                id="write-call",
                operations=(StoreStack(0, register("eax")),),
                terminator=ExternalCall(
                    dll="kernel32.dll",
                    symbol="WriteFile",
                    decorated_symbol="_WriteFile@20",
                    argument_words=5,
                    disposition="returns",
                    continuation="exit",
                ),
            ).to_payload(),
            SemanticBlock(
                id="exit",
                operations=(StoreStack(0, word(0)),),
                terminator=ExternalCall(
                    dll="kernel32.dll",
                    symbol="ExitProcess",
                    decorated_symbol="_ExitProcess@4",
                    argument_words=1,
                    disposition="terminates",
                    continuation=None,
                ),
            ).to_payload(),
        ],
        "static_objects": [
            StaticObject(
                id="message",
                section="read_only",
                alignment=1,
                data=b"Hello, world!\r\n",
            ).to_payload(),
            StaticObject(
                id="written",
                section="writable",
                alignment=4,
                data=b"\0\0\0\0",
            ).to_payload(),
        ],
        "observations": ["external-call", "termination"],
        "capabilities": [
            "conditional-branch",
            "direct-jump",
            "external-call",
            "internal-call",
            "internal-return",
            "register-state",
            "stack-memory",
            "static-relocation",
            "termination",
        ],
    })


def generate_phase0_corpus(
    *,
    out: Path,
    external_profile: Path,
    toolchain: str = "gnu",
    compiler: str | None = None,
    linker: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    out = Path(out).resolve()
    external_profile = Path(external_profile).resolve()
    if not external_profile.is_file():
        raise StageAInputError(f"Phase 0 external profile does not exist: {external_profile}")
    if out.exists() and any(out.iterdir()):
        if not force:
            raise StageAInputError(
                f"round-trip corpus output is not empty: {out}; use --force to replace it"
            )
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    if toolchain not in {"gnu", "llvm-msvc"}:
        raise StageAInputError(f"unsupported Phase 0 toolchain {toolchain!r}")
    case_id = (
        PHASE0_CASE_ID
        if toolchain == "gnu"
        else f"{PHASE0_CASE_ID}-llvm-msvc"
    )
    case_root = out / "cases" / case_id
    case_root.mkdir(parents=True)
    program = phase0_semantic_program()
    semantic_path = case_root / "semantic-program.json"
    write_json(semantic_path, program.to_payload())

    original_source = case_root / "original.S"
    candidate_source = case_root / "candidate.S"
    lower = (
        lower_semantic_program_to_gnu_assembly
        if toolchain == "gnu"
        else lower_semantic_program_to_llvm_msvc_assembly
    )
    original_source.write_text(
        lower(
            program,
            variant=AssemblyLoweringVariant("original"),
        ),
        encoding="utf-8",
    )
    candidate_source.write_text(
        lower(
            program,
            variant=AssemblyLoweringVariant(
                "candidate-reachable-nop",
                nop_before_external_symbols=("ExitProcess",),
            ),
        ),
        encoding="utf-8",
    )
    if toolchain == "gnu":
        build = lambda source, binary, linker_map: build_gnu_pe32(
            source=source,
            binary=binary,
            linker_map=linker_map,
            compiler=compiler or "i686-w64-mingw32-gcc",
        )
        toolchain_id = "pinned-mingw32-gnu-v1"
        toolchain_target = "i686-w64-mingw32"
        linker_name = "gnu-ld-via-gcc"
    else:
        build = lambda source, binary, linker_map: build_llvm_msvc_pe32(
            source=source,
            binary=binary,
            linker_map=linker_map,
            clang_cl=compiler or "clang-cl",
            linker=linker or "lld-link",
        )
        toolchain_id = "pinned-llvm-msvc-compatible-v1"
        toolchain_target = "i686-pc-windows-msvc"
        linker_name = Path(linker or "lld-link").name
    original = build(
        original_source,
        case_root / "original.exe",
        case_root / "original.map",
    )
    candidate = build(
        candidate_source,
        case_root / "candidate.exe",
        case_root / "candidate.map",
    )
    mapping_path = case_root / "relation-proposal.json"
    layout_path = case_root / "layout-contract.json"
    mapping = stage_a_generate_map(
        original=original.binary,
        candidate=candidate.binary,
        linker_map_original=original.linker_map,
        linker_map_candidate=candidate.linker_map,
        out=mapping_path,
        layout_contract_out=layout_path,
        original_flags="generated-semantic-assembly-v1",
        candidate_flags="generated-semantic-assembly-v1 reachable-nop",
    )
    if mapping.get("status") != "pass":
        raise StageAInputError(
            "Phase 0 mapping proposal is incomplete: "
            + json.dumps(mapping.get("issues", [])[:3], sort_keys=True)
        )
    mapping_file_payload = json.loads(mapping_path.read_text(encoding="utf-8"))
    mapping_file_payload["original"]["path"] = "original.exe"
    mapping_file_payload["candidate"]["path"] = "candidate.exe"
    mapping_file_payload["linker_maps"] = {
        "original": "original.map",
        "candidate": "candidate.map",
    }
    write_json(mapping_path, mapping_file_payload)
    relation_path = case_root / "relation-contract.json"
    relation = stage_a_generate_relation_contract(
        original=original.binary,
        candidate=candidate.binary,
        mapping=mapping_path,
        external_profile=external_profile,
        out=relation_path,
    )
    if relation.get("status") != "generated":
        raise StageAInputError(
            "Phase 0 relation contract is incomplete: "
            + json.dumps(relation.get("issues", [])[:3], sort_keys=True)
        )
    copied_profile = case_root / "external-profile.json"
    shutil.copyfile(external_profile, copied_profile)
    artifacts = artifact_refs(root=case_root, artifacts=(
        ("semantic_program", semantic_path),
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
    replay = (
        "spaghetti-extractor",
        "stage-a-fuzz-run",
        "--corpus",
        "corpus.json",
        "--mode",
        "proof-core",
        "--out",
        "run",
    )
    case = CaseManifest(
        id=case_id,
        semantic_program_sha256=sha256_file(semantic_path),
        parent_seed=0,
        template="winapi-console-write",
        transformations=("reachable-nop",),
        expectation=CaseExpectation(ExpectedDisposition.PASS, None, None),
        mutation=None,
        capability_profile=PHASE0_CAPABILITY_PROFILE,
        capabilities=program.capabilities,
        proof_families=(
            "static-context",
            "segment-refinement",
            "product-composition",
            "external-lockstep",
            "launch-realizability",
            "whole-program-acceptance",
        ),
        artifacts=artifacts,
        replay=replay,
        shard=0,
    )
    case_path = case_root / "case.json"
    write_case_manifest(case_path, case)
    corpus = CorpusManifest(
        generator_version=PHASE0_GENERATOR_VERSION,
        root_seed=0,
        capability_profile=PHASE0_CAPABILITY_PROFILE,
        toolchain=ToolchainIdentity(
            id=toolchain_id,
            target=toolchain_target,
            compiler=Path(original.compiler).name,
            compiler_version=original.compiler_version,
            linker=linker_name,
            linker_version=original.linker_version,
        ),
        cases=(CorpusCaseRef(
            id=case.id,
            path=case_path.relative_to(out).as_posix(),
            sha256=sha256_file(case_path),
            shard=0,
        ),),
        expected_counts=ExpectedCounts(1, 0, 0),
        shard_count=1,
    )
    corpus_path = out / "corpus.json"
    write_corpus_manifest(corpus_path, corpus)
    inventory_result = write_roundtrip_interface_inventory(
        out=out / "interface-inventory.json"
    )
    loaded = corpus.load_cases(out)
    return {
        "format": "stage-a-roundtrip-generation-v1",
        "status": "generated",
        "corpus": str(corpus_path),
        "corpus_sha256": sha256_file(corpus_path),
        "cases": len(loaded),
        "case_ids": [manifest.id for manifest, _root in loaded],
        "toolchain": corpus.toolchain.to_payload(),
        "interface_inventory": inventory_result,
    }
