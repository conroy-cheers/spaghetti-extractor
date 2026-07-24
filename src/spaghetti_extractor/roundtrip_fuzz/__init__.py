"""Generic round-trip qualification infrastructure for Stage A and Stage B."""

from .model import (
    ROUNDTRIP_CASE_FORMAT,
    ROUNDTRIP_CORPUS_FORMAT,
    ArtifactRef,
    CaseExpectation,
    CaseManifest,
    CorpusManifest,
    ExpectedDisposition,
    load_case_manifest,
    load_corpus_manifest,
)
from .discovery import (
    compare_discovery_proposals,
    discover_linker_map_pair,
    qualify_discovery_templates,
)
from .generator import SPIKE_CASES, generate_spike_corpus
from .image_contract import (
    STAGE_A_LOAD_IMAGE_CONTRACT_FORMAT,
    StageALoadImageContract,
    build_stage_a_load_image_contract,
    load_stage_a_load_image_contract,
    write_stage_a_load_image_contract,
)
from .qualification import (
    ROUNDTRIP_FEASIBILITY_REPORT_FORMAT,
    write_roundtrip_qualification_report,
)
from .reducer import (
    ArtifactPredicate,
    PredicateObservation,
    reduce_roundtrip_case_artifacts,
)

__all__ = [
    "ROUNDTRIP_CASE_FORMAT",
    "ROUNDTRIP_CORPUS_FORMAT",
    "ROUNDTRIP_FEASIBILITY_REPORT_FORMAT",
    "STAGE_A_LOAD_IMAGE_CONTRACT_FORMAT",
    "ArtifactRef",
    "CaseExpectation",
    "CaseManifest",
    "CorpusManifest",
    "ExpectedDisposition",
    "StageALoadImageContract",
    "load_case_manifest",
    "load_corpus_manifest",
    "SPIKE_CASES",
    "build_stage_a_load_image_contract",
    "generate_spike_corpus",
    "load_stage_a_load_image_contract",
    "ArtifactPredicate",
    "PredicateObservation",
    "compare_discovery_proposals",
    "discover_linker_map_pair",
    "qualify_discovery_templates",
    "reduce_roundtrip_case_artifacts",
    "write_roundtrip_qualification_report",
    "write_stage_a_load_image_contract",
]
