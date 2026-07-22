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
    "ArtifactRef",
    "CaseExpectation",
    "CaseManifest",
    "CorpusManifest",
    "ExpectedDisposition",
    "load_case_manifest",
    "load_corpus_manifest",
    "SPIKE_CASES",
    "generate_spike_corpus",
    "ArtifactPredicate",
    "PredicateObservation",
    "compare_discovery_proposals",
    "discover_linker_map_pair",
    "qualify_discovery_templates",
    "reduce_roundtrip_case_artifacts",
    "write_roundtrip_qualification_report",
]
