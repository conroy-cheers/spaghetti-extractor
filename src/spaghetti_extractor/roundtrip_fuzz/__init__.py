"""Generic round-trip qualification infrastructure for Stage A and Stage B."""

from importlib import import_module
from typing import Any


_EXPORT_MODULES = {
    "ROUNDTRIP_CASE_FORMAT": ".model",
    "ROUNDTRIP_CORPUS_FORMAT": ".model",
    "ArtifactRef": ".model",
    "CaseExpectation": ".model",
    "CaseManifest": ".model",
    "CorpusManifest": ".model",
    "ExpectedDisposition": ".model",
    "load_case_manifest": ".model",
    "load_corpus_manifest": ".model",
    "compare_discovery_proposals": ".discovery",
    "discover_linker_map_pair": ".discovery",
    "qualify_discovery_templates": ".discovery",
    "SPIKE_CASES": ".generator",
    "generate_spike_corpus": ".generator",
    "STAGE_A_LOAD_IMAGE_CONTRACT_FORMAT": ".image_contract",
    "StageALoadImageContract": ".image_contract",
    "build_stage_a_load_image_contract": ".image_contract",
    "load_stage_a_load_image_contract": ".image_contract",
    "write_stage_a_load_image_contract": ".image_contract",
    "ROUNDTRIP_FEASIBILITY_REPORT_FORMAT": ".qualification",
    "write_roundtrip_qualification_report": ".qualification",
    "ArtifactPredicate": ".reducer",
    "PredicateObservation": ".reducer",
    "reduce_roundtrip_case_artifacts": ".reducer",
}

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


def __getattr__(name: str) -> Any:
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(name)
    value = getattr(import_module(module_name, __name__), name)
    globals()[name] = value
    return value
