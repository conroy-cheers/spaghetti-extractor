"""Generated PE32 round-trip regression infrastructure."""

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
    "SPIKE_CASES": ".generator",
    "generate_spike_corpus": ".generator",
    "run_roundtrip_corpus": ".runner",
    "SPX_LOAD_IMAGE_CONTRACT_FORMAT": ".image_model",
    "LoadImageContract": ".image_model",
    "build_spx_load_image_contract": ".image_io",
    "load_spx_load_image_contract": ".image_io",
    "write_spx_load_image_contract": ".image_io",
}

__all__ = [
    "ROUNDTRIP_CASE_FORMAT",
    "ROUNDTRIP_CORPUS_FORMAT",
    "SPX_LOAD_IMAGE_CONTRACT_FORMAT",
    "ArtifactRef",
    "CaseExpectation",
    "CaseManifest",
    "CorpusManifest",
    "ExpectedDisposition",
    "LoadImageContract",
    "load_case_manifest",
    "load_corpus_manifest",
    "SPIKE_CASES",
    "build_spx_load_image_contract",
    "generate_spike_corpus",
    "load_spx_load_image_contract",
    "run_roundtrip_corpus",
    "write_spx_load_image_contract",
]


def __getattr__(name: str) -> Any:
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(name)
    value = getattr(import_module(module_name, __name__), name)
    globals()[name] = value
    return value
