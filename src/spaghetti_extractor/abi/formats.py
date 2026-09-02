"""Format ownership for physical-ABI artifacts."""

from __future__ import annotations

from ..artifacts.format_spec import FormatSpecV1


FORMAT_SPECS = (
    FormatSpecV1(
        literal="spaghetti-extractor-abi-declaration-ingestion-v1",
        version=1,
        owner=__name__,
        codec="spaghetti_extractor.abi.ingestion",
        role="operator_declaration_ingestion",
        state="active",
        symbol="ABI_DECLARATION_INGESTION_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-abi-match-resolution-v1",
        version=1,
        owner=__name__,
        codec=__name__,
        role="authority_resolution",
        state="retired",
        symbol="RETIRED_ABI_MATCH_RESOLUTION_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-catalog-call-contract-set-v1",
        version=1,
        owner=__name__,
        codec=__name__,
        role="authority_contract_set",
        state="retired",
        symbol="RETIRED_CATALOG_CALL_CONTRACT_SET_V1_FORMAT",
    ),
)

ABI_DECLARATION_INGESTION_FORMAT = FORMAT_SPECS[0].literal

__all__ = [spec.symbol for spec in FORMAT_SPECS] + ["FORMAT_SPECS"]
