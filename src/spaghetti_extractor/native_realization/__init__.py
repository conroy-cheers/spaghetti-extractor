"""One selected-provider-to-native-module realization domain."""

from importlib import import_module
from typing import Any

from .formats import NATIVE_REALIZATION_V2_FORMAT


_RECEIPT_EXPORTS = {
    "NativeRealizationV2Error",
    "NativeRealizationV2",
    "build_native_realization_v2",
    "write_native_realization_v2",
}


def __getattr__(name: str) -> Any:
    if name not in _RECEIPT_EXPORTS:
        raise AttributeError(name)
    return getattr(import_module(".receipt_v2", __name__), name)


__all__ = ["NATIVE_REALIZATION_V2_FORMAT", *_RECEIPT_EXPORTS]
