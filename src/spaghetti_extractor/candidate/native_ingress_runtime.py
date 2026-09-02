# ruff: noqa: F401
"""Public facade for generic IA-32 native-ingress runtime emission."""

from .native_ingress_runtime_abi import (
    PRIVATE_STACK_SLICE_BYTES,
    MINIMUM_RUNTIME_CONTROL_BYTES,
    align_up as _align_up,
)
from .native_ingress_runtime_model import (
    compact_callback_runtime_v1,
    physical_frame_transducer_v1,
    boundary_lifecycle_transducer_v1,
    _checked_lifecycle_bindings_v1,
    _capability_lifetime,
    NativeIngressSupportABI,
)
from .native_ingress_runtime_assembly import (
    render_native_ingress_assembly,
    _bridge_rows,
    _uint,
    _preserved_mask,
    _exception_record_projection_masks_v1,
    _seh_projection_masks,
)
from .native_ingress_runtime_header import (
    exact_tls_regions,
    render_native_ingress_header,
)
from .native_ingress_runtime_source import (
    render_native_ingress_source,
)

__all__ = [
    "PRIVATE_STACK_SLICE_BYTES",
    "MINIMUM_RUNTIME_CONTROL_BYTES",
    "NativeIngressSupportABI",
    "compact_callback_runtime_v1",
    "exact_tls_regions",
    "render_native_ingress_assembly",
    "render_native_ingress_header",
    "render_native_ingress_source",
]
