"""Checked typed call protocols.

The package deliberately keeps physical transport, portable C types, and
behavioral lifecycle facts separate.  Consumers should exchange
``CheckedCallProtocolV1`` records rather than reconstructing calling
conventions from word counts.
"""

from .frame import PhysicalCallFrameV2, PhysicalCallFrameV3
from .evidence import MachineCallEvidenceV1
from .callback import CallbackProtocolV2
from .callback_v3 import CallbackProtocolV3
from .compatibility import CallProtocolCompatibilityV1
from .lifecycle import CallLifecycleReceiptV1, CallLifecycleV1
from .intent import CallProtocolIntentV1
from .protocol import CheckedCallProtocolV1, IdiomaticCallViewV1
from .protocol_v2 import CheckedCallProtocolV2
from .relation import CallFrameRelationReceiptV1, CallFrameRelationV1
from .source import SourceNamingV1, render_call_header
from .types import PortableTypeGraphV1, TargetLayoutSetV1

__all__ = [
    "CallLifecycleV1",
    "CallLifecycleReceiptV1",
    "CallProtocolIntentV1",
    "CallbackProtocolV2",
    "CallbackProtocolV3",
    "CallProtocolCompatibilityV1",
    "CallFrameRelationV1",
    "CallFrameRelationReceiptV1",
    "CheckedCallProtocolV1",
    "CheckedCallProtocolV2",
    "IdiomaticCallViewV1",
    "PhysicalCallFrameV2",
    "PhysicalCallFrameV3",
    "MachineCallEvidenceV1",
    "PortableTypeGraphV1",
    "SourceNamingV1",
    "TargetLayoutSetV1",
    "render_call_header",
]
