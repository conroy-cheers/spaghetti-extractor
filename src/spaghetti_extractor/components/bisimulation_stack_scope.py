"""Explicit invocation-private stack scope, distinct from a region's cache anchor.

A register-affine cut projection transports the existing scope; it does not
allocate a frame, prove privacy, or authorize changing the observer domain.
"""

from collections.abc import Mapping
from dataclasses import dataclass

POLICY = "checked-invocation-private-stack-scope-v1"


@dataclass(frozen=True)
class PrivateStackScopeV1:
    register: str
    offset: int

    @classmethod
    def parse(cls, value):
        if not isinstance(value, Mapping) or set(value) != {"register", "offset"}:
            raise ValueError("private stack scope requires register and offset")
        if value["register"] not in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
            raise ValueError("private stack scope requires a PE32 register")
        if type(value["offset"]) is not int or not -(1 << 31) <= value["offset"] < (1 << 31):
            raise ValueError("private stack scope offset must be an int32")
        return cls(value["register"], value["offset"])

    def to_payload(self):
        return {"register": self.register, "offset": self.offset}

    def expression(self, state):
        # Evaluate before narrowing: wrapping does not transport a scope.
        return f"((int64_t){state}.{self.register} + INT64_C({self.offset}))"


def scope_expression(sync, state):
    scope = None if sync is None else sync.private_stack_scope
    return f"{state}.esp" if scope is None else scope.expression(state)


def scope_metadata(operation):
    return ({"private_stack_scope_policy": POLICY}
            if any(sync.private_stack_scope is not None for sync in operation.syncs) else {})


def validate_scope_model(planned, model):
    scopes = [PrivateStackScopeV1.parse(sync["private_stack_scope"])
              for sync in planned["source"]["syncs"] if "private_stack_scope" in sync]
    expected = {"private_stack_scope_policy": POLICY} if scopes else {}
    actual = {key: model[key] for key in ("private_stack_scope_policy",) if key in model}
    if actual != expected:
        raise ValueError("private stack scope transport differs from the proof plan")
    return expected
