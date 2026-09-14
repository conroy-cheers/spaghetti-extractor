"""Checked allocation flag domain and byte-initialization contract."""

from dataclasses import dataclass
from typing import Mapping

from ..errors import ToolkitInputError


class RangeAllocationError(ToolkitInputError):
    """An allocation contract is ambiguous or outside its checked argument frame."""


@dataclass(frozen=True, order=True)
class RangeAllocation:
    argument_masks: tuple[tuple[int, int], ...]
    initialization: str
    zero_argument: int | None = None
    zero_mask: int = 0

    def payload(self):
        return {
            "argument_masks": [{"argument_index": index, "allowed_mask": mask}
                               for index, mask in self.argument_masks],
            "initialization": {"kind": self.initialization, **(
                {"argument_index": self.zero_argument, "mask": self.zero_mask}
                if self.initialization == "argument_flag" else {})},
        }


def parse_range_allocation(value, *, argument_words, context):
    if value is None:
        return None
    if (not isinstance(value, Mapping) or set(value) != {"argument_masks", "initialization"}
            or type(argument_words) is not int or not 0 <= argument_words <= 256):
        raise RangeAllocationError(f"{context} requires explicit allocation masks and initialization")
    guards = value["argument_masks"]
    if not isinstance(guards, list) or len(guards) > argument_words:
        raise RangeAllocationError(f"{context} has malformed allocation masks")
    masks = {}
    for guard in guards:
        if not isinstance(guard, Mapping) or set(guard) != {"argument_index", "allowed_mask"}:
            raise RangeAllocationError(f"{context} has malformed allocation mask")
        index, mask = guard["argument_index"], guard["allowed_mask"]
        if (type(index) is not int or not 0 <= index < argument_words or index in masks
                or type(mask) is not int or not 0 <= mask <= 0xffffffff):
            raise RangeAllocationError(f"{context} has invalid allocation mask argument or value")
        masks[index] = mask
    init = value["initialization"]
    if not isinstance(init, Mapping) or not isinstance(init.get("kind"), str):
        raise RangeAllocationError(f"{context} has malformed allocation initialization")
    kind = init["kind"]
    if kind in {"uninitialized", "zero"} and set(init) == {"kind"}:
        return RangeAllocation(tuple(sorted(masks.items())), kind)
    if kind != "argument_flag" or set(init) != {"kind", "argument_index", "mask"}:
        raise RangeAllocationError(f"{context} has unsupported allocation initialization")
    index, mask = init["argument_index"], init["mask"]
    if (type(index) is not int or not 0 <= index < argument_words
            or type(mask) is not int or not 0 < mask <= 0xffffffff or mask & (mask - 1)
            or index not in masks or mask & ~masks[index]):
        raise RangeAllocationError(f"{context} zero flag must be one admitted argument bit")
    return RangeAllocation(tuple(sorted(masks.items())), kind, index, mask)


def validate_range_allocation_relations(value, *, argument_words, context):
    relations = value.get("result_register_relations", [])
    if not isinstance(relations, list):
        return
    for relation in relations:
        if not isinstance(relation, Mapping) or "allocation" not in relation:
            continue
        if (relation.get("relation") != "dynamic_range_base"
                or value.get("world_effect") != "dynamicRanges"
                or relation.get("ownership") is None or relation["allocation"] is None):
            raise RangeAllocationError(f"{context} allocation requires an owned dynamic range result")
        parse_range_allocation(relation["allocation"], argument_words=argument_words, context=context)
