"""Closed compact codecs for semantic-link reference membership sets."""

from __future__ import annotations

from collections.abc import Iterable


def encode_reference_index_set_v1(rows: Iterable[int]) -> str:
    """Encode a sorted unique nonnegative index set as delta ULEB128 hex."""

    indices = list(rows)
    if (
        indices != sorted(set(indices))
        or any(
            not isinstance(index, int)
            or isinstance(index, bool)
            or index < 0
            for index in indices
        )
    ):
        raise ValueError("reference indices must be sorted unique integers")
    encoded = bytearray()
    previous = 0
    for position, index in enumerate(indices):
        delta = index if position == 0 else index - previous
        while True:
            byte = delta & 0x7f
            delta >>= 7
            if delta:
                byte |= 0x80
            encoded.append(byte)
            if not delta:
                break
        previous = index
    return encoded.hex()


def decode_reference_index_set_v1(
    value: object, *, limit: int,
) -> tuple[int, ...]:
    """Decode and require the unique canonical encoding within a catalog."""

    if (
        not isinstance(value, str)
        or len(value) % 2
        or any(character not in "0123456789abcdef" for character in value)
        or not isinstance(limit, int)
        or isinstance(limit, bool)
        or limit < 0
    ):
        raise ValueError("reference index set encoding is malformed")
    encoded = bytes.fromhex(value)
    result: list[int] = []
    cursor = 0
    previous = 0
    while cursor < len(encoded):
        delta = 0
        shift = 0
        while True:
            if cursor >= len(encoded) or shift > 63:
                raise ValueError("reference index set varint is malformed")
            byte = encoded[cursor]
            cursor += 1
            delta |= (byte & 0x7f) << shift
            if not byte & 0x80:
                break
            shift += 7
        if result and delta == 0:
            raise ValueError("reference index set is not strictly increasing")
        index = delta if not result else previous + delta
        if index >= limit:
            raise ValueError("reference index set exceeds its catalog")
        result.append(index)
        previous = index
    if encode_reference_index_set_v1(result) != value:
        raise ValueError("reference index set encoding is noncanonical")
    return tuple(result)
