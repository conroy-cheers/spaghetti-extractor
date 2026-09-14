"""Checked unsigned machine-word input domains for external call contracts."""

from collections.abc import Mapping


class ArgumentDomainError(ValueError):
    pass


def checked_argument_domain(value, *, argument_words, context="external argument domain"):
    if not isinstance(value, list):
        raise ArgumentDomainError(f"{context} must be a list")
    result = []
    for row in value:
        if not isinstance(row, Mapping) or set(row) != {"argument_index", "minimum", "maximum"}:
            raise ArgumentDomainError(f"{context} has an unsupported constraint")
        index, minimum, maximum = (row[key] for key in ("argument_index", "minimum", "maximum"))
        if (any(type(item) is not int for item in (index, minimum, maximum)) or
                not 0 <= index < argument_words or not 0 <= minimum <= maximum <= 0xffffffff):
            raise ArgumentDomainError(f"{context} has an invalid index or interval")
        result.append(dict(row))
    indices = [row["argument_index"] for row in result]
    if indices != sorted(set(indices)):
        raise ArgumentDomainError(f"{context} must contain ordered distinct arguments")
    return tuple(result)


def word_in_domain(expression, constraint):
    return (f'(({expression}) >= UINT32_C({constraint["minimum"]}) && '
            f'({expression}) <= UINT32_C({constraint["maximum"]}))')
