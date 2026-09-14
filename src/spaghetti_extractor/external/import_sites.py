"""Bind normalized import behavior to its exact physical argument frame.

Callback provenance is a separate supplied checked adapter. This constructor
never invents one merely because a profile declares a callback effect.
"""

from dataclasses import fields

from .contracts import CheckedExternalSiteContract, CheckedExternalSiteContractError, CheckedStackArgument


def bind_import_site(behavior, *, argument_nodes, tail_jump=False, callback_adapter=None):
    if (behavior.callback_effect == "explicit") != (callback_adapter is not None):
        raise CheckedExternalSiteContractError("checked import site lacks matching callback provenance")
    argument_words = behavior.argument_words
    argument_nodes = list(argument_nodes)
    argument_base_offset = 4 if tail_jump else 0
    arguments = tuple(
        {
            "kind": "transfer_expression_node",
            "node": argument_nodes[index],
        }
        if index < len(argument_nodes)
        else {
            "kind": "captured_stack_word",
            "offset": argument_base_offset + 4 * index,
        }
        for index in range(argument_words)
    )
    stack_arguments = tuple(
        CheckedStackArgument(
            index,
            argument_base_offset + 4 * index,
            4,
            arguments[index],
        )
        for index in range(argument_words)
    )
    return CheckedExternalSiteContract(
        **{field.name: getattr(behavior, field.name) for field in fields(behavior)},
        transfer_kind="jump" if tail_jump else "call",
        disposition="tail_jump" if tail_jump else "returns_here",
        argument_base_offset=argument_base_offset,
        arguments=arguments,
        stack_arguments=stack_arguments,
        callback_adapter=callback_adapter,
    )
