"""External input-domain checks before invoking the native bridge."""

from ..external.argument_domains import word_in_domain


def argument_domain_source(sites):
    cases = []
    for index, site in enumerate(sites):
        contract = site.checked_external_contract
        if contract is None or not contract.argument_domain:
            continue
        lines = [f"  if (entry == &spx_native_bridges[{index}]) {{",
                 "    uint32_t fault = 0U, value;",
                 "    if (runtime->read == 0) return 0U;"]
        for constraint in contract.argument_domain:
            offset = contract.argument_base_offset + 4 * constraint["argument_index"]
            lines += [f"    if (input->esp > UINT32_MAX - UINT32_C({offset + 3})) return 0U;",
                      f"    value = runtime->read(runtime->context, input->esp + UINT32_C({offset}), 4U, &fault);",
                      f"    if (fault != 0U || !{word_in_domain('value', constraint)}) return 0U;"]
        cases += [*lines, "  }"]
    return "\n".join([
        "static uint32_t spx_native_arguments_admitted(spx_runtime *runtime,",
        "    const spx_native_bridge_entry *entry, const spx_machine_state *input) {",
        "  (void)runtime; (void)entry; (void)input;", *cases, "  return 1U;", "}"])
