"""Checked residual stack writes, separate from logical buffer permissions.

Footprints are relative to the operation's entry ESP. Cut probes must preserve
that anchor; declarations alone never grant summary replacement or byte reuse.
"""

from .bisimulation_exact_frame import PhysicalFrameSpec, MUTABLE_ACTIVE
from .bisimulation_support import PROOF_PRIVATE_STACK_ABOVE, PROOF_PRIVATE_STACK_BELOW

ACTIVE = "__CPROVER_spx_private_frame_active"
ANCHOR = "__CPROVER_spx_private_frame_anchor"


def parse_stack_writes(value):
    if not isinstance(value, (list, tuple)):
        raise ValueError("private stack writes must be an ordered list of offset/byte ranges")
    result = []
    for row in value:
        if not isinstance(row, dict) or set(row) != {"offset", "bytes"}:
            raise ValueError("private stack write range fields differ")
        offset, size = row["offset"], row["bytes"]
        if (type(offset) is not int or type(size) is not int or size <= 0
                or offset < -PROOF_PRIVATE_STACK_BELOW or offset + size > PROOF_PRIVATE_STACK_ABOVE):
            raise ValueError("private stack write range is outside the supported frame")
        if result and offset < result[-1][0] + result[-1][1]:
            raise ValueError("private stack write ranges must be ordered and disjoint")
        result.append((offset, size))
    return tuple(result)


def payload(ranges):
    return [{"offset": offset, "bytes": size} for offset, size in ranges]


def suffix(ranges):
    return "_".join(f"{'m' if offset < 0 else 'p'}{abs(offset)}n{size}" for offset, size in ranges)


def specs(ranges):
    name = suffix(ranges)
    if not name:
        raise ValueError("private frame requires a nonempty footprint")
    return tuple(PhysicalFrameSpec(f"exact_private_{kind}_frame",
        f"original-private-stack-{kind}-frame-v1", f"__CPROVER_spx_private_{kind}_{name}",
        f"spx-bisimulation-private-{kind}-frame:{name}",
        f"__CPROVER_spx_private_{kind}_probe_{name}_", f"private-{kind}-frame")
        for kind in ("write", "cut"))


def entry_prefix(ranges):
    return "__CPROVER_spx_private_entry_" + suffix(ranges) + "_"


def entry_domain(ranges):
    below = max(0, -min(offset for offset, _ in ranges))
    return {"minimum_esp": max(4, below), "image_exclusion_below_esp": below,
        "image_exclusion_above_esp": "original-private-high-offset",
        "private_low": "saturating-original-window", "nonvacuity": "ordinary-domain-inclusion-v1"}


def admission(ranges, *, stack, image_base, image_size, high):
    domain = entry_domain(ranges)
    return (f"({stack} >= UINT32_C({domain['minimum_esp']}) && "
        f"((uint64_t){stack} + {high} <= UINT64_C({image_base}) || "
        f"(uint64_t){stack} >= UINT64_C({image_base + image_size + domain['image_exclusion_below_esp']})))")


def activation(ranges):
    return f"{ACTIVE} = 1U; " if ranges else ""


def declarations(ranges):
    if not ranges:
        return ""
    write, cut = specs(ranges)
    conditions = [f"((int64_t)address >= (int64_t){ANCHOR} + INT64_C({offset}) && "
                  f"(int64_t)address < (int64_t){ANCHOR} + INT64_C({offset + size}))"
                  for offset, size in ranges]
    return f"""
static uint32_t {ACTIVE}, {ANCHOR};
void {write.guard}(uint32_t permitted) {{
  __CPROVER_assert({ACTIVE} == 0U || permitted, "{write.description}");
}}
void {cut.guard}(uint32_t anchor) {{
  __CPROVER_assert({ACTIVE} == 0U || anchor == {ANCHOR}, "{cut.description}");
}}
static uint32_t spx_proof_private_write_byte(uint32_t address) {{
  return ({' || '.join(conditions)}) &&
      spx_proof_is_private(&spx_exact_world, address) &&
      spx_proof_is_private(&spx_source_world, address);
}}
"""


def write_check(ranges):
    if not ranges:
        return ""
    # Every byte may belong to either logical writable views or a checked
    # private range. Whole-store alternatives would reject adjacent grants.
    allowed = " && ".join(f"(width <= {i}U || spx_proof_mutable_write_permitted(address + {i}U, 1U) || "
        f"spx_proof_private_write_byte(address + {i}U))" for i in range(4))
    return f"  {specs(ranges)[0].guard}(world != &spx_exact_world || ({allowed}));\n"


def initialization(ranges):
    return [f"  {ANCHOR} = initial_state.esp;"] if ranges else []


def cut_check(ranges):
    return [f"  {specs(ranges)[1].guard}(spx_proof_exact_output.esp);"] if ranges else []


def probe_source(proof_function, ranges):
    if not ranges:
        return ""
    entries = [spec.entry(proof_function) for spec in specs(ranges)] + [entry_prefix(ranges) + proof_function]
    return "\n".join(f"void {entry}(void) {{ {ACTIVE} = 1U; {MUTABLE_ACTIVE} = 3U; {proof_function}(); }}"
                     for entry in entries)


def validate_private_frame(value, *, spec, model, **kwargs):
    from .bisimulation_exact_frame import validate_physical_frame
    ranges = parse_stack_writes(model.get("private_stack_writes", []))
    if spec not in specs(ranges) or spec.description not in model["required_assertion_descriptions"]:
        raise ValueError("private frame lacks its declared footprint and guard")
    validate_physical_frame(value, spec=spec, model=model, **kwargs)


def checked_private_frame_operations(proof, *, artifacts, runtime_assurance=None):
    from .bisimulation_assurance import validate_runtime_assurance_binding
    validate_runtime_assurance_binding(proof, runtime_assurance)
    from pathlib import Path
    from .bisimulation_mutable_frame import CUT_FRAME
    from .bisimulation_exact_frame import validate_physical_frame
    shards = {(s["operation_id"], s["obligation_id"]): s for s in proof["shards"]}
    covered = []
    for operation_index, operation in enumerate(proof["models"]["operation_models"]):
        ranges = parse_stack_writes(operation.get("private_stack_writes", []))
        if not ranges:
            continue
        complete = proof.get("status") == "satisfied" and bool(operation["obligation_models"])
        for index, model in enumerate(operation["obligation_models"]):
            shard = shards[(operation["operation_id"], model["obligation_id"])]
            for spec in (*specs(ranges), CUT_FRAME):
                value = shard.get(spec.field)
                if value is None or value["result"]["status"] != "satisfied":
                    complete = False
                    continue
                validate_physical_frame(value, spec=spec, model=model, shard=shard, checker=proof["checker"], runtime_assurance=runtime_assurance,
                    artifacts=Path(artifacts) / f"operation-{operation_index:04d}-obligation-{index:04d}")
        if complete:
            covered.append(operation["operation_id"])
    return tuple(covered)



def consumed_stack_writes(connected, operation_id):
    entry = connected.get("entry_contract")
    if not entry or entry.get("policy") != "checked-mutable-callee-stack-entry-v1":
        return ()
    proof = entry["proof_system"]["proof"]
    operation = next((o for o in proof["models"]["operation_models"] if o["operation_id"] == operation_id), None)
    if operation is None:
        return ()
    ranges = parse_stack_writes(operation.get("private_stack_writes", []))
    shards = {(s["operation_id"], s["obligation_id"]): s for s in proof["shards"]}
    if not ranges or not operation["obligation_models"]:
        return ()
    for model in operation["obligation_models"]:
        shard = shards[(operation_id, model["obligation_id"])]
        if (shard.get("mutable_entry_contract", {}).get("policy") != "paired-mutable-entry-private-write-frame-v1"
                or shard["mutable_entry_contract"]["result"]["status"] != "satisfied"
                or any(shard.get(spec.field, {}).get("result", {}).get("status") != "satisfied" for spec in specs(ranges))):
            return ()
    return ranges


def call_assertions(connected):
    entry = connected.get("entry_contract")
    return [] if entry is None else [
        f"spx-bisimulation-connected-callee-private-poststate:{connected['component_id']}:{o['operation_id']}"
        for o in entry["operations"] if consumed_stack_writes(connected, o["operation_id"])]


def call_preparation(row):
    return ["      uint32_t private_entry_esp = call_state.esp;"] if consumed_stack_writes(row, row["operation_id"]) else []


def call_havoc(row):
    ranges = consumed_stack_writes(row, row["operation_id"])
    if not ranges:
        return []
    lines = ["      uint32_t private_write_fault = 0U;"]
    for offset, size in ranges:
        for byte in range(0, size, 4):
            width = min(4, size - byte)
            lines += [f"      rt->write(rt->context, (uint32_t)((int64_t)private_entry_esp + INT64_C({offset + byte})), "
                      f"{width}U, spx_nondet_u32(), &fault);", "      private_write_fault |= fault;"]
    return lines + [f'      __CPROVER_assert(private_write_fault == 0U, "spx-bisimulation-connected-callee-private-poststate:{row["component_id"]}:{row["operation_id"]}");',
                    "      __CPROVER_assume(private_write_fault == 0U);"]


def summary_write_count(connected_components):
    return sum(max((sum((size + 3) // 4 for _, size in consumed_stack_writes(c, o["operation_id"]))
                    for o in c.get("entry_contract", {}).get("operations", [])), default=0)
               for c in connected_components if c.get("entry_contract"))
