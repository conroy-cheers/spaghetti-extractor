"""Checked physical frames for repeated parameter-slot projections.

The frame protects pointer-storage bytes, not pointees. Native metadata, current
contents, reference validity and lifetime are still checked at the reached cut.
"""

import re

POLICY = "checked-preserved-parameter-slots-v1"
FIELD = "preserved_parameter_slots"
MODEL_FIELD = "parameter_slot_frame_policy"
GUARD = "spx_proof_parameter_slot_write_guard"
READER = "spx_proof_parameter_slot_output_read"


def parse_slots(value, captures, scope):
    if (not isinstance(value, list) or not value
            or any(not isinstance(name, str) for name in value)
            or value != sorted(set(value))):
        raise ValueError("preserved parameter slots require nonempty ordered unique capture names")
    if scope is None or scope.register != "esp":
        raise ValueError("preserved parameter slots require an explicit ESP-relative private stack scope")
    by_id = {capture.identity: capture for capture in captures}
    for name in value:
        capture = by_id.get(name)
        projection = {} if capture is None or capture.projection is None else capture.projection.payload
        base = projection.get("base", {})
        offset = base.get("offset")
        if (capture is None or capture.kind != "parameter" or capture.mode != "machine_codec"
                or projection.get("kind") not in {"view", "bytes_view"}
                or base.get("kind") != "stack" or base.get("width") != 32
                or type(offset) is not int or offset % 4 or not -1024 <= offset <= 4092):
            raise ValueError("preserved parameter slots require aligned PE32 stack-based parameter views")
    return tuple(value)


def configuration(sync):
    if sync is None or not sync.preserved_parameter_slots:
        return None
    names = parse_slots(list(sync.preserved_parameter_slots), sync.captures, sync.private_stack_scope)
    return {"sync_id": sync.identity, "offsets": sorted({
        capture.projection.payload["base"]["offset"] for capture in sync.captures if capture.identity in names})}


def description(config):
    return "spx-bisimulation-preserved-parameter-slot-writes:" + config["sync_id"]


def transports_anchor(start, target):
    """Equal ESP-affine scopes transport the regional anchor across any cut.

    The outgoing scope assertion must precede the substituted reads. The frame
    belongs to the starting region; the successor need not promise a new frame.
    A different scope offset can preserve invocation scope while changing ESP,
    so that case must keep its ordinary reads.
    """
    return (configuration(start) is not None and target.private_stack_scope is not None
            and start.private_stack_scope == target.private_stack_scope)


def metadata(operation):
    return {MODEL_FIELD: POLICY} if any(configuration(sync) for sync in operation.syncs) else {}


def validate_model(planned, model):
    from .bisimulation import BisimulationSyncV1
    syncs = [BisimulationSyncV1.parse(row, "parameter slot frame") for row in planned["source"]["syncs"]]
    present = any(configuration(sync) for sync in syncs)
    expected = {MODEL_FIELD: POLICY} if present else {}
    if {key: model[key] for key in (MODEL_FIELD,) if key in model} != expected:
        raise ValueError("parameter slot frame differs from the proof plan")
    if "obligation_id" in model:
        for sync in syncs:
            config = configuration(sync)
            if config and model["obligation_id"] == "sync:" + sync.identity:
                if description(config) not in model["required_assertion_descriptions"]:
                    raise ValueError("parameter slot frame omits its mandatory write guard")
    return expected


def world_fragments(config):
    if config is None:
        return {key: "" for key in ("declarations", "write", "reset")}
    if (not isinstance(config, dict) or set(config) != {"sync_id", "offsets"}
            or not isinstance(config["sync_id"], str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", config["sync_id"]) is None
            or not isinstance(config["offsets"], list) or not config["offsets"]
            or any(type(offset) is not int or offset % 4 or not -1024 <= offset <= 4092
                   for offset in config["offsets"])
            or config["offsets"] != sorted(set(config["offsets"]))):
        raise ValueError("parameter slot frame configuration is malformed")
    conditions = [f"((int64_t)address + width <= (int64_t)spx_exact_world.private_anchor + INT64_C({offset}) || "
                  f"(int64_t)spx_exact_world.private_anchor + INT64_C({offset + 4}) <= address)"
                  for offset in config["offsets"]]
    return {"declarations": f'''static void {GUARD}(uint32_t preserved) {{
  __CPROVER_assert(preserved, "{description(config)}");
  __CPROVER_assume(preserved);
}}
''', "write": f"  {GUARD}(world != &spx_exact_world || ({' && '.join(conditions)}));\n",
        # Validate nonwrapping coordinates even in a region without stores.
        "reset": f"  {GUARD}(" + " && ".join(
            f"((int64_t)spx_exact_world.private_anchor + INT64_C({offset}) >= 0 && "
            f"(int64_t)spx_exact_world.private_anchor + INT64_C({offset + 4}) <= INT64_C(4294967296))"
            for offset in config["offsets"]) + ");\n"}


def header_reader(config):
    if config is None:
        return []
    lines = [f"static uint32_t {READER}(uint32_t address, uint32_t width) {{",
             # Evaluate current read validity even when its value can be reused.
             "  uint32_t value = spx_proof_exact_output_read(address, width);"]
    for offset in config["offsets"]:
        slot = f"(uint32_t)((int64_t)spx_proof_exact_output.esp + INT64_C({offset}))"
        before = f"(uint32_t)((int64_t)spx_proof_exact_input.esp + INT64_C({offset}))"
        lines += [f"  if (width == 4U && address == {slot})",
                  f"    return spx_proof_exact_input_read({before}, 4U);"]
    return [*lines, "  return value;", "}"]
