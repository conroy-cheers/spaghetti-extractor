"""Supplementary checked clobber frames inside the existing paired proof.

Declarations propose a frame; only bound positive cut AND exit queries supply
it. Result registers remain observable at exits and may change at internal cuts.
ESP, references, memory and control are never waived by this rule.
"""

from .bisimulation_exact_frame import PhysicalFrameSpec, MUTABLE_ACTIVE, run_physical_frame_probe, validate_physical_frame

FIELDS = frozenset(("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "cf", "zf", "sf", "of", "pf", "df", "eflags"))
REGISTERS = FIELDS - {"cf", "zf", "sf", "of", "pf", "df", "eflags"}
ACTIVE = "__CPROVER_spx_clobber_frame_active"


def parse_clobbers(value):
    if (not isinstance(value, (list, tuple)) or any(not isinstance(v, str) or v not in FIELDS for v in value)
            or list(value) != sorted(set(value))):
        raise ValueError("machine clobbers must be ordered unique supported register/flag names")
    return tuple(value)


def result_registers(projection):
    result = []
    for row in projection.get("results", []):
        value = row.get("projection", {})
        if value.get("kind") == "view" and value.get("at") == "exit":
            value = value.get("base", {})
        if (value.get("kind") != "register" or value.get("width") != 32
                or value.get("register") not in REGISTERS or value.get("at") != "exit"):
            raise ValueError("clobber frames require full-width register result projections or direct view bases")
        result.append(value["register"])
    return tuple(sorted(set(result)))


def clobber_specs(clobbers, results):
    clobbers = parse_clobbers(clobbers)
    results = parse_clobbers(results)
    if not clobbers or set(results) - REGISTERS or set(clobbers) & set(results):
        raise ValueError("clobber frame must preserve separately mapped result registers")
    # Names bind the frame to raw solver properties as well as model metadata.
    suffix = "_".join(clobbers) + "__result_" + ("_".join(results) or "none")
    return tuple(PhysicalFrameSpec(f"exact_mutable_{kind}_clobber_frame",
        f"original-declared-{kind}-clobber-frame-wide-v1", f"__CPROVER_spx_{kind}_clobber_{suffix}",
        f"spx-bisimulation-mutable-{kind}-clobber-frame:{suffix}",
        f"__CPROVER_spx_{kind}_clobber_probe_{suffix}_", f"mutable-{kind}-clobber-frame")
        for kind in ("cut", "exit"))


def declarations(clobbers, results):
    if not clobbers:
        return []
    return [f"static uint32_t {ACTIVE};", *(f"void {spec.guard}(uint32_t equal) {{\n"
        f'  __CPROVER_assert({ACTIVE} == 0U || equal, "{spec.description}");\n}}'
        for spec in clobber_specs(clobbers, results))]


def frame_equalities(equalities, clobbers):
    """Filter exact field equalities only, preserving every other ABI field."""
    return [line for line in equalities if not any(
        line.split(" == ", 1)[0].endswith("." + field) for field in clobbers)]


def probe_source(proof_function, clobbers, results, private_stack_writes=()):
    from .bisimulation_private_frame import activation
    return "\n".join(f"void {spec.entry(proof_function)}(void) {{\n"
        f"  {activation(private_stack_writes)}{MUTABLE_ACTIVE} = 4U; {ACTIVE} = 1U;\n  {proof_function}();\n}}"
        for spec in clobber_specs(clobbers, results)) if clobbers else ""


def run_clobber_probes(*, task, entry, **kwargs):
    if (not task.get("machine_clobbers")
            or entry.get("mutable_entry_contract", {}).get("result", {}).get("status") != "satisfied"):
        return {}
    return {key: value for spec in clobber_specs(task["machine_clobbers"], task["machine_result_registers"])
            for key, value in run_physical_frame_probe(task=task, spec=spec, **kwargs).items()}


def validate_clobber_frame(value, *, spec, shard, model, **kwargs):
    if (spec not in clobber_specs(model.get("machine_clobbers", []), model.get("machine_result_registers", []))
            or shard.get("mutable_entry_contract", {}).get("result", {}).get("status") != "satisfied"
            or spec.description not in model["required_assertion_descriptions"]):
        raise ValueError("clobber frame lacks its checked wider entry or declared frame")
    validate_physical_frame(value, spec=spec, shard=shard, model=model, **kwargs)


def clobber_guarantee(proof, operation):
    clobbers = operation.get("machine_clobbers", [])
    if not clobbers:
        return False
    specs = clobber_specs(clobbers, operation.get("machine_result_registers", []))
    shards = {(s["operation_id"], s["obligation_id"]): s for s in proof["shards"]}
    return bool(operation["obligation_models"]) and all(
        model.get("machine_clobbers") == list(clobbers)
        and model.get("machine_result_registers") == operation.get("machine_result_registers")
        and all(spec.description in model["required_assertion_descriptions"] and
                shards[(operation["operation_id"], model["obligation_id"])].get(spec.field, {}).get("result", {}).get("status") == "satisfied"
                for spec in specs) for model in operation["obligation_models"])


def consumed_clobbers(connected, operation_id):
    entry = connected.get("entry_contract")
    if not entry or entry.get("policy") != "checked-mutable-callee-stack-entry-v1":
        return ()
    proof = entry["proof_system"]["proof"]
    operation = next((o for o in proof["models"]["operation_models"] if o["operation_id"] == operation_id), None)
    return tuple(operation["machine_clobbers"]) if operation is not None and clobber_guarantee(proof, operation) else ()


def call_assertions(connected):
    entry = connected.get("entry_contract")
    return [] if entry is None else [
        f"spx-bisimulation-connected-callee-clobber-state:{connected['component_id']}:{operation['operation_id']}"
        for operation in entry["operations"] if consumed_clobbers(connected, operation["operation_id"])]


def call_havoc(row):
    clobbers = consumed_clobbers(row, row["operation_id"])
    if not clobbers:
        return []
    return [f'      __CPROVER_assert(1U, "spx-bisimulation-connected-callee-clobber-state:{row["component_id"]}:{row["operation_id"]}");',
            *(f"      call_state.{field} = spx_nondet_u32();" for field in clobbers)]
