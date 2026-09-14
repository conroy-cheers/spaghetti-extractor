"""Checked machine frames for mutable suppliers, separate from entry admission.

The initial cut rule preserves architectural state exactly. This is an explicit
stronger guarantee, not a requirement on ordinary supplier qualification or
entry admission. Replacing an original call with its source adapter requires
this guarantee until a more general checked clobber relation is implemented.
"""

from pathlib import Path

from .bisimulation_exact_frame import PhysicalFrameSpec, MUTABLE_ACTIVE, run_physical_frame_probe, validate_physical_frame
from .bisimulation_clobber_frame import clobber_guarantee, clobber_specs, validate_clobber_frame


CUT = PhysicalFrameSpec("exact_mutable_cut_machine_frame", "original-identity-cut-machine-frame-wide-v1",
    "__CPROVER_spx_mutable_cut_machine_frame", "spx-bisimulation-mutable-cut-machine-frame",
    "__CPROVER_spx_mutable_cut_machine_probe_", "mutable-cut-machine-frame")
EXIT = PhysicalFrameSpec("exact_mutable_exit_machine_frame", "original-adapter-exit-machine-frame-wide-v1",
    "__CPROVER_spx_mutable_exit_machine_frame", "spx-bisimulation-mutable-exit-machine-frame",
    "__CPROVER_spx_mutable_exit_machine_probe_", "mutable-exit-machine-frame")
CUT_CHECK = "__CPROVER_spx_mutable_cut_machine_check"
SPECS = (CUT, EXIT)


def mutable_machine_frame_declarations():
    return "\n".join(line for spec in SPECS for line in (
        f"void {spec.guard}(uint32_t equal) {{",
        f'  __CPROVER_assert({MUTABLE_ACTIVE} != 4U || equal, "{spec.description}");', "}")) + "\n"


def mutable_machine_frame_probes(proof_function, private_stack_writes=()):
    from .bisimulation_private_frame import activation
    return "".join(f"\nvoid {spec.entry(proof_function)}(void) {{\n  {activation(private_stack_writes)}{MUTABLE_ACTIVE} = 4U;\n  {proof_function}();\n}}\n"
                   for spec in SPECS)


def run_mutable_machine_frame_probes(*, entry, **kwargs):
    if entry.get("mutable_entry_contract", {}).get("result", {}).get("status") != "satisfied":
        return {}
    return {key: value for spec in SPECS for key, value in run_physical_frame_probe(**kwargs, spec=spec).items()}


def validate_mutable_machine_frame(value, *, spec, shard, model, **kwargs):
    if spec not in SPECS:
        raise ValueError("mutable machine frame: unsupported rule")
    if shard.get("mutable_entry_contract", {}).get("result", {}).get("status") != "satisfied":
        raise ValueError("mutable machine frame: checked wider entry is absent")
    if spec.description not in model["required_assertion_descriptions"]:
        raise ValueError("mutable machine frame: required guard is absent")
    validate_physical_frame(value, spec=spec, shard=shard, model=model, **kwargs)


def mutable_machine_state_guarantee(proof, operation):
    """Derive a metadata fact after full supplier validation; never trust a flag."""
    shards = {(row["operation_id"], row["obligation_id"]): row for row in proof["shards"]}
    return clobber_guarantee(proof, operation) or (bool(operation["obligation_models"]) and all(
        spec.description in model["required_assertion_descriptions"] and
        shards[(operation["operation_id"], model["obligation_id"])].get(spec.field, {}).get("result", {}).get("status") == "satisfied"
        for model in operation["obligation_models"] for spec in SPECS))


def checked_mutable_machine_frame_operations(proof, *, artifacts, runtime_assurance=None):
    """Require wider qualification and both machine frames for every segment.

    The caller validates the ordinary supplier first. A failed machine frame
    supplies no adapter-substitution premise and leaves entry admission unchanged.
    """
    from .bisimulation_assurance import validate_runtime_assurance_binding
    validate_runtime_assurance_binding(proof, runtime_assurance)
    from .bisimulation_readable_entry import checked_mutable_entry_operations

    admitted = checked_mutable_entry_operations(proof, artifacts=artifacts, runtime_assurance=runtime_assurance)
    shards = {(row["operation_id"], row["obligation_id"]): row for row in proof["shards"]}
    complete = []
    for operation_index, operation in enumerate(proof["models"]["operation_models"]):
        covered = operation["operation_id"] in admitted
        clobbered = clobber_guarantee(proof, operation)
        specs = clobber_specs(operation["machine_clobbers"], operation["machine_result_registers"]) if clobbered else SPECS
        for index, model in enumerate(operation["obligation_models"]):
            shard = shards[(operation["operation_id"], model["obligation_id"])]
            for spec in specs:
                value = shard.get(spec.field)
                if value is None or value["result"]["status"] != "satisfied":
                    covered = False
                    continue
                (validate_clobber_frame if clobbered else validate_mutable_machine_frame)(value, spec=spec, model=model, shard=shard, checker=proof["checker"], runtime_assurance=runtime_assurance,
                    artifacts=Path(artifacts) / f"operation-{operation_index:04d}-obligation-{index:04d}")
        if covered:
            complete.append(operation["operation_id"])
    return tuple(complete)

