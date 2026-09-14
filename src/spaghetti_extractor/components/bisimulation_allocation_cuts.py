"""Bounded allocation histories at ordinary-C synchronization boundaries.

Class declarations name checked allocating services. They do not create incoming
authority: predecessors must establish the same metadata domain used to resume.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256

from .bisimulation_exact_frame import frame_private_low
from .bisimulation_lifetime_namespace import checked_lifetime_transitions, lifetime_namespace
from .bisimulation_support import BisimulationRefinementError

POLICY = "bounded-allocation-history-checked-class-current-memory-v2"


@dataclass(frozen=True)
class AllocationHistoryV1:
    maximum_instances: int
    classes: tuple[str, ...]

    @classmethod
    def parse(cls, value):
        if not isinstance(value, Mapping) or set(value) != {"maximum_instances", "classes"}:
            raise ValueError("allocation history requires maximum_instances and classes")
        maximum, classes = value["maximum_instances"], value["classes"]
        if type(maximum) is not int or not 0 < maximum < 0xffffffff:
            raise ValueError("allocation history maximum_instances must be a positive uint32 bound")
        if (not isinstance(classes, list) or not classes or
                any(not isinstance(name, str) or not name or "\0" in name for name in classes) or
                classes != sorted(set(classes))):
            raise ValueError("allocation history classes must be nonempty, ordered and unique")
        return cls(maximum, tuple(classes))

    def to_payload(self):
        return {"maximum_instances": self.maximum_instances, "classes": list(self.classes)}


def maximum_history(operations):
    return max((history.maximum_instances for operation in operations
                for history in [operation.entry_allocation_history,
                    *(sync.allocation_history for sync in operation.syncs)]
                if history is not None), default=0)


def history_metadata(operation):
    maximum = maximum_history([operation])
    return ({"allocation_history_policy": POLICY, "maximum_input_allocations": maximum}
            if maximum else {})


def validate_history_model(planned, model):
    """Bind an operation or segment's transport implementation to its intent."""
    histories = [AllocationHistoryV1.parse(sync["allocation_history"])
                 for sync in planned["source"]["syncs"] if "allocation_history" in sync]
    if "entry_allocation_history" in planned["source"]:
        histories.append(AllocationHistoryV1.parse(planned["source"]["entry_allocation_history"]))
    expected = ({"allocation_history_policy": POLICY,
                 "maximum_input_allocations": max(row.maximum_instances for row in histories)}
                if histories else {})
    actual = {key: model[key] for key in ("allocation_history_policy", "maximum_input_allocations")
              if key in model}
    if actual != expected or (expected and type(actual.get("maximum_input_allocations")) is not int):
        raise ValueError("allocation history transport differs from the proof plan")
    return expected


def history_recipes(history, *, specs, authority, inventory=None, requirements=None):
    # Local calls still owe their complete ABI/effect checks. Incoming class
    # provenance is independent of whether this consumer contains such a call.
    checked_lifetime_transitions(specs, authority=authority,
        inventory=inventory, requirements=requirements)
    if authority is None:
        raise BisimulationRefinementError("allocation cut class lacks a checked allocating service")
    producers, families = lifetime_namespace(authority, inventory=inventory, requirements=requirements)
    recipes = []
    for producer in producers:
        effect = producer["class_requirement"]["effect"]
        identity = producer["class_requirement"]["authority"]["id"]
        if identity not in history.classes:
            continue
        initialization = effect["allocation"]["initialization"]["kind"]
        selector = next(i + 1 for i, rule in enumerate(authority.rules) if rule.identity == identity)
        row = {"class": identity,
            "native_rule_selector": selector,
            "family": families[effect["ownership"]["family"]], "birth_class_selector": selector,
            "minimum_size": effect["minimum_size"],
            "owner_zero": effect["ownership"]["owner_argument"] is None,
            "zero_initialized": {"zero": 1, "uninitialized": 0, "argument_flag": None}[initialization]}
        recipes.append(row)
    if {row["class"] for row in recipes} != set(history.classes):
        raise BisimulationRefinementError("allocation cut class lacks a checked allocating service")
    return sorted(recipes, key=lambda row: row["class"])


def _class_predicate(recipe):
    expressions = [f"allocation->{name} == UINT32_C({recipe[name]})"
                   for name in ("native_rule_selector", "family", "birth_class_selector")]
    expressions += ["allocation->native_generation != UINT32_C(0)",
                    f"allocation->size >= UINT32_C({recipe['minimum_size']})"]
    if recipe["owner_zero"]:
        expressions.append("allocation->owner == UINT32_C(0)")
    if recipe["zero_initialized"] is not None:
        expressions.append(f"allocation->zero_initialized == UINT32_C({recipe['zero_initialized']})")
    return "(" + " && ".join(expressions) + ")"


def history_source(identity, history, recipes, *, stack_domain, private_low, entry=False, description_id=None):
    """Emit matched predecessor admission and fresh incoming-world construction.

    Both use the lifetime constructor's metadata predicate. Current bytes are
    represented by the existing common arbitrary input memory, not birth zeros.
    This does not reconstruct any source-local descriptor or logical origin.
    """
    maximum = history.maximum_instances
    prefix = "spx_proof_entry_allocation" if entry else "spx_proof_allocation"
    initialize = "spx_proof_initialize_entry_allocation_history" if entry else "spx_proof_initialize_allocation_history"
    description = "allocation-entry-input" if entry else "allocation-history-input"
    description_id = identity if description_id is None else description_id
    entry_check = (f'''  __CPROVER_assert({prefix}_history_admitted_{identity}(stack_pointer),
      "spx-bisimulation-allocation-entry-admission:{description_id}");''' if entry else "")
    class_check = " || ".join(_class_predicate(recipe) for recipe in recipes)
    rows = []
    restored = []
    for index in range(maximum):
        rows += [f"  if (world->allocation_count > UINT32_C({index})) {{",
            f"    const spx_proof_allocation *row = &world->allocations[{index}];",
            f"    if (!{prefix}_class_{identity}(row) ||",
            f"        spx_proof_allocation_input_admitted(world->allocations, UINT32_C({index}),",
            "            low, high, 0, row) != SPX_BOUNDARY_OK) return UINT32_C(0);", "  }"]
        restored += [f"  if (count > UINT32_C({index})) {{",
            "    spx_proof_allocation row = {",
            "      .base=spx_nondet_nonzero_u32(), .size=spx_nondet_u32(),",
            "      .family=spx_nondet_u32(), .owner=spx_nondet_u32(),",
            f"      .generation=UINT32_C({index + 2}), .live=spx_nondet_u32() & UINT32_C(1),",
            "      .zero_initialized=spx_nondet_u32() & UINT32_C(1),",
            "      .native_rule_selector=spx_nondet_u32(), .native_generation=spx_nondet_nonzero_u32(),",
            "      .birth_class_selector=spx_nondet_u32() };",
            f"    __CPROVER_assume({prefix}_class_{identity}(&row));",
            f"    __CPROVER_assume(spx_proof_allocation_input_admitted(spx_exact_world.allocations, UINT32_C({index}),",
            "        spx_exact_world.private_low, spx_exact_world.private_high, 0, &row) == SPX_BOUNDARY_OK);",
            f"    {prefix}_history_restore_{identity}(&row);", "  }"]
    return f"""
static uint32_t {prefix}_class_{identity}(const spx_proof_allocation *allocation) {{
  return {class_check};
}}
static uint32_t {prefix}_history_matches_{identity}(
    const spx_proof_world *world, uint32_t low, uint32_t high) {{
  if (world->allocation_count > UINT32_C({maximum})) return UINT32_C(0);
{chr(10).join(rows)}
  return UINT32_C(1);
}}
uint32_t {prefix}_history_admitted_{identity}(uint32_t stack_pointer) {{
  const uint32_t entry_esp = stack_pointer;
  if (!({stack_domain})) return UINT32_C(0);
  uint32_t low = {private_low}, high = stack_pointer + spx_proof_private_high_offset;
  return {prefix}_history_matches_{identity}(&spx_exact_world, low, high) &&
      {prefix}_history_matches_{identity}(&spx_source_world, low, high);
}}
static void {prefix}_history_restore_{identity}(const spx_proof_allocation *row) {{
  spx_boundary_status exact_status = spx_proof_restore_allocation_input(&spx_exact_world, row);
  spx_boundary_status source_status = spx_proof_restore_allocation_input(&spx_source_world, row);
  __CPROVER_assert(exact_status == SPX_BOUNDARY_OK && source_status == SPX_BOUNDARY_OK,
      "spx-bisimulation-{description}:{description_id}");
}}
static void {initialize}_{identity}({"uint32_t stack_pointer" if entry else "void"}) {{
  uint32_t count = spx_nondet_u32();
  __CPROVER_assume(count <= UINT32_C({maximum}));
{chr(10).join(restored)}
{entry_check}
}}
"""


def allocation_cut_sources(operation, *, specs, authority, inventory, requirements,
                           image_base, image_size, readable_entry=False, mutable_entry=False):
    # Delayed import avoids the existing view-domain/projection import cycle.
    from .bisimulation_view_extent import stack_admission_expression
    result = []
    boundaries = [(sync.identity, sync.allocation_history, False) for sync in operation.syncs]
    boundaries += [(operation.operation_id, operation.entry_allocation_history, True)]
    for identity, history, entry in boundaries:
        if history is None:
            continue
        recipes = history_recipes(history, specs=specs, authority=authority,
                                  inventory=inventory, requirements=requirements)
        result.append(history_source(entry_history_symbol(identity) if entry else identity,
            history, recipes, entry=entry, description_id=identity,
            stack_domain=stack_admission_expression(stack_pointer="stack_pointer",
                high_offset="spx_proof_private_high_offset", image_base=image_base, image_size=image_size,
                readable_entry=readable_entry, mutable_entry=mutable_entry),
            private_low=frame_private_low(readable_entry, mutable_entry)))
    return "\n".join(result)


def entry_history_initialization(operation):
    if operation.entry_allocation_history is None:
        return []
    identity = operation.operation_id
    symbol = entry_history_symbol(identity)
    return [f"  spx_proof_initialize_entry_allocation_history_{symbol}(initial_state.esp);"]


def entry_history_symbol(identity):
    # Operation IDs can contain punctuation that is not a C identifier.
    return "op_" + sha256(identity.encode("utf-8")).hexdigest()
