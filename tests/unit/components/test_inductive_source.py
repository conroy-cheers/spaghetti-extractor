from __future__ import annotations

import ctypes
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.compiler import (
    ComponentCompileError,
    compile_component,
)
from spaghetti_extractor.components.inductive_source import (
    InductiveSourceError,
    InductiveSourcePlanV1,
)
from spaghetti_extractor.components.interface_ir import PortableComponentInterfaceV2
from spaghetti_extractor.components.source import (
    build_component_source_package,
    component_operation_symbols,
)

from .test_interface_ir import _interface_v2


_SOURCE = r"""
spx_counter_add_control_v1 counter_add_initialize(
    spx_counter_add_state_v1 *state,
    spx_counter_context_v2 *context,
    uint32_t amount) {
  (void)context;
  state->remaining = amount;
  spx_counter_add_control_v1 result = {
    amount == 0u
      ? SPX_COUNTER_ADD_CONTROL_COMPLETE
      : SPX_COUNTER_ADD_CONTROL_RUNNING,
    SPX_COUNTER_ADD_PHASE_COUNTDOWN,
    SPX_COUNTER_ADD_COMPLETION_RETURN
  };
  return result;
}

spx_counter_add_control_v1 counter_add_step(
    spx_counter_add_state_v1 *state,
    uint32_t phase_id,
    spx_counter_context_v2 *context,
    uint32_t amount) {
  (void)phase_id;
  (void)context;
  (void)amount;
  state->remaining -= 1u;
  spx_counter_add_control_v1 result = {
    state->remaining == 0u
      ? SPX_COUNTER_ADD_CONTROL_COMPLETE
      : SPX_COUNTER_ADD_CONTROL_RUNNING,
    SPX_COUNTER_ADD_PHASE_COUNTDOWN,
    SPX_COUNTER_ADD_COMPLETION_RETURN
  };
  return result;
}

uint32_t counter_add_finish(
    const spx_counter_add_state_v1 *state,
    uint32_t completion_id,
    spx_counter_context_v2 *context,
    uint32_t amount) {
  (void)state;
  (void)completion_id;
  context->state.value += amount;
  return context->state.value;
}

void counter_reset_exact(spx_counter_context_v2 *context) {
  context->state.value = 0u;
}
"""


def _plan(interface: PortableComponentInterfaceV2) -> InductiveSourcePlanV1:
    return InductiveSourcePlanV1.create(
        interface=interface,
        operation_id="add",
        state=[{"id": "remaining", "type_id": "u32"}],
        phase_ids=["countdown"],
        completion_ids=["return"],
        symbols={
            "wrapper": "counter_add_inductive",
            "initialize": "counter_add_initialize",
            "step": "counter_add_step",
            "finish": "counter_add_finish",
        },
    )


class InductiveSourceTests(unittest.TestCase):
    def test_plan_round_trip_and_machine_free_generated_protocol(self) -> None:
        interface = PortableComponentInterfaceV2.parse(_interface_v2())
        plan = _plan(interface)

        self.assertEqual(InductiveSourcePlanV1.parse(plan.to_payload()), plan)
        header = plan.render_header(
            interface,
            {"add": "counter_add_inductive", "reset": "counter_reset_exact"},
        )
        wrapper = plan.render_wrapper(
            interface,
            {"add": "counter_add_inductive", "reset": "counter_reset_exact"},
            header="inductive.h",
        )
        self.assertIn("counter_add_step", header)
        self.assertIn("for (;;)", wrapper)
        for machine_name in ("eax", "ebx", "esp", "eip"):
            self.assertNotIn(machine_name, header.lower())
            self.assertNotIn(machine_name, wrapper.lower())

    @unittest.skipUnless(shutil.which("cc"), "C compiler unavailable")
    def test_compiler_generates_and_executes_public_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "counter.c"
            source_path.write_text(_SOURCE, encoding="ascii")
            package = root / "source"
            source = build_component_source_package(
                lift_unit_id="counter",
                files={"counter.c": source_path},
                shared_inputs={},
                operation_symbols={
                    "add": "counter_add_inductive",
                    "reset": "counter_reset_exact",
                },
                out_dir=package,
            )
            interface = PortableComponentInterfaceV2.parse(_interface_v2())
            output = root / "component.so"
            compile_component(
                package=package,
                source=source,
                compiler=Path(shutil.which("cc") or "cc"),
                output=output,
                interface=interface,
                operation_symbols=component_operation_symbols(source),
                inductive_source_plans=[_plan(interface)],
            )

            library = ctypes.CDLL(str(output))
            add = library.counter_add_inductive
            add.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            add.restype = ctypes.c_uint32
            context = (ctypes.c_void_p * 4)()
            self.assertEqual(add(ctypes.byref(context), 5), 5)
            self.assertEqual(add(ctypes.byref(context), 3), 8)

    def test_plan_rejects_stale_interface_and_wrapper_mismatch(self) -> None:
        interface = PortableComponentInterfaceV2.parse(_interface_v2())
        plan = _plan(interface)
        payload = plan.to_payload()
        payload["interface_sha256"] = "0" * 64
        core = dict(payload)
        core.pop("plan_sha256")
        from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3

        payload["plan_sha256"] = canonical_sha256_v3(core)
        stale = InductiveSourcePlanV1.parse(payload)
        with self.assertRaisesRegex(InductiveSourceError, "different interface"):
            stale.validate_for(
                interface,
                {"add": "counter_add_inductive", "reset": "counter_reset_exact"},
            )
        with self.assertRaisesRegex(InductiveSourceError, "wrapper differs"):
            plan.validate_for(
                interface,
                {"add": "counter_add_wrong", "reset": "counter_reset_exact"},
            )

    @unittest.skipUnless(shutil.which("cc"), "C compiler unavailable")
    def test_missing_helper_fails_closed_at_compile_time(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "counter.c"
            source_path.write_text(
                _SOURCE.replace("counter_add_step(", "counter_add_missing("),
                encoding="ascii",
            )
            package = root / "source"
            source = build_component_source_package(
                lift_unit_id="counter",
                files={"counter.c": source_path},
                shared_inputs={},
                operation_symbols={
                    "add": "counter_add_inductive",
                    "reset": "counter_reset_exact",
                },
                out_dir=package,
            )
            interface = PortableComponentInterfaceV2.parse(_interface_v2())
            with self.assertRaisesRegex(
                ComponentCompileError, "conflicting types|undefined reference"
            ):
                compile_component(
                    package=package,
                    source=source,
                    compiler=Path(shutil.which("cc") or "cc"),
                    output=root / "component.so",
                    interface=interface,
                    operation_symbols=component_operation_symbols(source),
                    inductive_source_plans=[_plan(interface)],
                )


if __name__ == "__main__":
    unittest.main()
