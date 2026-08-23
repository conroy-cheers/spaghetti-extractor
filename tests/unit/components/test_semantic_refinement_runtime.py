from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.refinement import check_component_refinement
from spaghetti_extractor.components.runtime_paths import (
    _covered_boundary_clause_ids,
    _direct_operation_effect_ids,
    render_finite_path_operation,
)
from spaghetti_extractor.components.source_profile import (
    check_component_source_profile,
)

from . import test_semantic_refinement as _support

ComponentMachineBindingV1 = _support.ComponentMachineBindingV1
ComponentSemanticContractV1 = _support.ComponentSemanticContractV1
PortableComponentInterfaceV2 = _support.PortableComponentInterfaceV2
build_operation_path_model = _support.build_operation_path_model


class SemanticRefinementRuntimeAndCbmcTests(unittest.TestCase):
    _fixture = _support.SemanticRefinementTests._fixture
    _service_fixture = _support.SemanticRefinementTests._service_fixture
    _bytes_fixture = _support.SemanticRefinementTests._bytes_fixture
    _state_fixture = _support.SemanticRefinementTests._state_fixture

    def test_interaction_owned_effect_covers_runtime_boundary(self) -> None:
        plan = SimpleNamespace(
            actions=(SimpleNamespace(identity="parameter.object"),),
            interactions=(SimpleNamespace(
                invoke_action=SimpleNamespace(
                    clause={"effect_ids": ["atomic_update"]}
                )
            ),),
        )

        self.assertEqual(
            _covered_boundary_clause_ids(plan),
            {"parameter.object", "effect.atomic_update"},
        )

    def test_service_owned_effect_is_not_a_direct_runtime_effect(self) -> None:
        interface = SimpleNamespace(
            services=(SimpleNamespace(
                identity="install_filter",
                effect_ids=("filter_replaced",),
            ),),
        )
        operation = SimpleNamespace(
            allowed_service_ids=("install_filter",),
            effect_ids=("filter_replaced", "local_update"),
        )

        self.assertEqual(
            _direct_operation_effect_ids(interface, operation),
            {"local_update"},
        )

    @unittest.skipUnless(shutil.which("cc"), "a C compiler is required")
    def test_exact_service_paths_render_an_executable_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = self._service_fixture(root)
            contract = ComponentSemanticContractV1.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            interface = PortableComponentInterfaceV2.parse(
                json.loads(paths["interface"].read_text(encoding="ascii"))
            )
            binding = ComponentMachineBindingV1.parse(
                json.loads(paths["binding"].read_text(encoding="ascii"))
            )
            model = build_operation_path_model(
                contract.payload["operations"][0], interface,
                contract.payload["services"],
            )
            adapter = render_finite_path_operation(
                interface=interface,
                operation=interface.operations[0],
                binding=binding.operations[0],
                service_bindings=binding.services,
                source_symbol="component_service_branch_run",
                adapter_symbol="spx_adapter_service_branch",
                model=model,
            )
            (root / "portable-component.h").write_text(
                interface.render_public_header(), encoding="ascii"
            )
            (root / "portable-component-implementation.h").write_text(
                interface.render_implementation_header(
                    {"run": "component_service_branch_run"}
                ),
                encoding="ascii",
            )
            (root / "state-machine-runtime.h").write_text(
                "#include <stdint.h>\n"
                "typedef struct { uint32_t eax,ebx,ecx,edx,esi,edi,ebp,esp,cf,zf,sf,of,pf,df,original_rva; } spx_machine_state;\n"
                "typedef struct { uint32_t offset,width,value; } spx_stack_input;\n"
                "typedef enum { SPX_CALL_EXTERNAL_IMPORT,SPX_CALL_INTERNAL_DIRECT,SPX_CALL_INDIRECT } spx_call_event_kind;\n"
                "typedef struct { spx_call_event_kind kind; uint32_t instruction_rva,call_index,target_rva,return_rva; const char *dll,*symbol; uint32_t ordinal,has_ordinal; const uint32_t *arguments; uint32_t argument_count; const spx_stack_input *stack_inputs; uint32_t stack_input_count; } spx_call_event;\n"
                "typedef enum { SPX_CALL_OK,SPX_CALL_UNIMPLEMENTED,SPX_CALL_DIVIDE_ERROR,SPX_CALL_MEMORY_FAULT,SPX_CALL_EXTERNAL_FAULT } spx_call_status;\n"
                "typedef struct spx_runtime { void *context; uint32_t (*read)(void*,uint32_t,uint32_t,uint32_t*); } spx_runtime;\n"
                "typedef struct { uint32_t kind,target,value; } spx_step_result;\n"
                "enum { SPX_UNIMPLEMENTED,SPX_DIVIDE_ERROR,SPX_MEMORY_FAULT,SPX_EXTERNAL_FAULT,SPX_RETURN,SPX_FALLTHROUGH,SPX_JUMP,SPX_INDIRECT_JUMP };\n"
                "spx_call_status spx_invoke_call(spx_runtime*,const spx_call_event*,const spx_machine_state*,spx_machine_state*);\n",
                encoding="ascii",
            )
            (root / "adapter.c").write_text(
                '#include "state-machine-runtime.h"\n'
                '#include "portable-component-implementation.h"\n'
                "static uint32_t component_read(spx_runtime *rt,uint32_t a,uint32_t w,uint32_t *f){return rt->read(rt->context,a,w,f);}\n"
                "static uint32_t component_parity(uint32_t v){return v;}\n"
                "static uint32_t component_sub_overflow(uint32_t a,uint32_t b,uint32_t c){return a^b^c;}\n"
                "static uint32_t component_add_overflow(uint32_t a,uint32_t b,uint32_t c){return a^b^c;}\n"
                + adapter,
                encoding="ascii",
            )
            completed = subprocess.run(
                [shutil.which("cc") or "cc", "-std=c11", "-Wall", "-Werror",
                 "-fsyntax-only", "-I", str(root), str(root / "adapter.c"),
                 str(paths["source"] / "sources" / "service-branch.c")],
                text=True, capture_output=True, check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    @unittest.skipUnless(shutil.which("cc"), "a C compiler is required")
    def test_state_paths_render_an_executable_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = self._state_fixture(root)
            contract = ComponentSemanticContractV1.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            interface = PortableComponentInterfaceV2.parse(
                json.loads(paths["interface"].read_text(encoding="ascii"))
            )
            binding = ComponentMachineBindingV1.parse(
                json.loads(paths["binding"].read_text(encoding="ascii"))
            )
            model = build_operation_path_model(
                contract.payload["operations"][0], interface,
                contract.payload["services"],
            )
            adapter = render_finite_path_operation(
                interface=interface,
                operation=interface.operations[0],
                binding=binding.operations[0],
                service_bindings=binding.services,
                source_symbol="component_counter_add",
                adapter_symbol="spx_adapter_counter",
                model=model,
            )
            (root / "portable-component.h").write_text(
                interface.render_public_header(), encoding="ascii"
            )
            (root / "portable-component-implementation.h").write_text(
                interface.render_implementation_header(
                    {"add": "component_counter_add"}
                ),
                encoding="ascii",
            )
            (root / "state-machine-runtime.h").write_text(
                "#include <stdint.h>\n"
                "typedef struct { uint32_t eax,ebx,ecx,edx,esi,edi,ebp,esp,cf,zf,sf,of,pf,df,original_rva; } spx_machine_state;\n"
                "typedef struct { uint32_t offset,width,value; } spx_stack_input;\n"
                "typedef enum { SPX_CALL_EXTERNAL_IMPORT,SPX_CALL_INTERNAL_DIRECT,SPX_CALL_INDIRECT } spx_call_event_kind;\n"
                "typedef struct { spx_call_event_kind kind; uint32_t instruction_rva,call_index,target_rva,return_rva; const char *dll,*symbol; uint32_t ordinal,has_ordinal; const uint32_t *arguments; uint32_t argument_count; const spx_stack_input *stack_inputs; uint32_t stack_input_count; } spx_call_event;\n"
                "typedef enum { SPX_CALL_OK,SPX_CALL_UNIMPLEMENTED,SPX_CALL_DIVIDE_ERROR,SPX_CALL_MEMORY_FAULT,SPX_CALL_EXTERNAL_FAULT } spx_call_status;\n"
                "typedef struct spx_runtime { void *context; uint32_t (*read)(void*,uint32_t,uint32_t,uint32_t*); void (*write)(void*,uint32_t,uint32_t,uint32_t,uint32_t*); } spx_runtime;\n"
                "typedef struct { uint32_t kind,target,value; } spx_step_result;\n"
                "enum { SPX_UNIMPLEMENTED,SPX_DIVIDE_ERROR,SPX_MEMORY_FAULT,SPX_EXTERNAL_FAULT,SPX_RETURN,SPX_FALLTHROUGH,SPX_JUMP,SPX_INDIRECT_JUMP };\n"
                "spx_call_status spx_invoke_call(spx_runtime*,const spx_call_event*,const spx_machine_state*,spx_machine_state*);\n",
                encoding="ascii",
            )
            (root / "adapter.c").write_text(
                '#include "state-machine-runtime.h"\n'
                '#include "portable-component-implementation.h"\n'
                "static uint32_t component_read(spx_runtime *rt,uint32_t a,uint32_t w,uint32_t *f){return rt->read(rt->context,a,w,f);}\n"
                "static void component_write(spx_runtime *rt,uint32_t a,uint32_t w,uint32_t v,uint32_t *f){rt->write(rt->context,a,w,v,f);}\n"
                "static uint32_t component_parity(uint32_t v){return v;}\n"
                "static uint32_t component_sub_overflow(uint32_t a,uint32_t b,uint32_t c){return a^b^c;}\n"
                "static uint32_t component_add_overflow(uint32_t a,uint32_t b,uint32_t c){return a^b^c;}\n"
                + adapter,
                encoding="ascii",
            )
            completed = subprocess.run(
                [shutil.which("cc") or "cc", "-std=c11", "-Wall", "-Werror",
                 "-fsyntax-only", "-I", str(root), str(root / "adapter.c"),
                 str(paths["source"] / "sources" / "counter.c")],
                text=True, capture_output=True, check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    @unittest.skipUnless(shutil.which("cbmc"), "CBMC is supplied by the Nix component check")
    def test_cbmc_accepts_matching_source_for_all_u32_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._fixture(Path(temporary))
            receipt = check_component_refinement(
                semantic_contract=paths["contract"], interface=paths["interface"],
                source_package=paths["source"], source_profile=paths["profile"],
                cbmc=Path(shutil.which("cbmc") or "cbmc"),
            )
        self.assertEqual(receipt["status"], "satisfied", receipt["issues"])
        self.assertEqual(receipt["component_id"], "increment-component")
        self.assertTrue(receipt["activation_authorized"])

    @unittest.skipUnless(shutil.which("cbmc"), "CBMC is supplied by the Nix component check")
    def test_cbmc_accepts_machine_derived_read_only_byte_view(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._bytes_fixture(Path(temporary))
            receipt = check_component_refinement(
                semantic_contract=paths["contract"], interface=paths["interface"],
                source_package=paths["source"], source_profile=paths["profile"],
                cbmc=Path(shutil.which("cbmc") or "cbmc"),
            )
        self.assertEqual(receipt["status"], "satisfied", receipt["issues"])
        self.assertGreater(receipt["checks"][0]["properties"], 0)
        self.assertTrue(receipt["checks"][0]["property_ids"])

    @unittest.skipUnless(shutil.which("cbmc"), "CBMC is supplied by the Nix component check")
    def test_cbmc_quantifies_over_narrow_logical_type_without_cast_violation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._fixture(
                Path(temporary),
                "(uint32_t)value",
                parameter_c_type="uint16_t",
                machine_expression={
                    "op": "and32", "args": [
                        {"op": "reg", "name": "ecx", "width": 32},
                        {"op": "const", "value": 0xffff, "width": 32},
                    ],
                },
            )
            receipt = check_component_refinement(
                semantic_contract=paths["contract"], interface=paths["interface"],
                source_package=paths["source"], source_profile=paths["profile"],
                cbmc=Path(shutil.which("cbmc") or "cbmc"),
            )
        self.assertEqual(receipt["status"], "satisfied", receipt["issues"])

    @unittest.skipUnless(shutil.which("cbmc"), "CBMC is supplied by the Nix component check")
    def test_cbmc_reports_a_source_mapped_counterexample(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._fixture(Path(temporary), "value + UINT32_C(2)")
            receipt = check_component_refinement(
                semantic_contract=paths["contract"], interface=paths["interface"],
                source_package=paths["source"], source_profile=paths["profile"],
                cbmc=Path(shutil.which("cbmc") or "cbmc"),
            )
        self.assertEqual(receipt["status"], "violated", receipt["issues"])
        self.assertEqual(receipt["issues"][0]["code"], "cbmc_counterexample")
        self.assertIsNotNone(receipt["issues"][0]["source"])

    @unittest.skipUnless(shutil.which("cbmc"), "CBMC is supplied by the Nix component check")
    def test_cbmc_accepts_exact_service_trace_for_all_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._service_fixture(Path(temporary))
            receipt = check_component_refinement(
                semantic_contract=paths["contract"], interface=paths["interface"],
                source_package=paths["source"], source_profile=paths["profile"],
                cbmc=Path(shutil.which("cbmc") or "cbmc"),
            )
        self.assertEqual(receipt["status"], "satisfied", receipt["issues"])

    @unittest.skipUnless(shutil.which("cbmc"), "CBMC is supplied by the Nix component check")
    def test_cbmc_accepts_read_only_byte_view_service_trace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._service_fixture(Path(temporary), byte_view=True)
            receipt = check_component_refinement(
                semantic_contract=paths["contract"], interface=paths["interface"],
                source_package=paths["source"], source_profile=paths["profile"],
                cbmc=Path(shutil.which("cbmc") or "cbmc"),
            )
        self.assertEqual(receipt["status"], "satisfied", receipt["issues"])

    @unittest.skipUnless(shutil.which("cbmc"), "CBMC is supplied by the Nix component check")
    def test_cbmc_rejects_wrong_service_argument(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._service_fixture(Path(temporary), argument="value + UINT32_C(1)")
            receipt = check_component_refinement(
                semantic_contract=paths["contract"], interface=paths["interface"],
                source_package=paths["source"], source_profile=paths["profile"],
                cbmc=Path(shutil.which("cbmc") or "cbmc"),
            )
        self.assertEqual(receipt["status"], "violated", receipt["issues"])
        self.assertEqual(receipt["issues"][0]["code"], "cbmc_counterexample")

    @unittest.skipUnless(shutil.which("cbmc"), "CBMC is supplied by the Nix component check")
    def test_cbmc_accepts_state_update_for_all_inputs_and_states(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._state_fixture(Path(temporary))
            receipt = check_component_refinement(
                semantic_contract=paths["contract"], interface=paths["interface"],
                source_package=paths["source"], source_profile=paths["profile"],
                cbmc=Path(shutil.which("cbmc") or "cbmc"),
            )
        self.assertEqual(receipt["status"], "satisfied", receipt["issues"])

    @unittest.skipUnless(shutil.which("cbmc"), "CBMC is supplied by the Nix component check")
    def test_cbmc_rejects_wrong_state_update(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._state_fixture(
                Path(temporary),
                source_update="context->state.value + amount + UINT32_C(1)",
            )
            receipt = check_component_refinement(
                semantic_contract=paths["contract"], interface=paths["interface"],
                source_package=paths["source"], source_profile=paths["profile"],
                cbmc=Path(shutil.which("cbmc") or "cbmc"),
            )
        self.assertEqual(receipt["status"], "violated", receipt["issues"])

    def test_restricted_c_rejects_volatile_storage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._fixture(Path(temporary))
            source = paths["source"] / "sources" / "increment.c"
            source.write_text(source.read_text() + "volatile uint32_t bad;\n")
            manifest = json.loads((paths["source"] / "source-package.json").read_text())
            row = manifest["files"][0]
            row["size"] = source.stat().st_size
            row["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            core = dict(manifest)
            core.pop("implementation_sha256")
            manifest["implementation_sha256"] = canonical_sha256_v3(core)
            (paths["source"] / "source-package.json").write_text(json.dumps(manifest))
            profile = check_component_source_profile(package=paths["source"])
        self.assertEqual(profile["status"], "incomplete")
        self.assertEqual(profile["issues"][0]["code"], "restricted_c_volatile_storage")



if __name__ == "__main__":
    unittest.main()
