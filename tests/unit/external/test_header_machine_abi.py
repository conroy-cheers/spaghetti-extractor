from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.external.environment import (
    lower_machine_import_boundary_v1,
)
from spaghetti_extractor.external.header_machine_abi import (
    extract_header_machine_abi_profile,
    write_header_abi_probe_source,
)
from spaghetti_extractor.external.machine_import_profiles import (
    MachineImportIdentity,
    load_machine_import_profile_set,
)


def _function(
    name: str, qualified: str, parameters: list[str]
) -> dict[str, object]:
    return {
        "kind": "FunctionDecl",
        "name": name,
        "type": {"qualType": qualified},
        "inner": [
            {"kind": "ParmVarDecl", "type": {"qualType": parameter}}
            for parameter in parameters
        ],
    }


class HeaderMachineAbiTests(unittest.TestCase):
    def test_clang_abi_is_normalized_into_canonical_physical_frames(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "fixture.h"
            header.write_text("reviewed fixture header\n", encoding="ascii")
            ast = root / "ast.json"
            ast.write_text(
                json.dumps({
                    "kind": "TranslationUnitDecl",
                    "inner": [
                        _function(
                            "fixture_copy",
                            "Box (Box, double)",
                            ["Box", "double"],
                        ),
                        _function(
                            "fixture_measure", "double (Box)", ["Box"]
                        ),
                        _function("unrelated", "int (int)", ["int"]),
                    ],
                }),
                encoding="utf-8",
            )
            probe = root / "probe.c"
            declarations = write_header_abi_probe_source(
                ast_json=ast,
                includes=["fixture.h"],
                function_prefixes=["fixture_"],
                out=probe,
            )
            llvm = root / "probe.ll"
            llvm.write_text(
                "\n".join([
                    "@spx_argument_0_0 = global [16 x i8] zeroinitializer",
                    "@spx_argument_alignment_0_0 = global [4 x i8] zeroinitializer",
                    "@spx_argument_0_1 = global [8 x i8] zeroinitializer",
                    "@spx_argument_alignment_0_1 = global [8 x i8] zeroinitializer",
                    "@spx_result_0 = global [16 x i8] zeroinitializer",
                    "@spx_result_alignment_0 = global [4 x i8] zeroinitializer",
                    "@spx_argument_1_0 = global [16 x i8] zeroinitializer",
                    "@spx_argument_alignment_1_0 = global [4 x i8] zeroinitializer",
                    "@spx_result_1 = global [8 x i8] zeroinitializer",
                    "@spx_result_alignment_1 = global [8 x i8] zeroinitializer",
                    (
                        "declare void @fixture_copy(ptr sret(%struct.Box), "
                        "ptr byval(%struct.Box), double)"
                    ),
                    (
                        "declare double @fixture_measure("
                        "ptr byval(%struct.Box))"
                    ),
                    "",
                ]),
                encoding="utf-8",
            )
            output = root / "profile.json"
            payload = extract_header_machine_abi_profile(
                ast_json=ast,
                llvm_ir=llvm,
                headers=[header],
                includes=["fixture.h"],
                function_prefixes=["fixture_"],
                profile_id="fixture-public-abi-v1",
                provider_dll="fixture.dll",
                clang_version="clang fixture",
                out=output,
            )
            contracts = load_machine_import_profile_set([output]).by_identity()
            probe_text = probe.read_text(encoding="utf-8")

        self.assertEqual(
            [declaration.name for declaration in declarations],
            ["fixture_copy", "fixture_measure"],
        )
        self.assertIn("spx_argument_0_0[sizeof(Box)]", probe_text)
        self.assertEqual(payload["counts"], {
            "declarations": 2,
            "fixed": 2,
            "variadic": 0,
        })

        copy_contract = contracts[
            MachineImportIdentity("fixture.dll", "symbol", "fixture_copy")
        ]
        self.assertEqual(copy_contract.argument_words, 7)
        copy_boundary = lower_machine_import_boundary_v1(
            copy_contract,
            abi_dialect="pe32-i386-gnu-v1",
            image_selector="fixture-image",
        )
        copy_frame = copy_boundary["physical_call_frame_v3"]["transport"]
        self.assertEqual(
            [argument["role"] for argument in copy_frame["arguments"]],
            ["hidden_sret", "parameter", "parameter"],
        )
        self.assertEqual(
            [
                argument["fragments"][0]["location"]["stack_offset_bytes"]
                for argument in copy_frame["arguments"]
            ],
            [4, 8, 24],
        )
        self.assertEqual(copy_frame["results"][0]["pass_mode"], "indirect")

        measure_contract = contracts[
            MachineImportIdentity("fixture.dll", "symbol", "fixture_measure")
        ]
        self.assertEqual(measure_contract.argument_words, 4)
        measure_boundary = lower_machine_import_boundary_v1(
            measure_contract,
            abi_dialect="pe32-i386-gnu-v1",
            image_selector="fixture-image",
        )
        result = measure_boundary["physical_call_frame_v3"]["transport"][
            "results"
        ][0]
        self.assertEqual(result["fragments"][0]["location"]["bank"], "x87")
        self.assertEqual(result["fragments"][0]["location"]["name"], "st0")


if __name__ == "__main__":
    unittest.main()
