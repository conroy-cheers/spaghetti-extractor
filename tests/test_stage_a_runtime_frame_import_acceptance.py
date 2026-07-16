from tests.stage_a_relational_support import *


class StageARuntimeFrameImportAcceptanceTests(StageARelationalTestBase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_shared_callee_keeps_callsite_import_relation_on_its_own_frame(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = (
                b"\x85\xc0"                          # test eax, eax
                b"\x74\x1c"                          # jz caller-without-import
                b"\x8b\x35" + struct.pack("<I", iat_address)
                + b"\xe8\x31\x00\x00\x00"          # call shared-callee
                + b"\xeb\xfe"                        # first continuation loop
                + b"\x90" * 0x0F
                + b"\xe8\x1b\x00\x00\x00"          # second call, same callee
                + b"\xeb\xfe"                        # second continuation loop
                + b"\x90" * 0x19
                + b"\xc3"                            # shared-callee
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(code, symbol="GetTickCount"))
            candidate.write_bytes(_pe32_import_image(code, symbol="GetTickCount"))
            pairs = [
                {"original": register, "candidate": register}
                for register in ("eax", "ebx", "ecx", "edx", "ebp")
            ]
            region_rows = (
                ("choose-caller", 0x1000, 4),
                ("iat-seed", 0x1004, 6),
                ("caller-with-import", 0x100A, 5),
                ("import-continuation", 0x100F, 2),
                ("caller-without-import", 0x1020, 5),
                ("plain-continuation", 0x1025, 2),
                ("shared-callee", 0x1040, 1),
            )
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": index, "original_rva": rva, "candidate_rva": rva}
                    for index, (_, rva, _) in enumerate(region_rows)
                ],
                "regions": [
                    {
                        "id": name,
                        "root": index == 0,
                        "original": {"rva": rva, "size": size},
                        "candidate": {"rva": rva, "size": size},
                        "inputs": pairs,
                        "outputs": pairs,
                    }
                    for index, (name, rva, size) in enumerate(region_rows)
                ],
                "padding": [
                    {
                        "id": "first-caller-padding",
                        "side": "both",
                        "rva": 0x1011,
                        "size": 0x0F,
                    },
                    {
                        "id": "second-caller-padding",
                        "side": "both",
                        "rva": 0x1027,
                        "size": 0x19,
                    },
                ],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result.get("status"), "prepared", result)
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            normalized = json.loads(
                (prepared / "relation-contract.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                [relation["original"] for relation in
                 normalized["regions"][2]["input_import_relations"]],
                ["esi"],
            )
            self.assertEqual(
                normalized["regions"][4]["input_import_relations"], []
            )
            self.assertEqual(
                normalized["regions"][5]["input_import_relations"], []
            )

            callee_states = [
                state for state in result["acceptance"]["control_states"]
                if state["node_id"] == 6
            ]
            self.assertEqual(len(callee_states), 2, callee_states)
            state_by_continuation = {
                state["calls"][0]: state for state in callee_states
            }
            self.assertEqual(set(state_by_continuation), {3, 5})
            self.assertEqual(
                [relation["original"] for relation in
                 state_by_continuation[3]["frame_offsets"][0][
                     "preserved_imports"
                 ]],
                ["esi"],
            )
            self.assertNotIn(
                "preserved_imports",
                state_by_continuation[5]["frame_offsets"][0],
            )

            return_step = next(
                step for step in result["acceptance"]["node_steps"]
                if step["kind"] == "return"
            )
            self.assertEqual(len(return_step["cases"]), 2)
            return_case_by_target = {
                case["target_node_id"]: case for case in return_step["cases"]
            }
            self.assertEqual(
                [relation["original"] for relation in
                 return_case_by_target[3]["active_frame_imports"]],
                ["esi"],
            )
            self.assertEqual(
                return_case_by_target[5]["active_frame_imports"], []
            )

            acceptance_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((prepared / "lean" / "StageA").glob(
                    "RelationalAcceptance*.lean"
                ))
            )
            self.assertIn("seedsPreservedImportsFrom", acceptance_source)
            self.assertIn(
                "RelationalRuntimeCallImportsHold.afterInternal",
                acceptance_source,
            )
            self.assertIn("frameContinuation", acceptance_source)
            self.assertIn("pe32ProgramsEquivalent", acceptance_source)

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertIn(
                "candidatePE32ProgramsEquivalent' depends on axioms",
                lean["stdout"],
            )
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])
