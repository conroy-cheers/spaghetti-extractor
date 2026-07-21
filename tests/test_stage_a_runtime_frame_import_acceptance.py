from tests.stage_a_relational_support import *


class StageARuntimeFrameImportAcceptanceTests(StageARelationalTestBase):
    def _returning_thunk_then_register_call_contract(
        self, root: Path, *, preserve_esi: bool,
    ) -> tuple[Path, Path, Path]:
        iat_address = 0x400000 + 0x2000 + 0x40
        code = (
            b"\x8b\x35" + struct.pack("<I", iat_address)
            + b"\xe8\x25\x00\x00\x00"
            + b"\xff\xd6"
            + b"\x31\xf6"
            + b"\xe8\x1c\x00\x00\x00"
            + b"\xeb\xfe"
            + b"\x90" * 0x1A
            + b"\xff\x25" + struct.pack("<I", iat_address)
        )
        original = root / "original.exe"
        candidate = root / "candidate.exe"
        original.write_bytes(_pe32_import_image(code, symbol="GetTickCount"))
        candidate.write_bytes(original.read_bytes())
        pairs = [
            {"original": register, "candidate": register}
            for register in (
                "eax", "ebx", "ecx", "edx", "edi", "ebp"
            )
        ]
        region_rows = (
            ("iat-seed", 0x1000, 6),
            ("call-import-thunk-with-fact", 0x1006, 5),
            ("call-preserved-import-register", 0x100B, 2),
            ("clear-import-register", 0x100D, 2),
            ("call-import-thunk-without-fact", 0x100F, 5),
            ("plain-continuation-loop", 0x1014, 2),
            ("get-tick-count-import-thunk", 0x1030, 6),
        )
        machine_contract = {
            "id": 0,
            "import": {"dll": "kernel32.dll", "symbol": "GetTickCount"},
            "memory_effect": "none",
            "memory_footprints": [],
            "world_effect": "none",
        }
        if preserve_esi:
            machine_contract.update({
                "abi_template": "pe32-stdcall-v1",
                "argument_words": 0,
            })
        else:
            machine_contract.update({
                "stack_argument_offsets": [],
                "stack_result_delta": 0,
                "preserved_registers": ["ebx", "edi", "ebp"],
                "clobbered_registers": ["eax", "ecx", "edx", "esi"],
            })
        relation = root / "relation.json"
        relation.write_text(json.dumps({
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
            "machine_import_call_contracts": [machine_contract],
            "padding": [
                {"id": "second-path-padding", "side": "both",
                 "rva": 0x1016, "size": 0x1A},
            ],
            "memory_relation": {"mode": "identity"},
        }), encoding="utf-8")
        return original, candidate, relation

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_returning_import_thunk_preserves_active_import_fact_to_continuation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, candidate, contract = (
                self._returning_thunk_then_register_call_contract(
                    root, preserve_esi=True,
                )
            )
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
                normalized["regions"][6]["input_import_relations"], []
            )
            sites = json.loads(
                (prepared / "relational-external-call-sites.json").read_text(
                    encoding="utf-8"
                )
            )
            thunk_site = next(
                site for site in sites["candidates"]
                if site.get("site_kind") == "direct_import_thunk"
                and site["target_region_index"] == 2
            )
            self.assertEqual(
                [relation["original"] for relation in
                 thunk_site["target_import_relations_from_active_frame"]],
                ["esi"],
            )
            thunk_step = next(
                step for step in result["acceptance"]["node_steps"]
                if step["kind"] == "external_jump"
            )
            thunk_case = next(
                case for case in thunk_step["cases"]
                if case["target_region_index"] == 2
            )
            self.assertEqual(
                [relation["original"] for relation in
                 thunk_case["control_state"]["frame_offsets"][0][
                     "preserved_imports"
                 ]],
                ["esi"],
            )
            acceptance_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((prepared / "lean" / "StageA").glob(
                    "RelationalAcceptance*.lean"
                ))
            )
            self.assertIn(
                "withAdditionalImportRegisterRelations", acceptance_source
            )
            self.assertIn("activeImportsNext", acceptance_source)
            self.assertIn(
                "resolveWorldImportCall_zeroArguments_of_binding",
                acceptance_source,
            )
            self.assertIn(
                "normalizeImportReturnSlotState_nextMachineState_eq_of_compatible",
                acceptance_source,
            )
            self.assertIn("originalCodeMissing", acceptance_source)

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    def test_returning_import_thunk_clobber_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, candidate, contract = (
                self._returning_thunk_then_register_call_contract(
                    root, preserve_esi=False,
                )
            )

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "prepared",
            )

            self.assertEqual(result["acceptance"]["status"], "incomplete", result)
            self.assertIn(
                2,
                result["composition_progress"]["frontiers"][
                    "decoded_control_node_ids"
                ],
                result,
            )

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
                + b"\xe8\x0b\x00\x00\x00"         # shared calls leaf
                + b"\xc3"                            # shared continuation
                + b"\x90" * 0x0A
                + b"\xc3"                            # leaf return
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
                ("shared-callee-call", 0x1040, 5),
                ("shared-callee-return", 0x1045, 1),
                ("leaf-return", 0x1050, 1),
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
                    {
                        "id": "shared-callee-padding",
                        "side": "both",
                        "rva": 0x1046,
                        "size": 0x0A,
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
            self.assertEqual(
                result["composition_progress"]["frontiers"]["stack_invariant"],
                [],
                result,
            )
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
            shared_call_step = next(
                step for step in result["acceptance"]["node_steps"]
                if step["node_id"] == 6
            )
            self.assertEqual(shared_call_step["kind"], "call")
            self.assertEqual(len(shared_call_step["cases"]), 2)
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
                "RelationalRuntimeCallFactsHold.afterInternal",
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
