from tests.stage_a_relational_support import *


class StageARuntimeFrameRegisterAcceptanceTests(StageARelationalTestBase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_shared_external_callee_keeps_caller_local_register_fact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = (
                b"\x85\xc0"                          # test eax, eax
                + b"\x74\x1c"                        # jz caller-without-fact
                + b"\xbe\x78\x56\x34\x12"        # mov esi, 0x12345678
                + b"\xe8\x32\x00\x00\x00"        # call shared-callee
                + b"\xe9\x3d\x00\x00\x00"        # first continuation to sink
                + b"\x90" * 0x0D
                + b"\xe8\x1b\x00\x00\x00"        # second call, same callee
                + b"\xe9\x26\x00\x00\x00"        # second continuation to sink
                + b"\x90" * 0x16
                + b"\xff\x15" + struct.pack("<I", iat_address)
                + b"\xc3"
                + b"\x90" * 0x09
                + b"\xeb\xfe"                        # shared terminal loop
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(code, symbol="GetTickCount"))
            candidate.write_bytes(_pe32_import_image(code, symbol="GetTickCount"))
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "ebp", "esp"
                )
            ]
            continuation_pairs = [
                pair for pair in pairs
                if pair["original"] in {"ebx", "esi", "ebp"}
            ]
            region_rows = (
                ("choose-caller", 0x1000, 4),
                ("caller-with-fact", 0x1004, 10),
                ("fact-continuation", 0x100E, 5),
                ("caller-without-fact", 0x1020, 5),
                ("plain-continuation", 0x1025, 5),
                ("shared-callee-external-call", 0x1040, 6),
                ("shared-callee-return", 0x1046, 1),
                ("shared-terminal-loop", 0x1050, 2),
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
                        "inputs": (
                            continuation_pairs if index in {2, 4, 7} else pairs
                        ),
                        "outputs": (
                            continuation_pairs if index in {2, 4, 7} else pairs
                        ),
                    }
                    for index, (name, rva, size) in enumerate(region_rows)
                ],
                "machine_import_call_contracts": [{
                    "id": 0,
                    "import": {
                        "dll": "kernel32.dll", "symbol": "GetTickCount",
                    },
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 0,
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }],
                "padding": [
                    {
                        "id": "first-caller-padding",
                        "side": "both",
                        "rva": 0x1013,
                        "size": 0x0D,
                    },
                    {
                        "id": "second-caller-padding",
                        "side": "both",
                        "rva": 0x102A,
                        "size": 0x16,
                    },
                    {
                        "id": "shared-callee-padding",
                        "side": "both",
                        "rva": 0x1047,
                        "size": 0x09,
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
            register_analysis = json.loads(
                (prepared / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            seeded_relation = next(
                relation
                for relation in register_analysis["regions"][1]["outputs"]
                if relation["original"] == "esi"
            )
            self.assertEqual(seeded_relation, {
                "original": "esi",
                "candidate": "esi",
                "relation": "fixed_word",
                "value": 0x12345678,
            })
            self.assertFalse(any(
                relation["original"] == "esi"
                and relation.get("relation") == "fixed_word"
                for relation in register_analysis["regions"][3]["inputs"]
            ))

            callee_states = [
                state for state in result["acceptance"]["control_states"]
                if state["node_id"] == 5
            ]
            self.assertEqual(len(callee_states), 2, callee_states)
            state_by_continuation = {
                state["calls"][0]: state for state in callee_states
            }
            self.assertEqual(set(state_by_continuation), {2, 4})
            carried_relation = state_by_continuation[2]["frame_offsets"][0][
                "preserved_relations"
            ][0]
            self.assertEqual(
                {
                    key: value for key, value in carried_relation.items()
                    if key != "origin"
                },
                seeded_relation,
            )
            self.assertEqual(
                carried_relation["origin"]["region_index"], 1
            )
            self.assertNotIn(
                "preserved_relations",
                state_by_continuation[4]["frame_offsets"][0],
            )

            external_step = next(
                step for step in result["acceptance"]["node_steps"]
                if step["node_id"] == 5
            )
            self.assertEqual(external_step["kind"], "external_call")
            self.assertEqual(len(external_step["cases"]), 2)
            return_step = next(
                step for step in result["acceptance"]["node_steps"]
                if step["kind"] == "return"
            )
            return_case_by_target = {
                case["target_node_id"]: case for case in return_step["cases"]
            }
            self.assertEqual(
                return_case_by_target[2]["active_frame_relations"],
                [seeded_relation],
            )
            self.assertEqual(
                return_case_by_target[4]["active_frame_relations"], []
            )

            acceptance_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((prepared / "lean" / "StageA").glob(
                    "RelationalAcceptance*.lean"
                ))
            )
            self.assertIn("seedsPreservedRelationsFromOutputClaims", acceptance_source)
            self.assertIn("RelationalRuntimeCallFactsHold.afterExternal", acceptance_source)
            self.assertIn("pe32ProgramsEquivalent", acceptance_source)

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])
