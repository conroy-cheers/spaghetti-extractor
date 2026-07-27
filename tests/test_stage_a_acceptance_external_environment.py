from tests.stage_a_relational_support import *
from spaghetti_extractor.relational.schema import (
    PROTOCOL_CALLBACK_CONTROL_FORMAT,
    RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
)
from spaghetti_extractor.relational.lean.acceptance import (
    _acceptance_segment_imports,
    _frame_relations_requiring_internal_preservation,
    _lean_frame_exact_word_register_output_claim,
    _lean_acceptance_linked_shallow_lift,
    _lean_acceptance_linked_shallow_node,
    _lean_return_slot_frame_transfer_claim,
    _lean_runtime_call_import_transfer_claim,
    _launch_check_ranges,
    _launch_state_predicates_structurally_true,
    _launch_structural_image_ranges,
    _runtime_frame_protected_bytes,
    _segment_module_ownership,
    _semantic_bool_is_structural_tautology,
)
from spaghetti_extractor.relational.lean.expressions import (
    _lean_direct_call_prepared_exact_word_seed_claim,
)
from typing import Any


class StageAAcceptanceExternalEnvironmentTests(StageARelationalTestBase):
    def test_protocol_contract_without_decoded_site_cannot_reach_acceptance(self):
        plan = _whole_program_acceptance_plan(
            {
                "machine_import_call_contracts": [{
                    "id": 3,
                    "import": {"dll": "msvcrt.dll", "symbol": "exit"},
                    "disposition": "protocol",
                }],
                "regions": [],
            },
            [],
            {
                "nodes": [],
                "edges": [],
                "root_node_ids": [],
                "evidence": {"reachable_product_local_complete": False},
            },
            {"edges": [], "regions": []},
            [],
            [],
        )

        self.assertEqual(plan["status"], "incomplete")
        self.assertEqual(plan["protocol_callback_node_ids"], [])
        self.assertIn(
            "reachable_product_local_incomplete",
            {blocker["code"] for blocker in plan["blockers"]},
        )
        self.assertNotEqual(plan["profile"], "stateful-external-protocol-v1")

    def test_linked_shallow_lift_threads_protocol_environment_pair(self):
        source = _lean_acceptance_linked_shallow_lift(
            parameterized_environment=True,
            parameterized_protocol_environment=True,
        )

        self.assertIn(
            "(originalProtocolEnvironment candidateProtocolEnvironment : "
            "WorldExternalProtocolEnvironment)",
            source,
        )
        self.assertIn(
            "(originalWorldProgram originalEnvironment originalProtocolEnvironment)",
            source,
        )
        self.assertIn(
            "(candidateWorldProgram candidateEnvironment candidateProtocolEnvironment)",
            source,
        )

    def test_linked_shallow_node_threads_protocol_environment_pair(self):
        source = _lean_acceptance_linked_shallow_node(
            {"kind": "external_protocol", "node_id": 7},
            parameterized_environment=True,
            parameterized_protocol_environment=True,
        )

        self.assertIn(
            "acceptanceLinkedRunningNodeRefinedOfShallow\n"
            "    originalEnvironment candidateEnvironment "
            "originalProtocolEnvironment candidateProtocolEnvironment 7",
            source,
        )
        self.assertIn(
            "acceptanceRunningNode7Refined originalEnvironment "
            "candidateEnvironment originalProtocolEnvironment "
            "candidateProtocolEnvironment environmentRefines",
            source,
        )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_external_call_loop_checks_paired_environment_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = b"\xff\x15" + struct.pack("<I", iat_address) + b"\xeb\xf8"
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(
                code, symbol="GetTickCount",
            ))
            candidate.write_bytes(_pe32_import_image(
                code, symbol="GetTickCount",
            ))
            pairs = [
                {"original": register, "candidate": register}
                for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            ]
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1006, "candidate_rva": 0x1006},
                ],
                "regions": [
                    {
                        "id": "import-call", "root": True,
                        "original": {"rva": 0x1000, "size": 6},
                        "candidate": {"rva": 0x1000, "size": 6},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "continuation-loop", "root": False,
                        "original": {"rva": 0x1006, "size": 2},
                        "candidate": {"rva": 0x1006, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "machine_import_call_contracts": [{
                    "id": 0,
                    "import": {
                        "dll": "kernel32.dll", "symbol": "GetTickCount",
                    },
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 0,
                    "result_register_relations": [{
                        "register": "eax", "relation": "exact",
                    }],
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["acceptance"]["profile"], "paired-external-call-v1"
            )
            self.assertEqual(
                [step["kind"] for step in result["acceptance"]["node_steps"]],
                ["external_call", "jump"],
            )
            generated_acceptance = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((prepared / "lean" / "StageA").glob(
                    "RelationalAcceptance*.lean"
                ))
            )
            self.assertIn(
                "OpaqueLockstepExternalEnvironmentsRefine staticProofContext",
                generated_acceptance,
            )
            self.assertIn(
                "OpaqueLockstepExternalEnvironmentsRefine.atReturning",
                generated_acceptance,
            )
            self.assertIn(
                "CheckedOpaqueLockstepEnvironment.at",
                generated_acceptance,
            )
            opaque_inventory = json.loads(
                (prepared / "opaque-lockstep-environment.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                opaque_inventory["format"],
                "stage-a-relational-opaque-lockstep-environment-v2",
            )
            self.assertEqual(
                [site["disposition"] for site in opaque_inventory["call_sites"]],
                ["returns"],
            )
            self.assertIn(
                "environmentsRefined := environmentRefines.externalRefines",
                generated_acceptance,
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for allocation proofs")
    def test_external_allocation_and_dynamic_write_close_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image_base = 0x400000
            iat_address = image_base + 0x2000 + 0x40
            code = (
                b"\xc7\x04\x24\x04\x00\x00\x00"
                + b"\xff\x15" + struct.pack("<I", iat_address)
                + b"\x89\x18\xeb\xfc"
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(
                code, dll="TEST.dll", symbol="AllocateWord",
            ))
            candidate.write_bytes(_pe32_import_image(
                code, dll="TEST.dll", symbol="AllocateWord",
            ))
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x100d, "candidate_rva": 0x100d},
                ],
                "regions": [
                    {
                        "id": "allocate", "root": True,
                        "original": {"rva": 0x1000, "size": 13},
                        "candidate": {"rva": 0x1000, "size": 13},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "write-loop", "root": False,
                        "original": {"rva": 0x100d, "size": 4},
                        "candidate": {"rva": 0x100d, "size": 4},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "machine_import_call_contracts": [{
                    "id": 0,
                    "import": {"dll": "test.dll", "symbol": "AllocateWord"},
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 1,
                    "result_register_relations": [{
                        "register": "eax",
                        "relation": "dynamic_range_base",
                        "size": {"kind": "argument", "argument": 0, "scale": 1},
                        "minimum_size": 4,
                        "required_words": [{
                            "offset": 0, "relation": "related_word",
                        }],
                        "nullable": False,
                    }],
                    "memory_effect": "newDynamicRanges",
                    "memory_footprints": [],
                    "world_effect": "dynamicRanges",
                }],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertIn("acceptance", result, result)
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["acceptance"]["profile"], "paired-external-call-v1",
            )
            external_results = json.loads(
                (prepared / "relational-external-result-invariants.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(external_results["counts"], {
                "attached": 1, "rejected": 0,
            })
            self.assertEqual(
                external_results["attached"][0]["relation"]["required_words"],
                [{"offset": 0, "kind": "relatedWord"}],
            )
            self.assertEqual(
                external_results["attached"][0]["relation"]["active_words"],
                [],
            )
            proof_ir = json.loads(
                (prepared / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            self.assertTrue(any(
                any(
                    write.get("kind") == "dynamic_word"
                    for write in (
                        ((obligation.get("analysis") or {}).get("certificate") or {})
                        .get("paired_prepared_writes_claim", {})
                        .get("writes", [])
                    )
                )
                for obligation in proof_ir["obligations"]
            ), proof_ir)
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for protocol proofs")
    def test_protocol_call_and_callback_return_close_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = (
                b"\xff\x15" + struct.pack("<I", iat_address)
                + b"\x31\xc0\xc3"
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(code, symbol="ProtocolStep"))
            candidate.write_bytes(_pe32_import_image(code, symbol="ProtocolStep"))
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1006, "candidate_rva": 0x1006},
                ],
                "protocol_callback_control": {
                    "format": PROTOCOL_CALLBACK_CONTROL_FORMAT,
                    "states": [{
                        "target_id": 1,
                        "active_frame_offset": {
                            "original_register": "esp", "original": 0,
                            "candidate_register": "esp", "candidate": 0,
                        },
                        "return_invariant": {"kind": "terminal"},
                    }],
                },
                "regions": [
                    {
                        "id": "protocol-call", "root": True,
                        "original": {"rva": 0x1000, "size": 6},
                        "candidate": {"rva": 0x1000, "size": 6},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "callback-return", "root": False,
                        "original": {"rva": 0x1006, "size": 3},
                        "candidate": {"rva": 0x1006, "size": 3},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "machine_import_call_contracts": [{
                    "id": 0,
                    "import": {
                        "dll": "kernel32.dll", "symbol": "ProtocolStep",
                    },
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 0,
                    "disposition": "protocol",
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                [step["kind"] for step in result["acceptance"]["node_steps"]],
                ["external_protocol", "terminate"],
            )
            self.assertEqual(
                result["acceptance"]["protocol_callback_node_ids"], [1]
            )
            self.assertEqual(
                _validate_prepared_relational(prepared)["acceptance"]["status"],
                "ready",
            )
            self.assertEqual(
                result["acceptance"]["linked_acceptance"],
                {
                    "status": "ready",
                    "profile": "lean-checked-shallow-profile-compatibility-v1",
                    "theorem": RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
                    "blockers": [],
                },
            )
            generated_acceptance = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((prepared / "lean" / "StageA").glob(
                    "RelationalAcceptance*.lean"
                ))
            )
            self.assertIn(
                "theorem candidatePE32ProgramsEquivalentLinked",
                generated_acceptance,
            )
            self.assertIn(
                "(originalProtocolEnvironment candidateProtocolEnvironment : "
                "WorldExternalProtocolEnvironment)",
                generated_acceptance,
            )
            self.assertIn(
                "protocolRefines : LinkedWorldExternalProtocolEnvironmentsRefine",
                generated_acceptance,
            )
            self.assertIn(
                "LinkedWholeProgramCertificate staticProofContext",
                generated_acceptance,
            )
            self.assertIn(
                "protocolEnvironmentsRefined := protocolRefines",
                generated_acceptance,
            )
            self.assertIn(
                "ReachableLinkedCallbackRunningProductNodesRefined.of_shallow",
                generated_acceptance,
            )
            self.assertIn("using outputX87.1", generated_acceptance)
            self.assertNotIn(
                "LinkedWorldExternalProtocolEnvironmentsRefine.of_no_protocol_sites",
                generated_acceptance,
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

            repeated = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "prepared-repeated",
            )
            self.assertEqual(
                repeated["acceptance"]["protocol_callback_states"],
                result["acceptance"]["protocol_callback_states"],
            )
            self.assertEqual(
                repeated["interface_manifest_sha256"],
                result["interface_manifest_sha256"],
            )

            region_input_contract = json.loads(contract.read_text(encoding="utf-8"))
            region_input_contract["protocol_callback_control"]["states"][0][
                "return_invariant"
            ] = {"kind": "region_input", "target_id": 1}
            region_input_path = root / "region-input-relation.json"
            region_input_path.write_text(
                json.dumps(region_input_contract), encoding="utf-8"
            )
            region_input = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=region_input_path,
                out=root / "prepared-region-input",
            )
            self.assertEqual(region_input["acceptance"]["status"], "incomplete")
            self.assertIn(
                "callback_return_invariant_profile_incomplete",
                {
                    blocker["code"]
                    for blocker in region_input["acceptance"]["blockers"]
                },
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for import-thunk proofs")
    def test_nested_direct_import_thunk_preserves_outer_runtime_frame_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = (
                b"\xe8\x02\x00\x00\x00"
                b"\xeb\xfe"
                b"\xe8\x02\x00\x00\x00"
                b"\xeb\xf7"
                b"\xff\x25" + struct.pack("<I", iat_address)
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(
                code, symbol="GetTickCount", dll="kernel32.dll"
            ))
            candidate.write_bytes(_pe32_import_image(
                code, symbol="GetTickCount", dll="kernel32.dll"
            ))
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            continuation_pairs = pairs
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1005, "candidate_rva": 0x1005},
                    {"id": 2, "original_rva": 0x1007, "candidate_rva": 0x1007},
                    {"id": 3, "original_rva": 0x100C, "candidate_rva": 0x100C},
                    {"id": 4, "original_rva": 0x100E, "candidate_rva": 0x100E},
                ],
                "regions": [
                    {
                        "id": "root-caller", "root": True,
                        "original": {"rva": 0x1000, "size": 5},
                        "candidate": {"rva": 0x1000, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "root-continuation-loop", "root": False,
                        "original": {"rva": 0x1005, "size": 2},
                        "candidate": {"rva": 0x1005, "size": 2},
                        "inputs": continuation_pairs,
                        "outputs": continuation_pairs,
                    },
                    {
                        "id": "wrapper-call-import", "root": False,
                        "original": {"rva": 0x1007, "size": 5},
                        "candidate": {"rva": 0x1007, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "wrapper-continuation-jump", "root": False,
                        "original": {"rva": 0x100C, "size": 2},
                        "candidate": {"rva": 0x100C, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "get-tick-count-import-thunk", "root": False,
                        "original": {"rva": 0x100E, "size": 6},
                        "candidate": {"rva": 0x100E, "size": 6},
                        "inputs": pairs, "outputs": pairs,
                    },
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
                "padding": [],
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
                [step["kind"] for step in result["acceptance"]["node_steps"]],
                ["call", "jump", "call", "jump", "external_jump"],
            )
            thunk_step = result["acceptance"]["node_steps"][4]
            self.assertEqual(thunk_step["control_state"]["calls"], [3, 1])
            self.assertEqual(
                len(thunk_step["return_slot_external_jump_transfer_claims"]), 1
            )
            claim = thunk_step["return_slot_external_jump_transfer_claims"][0]
            self.assertEqual(claim["source"]["locations"][0]["original"], 4)
            transfer = claim["transfers"][0]
            self.assertEqual(transfer["boundary_target"]["original"], 0)
            self.assertEqual(claim["target"]["locations"][0]["original"], 0)
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_nested_external_call_preserves_internal_runtime_frame_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = (
                b"\xe8\x02\x00\x00\x00"
                b"\xeb\xfe"
                b"\x83\xec\x04"
                b"\xc7\x04\x24\x00\x00\x00\x00"
                b"\xff\x15" + struct.pack("<I", iat_address)
                + b"\xc3"
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(code, symbol="Sleep"))
            candidate.write_bytes(_pe32_import_image(code, symbol="Sleep"))
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            preserved_pairs = [
                pair for pair in pairs
                if pair["original"] in {"ebx", "esi", "edi", "ebp"}
            ]
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1005, "candidate_rva": 0x1005},
                    {"id": 2, "original_rva": 0x1007, "candidate_rva": 0x1007},
                    {"id": 3, "original_rva": 0x1017, "candidate_rva": 0x1017},
                ],
                "regions": [
                    {
                        "id": "caller", "root": True,
                        "original": {"rva": 0x1000, "size": 5},
                        "candidate": {"rva": 0x1000, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "continuation-loop", "root": False,
                        "original": {"rva": 0x1005, "size": 2},
                        "candidate": {"rva": 0x1005, "size": 2},
                        "inputs": preserved_pairs, "outputs": preserved_pairs,
                    },
                    {
                        "id": "callee-import-call", "root": False,
                        "original": {"rva": 0x1007, "size": 16},
                        "candidate": {"rva": 0x1007, "size": 16},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "callee-return", "root": False,
                        "original": {"rva": 0x1017, "size": 1},
                        "candidate": {"rva": 0x1017, "size": 1},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "machine_import_call_contracts": [{
                    "id": 0,
                    "import": {"dll": "kernel32.dll", "symbol": "Sleep"},
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 1,
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }],
                "padding": [],
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
                [step["kind"] for step in result["acceptance"]["node_steps"]],
                ["call", "jump", "external_call", "return"],
            )
            external_step = result["acceptance"]["node_steps"][2]
            self.assertEqual(len(external_step["control_state"]["calls"]), 1)
            self.assertEqual(
                len(external_step["return_slot_external_transfer_claims"]), 1
            )
            claim = external_step["return_slot_external_transfer_claims"][0]
            self.assertEqual(claim["source"]["locations"][0]["original"], 0)
            transfer = claim["transfers"][0]
            self.assertEqual(transfer["internal_target"]["original"], 4)
            self.assertEqual(claim["target"]["locations"][0]["original"], 0)
            self.assertEqual(
                len(transfer["memory_claim"]["original_write_witnesses"]), 1
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for import-thunk proofs")
    def test_direct_import_thunk_checks_runtime_frame_and_environment_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = (
                b"\xe8\x02\x00\x00\x00"
                b"\xeb\xfe"
                b"\xff\x25" + struct.pack("<I", iat_address)
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(code, symbol="GetTickCount"))
            candidate.write_bytes(_pe32_import_image(code, symbol="GetTickCount"))
            pairs = [
                {"original": register, "candidate": register}
                for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            ]
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1005, "candidate_rva": 0x1005},
                    {"id": 2, "original_rva": 0x1007, "candidate_rva": 0x1007},
                ],
                "regions": [
                    {
                        "id": "caller", "root": True,
                        "original": {"rva": 0x1000, "size": 5},
                        "candidate": {"rva": 0x1000, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "continuation-loop", "root": False,
                        "original": {"rva": 0x1005, "size": 2},
                        "candidate": {"rva": 0x1005, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "get-tick-count-import-thunk", "root": False,
                        "original": {"rva": 0x1007, "size": 6},
                        "candidate": {"rva": 0x1007, "size": 6},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "machine_import_call_contracts": [{
                    "id": 0,
                    "import": {"dll": "kernel32.dll", "symbol": "GetTickCount"},
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 0,
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["acceptance"]["linked_acceptance"],
                {
                    "status": "ready",
                    "profile": "lean-checked-shallow-profile-compatibility-v1",
                    "theorem": (
                        "StageA.GeneratedRelational."
                        "candidatePE32ProgramsEquivalentLinked"
                    ),
                    "blockers": [],
                },
                result,
            )
            self.assertEqual(
                [step["kind"] for step in result["acceptance"]["node_steps"]],
                ["call", "jump", "external_jump"],
            )
            sites = json.loads(
                (prepared / "relational-external-call-sites.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(sites["counts"], {"candidates": 1, "gaps": 0})
            self.assertEqual(
                sites["candidates"][0]["dispatch_profile"],
                "checked_direct_import_thunk",
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertIn(
                "candidatePE32ProgramsEquivalentLinked' depends on axioms",
                lean["stdout"],
            )
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for callback proofs")
    def test_tail_jump_import_wrapper_registers_mapped_callback_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = (
                b"\xe8\x02\x00\x00\x00"
                + b"\xeb\xfe"
                + b"\xe8\x02\x00\x00\x00"
                + b"\xeb\xf7"
                + b"\xe9\x00\x00\x00\x00"
                + b"\xff\x25" + struct.pack("<I", iat_address)
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(
                code, symbol="atexit", dll="msvcrt.dll",
            ))
            candidate.write_bytes(original.read_bytes())
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1005, "candidate_rva": 0x1005},
                    {"id": 2, "original_rva": 0x1007, "candidate_rva": 0x1007},
                    {"id": 3, "original_rva": 0x100C, "candidate_rva": 0x100C},
                    {"id": 4, "original_rva": 0x100E, "candidate_rva": 0x100E},
                    {"id": 5, "original_rva": 0x1013, "candidate_rva": 0x1013},
                ],
                "regions": [
                    {
                        "id": "outer-caller", "root": True,
                        "original": {"rva": 0x1000, "size": 5},
                        "candidate": {"rva": 0x1000, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "registered-callback-continuation", "root": False,
                        "original": {"rva": 0x1005, "size": 2},
                        "candidate": {"rva": 0x1005, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "register-callback", "root": False,
                        "original": {"rva": 0x1007, "size": 5},
                        "candidate": {"rva": 0x1007, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "registration-continuation", "root": False,
                        "original": {"rva": 0x100C, "size": 2},
                        "candidate": {"rva": 0x100C, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "atexit-tail-wrapper", "root": False,
                        "original": {"rva": 0x100E, "size": 5},
                        "candidate": {"rva": 0x100E, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "atexit-import-thunk", "root": False,
                        "original": {"rva": 0x1013, "size": 6},
                        "candidate": {"rva": 0x1013, "size": 6},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "machine_import_call_contracts": [{
                    "id": 0,
                    "import": {"dll": "msvcrt.dll", "symbol": "atexit"},
                    "abi_template": "pe32-cdecl-v1",
                    "argument_words": 1,
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "callbackRegistration",
                    "world_effect_argument": 0,
                }],
                "padding": [],
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
            sites = json.loads(
                (prepared / "relational-external-call-sites.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(sites["counts"], {"candidates": 1, "gaps": 0})
            site = sites["candidates"][0]
            self.assertEqual(site["source_region_index"], 5)
            self.assertEqual(site["call_target_region_index"], 4)
            self.assertEqual(site["tail_jump_region_indices"], [4])
            self.assertEqual(len(site["tail_jump_edge_indices"]), 1)
            self.assertEqual(site["machine_contract_id"], 0)
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for external termination proofs")
    def test_nonreturning_import_thunk_terminates_whole_program_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = (
                b"\xe8\x02\x00\x00\x00"
                b"\xeb\xfe"
                b"\xff\x25" + struct.pack("<I", iat_address)
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(
                code, symbol="_amsg_exit", dll="msvcrt.dll",
            ))
            candidate.write_bytes(original.read_bytes())
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1005, "candidate_rva": 0x1005},
                    {"id": 2, "original_rva": 0x1007, "candidate_rva": 0x1007},
                ],
                "regions": [
                    {
                        "id": "caller", "root": True,
                        "original": {"rva": 0x1000, "size": 5},
                        "candidate": {"rva": 0x1000, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "syntactic-continuation", "root": False,
                        "original": {"rva": 0x1005, "size": 2},
                        "candidate": {"rva": 0x1005, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "amsg-exit-import-thunk", "root": False,
                        "original": {"rva": 0x1007, "size": 6},
                        "candidate": {"rva": 0x1007, "size": 6},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "machine_import_call_contracts": [{
                    "id": 0,
                    "import": {"dll": "msvcrt.dll", "symbol": "_amsg_exit"},
                    "abi_template": "pe32-cdecl-v1",
                    "argument_words": 1,
                    "disposition": "terminates",
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                [step["kind"] for step in result["acceptance"]["node_steps"]],
                ["call", "external_terminate"],
            )
            terminal_step = next(
                step for step in result["acceptance"]["node_steps"]
                if step["kind"] == "external_terminate"
            )
            self.assertEqual(terminal_step["control_state"]["calls"], [1])
            self.assertEqual(
                terminal_step["machine_contract"]["disposition"], "terminates"
            )
            product_graph = json.loads(
                (prepared / "relational-product-graph.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                product_graph["evidence"]["runtime_call_continuations"],
                [{"source_node_id": 0, "continuation_node_ids": [1]}],
            )
            self.assertEqual(
                product_graph["evidence"]["terminating_call_continuations"],
                [{
                    "source_node_id": 0,
                    "continuation_node_id": 1,
                    "continuation_target_id": 1,
                    "call_edge_id": 0,
                    "call_target_node_id": 2,
                    "external_jump_node_id": 2,
                    "external_site_id": int(terminal_step["external_site"]["id"]),
                    "machine_contract_id": 0,
                }],
            )
            self.assertEqual(
                product_graph["evidence"]["declared_reachable_node_ids"],
                [0, 2],
            )
            self.assertEqual(
                product_graph["evidence"]["potential_reachable_node_ids"],
                [0, 2],
            )
            self.assertEqual(
                product_graph["evidence"]["reachable_feasible_edge_ids"],
                [0],
            )
            self.assertEqual(
                result["composition_progress"]["reachability"]["rooted_node_ids"],
                [0, 2],
            )
            register_relations = json.loads(
                (prepared / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            call_edge = next(
                edge for edge in register_relations["edges"]
                if edge["source_region_index"] == 0
                and edge["target_region_index"] == 2
            )
            self.assertNotIn(
                "returning_external_thunk_contract_id", call_edge
            )
            normalized_contract = json.loads(
                (prepared / "relation-contract.json").read_text(encoding="utf-8")
            )
            semantic_ir = json.loads(
                (prepared / "relational-semantic-ir.json").read_text(
                    encoding="utf-8"
                )
            )
            external_sites = json.loads(
                (prepared / "relational-external-call-sites.json").read_text(
                    encoding="utf-8"
                )
            )["candidates"]
            direct_sites = [
                site for site in external_sites
                if site.get("site_kind") == "direct_import_thunk"
            ]
            self.assertEqual(len(direct_sites), 1)
            ambiguous_graph = _relational_product_graph(
                normalized_contract,
                [
                    {
                        "original_ir": region["original"],
                        "candidate_ir": region["candidate"],
                    }
                    for region in semantic_ir["regions"]
                ],
                register_relations,
                [],
                original_image_base=0x400000,
                candidate_image_base=0x400000,
                external_call_candidates=[
                    *external_sites,
                    {**direct_sites[0], "id": int(direct_sites[0]["id"]) + 100},
                ],
            )
            self.assertEqual(
                ambiguous_graph["evidence"]["terminating_call_continuations"],
                [],
            )
            self.assertEqual(
                ambiguous_graph["evidence"]["declared_reachable_node_ids"],
                [0, 1, 2],
            )
            callsite = json.loads(
                (prepared / "relational-callsite-preservation.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(callsite["counts"]["proposal_edges"], 0)
            self.assertEqual(
                terminal_step["control_state"]["frame_offsets"][0].get(
                    "import_relations", []
                ),
                [],
            )
            self.assertEqual(
                terminal_step["control_state"]["frame_offsets"][0].get(
                    "register_relations", []
                ),
                [],
            )
            self.assertEqual(
                result["acceptance"]["launch_realizability"]["profile"],
                "paired-preferred-base-import-stack-v1",
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])
