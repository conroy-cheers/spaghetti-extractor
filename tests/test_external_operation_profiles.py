from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.external_interface_profiles import (
    EXTERNAL_INTERFACE_PROFILE_FORMAT,
    load_external_interface_profile,
)
from spaghetti_extractor.external_operation_profiles import (
    EXTERNAL_OPERATION_CONTRACT_FORMAT,
    EXTERNAL_OPERATION_PROFILE_FORMAT,
    ArgumentFootprintSize,
    CallbackSelector,
    DirectImportSelector,
    DiscriminatorOutputView,
    ExternalOperationProfileError,
    OutArgumentOutput,
    ResolverResultSelector,
    ReturnRegisterOutput,
    TableSlotSelector,
    convert_external_interface_profile,
    load_external_operation_contract,
    load_external_operation_profile,
    parse_external_operation_contract,
    parse_external_operation_profile,
)
from spaghetti_extractor.machine_import_profiles import MachineImportIdentity


def environment_contract(
    contract_id: str,
    *,
    memory_footprints: list[dict[str, object]] | None = None,
    world_effects: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "format": EXTERNAL_OPERATION_CONTRACT_FORMAT,
        "id": contract_id,
        "status": "complete",
        "memory_footprints": memory_footprints or [],
        "world_effects": world_effects or [],
    }


def operation(
    operation_id: str,
    *,
    argument_words: int = 1,
    contract_id: str = "pure",
    outputs: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "id": operation_id,
        "abi_template": "pe32-stdcall-v1",
        "argument_words": argument_words,
        "environment_contract_id": contract_id,
        "output_rules": outputs or [],
    }


def profile() -> dict[str, object]:
    return {
        "format": EXTERNAL_OPERATION_PROFILE_FORMAT,
        "id": "generic-operations",
        "model": "x86-pe32",
        "status": "complete",
        "provenance": {"kind": "fixture"},
        "table_views": [
            {"id": "IRoot", "table": "IRootTable"},
            {"id": "IAlternate", "table": "IAlternateTable"},
        ],
        "operations": [
            operation(
                "create",
                argument_words=3,
                contract_id="create-environment",
                outputs=[{
                    "kind": "out_argument",
                    "argument_index": 2,
                    "write_width": 4,
                    "success_guard": {
                        "kind": "masked_equals",
                        "register": "eax",
                        "mask": 0x80000000,
                        "value": 0,
                    },
                    "view": {
                        "kind": "discriminator",
                        "argument_index": 1,
                        "cases": [
                            {"value": 1, "view_id": "IRoot"},
                            {"value": 2, "view_id": "IAlternate"},
                        ],
                    },
                }],
            ),
            operation("release"),
            operation("resolver", argument_words=2),
            operation(
                "resolved-target",
                outputs=[{
                    "kind": "return_register",
                    "register": "eax",
                    "success_guard": {"kind": "nonzero", "register": "eax"},
                    "view": {"kind": "fixed", "view_id": "IAlternate"},
                }],
            ),
            operation("callback", contract_id="callback-environment"),
        ],
        "selectors": [
            {
                "kind": "direct_import",
                "operation_id": "create",
                "import": {"dll": "example.dll", "symbol": "Create"},
            },
            {
                "kind": "table_slot",
                "operation_id": "release",
                "view_id": "IRoot",
                "slot": 0,
            },
            {
                "kind": "direct_import",
                "operation_id": "resolver",
                "import": {"dll": "example.dll", "ordinal": 7},
            },
            {
                "kind": "resolver_result",
                "operation_id": "resolved-target",
                "resolver_operation_id": "resolver",
                "result_id": "alternate-entry",
            },
            {
                "kind": "callback",
                "operation_id": "callback",
                "callback_id": "completion-callback",
            },
        ],
        "environment_contracts": [
            environment_contract("pure"),
            environment_contract(
                "create-environment",
                memory_footprints=[
                    {
                        "access": "read",
                        "base_argument": 0,
                        "offset": 0,
                        "size": {
                            "kind": "argument",
                            "argument_index": 1,
                            "scale": 4,
                            "maximum_bytes": 1024,
                        },
                        "nullable": False,
                    },
                    {
                        "access": "write",
                        "base_argument": 2,
                        "offset": 0,
                        "size": {"kind": "fixed", "bytes": 4},
                        "nullable": False,
                    },
                ],
                world_effects=[{"kind": "opaqueResources"}],
            ),
            environment_contract(
                "callback-environment",
                world_effects=[{
                    "kind": "callbackRegistration",
                    "argument_index": 0,
                    "callback_id": "completion-callback",
                }],
            ),
        ],
    }


def v1_profile() -> dict[str, object]:
    return {
        "format": EXTERNAL_INTERFACE_PROFILE_FORMAT,
        "id": "legacy-interfaces",
        "model": "x86-pe32",
        "status": "complete",
        "provenance": {"kind": "fixture"},
        "factories": [{
            "id": "factory",
            "import": {"dll": "legacy.dll", "symbol": "CreateRoot"},
            "declaration": "CreateRoot",
            "abi_template": "pe32-stdcall-v1",
            "argument_words": 2,
            "out_interfaces": [{
                "argument_index": 1,
                "interface_id": "IRoot",
                "write_width": 4,
            }],
        }],
        "interfaces": [{
            "id": "IRoot",
            "vtable": "IRootVtbl",
            "methods": [
                {
                    "name": "Release",
                    "slot": 0,
                    "offset": 0,
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 1,
                    "out_interfaces": [],
                },
                {
                    "name": "OpenChild",
                    "slot": 1,
                    "offset": 4,
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 2,
                    "out_interfaces": [{
                        "argument_index": 1,
                        "interface_id": "IRoot",
                        "write_width": 4,
                    }],
                },
            ],
        }],
    }


class ExternalOperationProfileTests(unittest.TestCase):
    def test_accepts_pointed_byte_discriminator_for_iid_views(self) -> None:
        payload = profile()
        output = payload["operations"][0]["output_rules"][0]["view"]
        output["read_bytes"] = 16
        output["cases"] = [
            {"bytes_sha256": "1" * 64, "view_id": "IRoot"},
            {"bytes_sha256": "2" * 64, "view_id": "IAlternate"},
        ]

        parsed = parse_external_operation_profile(payload)

        selected = parsed.operations_by_id()["create"].output_rules[0]
        self.assertIsInstance(selected.view, DiscriminatorOutputView)
        self.assertEqual(selected.view.read_bytes, 16)

    def test_rejects_mixed_scalar_and_pointed_discriminator_cases(self) -> None:
        payload = profile()
        output = payload["operations"][0]["output_rules"][0]["view"]
        output["read_bytes"] = 16
        output["cases"][0] = {
            "bytes_sha256": "1" * 64,
            "view_id": "IRoot",
        }
        with self.assertRaises(ExternalOperationProfileError):
            parse_external_operation_profile(payload)

    def test_loads_all_selector_output_and_environment_variants(self) -> None:
        payload = profile()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "operations.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_external_operation_profile(path)

        self.assertEqual(loaded.profile_id, "generic-operations")
        self.assertEqual(len(loaded.sha256), 64)
        self.assertEqual(
            {type(selector) for selector in loaded.selectors},
            {
                DirectImportSelector,
                TableSlotSelector,
                ResolverResultSelector,
                CallbackSelector,
            },
        )
        imported = MachineImportIdentity("example.dll", "symbol", "Create")
        create = loaded.operation_for_import(imported)
        self.assertIsNotNone(create)
        assert create is not None
        self.assertEqual(create.abi.template, "pe32-stdcall-v1")
        self.assertEqual(create.argument_words, 3)
        self.assertIsInstance(create.output_rules[0], OutArgumentOutput)
        output = create.output_rules[0]
        assert isinstance(output, OutArgumentOutput)
        self.assertIsInstance(output.view, DiscriminatorOutputView)
        self.assertEqual(output.success_guard.kind, "masked_equals")

        method = loaded.operation_for_table_slot("IRoot", 0)
        self.assertIsNotNone(method)
        assert method is not None
        self.assertEqual(method.receiver_resource.as_json(), {
            "argument_index": 0,
            "view_id": "IRoot",
            "required_state": "live",
            "dispatch_slot": 0,
            "lifecycle_effect": "may_release",
        })
        selector = next(
            item for item in loaded.selectors if isinstance(item, TableSlotSelector)
        )
        self.assertEqual(selector.offset, 0)

        contract = loaded.contracts_by_id()["create-environment"]
        self.assertIsInstance(contract.memory_footprints[0].size, ArgumentFootprintSize)
        self.assertEqual(contract.world_effects[0].kind, "opaqueResources")
        callback = loaded.contracts_by_id()["callback-environment"]
        self.assertEqual(callback.world_effects[0].argument_index, 0)
        self.assertEqual(
            callback.world_effects[0].callback_id, "completion-callback"
        )
        self.assertEqual(
            loaded.operation_for_resolver_result("resolver", "alternate-entry").operation_id,
            "resolved-target",
        )
        self.assertEqual(
            loaded.operation_for_callback("completion-callback").operation_id,
            "callback",
        )

    def test_explicit_receiver_contract_can_declare_release(self) -> None:
        payload = profile()
        payload["operations"][1]["receiver_resource"] = {
            "argument_index": 0,
            "view_id": "IRoot",
            "required_state": "live",
            "dispatch_slot": 0,
            "lifecycle_effect": "release",
        }

        parsed = parse_external_operation_profile(payload)

        receiver = parsed.operations_by_id()["release"].receiver_resource
        self.assertIsNotNone(receiver)
        assert receiver is not None
        self.assertEqual(receiver.lifecycle_effect, "release")
        self.assertEqual(
            parsed.as_json()["operations"][1]["receiver_resource"],
            receiver.as_json(),
        )

    def test_rejects_receiver_contract_without_exact_table_dispatch(self) -> None:
        cases: list[tuple[dict[str, object], str]] = []
        wrong_slot = profile()
        wrong_slot["operations"][1]["receiver_resource"] = {
            "argument_index": 0,
            "view_id": "IRoot",
            "required_state": "live",
            "dispatch_slot": 1,
            "lifecycle_effect": "release",
        }
        cases.append((wrong_slot, "differs from its table dispatch"))
        direct_import = profile()
        direct_import["operations"][0]["receiver_resource"] = {
            "argument_index": 0,
            "view_id": "IRoot",
            "required_state": "live",
            "dispatch_slot": 0,
            "lifecycle_effect": "preserve",
        }
        cases.append((direct_import, "requires one exact table-slot selector"))
        not_live = profile()
        not_live["operations"][1]["receiver_resource"] = {
            "argument_index": 0,
            "view_id": "IRoot",
            "required_state": "released",
            "dispatch_slot": 0,
            "lifecycle_effect": "release",
        }
        cases.append((not_live, "must require a live resource"))

        for payload, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ExternalOperationProfileError, message):
                    parse_external_operation_profile(payload)

    def test_profile_round_trip_is_typed_and_canonical(self) -> None:
        first = parse_external_operation_profile(profile())
        second = parse_external_operation_profile(first.as_json())

        self.assertEqual(second.as_json(), first.as_json())
        self.assertEqual(second.sha256, first.sha256)
        self.assertEqual(
            second.selectors_by_operation_id()["resolver"][0].operation_id,
            "resolver",
        )

    def test_profile_identity_is_independent_of_json_whitespace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            compact = Path(temporary) / "compact.json"
            pretty = Path(temporary) / "pretty.json"
            compact.write_text(
                json.dumps(profile(), separators=(",", ":")),
                encoding="utf-8",
            )
            pretty.write_text(json.dumps(profile(), indent=4), encoding="utf-8")

            compact_profile = load_external_operation_profile(compact)
            pretty_profile = load_external_operation_profile(pretty)

        self.assertEqual(compact_profile.sha256, pretty_profile.sha256)

    def test_table_view_access_distinguishes_object_and_direct_tables(self) -> None:
        payload = profile()
        payload["table_views"][1]["access"] = "direct_table"
        parsed = parse_external_operation_profile(payload)

        self.assertEqual(parsed.views_by_id()["IRoot"].access, "object_table")
        self.assertEqual(parsed.views_by_id()["IAlternate"].access, "direct_table")

        payload["table_views"][1]["access"] = "descriptor_chain"
        with self.assertRaisesRegex(ExternalOperationProfileError, "access"):
            parse_external_operation_profile(payload)

    def test_direct_table_dispatch_does_not_invent_a_receiver(self) -> None:
        payload = profile()
        payload["table_views"][1]["access"] = "direct_table"
        payload["selectors"][1]["view_id"] = "IAlternate"

        parsed = parse_external_operation_profile(payload)

        self.assertIsNone(
            parsed.operations_by_id()["release"].receiver_resource
        )

    def test_environment_contract_is_standalone_and_has_no_operation_identity(self) -> None:
        payload = environment_contract(
            "release",
            world_effects=[{
                "kind": "dynamicRangeRelease",
                "argument_index": 0,
            }],
        )
        parsed = parse_external_operation_contract(payload)
        self.assertNotIn("operation_id", parsed.as_json())
        self.assertNotIn("abi_template", parsed.as_json())

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_external_operation_contract(path)
        self.assertEqual(loaded, parsed)

    def test_accepts_all_success_guard_variants(self) -> None:
        for guard in (
            {"kind": "equals", "register": "eax", "value": 0},
            {
                "kind": "masked_equals",
                "register": "eax",
                "mask": 0x80000000,
                "value": 0,
            },
            {"kind": "nonzero", "register": "eax"},
        ):
            payload = profile()
            payload["operations"][3]["output_rules"][0]["success_guard"] = guard
            parsed = parse_external_operation_profile(payload)
            output = parsed.operations_by_id()["resolved-target"].output_rules[0]
            self.assertIsInstance(output, ReturnRegisterOutput)
            self.assertEqual(output.success_guard.kind, guard["kind"])

    def test_rejects_top_level_shape_and_state_errors(self) -> None:
        cases: list[tuple[dict[str, object], str]] = []
        unknown = profile()
        unknown["extension"] = True
        cases.append((unknown, "unknown extension"))
        unsupported = profile()
        unsupported["format"] = "stage-a-external-operation-profile-v1"
        cases.append((unsupported, "unsupported.*format"))
        incomplete = profile()
        incomplete["status"] = "draft"
        cases.append((incomplete, "not complete"))
        wrong_model = profile()
        wrong_model["model"] = "x86-64"
        cases.append((wrong_model, "unsupported.*model"))
        no_operations = profile()
        no_operations["operations"] = []
        cases.append((no_operations, "has no operations"))

        for payload, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ExternalOperationProfileError, message):
                    parse_external_operation_profile(payload)

    def test_rejects_non_json_provenance_and_invalid_supplied_digest(self) -> None:
        malformed = profile()
        malformed["provenance"]["score"] = float("nan")
        with self.assertRaisesRegex(ExternalOperationProfileError, "not finite JSON"):
            parse_external_operation_profile(malformed)

        with self.assertRaisesRegex(ExternalOperationProfileError, "lowercase SHA-256"):
            parse_external_operation_profile(profile(), payload_sha256="invalid")

    def test_rejects_operation_abi_arity_and_field_errors(self) -> None:
        mutations = (
            ("unknown declaration", lambda row: row.update({"declaration": "Create"})),
            ("unsupported ABI", lambda row: row.update({"abi_template": "fastcall"})),
            ("argument words", lambda row: row.update({"argument_words": 65})),
            ("argument words", lambda row: row.update({"argument_words": True})),
            ("duplicate external-operation ID", lambda row: row.update({"id": "release"})),
            (
                "unknown environment contract",
                lambda row: row.update({"environment_contract_id": "missing"}),
            ),
        )
        for message, mutate in mutations:
            payload = profile()
            mutate(payload["operations"][0])
            with self.subTest(message=message):
                with self.assertRaisesRegex(ExternalOperationProfileError, message):
                    parse_external_operation_profile(payload)

    def test_rejects_ambiguous_or_dangling_selectors(self) -> None:
        cases: list[tuple[dict[str, object], str]] = []
        duplicate = profile()
        duplicate["selectors"].append(copy.deepcopy(duplicate["selectors"][0]))
        cases.append((duplicate, "duplicate external-operation selector"))
        dangling = profile()
        dangling["selectors"][0]["operation_id"] = "missing"
        cases.append((dangling, "unknown operation"))
        unselected = profile()
        unselected["selectors"] = unselected["selectors"][1:]
        cases.append((unselected, "operations have no selectors: create"))
        bad_view = profile()
        bad_view["selectors"][1]["view_id"] = "IUnknown"
        cases.append((bad_view, "unknown view"))
        bad_resolver = profile()
        bad_resolver["selectors"][3]["resolver_operation_id"] = "missing"
        cases.append((bad_resolver, "unknown resolver operation"))

        for payload, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ExternalOperationProfileError, message):
                    parse_external_operation_profile(payload)

    def test_rejects_invalid_import_and_selector_variants(self) -> None:
        both = profile()
        both["selectors"][0]["import"]["ordinal"] = 1
        unsupported = profile()
        unsupported["selectors"][0] = {
            "kind": "address",
            "operation_id": "create",
            "rva": 0x1000,
        }
        extra = profile()
        extra["selectors"][4]["argument_index"] = 0

        for payload, message in (
            (both, "exactly one symbol or ordinal"),
            (unsupported, "unsupported kind"),
            (extra, "unknown argument_index"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ExternalOperationProfileError, message):
                    parse_external_operation_profile(payload)

    def test_rejects_resolver_self_reference_and_cycles(self) -> None:
        self_reference = profile()
        self_reference["selectors"][3]["resolver_operation_id"] = "resolved-target"
        with self.assertRaisesRegex(ExternalOperationProfileError, "resolve itself"):
            parse_external_operation_profile(self_reference)

        cycle = profile()
        cycle["selectors"][2] = {
            "kind": "resolver_result",
            "operation_id": "resolver",
            "resolver_operation_id": "resolved-target",
            "result_id": "resolver-entry",
        }
        with self.assertRaisesRegex(ExternalOperationProfileError, "form a cycle"):
            parse_external_operation_profile(cycle)

    def test_rejects_invalid_output_locations_and_views(self) -> None:
        cases: list[tuple[dict[str, object], str]] = []
        preserved = profile()
        preserved["operations"][3]["output_rules"][0]["register"] = "ebx"
        cases.append((preserved, "preserved register"))
        out_of_range = profile()
        out_of_range["operations"][0]["output_rules"][0]["argument_index"] = 3
        cases.append((out_of_range, "output argument is out of range"))
        unknown_view = profile()
        unknown_view["operations"][3]["output_rules"][0]["view"]["view_id"] = "missing"
        cases.append((unknown_view, "unknown output views"))
        duplicate = profile()
        duplicate["operations"][3]["output_rules"].append(
            copy.deepcopy(duplicate["operations"][3]["output_rules"][0])
        )
        cases.append((duplicate, "duplicate output location"))
        missing_footprint = profile()
        missing_footprint["environment_contracts"][1]["memory_footprints"] = []
        cases.append((missing_footprint, "lacks a bounded write footprint"))

        for payload, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ExternalOperationProfileError, message):
                    parse_external_operation_profile(payload)

    def test_callable_output_requires_a_matching_resolver_selector(self) -> None:
        payload = profile()
        payload["operations"][2]["output_rules"] = [{
            "kind": "return_operation",
            "register": "eax",
            "result_id": "alternate-entry",
            "success_guard": {"kind": "nonzero", "register": "eax"},
        }]
        parsed = parse_external_operation_profile(payload)
        self.assertEqual(
            parsed.operations_by_id()["resolver"].output_rules[0].result_id,
            "alternate-entry",
        )

        payload["operations"][2]["output_rules"][0]["result_id"] = "missing"
        with self.assertRaisesRegex(
            ExternalOperationProfileError, "no resolver-result selector"
        ):
            parse_external_operation_profile(payload)

    def test_callback_registration_requires_a_declared_callback_protocol(self) -> None:
        payload = profile()
        payload["environment_contracts"][2]["world_effects"][0][
            "callback_id"
        ] = "missing-callback"
        with self.assertRaisesRegex(ExternalOperationProfileError, "unknown callback"):
            parse_external_operation_profile(payload)

    def test_rejects_invalid_discriminator_and_guard_shapes(self) -> None:
        cases: list[tuple[dict[str, object], str]] = []
        no_cases = profile()
        no_cases["operations"][0]["output_rules"][0]["view"]["cases"] = []
        cases.append((no_cases, "at least one case"))
        duplicate_case = profile()
        duplicate_case["operations"][0]["output_rules"][0]["view"]["cases"][1]["value"] = 1
        cases.append((duplicate_case, "duplicate.*discriminator value"))
        bad_discriminator = profile()
        bad_discriminator["operations"][0]["output_rules"][0]["view"]["argument_index"] = 3
        cases.append((bad_discriminator, "discriminator argument is out of range"))
        bad_mask = profile()
        bad_mask["operations"][0]["output_rules"][0]["success_guard"]["value"] = 1
        cases.append((bad_mask, "value must fit"))
        preserved_guard = profile()
        preserved_guard["operations"][3]["output_rules"][0]["success_guard"]["register"] = "esi"
        cases.append((preserved_guard, "guard reads a preserved register"))

        for payload, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ExternalOperationProfileError, message):
                    parse_external_operation_profile(payload)

    def test_rejects_contract_shape_and_bounds_errors(self) -> None:
        cases: list[tuple[dict[str, object], str]] = []
        incomplete = profile()
        incomplete["environment_contracts"][0]["status"] = "draft"
        cases.append((incomplete, "unsupported status"))
        unknown_field = profile()
        unknown_field["environment_contracts"][0]["operation_id"] = "release"
        cases.append((unknown_field, "unknown operation_id"))
        bad_access = profile()
        bad_access["environment_contracts"][1]["memory_footprints"][0]["access"] = "execute"
        cases.append((bad_access, "unsupported access"))
        bad_size = profile()
        bad_size["environment_contracts"][1]["memory_footprints"][0]["size"]["maximum_bytes"] = 2
        cases.append((bad_size, "scale exceeds"))
        bad_effect = profile()
        bad_effect["environment_contracts"][2]["world_effects"][0]["kind"] = "anything"
        cases.append((bad_effect, "unsupported kind"))
        effect_out_of_range = profile()
        effect_out_of_range["environment_contracts"][2]["world_effects"][0]["argument_index"] = 1
        cases.append((effect_out_of_range, "world-effect argument is out of range"))

        for payload, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ExternalOperationProfileError, message):
                    parse_external_operation_profile(payload)

    def test_rejects_unused_and_argument_incompatible_contracts(self) -> None:
        unused = profile()
        unused["environment_contracts"].append(environment_contract("unused"))
        with self.assertRaisesRegex(ExternalOperationProfileError, "unused: unused"):
            parse_external_operation_profile(unused)

        base_out_of_range = profile()
        base_out_of_range["environment_contracts"][1]["memory_footprints"][0]["base_argument"] = 3
        with self.assertRaisesRegex(ExternalOperationProfileError, "base argument is out of range"):
            parse_external_operation_profile(base_out_of_range)

        size_out_of_range = profile()
        size_out_of_range["environment_contracts"][1]["memory_footprints"][0]["size"]["argument_index"] = 3
        with self.assertRaisesRegex(ExternalOperationProfileError, "size argument is out of range"):
            parse_external_operation_profile(size_out_of_range)

    def test_rejects_non_json_files_and_contract_format_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.json"
            path.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(ExternalOperationProfileError, "cannot read"):
                load_external_operation_profile(path)

        wrong = environment_contract("wrong")
        wrong["format"] = EXTERNAL_OPERATION_PROFILE_FORMAT
        with self.assertRaisesRegex(ExternalOperationProfileError, "unsupported format"):
            parse_external_operation_contract(wrong)

    def test_converts_v1_interface_profile_without_mutating_or_wiring_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "legacy.json"
            path.write_text(json.dumps(v1_profile()), encoding="utf-8")
            legacy = load_external_interface_profile(path)
            original_provenance = copy.deepcopy(dict(legacy.provenance))

            converted = convert_external_interface_profile(legacy)

        self.assertEqual(dict(legacy.provenance), original_provenance)
        self.assertEqual(converted.profile_id, legacy.profile_id)
        self.assertEqual(converted.model, legacy.model)
        self.assertEqual(
            converted.provenance["compatibility"]["source_format"],
            EXTERNAL_INTERFACE_PROFILE_FORMAT,
        )
        self.assertEqual(
            converted.provenance["compatibility"]["source_sha256"],
            legacy.sha256,
        )
        identity = MachineImportIdentity("legacy.dll", "symbol", "CreateRoot")
        factory = converted.operation_for_import(identity)
        self.assertIsNotNone(factory)
        assert factory is not None
        self.assertEqual(factory.argument_words, 2)
        self.assertIsInstance(factory.output_rules[0], OutArgumentOutput)
        factory_contract = converted.contracts_by_id()[
            factory.environment_contract_id
        ]
        self.assertEqual(factory_contract.status, "incomplete")
        self.assertEqual(
            factory_contract.blockers,
            (
                "legacy_interface_profile_has_no_complete_external_effect_contract",
            ),
        )
        self.assertEqual(factory_contract.memory_footprints[0].size.bytes, 4)

        method = converted.operation_for_table_slot("IRoot", 1)
        self.assertIsNotNone(method)
        assert method is not None
        self.assertEqual(method.argument_words, 2)
        self.assertEqual(method.receiver_resource.as_json(), {
            "argument_index": 0,
            "view_id": "IRoot",
            "required_state": "live",
            "dispatch_slot": 1,
            "lifecycle_effect": "preserve",
        })
        release = converted.operation_for_table_slot("IRoot", 0)
        self.assertIsNotNone(release)
        assert release is not None
        self.assertEqual(
            release.receiver_resource.lifecycle_effect,
            "may_release",
        )
        self.assertEqual(converted.views_by_id()["IRoot"].table, "IRootVtbl")
        self.assertEqual(converted.as_json()["format"], EXTERNAL_OPERATION_PROFILE_FORMAT)

    def test_conversion_requires_a_loaded_v1_profile(self) -> None:
        with self.assertRaisesRegex(TypeError, "ExternalInterfaceProfile"):
            convert_external_interface_profile(profile())


if __name__ == "__main__":
    unittest.main()
