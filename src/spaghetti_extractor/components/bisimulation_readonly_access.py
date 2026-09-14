"""Check opacity of view transport in compiler-produced source GOTO bodies.

This is a supplementary source-profile premise, not a frame or dependence
theorem. Run it on the separately compiled authored sources, before adding the
trusted view accessors or proof harness. Source-location strings are not used
to decide which bodies are trusted (C can change those strings with #line).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3


READONLY_ACCESS_POLICY = "typed-goto-opaque-view-transport-v1"
MUTABLE_ACCESS_POLICY = "typed-goto-opaque-mutable-view-transport-v1"
SHARED_ACCESS_POLICY = "typed-goto-opaque-shared-state-services-v1"
READONLY_HELPERS = frozenset({"spx_view_read_u8", "spx_ref_derive", "spx_ref_difference"})
_GENERATED_ENTRIES = frozenset({"__CPROVER__start", "__CPROVER_initialize"})
_VIEW_TAG = "tag-spx_view_v1"
_VIEW_FIELDS = frozenset({"base", "extent", "element_width"})
_STATEMENTS = {"ASSIGN": "assign", "DECL": "decl", "DEAD": "dead",
               "FUNCTION_CALL": "function_call", "SET_RETURN_VALUE": "return", "OTHER": "expression"}
_CONTROL = frozenset({"GOTO", "SKIP", "LOCATION", "END_FUNCTION"})


def _named(value: Mapping, key: str) -> Mapping:
    named = value.get("namedSub", {})
    result = named.get(key, {}) if isinstance(named, Mapping) else {}
    return result if isinstance(result, Mapping) else {}


def _identifier(value: Mapping, key: str) -> str:
    return str(_named(value, key).get("id", ""))


def _type(value: Mapping) -> Mapping:
    return _named(value, "type")


def _tag(value: Mapping) -> str:
    return _identifier(_type(value), "identifier")


def _children(value: Mapping) -> list[Mapping]:
    children = value.get("sub", [])
    if not isinstance(children, list) or any(not isinstance(row, Mapping) for row in children):
        raise ValueError("source GOTO expression operands are malformed")
    return children


def _normalized_type(value: Mapping) -> object:
    # Const qualification does not expose object representation. The GOTO
    # compiler has already resolved typedefs and checked the conversion.
    return {key: ({name: _normalized_type(item) if isinstance(item, Mapping) else item
                  for name, item in member.items()
                  if name not in {"C_constant", "C_volatile", "#source_location"}}
                 if key == "namedSub" and isinstance(member, Mapping)
                 else [_normalized_type(item) for item in member]
                 if isinstance(member, list) else member)
            for key, member in value.items()}


def _view_member(value: Mapping) -> tuple[str, Mapping] | None:
    children = _children(value)
    if value.get("id") == "member" and len(children) == 1 and _tag(children[0]) == _VIEW_TAG:
        return _identifier(value, "component_name"), children[0]
    return None


def check_readonly_source_access(
    functions: Sequence[Mapping[str, object]], *, operation_symbols: Sequence[str],
    context_tag: str,
) -> dict[str, object]:
    return check_memory_source_access(functions, operation_symbols=operation_symbols,
                                      context_tag=context_tag, mutable=False)


def check_memory_source_access(
    functions: Sequence[Mapping[str, object]], *, operation_symbols: Sequence[str],
    context_tag: str, mutable: bool = False, dependency_symbols: Sequence[str] = (),
    boundary_bundle=None,
) -> dict[str, object]:
    """Reject unmodeled transport observations in every authored helper body.

    Logical metadata and descriptor equality remain observable. Callback/context
    members may only occur together in an access on the same descriptor. Mutable
    mode additionally admits checked writes; its policy identity remains distinct.
    Supplying a canonical boundary bundle selects a separate shared-state/service
    opacity policy. It admits named logical view fields and typed service calls
    with their own opaque context, but proves no service semantics or write frame.
    Pointer reinterpretation, ordering, unions and addresses of view fields are
    outside this initial summary profile. The solver must still check all frame,
    readable-memory, source-definedness, dependence and progress obligations.
    """
    state_names, service_arities = set(), {}
    boundary_sha256 = None
    if boundary_bundle is not None:
        from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
        from .machine_overlay_services_v5 import _c_identifier

        bundle = compile_component_interface_v5(
            ComponentInterfaceIntentV1.parse(boundary_bundle.intent.to_payload()))
        expected_tag = f"tag-spx_{_c_identifier(bundle.interface.identity)}_context_v5"
        if (not mutable or context_tag != expected_tag or
                any(item.value.interpretation != "view" for item in bundle.interface.state)):
            raise ValueError("shared source opacity requires canonical view state and context")
        state_names = {_c_identifier(item.value.identity) for item in bundle.interface.state}
        service_arities = {_c_identifier(item.identity): 1 + len(
            bundle.intent.schema.signature_index[item.signature_id].parameters)
            for item in bundle.interface.services}
        boundary_sha256 = bundle.interface.interface_sha256
    if (not isinstance(functions, (list, tuple)) or not functions
            or any(not isinstance(row, Mapping) for row in functions)
            or not operation_symbols or len(set(operation_symbols)) != len(operation_symbols)):
        raise ValueError("source GOTO function inventory is malformed")
    names = [row.get("name") for row in functions]
    if any(not isinstance(name, str) or not name for name in names) or len(set(names)) != len(names):
        raise ValueError("source GOTO function identities are malformed")
    bodies = {str(row["name"]) for row in functions if row.get("isBodyAvailable") is True}
    dependencies = frozenset(dependency_symbols)
    if len(dependencies) != len(dependency_symbols) or dependencies & bodies:
        raise ValueError("source dependency symbols are duplicated or have authored bodies")
    if not set(operation_symbols) <= bodies:
        raise ValueError("source GOTO inventory omits an operation body")
    issues: list[dict[str, object]] = []
    checked: list[str] = []
    calls: set[tuple[str, str]] = set()
    locals_: set[str] = set()

    def member_base(value, name):
        children = _children(value)
        if (value.get("id") == "member" and len(children) == 1 and
                _identifier(value, "component_name") == name):
            return children[0]
        return None

    def component_pointer(value):
        children = _children(value)
        if value.get("id") == "dereference" and _tag(value) == context_tag and len(children) == 1:
            return children[0]
        return None

    def state_view_pointer(value):
        if (value.get("id") != "member" or _tag(value) != _VIEW_TAG or
                _identifier(value, "component_name") not in state_names):
            return None
        children = _children(value)
        state = member_base(children[0], "state") if len(children) == 1 else None
        return component_pointer(state) if state is not None else None

    def service_receiver(value, field):
        service = member_base(value, field)
        if service is None or service.get("id") != "dereference" or len(_children(service)) != 1:
            return None
        context = member_base(_children(service)[0], "services")
        return component_pointer(context) if context is not None else None

    def dependency_context(value):
        # Only the canonical context->services->context transport is opaque.
        # The generated dependency model separately checks the supplied token.
        def member(term, name):
            children = _children(term)
            if term.get("id") != "member" or _identifier(term, "component_name") != name or len(children) != 1:
                return None
            return children[0]
        services = member(value, "context")
        if services is None or services.get("id") != "dereference" or len(_children(services)) != 1:
            return False
        context = member(_children(services)[0], "services")
        if context is None or context.get("id") != "dereference" or _tag(context) != context_tag or len(_children(context)) != 1:
            return False
        scan(_children(context)[0])
        return True

    def scan(value: Mapping, *, allowed: frozenset[int] = frozenset()) -> None:
        if id(value) in allowed:
            return
        kind = value.get("id")
        if not isinstance(kind, str):
            raise ValueError("source GOTO expression has no kind")
        children = _children(value)
        typ = _type(value)
        state_pointer = state_view_pointer(value)
        if state_pointer is not None:
            # Only the selected logical field is visible. Whole-context copies,
            # service tables and transport fields remain opaque. A separate
            # frame theorem must decide whether mutations of this view are legal.
            scan(state_pointer)
            return
        if kind == "symbol" and _identifier(value, "identifier") not in locals_:
            raise ValueError("read-only summary observes nonlocal storage or a function representation")
        if typ.get("id") in {"union", "union_tag"}:
            raise ValueError("union representation is outside the read-only summary profile")
        if kind == "dereference" and _tag(value) == context_tag:
            raise ValueError("read-only summary observes private component context")
        member = _view_member(value)
        if member is not None and member[0] not in _VIEW_FIELDS:
            raise ValueError("read-only summary observes or changes view transport")
        if kind == "address_of" and children:
            def has_view_field(term: Mapping) -> bool:
                return _view_member(term) is not None or any(has_view_field(c) for c in _children(term))
            if has_view_field(children[0]):
                raise ValueError("read-only summary exposes the address of view metadata")
        if kind == "typecast" and len(children) == 1:
            source_type = _type(children[0])
            if "pointer" in {typ.get("id"), source_type.get("id")}:
                null = children[0].get("id") == "constant" and _identifier(children[0], "value") == "0"
                if not null and typ.get("id") != "empty" and _normalized_type(typ) != _normalized_type(source_type):
                    raise ValueError("pointer reinterpretation is outside the read-only summary profile")
        if kind in {"pointer_object", "pointer_offset", "pointer_diff", "object_size"} or (
            kind in {"lt", "le", "gt", "ge", "<", "<=", ">", ">=", "+", "-"}
            and any(_type(c).get("id") == "pointer" for c in children)
        ):
            raise ValueError("pointer representation is outside the read-only summary profile")
        for child in children:
            scan(child, allowed=allowed)

    for function in functions:
        name = str(function["name"])
        if not function.get("isBodyAvailable") or name in _GENERATED_ENTRIES:
            continue
        if name.startswith("__CPROVER_") or function.get("isInternal"):
            raise ValueError("source GOTO inventory contains an unexpected intrinsic body")
        instructions = function.get("instructions")
        if not isinstance(instructions, list) or not instructions:
            raise ValueError("source GOTO body instructions are missing")
        parameters = function.get("parameterIdentifiers")
        if not isinstance(parameters, list) or any(not isinstance(item, str) for item in parameters):
            raise ValueError("source GOTO parameter inventory is malformed")
        locals_ = set(parameters)
        for instruction in instructions:
            if isinstance(instruction, Mapping) and instruction.get("instructionId") == "DECL":
                declaration = instruction.get("code", {})
                if isinstance(declaration, Mapping):
                    operands = _children(declaration)
                    if len(operands) == 1 and operands[0].get("id") == "symbol":
                        locals_.add(_identifier(operands[0], "identifier"))
        checked.append(name)
        for instruction in instructions:
            if not isinstance(instruction, Mapping):
                raise ValueError("source GOTO instruction is malformed")
            try:
                instruction_id = instruction.get("instructionId")
                if instruction_id not in _STATEMENTS.keys() | _CONTROL:
                    raise ValueError("source GOTO instruction is outside the read-only summary profile")
                code = instruction.get("code", {"id": "nil"})
                if not isinstance(code, Mapping):
                    raise ValueError("source GOTO instruction code is malformed")
                if instruction_id in _STATEMENTS and _identifier(code, "statement") != _STATEMENTS[instruction_id]:
                    raise ValueError("source GOTO instruction statement is inconsistent")
                if instruction_id == "GOTO" and not isinstance(instruction.get("guard"), Mapping):
                    raise ValueError("source GOTO branch guard is missing")
                allowed: set[int] = set()
                if _identifier(code, "statement") == "function_call":
                    call = _children(code)
                    if len(call) != 3:
                        raise ValueError("source GOTO call is malformed")
                    target, arguments = call[1], _children(call[2])
                    if target.get("id") == "symbol":
                        callee = _identifier(target, "identifier")
                        if callee not in bodies | READONLY_HELPERS | dependencies | ({"spx_view_write_u8"} if mutable else set()) or callee in _GENERATED_ENTRIES:
                            raise ValueError("read-only summary calls an unmodeled function")
                        if callee in dependencies:
                            if not arguments or not dependency_context(arguments[0]):
                                raise ValueError("summary dependency does not use its component service context")
                            allowed.add(id(arguments[0]))
                        calls.add((name, callee))
                        allowed.add(id(target))
                    else:
                        operands = _children(target)
                        method = _view_member(operands[0]) if target.get("id") == "dereference" and len(operands) == 1 else None
                        service_field = _identifier(operands[0], "component_name") if len(operands) == 1 else ""
                        service_pointer = (service_receiver(operands[0], service_field)
                            if target.get("id") == "dereference" and len(operands) == 1
                            and service_field in service_arities else None)
                        if service_pointer is not None:
                            if (len(arguments) != service_arities[service_field] or
                                    service_receiver(arguments[0], "context") != service_pointer):
                                raise ValueError("service call does not use its own component context")
                            scan(service_pointer)
                            allowed.update((id(target), id(arguments[0])))
                            calls.add((name, "service:" + service_field))
                        else:
                            if method is None or method[0] not in ({"read_u8", "read", "write_u8", "write"} if mutable else {"read_u8", "read"}):
                                raise ValueError("read-only summary has an unmodeled indirect call")
                            field, receiver = method
                            expected_context = "context" if field in {"read_u8", "write_u8"} else "access_context"
                            context = _view_member(arguments[0]) if arguments else None
                            if (len(arguments) != (3 if field in {"read_u8", "write_u8"} else 5)
                                    or context is None or context != (expected_context, receiver)):
                                raise ValueError("view read does not use its own transport context")
                            if field in {"read", "write"} and _view_member(arguments[1]) != ("base", receiver):
                                raise ValueError("view span read does not use its own reference")
                            scan(receiver)
                            allowed.update((id(target), id(arguments[0])))
                scan(code, allowed=frozenset(allowed))
                guard = instruction.get("guard")
                if guard is not None:
                    if not isinstance(guard, Mapping):
                        raise ValueError("source GOTO guard is malformed")
                    scan(guard)
            except ValueError as error:
                issues.append({"function": name, "location": instruction.get("locationNumber"),
                               "code": "shared_source_transport_not_opaque" if boundary_sha256 is not None
                               else "readonly_summary_transport_not_opaque", "detail": str(error)})
    core = {"status": "incomplete" if issues else "satisfied", "authorizing": False,
            "policy": MUTABLE_ACCESS_POLICY if mutable else READONLY_ACCESS_POLICY, "operation_symbols": sorted(operation_symbols),
            "context_tag": context_tag, "functions": sorted(checked), "issues": issues,
            "call_edges": [list(edge) for edge in sorted(calls)],
            "inventory_sha256": canonical_sha256_v3(functions)}
    if dependencies:
        core.update(policy="typed-goto-opaque-memory-dependencies-v2", dependency_symbols=sorted(dependencies))
    if boundary_sha256 is not None:
        core.update(policy=SHARED_ACCESS_POLICY, interface_sha256=boundary_sha256,
                    state_views=sorted(state_names), service_arities=service_arities)
    return {**core, "receipt_sha256": canonical_sha256_v3(core)}
