"""Recheck retained local readable-contract evidence; never grant authority."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import tempfile
from pathlib import Path
from collections.abc import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..transfer.runtime_abi import exact_runtime_header
from .bisimulation_readonly_access import check_memory_source_access
from .bisimulation_readonly_model import (
    READONLY_CONTRACT_POLICY, READONLY_MODEL_POLICY, fixed_readonly_summary_operations,
    readonly_checker_options, render_readonly_source_model,
    MUTABLE_CONTRACT_POLICY, MUTABLE_MODEL_POLICY, fixed_mutable_summary_operations, render_mutable_source_model,
    mutable_checker_options,
)
from .bisimulation_summary_contracts import _cyclic_calls
from .cbmc_backend import _output_sha256, _parse_json, _property_statuses
from .component_c_v5 import render_component_c_headers_v5
from .inductive_refinement import _write_cbmc_stdint
from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from .machine_overlay_services_v5 import _c_identifier
from .source import load_component_source_package, component_operation_symbols, _safe_manifest_path, _canonical_sha256
from .formats import COMPONENT_SOURCE_PACKAGE_V3_FORMAT
from .source_profile import check_component_source_profile
from . import bisimulation_source_dependencies as source_dependencies


def validate_readonly_source_contracts(value: Mapping[str, object], *, artifacts: Path | None = None) -> None:
    _validate_memory_source_contracts(value, artifacts=artifacts, mutable=False)


def validate_mutable_source_contracts(value: Mapping[str, object], *, artifacts: Path | None = None) -> None:
    """Validate local mutable evidence; readonly supplier readers stay strict."""
    _validate_memory_source_contracts(value, artifacts=artifacts, mutable=True)


def validate_shared_source_contracts(value, *, artifacts=None):
    """Validate auxiliary shared-source evidence without admitting substitution."""
    _validate_memory_source_contracts(value, artifacts=artifacts, mutable=True, shared=True)


def _validate_memory_source_contracts(value: Mapping[str, object], *, artifacts: Path | None, mutable: bool, ancestors=(), shared=False) -> None:
    """Require exact retained inputs and outputs, not just a self-consistent hash.

    Without an artifact tree, validate the certificate's complete claims and
    reconstruct its generated model meaning. With a tree, additionally recheck
    the actual source/profile, tools, compiler/solver outputs and GOTO bytes.
    Production supplier binding must use the latter. Neither mode establishes
    the supplier's exact/source proof or the consumer's entry transport.
    """
    shape = fixed_mutable_summary_operations if mutable else fixed_readonly_summary_operations
    renderer = render_mutable_source_model if mutable else render_readonly_source_model
    from .bisimulation_shared_model import (
        SHARED_CONTRACT_POLICY, SHARED_MODEL_POLICY, shared_source_shape, render_shared_source_model,
        SHARED_DEPENDENCY_POLICY, SHARED_DEPENDENCY_MODEL,
    )
    if shared:
        shape = shared_source_shape
        renderer = lambda **args: render_shared_source_model(**args, shared_contract=value["shared_contract"])
    fields = {"status", "authorizing", "policy", "model_policy", "checker_options",
              "interface_sha256", "interface_intent", "authored_goto_sha256", "source_package",
              "source_profile", "operation_symbols", "source_dependencies", "headers_sha256",
              "support_headers", "tools", "checks", "models", "inventories", "commands", "receipt_sha256"}
    composed = isinstance(value, Mapping) and value.get("policy") in {
        source_dependencies.MUTABLE_POLICY, source_dependencies.READONLY_POLICY, SHARED_DEPENDENCY_POLICY}
    if shared:
        fields.add("shared_contract")
    if composed:
        fields.add("summary_dependencies")

    def require(condition, detail):
        if not condition:
            raise ValueError(("mutable" if mutable else "read-only") + " contract evidence: " + detail)

    require(isinstance(value, Mapping) and set(value) == fields, "fields differ")
    require(value["receipt_sha256"] == canonical_sha256_v3(
        {k: v for k, v in value.items() if k != "receipt_sha256"}), "receipt digest is stale")
    require(value["status"] == "satisfied" and value["authorizing"] is False
            and value["policy"] == ((SHARED_DEPENDENCY_POLICY if composed else SHARED_CONTRACT_POLICY) if shared else (source_dependencies.MUTABLE_POLICY if mutable else source_dependencies.READONLY_POLICY) if composed else
                                    (MUTABLE_CONTRACT_POLICY if mutable else READONLY_CONTRACT_POLICY))
            and value["model_policy"] == ((SHARED_DEPENDENCY_MODEL if composed else SHARED_MODEL_POLICY) if shared else (source_dependencies.MUTABLE_MODEL if mutable else source_dependencies.READONLY_MODEL) if composed else
                                          (MUTABLE_MODEL_POLICY if mutable else READONLY_MODEL_POLICY)),
            "local proof policy is unsupported or incomplete")
    options = value["checker_options"]
    require(isinstance(options, list) and len(options) == (15 if mutable else 13) and isinstance(options[8], str)
            and options[8].isdigit(), "checker options are malformed")
    option_builder = mutable_checker_options if mutable else readonly_checker_options
    require(options == option_builder(int(options[8])), "checker options are weakened")
    bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(value["interface_intent"]))
    operations = shape(bundle)
    require(operations is not None and value["interface_sha256"] == bundle.interface.interface_sha256,
            "interface or readable domain is stale")
    root = artifacts.resolve() if artifacts is not None else None
    summary_rows = value["summary_dependencies"] if composed else []
    if composed:
        source_dependencies.validate_dependencies(summary_rows, component_id=bundle.interface.identity,
                                                  artifacts=root, ancestors=ancestors)

    def is_digest(item):
        return isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) is not None

    def content(name):
        path = root / name
        require(path.is_file() and path.resolve().is_relative_to(root), "missing or escaped artifact " + name)
        return path.read_bytes()

    def bound_file(name, digest):
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                and (root is None or hashlib.sha256(content(name)).hexdigest() == digest), "stale artifact " + name)

    source = value["source_package"]
    require(isinstance(source, Mapping) and set(source) == {"format", "lift_unit_id", "files", "shared_inputs",
            "operation_symbols", "implementation_sha256"} and source["format"] == COMPONENT_SOURCE_PACKAGE_V3_FORMAT
            and source["implementation_sha256"] == _canonical_sha256({
                k: v for k, v in source.items() if k != "implementation_sha256"}), "source package binding is stale")
    listed = set()
    for field, role in (("files", "source"), ("shared_inputs", "shared_input")):
        require(isinstance(source[field], list), "source inventory is malformed")
        for row in source[field]:
            require(isinstance(row, Mapping) and set(row) == {"path", "role", "sha256", "size"}, "source row fields differ")
            name = _safe_manifest_path(row["path"]).as_posix()
            require(name == row["path"] and name not in listed and row["role"] == role and is_digest(row["sha256"])
                    and isinstance(row["size"], int) and not isinstance(row["size"], bool) and row["size"] >= 0,
                    "source row is malformed or duplicated")
            listed.add(name)
    profile_core = {"status": "satisfied", "profile_id": "portable-component-c11-cbmc-v1",
        "component_id": source["lift_unit_id"], "bindings": {"implementation_sha256": source["implementation_sha256"]},
        "issues": [], "policy": {"compiler_semantics_assumed_correct": True, "raw_machine_addresses_forbidden": True,
            "undeclared_mutable_globals_forbidden": True, "operator_behavior_examples_used": False}}
    require(value["source_profile"] == {**profile_core, "receipt_sha256": canonical_sha256_v3(profile_core)},
            "source profile claims are stale")
    with tempfile.TemporaryDirectory(prefix="spx-readonly-evidence-") as directory:
        check_root = Path(directory)
        if root is not None:
            (check_root / "sources").symlink_to(root / "inputs", target_is_directory=True)
            (check_root / "source-package.json").write_text(json.dumps(source))
            source = load_component_source_package(check_root)
            require(check_component_source_profile(package=check_root) == value["source_profile"], "source profile is stale")
        stdint = check_root / "stdint.h"
        _write_cbmc_stdint(stdint)
        support = {"stdint.h": stdint.read_text(),
                   "stddef.h": "typedef unsigned int size_t;\ntypedef int ptrdiff_t;\n#define NULL ((void *)0)\n",
                   "state-machine-runtime.h": exact_runtime_header()}
    symbols = component_operation_symbols(source)
    require(value["operation_symbols"] == symbols and set(symbols) == set(operations)
            and source["lift_unit_id"] == bundle.interface.identity, "source operation bindings differ")
    headers = source_dependencies.dependency_headers(render_component_c_headers_v5(bundle, symbols), summary_rows)
    require(value["headers_sha256"] == canonical_sha256_v3(headers), "generated headers are stale")
    support.update(headers)
    require(value["support_headers"] == {name: hashlib.sha256(text.encode()).hexdigest()
                                         for name, text in support.items()}, "support header meaning changed")
    allowed_inputs = {"include/" + name: digest for name, digest in value["support_headers"].items()}
    for row in [*source["files"], *source["shared_inputs"]]:
        name = row["path"]
        require(name.endswith((".c", ".h")), "unsupported source input")
        if row in source["shared_inputs"]:
            require(name in headers and row["sha256"] == hashlib.sha256(headers[name].encode()).hexdigest(),
                    "unmodeled shared input")
        else:
            require(Path(name).name not in support, "authored source shadows a support header")
        allowed_inputs["inputs/" + name] = row["sha256"]
    for name, digest in allowed_inputs.items():
        bound_file(name, digest)
    bound_file("authored.goto", value["authored_goto_sha256"])
    authored = ["inputs/" + row["path"] for row in source["files"] if row["path"].endswith(".c")]
    require(bool(authored), "no authored C bodies")

    def unique_rows(rows, key):
        require(isinstance(rows, list) and all(isinstance(r, Mapping) and key in r for r in rows),
                key + " inventory is malformed")
        indexed = {row[key]: row for row in rows}
        require(len(indexed) == len(rows), "duplicate " + key)
        return indexed

    commands = unique_rows(value["commands"], "step")
    inventories = unique_rows(value["inventories"], "step")
    consumed_commands, consumed_inventories = set(), set()
    tool_digests = {}
    require(isinstance(value["tools"], Mapping) and set(value["tools"]) == {"goto_cc", "goto_instrument", "cbmc"}
            and all(is_digest(item) for item in value["tools"].values()),
            "tool inventory differs")

    def command(step, tool, arguments, *, solver=False):
        require(step in commands, "missing command " + step)
        row = commands[step]
        require(set(row) == ({"step", "command", "cwd", "output_sha256"} if solver else
                             {"step", "command", "cwd", "exit_code", "output_sha256"}), "command fields differ")
        cmd = row["command"]
        require(isinstance(cmd, list) and len(cmd) == len(arguments) + 1 and cmd[1:] == arguments
                and isinstance(cmd[0], str) and row["cwd"] == "$MODEL_ROOT"
                and (solver or row["exit_code"] == 0), "weakened command " + step)
        require(is_digest(row["output_sha256"]), "command output digest is malformed")
        consumed_commands.add(step)
        if root is None:
            return None, row["output_sha256"]
        executable = Path(cmd[0])
        require(executable.is_file(), "tool is missing for " + step)
        if executable not in tool_digests:
            tool_digests[executable] = hashlib.sha256(executable.read_bytes()).hexdigest()
        require(tool_digests[executable] == value["tools"][tool], "tool bytes differ for " + step)
        stdout, stderr = content(step + ".stdout"), content(step + ".stderr")
        output_hash = _output_sha256(stdout, stderr) if solver else hashlib.sha256(stdout + stderr).hexdigest()
        require(output_hash == row["output_sha256"], "command output is stale for " + step)
        consumed_commands.add(step)
        return stdout.decode(), row["output_sha256"]

    def inventory(name, kind):
        step = name + "-" + kind
        stdout, _ = command(step, "goto_instrument", ["--show-goto-functions" if kind == "functions" else "--show-loops",
                                                      "--json-ui", name + ".goto"])
        require(step in inventories and isinstance(inventories[step].get("rows"), list), "missing compiler inventory " + step)
        rows = ([inventories[step]["rows"]] if stdout is None else
                [row[kind] for row in json.loads(stdout) if kind in row])
        require(len(rows) == 1 and isinstance(rows[0], list), "compiler inventory is malformed")
        require(step in inventories and inventories[step] == {
            "step": step, "kind": kind, "sha256": canonical_sha256_v3(rows[0]), "rows": rows[0]},
            "compiler inventory is stale for " + step)
        consumed_inventories.add(step)
        return rows[0]

    prefix = ["--i386-win32", "-nostdinc", "-I", "include", "-I", "inputs"]
    dependencies = unique_rows(value["source_dependencies"], "source")
    require(set(dependencies) == set(authored), "include dependency coverage differs")
    for index, name in enumerate(authored):
        stdout, _ = command(f"authored-{index:04d}-dependencies", "goto_cc",
                             [*prefix, "-M", "-MT", "spx_readonly_dependencies", name])
        if stdout is None:
            inputs = dependencies[name].get("inputs")
            require(isinstance(inputs, list) and all(isinstance(row, Mapping) and isinstance(row.get("path"), str)
                    for row in inputs), "include dependency inventory is malformed")
            names = [row["path"] for row in inputs]
            require(names == sorted(set(names)), "include dependency paths are not canonical")
        else:
            declaration = stdout.replace("\\\n", " ").strip()
            marker = "spx_readonly_dependencies:"
            require(declaration.startswith(marker), "include dependency output is malformed")
            paths = {(root / path).resolve() for path in shlex.split(declaration[len(marker):])}
            require(paths and all(path.is_relative_to(root) for path in paths), "include escaped the bound model")
            names = sorted(str(path.relative_to(root)) for path in paths)
        require(name in names and set(names) <= set(allowed_inputs), "unbound compiler include")
        require(dependencies[name] == {"source": name, "inputs": [
            {"path": path, "sha256": allowed_inputs[path]} for path in names]}, "include dependency bytes are stale")
    command("authored-compile", "goto_cc", [*prefix, *authored, "--function", symbols[operations[0]], "-o", "authored.goto"])
    functions = inventory("authored", "functions")
    inventory("authored", "loops")
    opacity = check_memory_source_access(functions, operation_symbols=list(symbols.values()),
        context_tag=f"tag-spx_{_c_identifier(bundle.interface.identity)}_context_v5", mutable=mutable,
        dependency_symbols=[row['symbol'] for row in summary_rows],
        boundary_bundle=bundle if shared else None)
    require(opacity["status"] == "satisfied" and not _cyclic_calls([tuple(edge) for edge in opacity["call_edges"]]),
            "source access or progress premise fails")
    require(isinstance(value["checks"], list) and value["checks"][:1] == [{"kind": "source_opacity", **opacity}],
            "checked source opacity is stale")
    expected_checks = [{"kind": "source_opacity", **opacity}]
    expected_models = []
    require(isinstance(value["models"], list) and len(value["models"]) == 2 * len(operations)
            and len(value["checks"]) == 1 + 2 * len(operations), "model or result coverage differs")
    for operation in operations:
        for kind in ("frame", "input_dependence"):
            name = _c_identifier(operation) + "-" + kind
            generated, entry = renderer(bundle=bundle, operation_id=operation,
                symbol=symbols[operation], kind=kind, summary_dependencies=summary_rows)
            model = value["models"][len(expected_models)]
            require(isinstance(model, Mapping) and all(is_digest(model.get(field)) for field in
                    ("source_sha256", "raw_goto_sha256", "checked_goto_sha256")), "model digests are malformed")
            require(kind == "frame" or model["raw_goto_sha256"] == model["checked_goto_sha256"],
                    "uninstrumented model has conflicting GOTO bindings")
            require(root is None or content(name + ".c") == generated.encode(), "generated model meaning changed for " + name)
            command(name + "-compile", "goto_cc", [*prefix, name + ".c", *authored, "--function", entry, "-o", name + ".goto"])
            inventory(name, "functions")
            inventory(name, "loops")
            checked = name + ".goto"
            if kind == "frame":
                checked = name + "-checked.goto"
                command(name + "-instrument", "goto_instrument",
                        ["--dfcc", entry, "--enforce-contract", symbols[operation], name + ".goto", checked])
            stdout, output_hash = command(name + "-check", "cbmc", [checked, "--function", entry, *options], solver=True)
            if stdout is None:
                check = value["checks"][len(expected_checks)]
                require(isinstance(check, Mapping) and isinstance(check.get("property_ids"), list)
                        and all(isinstance(item, str) and item for item in check["property_ids"])
                        and check["property_ids"] == sorted(set(check["property_ids"])), "property inventory is malformed")
                statuses = {item: "SUCCESS" for item in check["property_ids"]}
            else:
                payload = _parse_json(stdout)
                statuses = _property_statuses(payload) if payload is not None else {}
            require(statuses and set(statuses.values()) == {"SUCCESS"}, "solver output does not establish the contract")
            require(entry + ".assertion.1" in statuses, "required relational assertion is absent")
            if mutable and kind == "input_dependence":
                require(entry + ".assertion.2" in statuses, "required post-memory assertion is absent")
            if shared:
                aliases = (2,) if kind == "frame" else (3, 4)
                require(all(entry + f".assertion.{index}" in statuses for index in aliases),
                        "required authored result-alias assertion is absent")
                from .normal_exit_postconditions import shared_result_postcondition
                requested = next(row for row in value['shared_contract']['relation_intent']['operations']
                                 if row['operation_id'] == operation)['requirements'][0]['expression']
                if shared_result_postcondition(requested, bundle=bundle, operation_id=operation)[2]:
                    zeros = (3,) if kind == 'frame' else (5, 6)
                    require(all(entry + f'.assertion.{index}' in statuses for index in zeros),
                            'required authored current-zero assertion is absent')
            expected_checks.append({"operation_id": operation, "kind": kind, "status": "satisfied",
                "code": "cbmc_properties_satisfied", "properties": len(statuses),
                "property_ids": sorted(statuses), "output_sha256": output_hash})
            expected_models.append({"operation_id": operation, "kind": kind, "entry": entry,
                "source_sha256": hashlib.sha256(generated.encode()).hexdigest(),
                "raw_goto_sha256": model["raw_goto_sha256"] if root is None else hashlib.sha256(content(name + ".goto")).hexdigest(),
                "checked_goto_sha256": model["checked_goto_sha256"] if root is None else hashlib.sha256(content(checked)).hexdigest()})
    require(value["checks"] == expected_checks and value["models"] == expected_models,
            "model or result binding is stale")
    require(consumed_commands == set(commands) and consumed_inventories == set(inventories),
            "unconsumed command or inventory evidence")


def checked_readonly_summary_certificate(**kwargs):
    return _checked_memory_summary_certificate(**kwargs, mutable=False)


def checked_mutable_summary_certificate(**kwargs):
    return _checked_memory_summary_certificate(**kwargs, mutable=True)


def _checked_memory_summary_certificate(
    *, bound: Mapping[str, object], bundle, source: Mapping[str, object],
    source_profile_sha256: str, operation_symbols: Mapping[str, str],
    headers: Mapping[str, str], artifacts: Path, mutable: bool, shared: bool = False,
) -> Mapping[str, object]:
    """Bind local evidence to a supplier already qualified by the enclosing gate.

    The retained-byte check is mandatory here. Certificate-only validation in a
    receipt reader does not replace the producer's compiler/solver evidence.
    """
    certificate = bound.get("certificate")
    if not isinstance(certificate, Mapping):
        raise ValueError("connected read-only source certificate is missing")
    validator = (validate_shared_source_contracts if shared else
                 validate_mutable_source_contracts if mutable else validate_readonly_source_contracts)
    validator(certificate, artifacts=artifacts)
    if (bound.get("implementation_sha256") != source.get("implementation_sha256")
            or bound.get("source_profile_sha256") != source_profile_sha256
            or certificate["interface_intent"] != bundle.intent.to_payload()
            or certificate["interface_sha256"] != bundle.interface.interface_sha256
            or certificate["source_package"] != source
            or certificate["source_profile"]["receipt_sha256"] != source_profile_sha256
            or certificate["operation_symbols"] != dict(operation_symbols)
            or certificate["headers_sha256"] != canonical_sha256_v3(source_dependencies.dependency_headers(
                dict(headers), certificate.get('summary_dependencies', [])))):
        raise ValueError("connected read-only source certificate binding is stale")
    return certificate


def checked_connected_source_contract(*, bound, bundle, source, source_profile_sha256,
                                      operation_symbols, headers, readonly_artifacts=None, qualified_models=None):
    """Check supplier evidence; readable contracts still select checked replay."""
    from .bisimulation_summary_contracts import checked_scalar_summary_certificate

    if bound is not None and not isinstance(bound, Mapping):
        raise ValueError("connected source summary is malformed")
    arguments = dict(bound=bound, bundle=bundle, source=source,
                     source_profile_sha256=source_profile_sha256,
                     operation_symbols=operation_symbols, headers=headers)
    certificate = None if bound is None else bound.get("certificate")
    if isinstance(certificate, Mapping) and certificate.get("policy") == "fixed-shared-view-service-source-dependencies-v1":
        raise ValueError("composed shared source evidence requires transitive machine qualification, which is not implemented")
    if isinstance(certificate, Mapping) and certificate.get("policy") == "fixed-shared-view-service-source-contract-v1":
        if not isinstance(readonly_artifacts, (str, Path)) or qualified_models is None:
            raise ValueError("shared source contracts require checked supplier models and retained source evidence")
        if qualified_models.get('source_summary_contracts') != bound:
            raise ValueError('shared source contract differs from its paired supplier')
        _checked_memory_summary_certificate(**arguments, artifacts=Path(readonly_artifacts), mutable=True, shared=True)
        # Source evidence alone selects no strategy. Shared entry, alias and
        # machine frames are checked by the entry-contract and parent-world rule.
        return None
    if isinstance(certificate, Mapping) and certificate.get("policy") in source_dependencies.MEMORY_POLICIES:
        source_dependencies.validate_qualified_dependencies(certificate,
            connected=None if qualified_models is None else qualified_models.get('connected_components'),
            component_id=certificate['interface_intent']['id'])
        if not isinstance(readonly_artifacts, (str, Path)):
            raise ValueError("connected read-only source contract lacks retained models")
        checker = (checked_mutable_summary_certificate if certificate["policy"] in source_dependencies.MUTABLE_POLICIES
                   else checked_readonly_summary_certificate)
        checker(**arguments, artifacts=Path(readonly_artifacts))
        # Source purity does not establish the qualified original's entry or
        # private-memory frame at this caller. Keep replay until both are checked.
        return None
    return checked_scalar_summary_certificate(**arguments)
