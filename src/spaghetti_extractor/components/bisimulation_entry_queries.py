"""Independent entry qualification using the existing partitioned CBMC engine.

These checks remain conditional on the selected runtime contracts. A complete
entry is not a component theorem, caller admission or activation authorization.
Every ordinary region still executes against its original compiled model.
"""

import hashlib
import json
from pathlib import Path

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_diagnostics import ProofQueryTimings
from .bisimulation_evidence import _sha256, _validate_partitioned_property_evidence
from .bisimulation_query_evidence import CbmcQueryEvidence
from .bisimulation_support import BisimulationRefinementError


POLICY = "independent-source-entry-queries-v1"
FRONTIER = "spx-source-entry:escaped-cut"


def _status(properties, witness):
    statuses = {properties.get("status"), witness.get("status")}
    return "violated" if "violated" in statuses else "satisfied" if statuses == {"satisfied"} else "incomplete"


def run_entry_queries(task, entry, *, timeout_seconds):
    """Check the separate model only after its actual prefix relation matches."""
    from .bisimulation_execution import _run_partitioned_properties, _run_cover_queries

    prefix = entry.get("prefix_correspondence", {})
    if entry.get("status") != "compiled" or prefix.get("status") != "matched":
        return entry
    if task.get("assurance") is None:
        raise BisimulationRefinementError("independent entry queries require conditional assurance")
    model = Path(task["goto_model"]).parent / "source-entry" / "model.goto"
    digest = hashlib.sha256(model.read_bytes()).hexdigest()
    if digest != entry["goto_model_sha256"] or digest != prefix["entry_goto_model_sha256"]:
        raise BisimulationRefinementError("independent entry query model changed after correspondence")
    root = prefix["entry_function"]
    required = prefix["required_assertion_descriptions"]
    previous = (task.get("previous_query_evidence") or {}).get("source_entry")
    cache = CbmcQueryEvidence(model=model, checker=task["cbmc"], compiler=task["compile_command"][0],
        output=model.parent / "query-evidence", previous=previous, smt_solver=task.get("smt_solver"),
        assurance=task["assurance"])
    timings = ProofQueryTimings(model, {"operation_id": task["operation_id"],
        "obligation_id": task["obligation_id"], "proof_function": root,
        "model_scope": "independent_source_entry", "query_timeout_seconds": timeout_seconds}, query_evidence=cache)
    cover_queries = []
    for query in task["cover_queries"]:
        command = query["command"]
        if (command[:2] != [str(task["cbmc"]), str(task["goto_model"])] or command.count("--function") != 1
                or command[command.index("--function") + 1] != root):
            raise BisimulationRefinementError("independent entry cover root or model differs")
        cover_queries.append({**query, "command": [command[0], str(model), *command[2:]]})
    cover_recipe = {"backend": "cbmc", "goto_model_role": "shared_property_and_relation",
        "strategy": "per_goal_formula_sliced_v1" if len(task["witness_functions"]) <= 2 else "aggregate_formula_sliced_v1",
        "queries": [{"functions": query["expected_functions"], "arguments": query["command"][2:]}
                    for query in cover_queries]}
    properties = _run_partitioned_properties(cbmc=task["cbmc"], goto_model=model,
        command=task["property_checker_command"], proof_function=root,
        required_assertion_descriptions=required, timeout_seconds=timeout_seconds, timings=timings,
        uniform_entry=True, required_assertion_sites=prefix["assertion_sites"])
    witness = _run_cover_queries(cover_queries, timeout_seconds=timeout_seconds, timings=timings)
    checked = {"policy": POLICY, "authorizing": False, "assurance": task["assurance"],
        "goto_model_sha256": digest, "entry_function": root,
        "preparation_binding_sha256": entry["preparation"]["binding_sha256"],
        "prefix_relation_sha256": prefix["relation_sha256"],
        "property_checker_command": task["property_checker_command"], "nonvacuity_checker_command": cover_recipe,
        "required_assertion_descriptions": required,
        "checker": {"cbmc_sha256": cache.tools["checker_sha256"], "goto_cc_sha256": cache.tools["compiler_sha256"]},
        "status": _status(properties, witness), "property_result": properties, "nonvacuity": witness,
        "executed_queries": cache.executed, "reused_queries": cache.reused}
    checked["receipt_sha256"] = canonical_sha256_v3(checked)
    (model.parent / "entry-check.json").write_text(json.dumps(checked, indent=2) + "\n")
    complete = checked["status"] == "satisfied"
    return {**entry, "entry_check": checked, "source_conformance_checked": complete,
            "entry_obligations_checked": complete}


def validate_entry_check(checked, *, entry, model, assurance, checker):
    """Require the same complete partition reader as ordinary regional proofs."""
    fields = {"policy", "authorizing", "assurance", "goto_model_sha256", "entry_function",
              "preparation_binding_sha256", "prefix_relation_sha256", "property_checker_command",
              "nonvacuity_checker_command", "required_assertion_descriptions", "checker", "status",
              "property_result", "nonvacuity", "executed_queries", "reused_queries", "receipt_sha256"}
    prefix = entry.get("prefix_correspondence", {})
    if (not isinstance(checked, dict) or set(checked) != fields or checked["policy"] != POLICY
            or checked["authorizing"] is not False or checked["assurance"] != assurance
            or prefix.get("status") != "matched"
            or checked["goto_model_sha256"] != entry["goto_model_sha256"]
            or checked["entry_function"] != prefix["entry_function"]
            or checked["preparation_binding_sha256"] != entry["preparation"]["binding_sha256"]
            or checked["prefix_relation_sha256"] != prefix["relation_sha256"]
            or checked["property_checker_command"] != model["property_checker_command"]
            or checked["nonvacuity_checker_command"] != model["nonvacuity_checker_command"]
            or checked["required_assertion_descriptions"] != prefix.get("required_assertion_descriptions")
            or FRONTIER not in checked["required_assertion_descriptions"]
            or checked["checker"] != {key: checker.get(key) for key in ("cbmc_sha256", "goto_cc_sha256")}
            or any(type(checked[field]) is not int or checked[field] < 0 for field in ("executed_queries", "reused_queries"))
            or checked["receipt_sha256"] != canonical_sha256_v3({key: value for key, value in checked.items()
                                                                if key != "receipt_sha256"})):
        raise ValueError("independent entry query binding or authority differs")
    properties, witness = checked["property_result"], checked["nonvacuity"]
    if (not isinstance(properties, dict) or not isinstance(witness, dict)
            or any(value.get("status") not in {"satisfied", "violated", "incomplete"} for value in (properties, witness))
            or checked["status"] != _status(properties, witness)):
        raise ValueError("independent entry query aggregate differs")
    _sha256(properties.get("output_sha256"), "independent entry properties")
    _sha256(witness.get("output_sha256"), "independent entry coverage")
    _validate_partitioned_property_evidence(shard=properties, model={
        "property_checker_command": checked["property_checker_command"],
        "proof_function": checked["entry_function"], "required_assertion_descriptions": checked["required_assertion_descriptions"],
        "required_assertion_descriptions_sha256": canonical_sha256_v3(checked["required_assertion_descriptions"]),
        "required_assertion_sites": prefix["assertion_sites"]}, uniform_entry=True)
    recipes = checked["nonvacuity_checker_command"]["queries"]
    queries = witness.get("queries")
    expected = sorted({function for row in recipes for function in row["functions"]})
    if (not isinstance(queries, list) or len(queries) != len(recipes)
            or canonical_sha256_v3(queries) != witness["output_sha256"]
            or witness.get("expected_functions") != expected):
        raise ValueError("independent entry cover inventory differs")
    for query, recipe in zip(queries, recipes):
        if (not isinstance(query, dict) or set(query) not in (
                {"functions", "status", "code", "output_sha256"},
                {"functions", "status", "code", "output_sha256", "detail"})
                or query.get("functions") != recipe["functions"]
                or query.get("status") not in {"satisfied", "violated", "incomplete"}):
            raise ValueError("independent entry cover query differs")
        _sha256(query.get("output_sha256"), "independent entry cover query")
    if witness["status"] == "satisfied" and (
            witness.get("code") != "cbmc_nonvacuity_witness" or witness.get("witnessed_functions") != expected
            or not witness.get("property_ids") or any(row["status"] != "satisfied" for row in queries)):
        raise ValueError("independent entry lacks complete nonvacuity evidence")
    if properties["status"] == "satisfied":
        ids = [row["property_id"] for row in properties["partitioned_evidence"]["assertions"]]
        if (properties.get("code") != "cbmc_properties_satisfied" or properties.get("property_ids") != ids
                or properties.get("properties") != len(ids)):
            raise ValueError("independent entry omitted required assertions")


def entry_query_summary(checked):
    """Keep public feedback compact; full inventories stay in the engine packet."""
    return {**{key: checked[key] for key in ("policy", "status", "entry_function", "executed_queries",
                                           "reused_queries", "receipt_sha256")},
            "property_status": checked["property_result"]["status"],
            "nonvacuity_status": checked["nonvacuity"]["status"]}
