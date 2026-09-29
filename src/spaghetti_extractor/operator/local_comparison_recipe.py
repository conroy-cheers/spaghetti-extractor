"""Editable boundary and local-fixture recipes over existing component APIs."""
from __future__ import annotations

from pathlib import Path


def write_boundary_revision_recipe(root: Path, *, target: str, component: str, plan: dict) -> Path:
    """Expose the existing revision transaction without replacing operator edits."""
    relative = Path('revise-boundary.py') if component == plan['component_id'] else Path('dependencies') / component / 'revise-boundary.py'
    recipe = root / relative
    if recipe.exists():
        return relative
    workspace = 'parent' if component == plan['component_id'] else 'parents[2]'
    recipe.write_text(f'''"""Revise {component}'s boundary while retaining current C and comparison setup.

Fill in boundary_changes(unit), then run:
    python revise-boundary.py --output /path/to/revised-comparison
Changed incoming contracts require explicit --review-requirement CONSUMER/REQUIREMENT.
Review records do not establish compatibility or tested behavior.
"""
import argparse
from pathlib import Path
import shlex

from spaghetti_extractor.components.comparison_package import load_comparison_package, revise_comparison_package

WORKSPACE = Path(__file__).resolve().{workspace}
COMPONENT = {component!r}


def boundary_changes(unit):
    # unit is this component's current declaration, not a copy of its callers.
    # Return only reviewed changes; omitted C, adapters and declarations stay put.
    # Example: return dict(assumptions=[*unit["assumptions"], "Your reviewed premise."])
    # An edited interface copy can use:
    #   import json
    #   from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
    #   interface = ComponentInterfaceIntentV1.parse(json.loads(Path("/path/to/proposal.json").read_text()))
    #   return dict(interface=interface)
    # Existing operation resource declarations rebind when their input/result
    # declarations and reachable types stay unchanged. Changed values/types need
    # explicitly reviewed resource_checks; prior comparison evidence never carries.
    # Source/adapter/header mappings and other existing revision API fields are
    # also available. Keep named caller reviews in --review-requirement below.
    # To supply an existing service with a newly lifted component:
    #   from spaghetti_extractor.components.comparison_composition import bind_dependencies
    #   added = bind_dependencies(services={{"service_name": Path("/path/to/supplier")}})
    #   return dict(dependencies=added["dependencies"],
    #               requirements=[*unit.get("requirements", []), *added["requirements"]])
    # Include reviewed service_bridge and C adapter changes that route the call.
    # A separately defined adapter can request declare=True in its binding:
    # the generator emits its extern prototype using the selected C transport.
    # This avoids a handwritten prototype; semantic conversions still need C.
    return {{}}


def revise(output, reviewed_requirements=None):
    plan, _ = load_comparison_package(WORKSPACE)
    unit = plan if COMPONENT == plan["component_id"] else next(
        row for row in plan["dependencies"] if row["id"] == COMPONENT)
    changes = boundary_changes(unit)
    if not isinstance(changes, dict) or not changes:
        raise ValueError("fill boundary_changes(unit) with the reviewed declaration changes")
    if "reviewed_requirements" in changes:
        raise ValueError("name caller reviews with --review-requirement")
    revise_comparison_package(package=WORKSPACE, component_id=COMPONENT, output=output,
        reviewed_requirements=reviewed_requirements, **changes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--review-requirement", action="append", metavar="CONSUMER/REQUIREMENT",
                        help="record a reviewed caller premise; repeat for each affected requirement")
    args = parser.parse_args()
    try:
        revise(args.output, args.review_requirement)
    except (OSError, ValueError) as exc:
        parser.error("edit " + str(Path(__file__).resolve()) + ": " + str(exc))
    print("Prepared boundary revision: " + str(args.output.resolve()))
    print("Next: " + shlex.join(["spaghetti-extractor", "component", "start", {target!r}, COMPONENT,
        "--comparison-package", str(args.output.resolve()), "--output", "/path/to/revised-work"]))
    print("Check affected consumers before integration. Preparation supplies no behavior or compatibility evidence.")


if __name__ == "__main__":
    main()
''', encoding='utf-8')
    return relative


def write_local_comparison_recipe(root: Path, *, target: str, component: str, plan: dict) -> Path | None:
    """Keep operator edits; this helper supplies neither a fixture nor evidence."""
    if component == plan['component_id']:
        return None
    relative = Path('dependencies') / component / 'prepare-local.py'
    recipe = root / relative
    if recipe.exists():
        return relative
    recipe.write_text(f'''"""Define a local comparison for {component} from this selected workspace.

Fill in local_fixture(), then run:
    python prepare-local.py --output /path/to/local-comparison
Preparation copies current inputs; it does not execute either implementation.
"""
import argparse
from pathlib import Path
import shlex

from spaghetti_extractor.components.comparison_environment import retained_component_inputs, observation_headers
from spaghetti_extractor.components.comparison_package import prepare_comparison_package, retained_comparison_environment

# Moving the complete workspace keeps these paths valid.
WORKSPACE = Path(__file__).resolve().parents[2]
COMPONENT = {component!r}


def local_fixture():
    # The component's C, interface, shared headers, services, assumptions and
    # declared supplier closure come from this workspace. Do not copy them here.
    # Choose an original entry/driver, state transport and meaningful observations.
    return dict(
        adapter_files={{}},       # e.g. {{"driver.c": WORKSPACE / "local-driver.c"}}
        include_files={{}},       # e.g. observation_headers() for portable JSON output; existing headers are retained
        original_files=[],      # materialized original paths, e.g. ["runtime/original.dll"]
        oracle_kind={plan['original']['kind']!r},  # review for the chosen local oracle
        cases=[],               # e.g. [dict(id="empty", arguments=[""])]
        observation_fields=[],  # JSON fields emitted by the driver on both sides
        scope="",               # local admission, environment and observation limits
        # export_adapters=["adapters/bridge.c"],  # when the entry needs an exported bridge
    )


def prepare(output):
    fixture = local_fixture()
    environment = retained_comparison_environment(WORKSPACE)
    with retained_component_inputs(WORKSPACE, component_id=COMPONENT, retain_dependencies=True) as inputs:
        headers = fixture.pop("include_files", {{}})
        overlap = inputs["include_files"].keys() & headers.keys()
        if overlap:
            raise ValueError("local adapter headers replace retained shared headers: " + ", ".join(sorted(overlap)))
        inputs["include_files"].update(headers)
        prepare_comparison_package(**inputs, **environment, **fixture, output=output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        prepare(args.output)
    except (OSError, ValueError) as exc:
        parser.error("edit " + str(Path(__file__).resolve()) + ": " + str(exc))
    print("Prepared local comparison: " + str(args.output.resolve()))
    print("Next: " + shlex.join(["spaghetti-extractor", "component", "start", {target!r}, COMPONENT,
        "--comparison-package", str(args.output.resolve()), "--output", "/path/to/local-work"]))
    print("Run subsequent Wine comparisons inside spaghetti-headless-wayland.")


if __name__ == "__main__":
    main()
''', encoding='utf-8')
    return relative
