# Composable Component Lifting

The component framework is the supported unit of Stage B work. It separates
the exact structural program from operator choices about how much code to lift
at once.

## Two Different Graphs

The machine-IR graph is canonical and target-independent. It contains every
statically discovered executable unit and its machine effects. Component
boundaries never alter this graph.

The authored component catalog is a work graph. A leaf selects one exact
discovery proposal. A group is the union of leaves or other groups. Different
groups may overlap because they are alternative ways to organize work. A
selected configuration may not overlap: every selected machine unit has one
owner.

This permits an operator to lift one block-sized component, a procedure, or a
large subsystem without first understanding the rest of the target. Unselected
and unqualified units continue to use the complete machine-IR fallback.

## Contract Pipeline

For every leaf and group, the Nix graph independently produces:

1. exact unit membership bound to the machine IR and reconstruction plan;
2. a machine boundary derived from the union of those units;
3. a conservative machine-shaped logical interface;
4. an optional operator-reviewed interface;
5. a checker result proving every machine effect is represented exactly once.

Edges and calls between members of a group are internal and disappear from the
group boundary. Entries, exits, memory effects, external calls, and faults that
cross the group boundary remain explicit. A review may rename or coarsen the
logical interface, but omitting or duplicating a machine effect makes the
contract `incomplete` or `violated`.

Contract derivations are independent. Changing one review rebuilds that
contract and configurations that consume it, not machine extraction or other
component contracts.

## Qualification Profiles

`structural-draft-v1` is for discovery and scaffolding. It never authorizes a
portable replacement.

`bounded-equivalence-v1` accepts generated exhaustive or CBMC evidence for the
declared finite domain. It does not claim equivalence outside that domain.

`validation-backed-v1` accepts candidate-only functional evidence. It records
that assurance is limited to the tested scope. The original binary must not be
executed to produce this evidence.

Every evidence artifact binds the exact contract and implementation hashes.
Qualification and ownership are separate checks: qualified overlapping
components still cannot be activated together.

The implementation hash is derived from a component source-package artifact,
not copied from the evidence report. Source packages preserve relative paths,
classify source and shared inputs, and hash every byte. Editing any source or
header therefore invalidates qualification before a portable replacement can
remain active.

## Configuration Safety

The activation plan covers every structural machine unit exactly once:

- an enabled, checked, qualified component selects a portable replacement;
- a draft or unqualified component retains machine-IR fallback;
- every unselected unit retains machine-IR fallback.

An enabled component with missing evidence produces a localized `incomplete`
issue while retaining complete fallback ownership. The component artifact does
not claim that the fallback is executable or release-ready: those properties
are established later by the fallback-coverage and candidate-authority gates.
Portable implementations never silently fall back after activation, because
that would give one unit two runtime meanings.

## Nix Interface

Targets consume `flake.lib.mkTargetSdkV2`. The component DAG is available as
`sdk.lifting.componentContractsV2` and exposes:

- `resolution` for exact leaves, groups, and configurations;
- `contracts.<id>` for independently cached boundary contracts;
- `sourcePackages.<id>` for exact content-bound portable inputs;
- `qualifications.<id>` for supplied evidence;
- `activationPlans.<configuration>` for total implementation ownership;
- `sourceBundles.<configuration>` for the sources of active replacements.

Target bundles contain only declarative intent and target source. Adding a new
target does not require new toolkit code. Generic machinery should be extended
only when a target exposes a reusable missing capability, with a small generic
fixture added before relying on it for that target.
