# Documentation Index

The primary project direction is
[high-assurance-reimplementation-direction.md](high-assurance-reimplementation-direction.md).
It defines how formal checking, independent ISA qualification, executable IR,
candidate-only validation, and progressive source reconstruction combine to
minimize realistic reimplementation mistakes. A mandatory end-to-end Lean
theorem is no longer the primary completion condition.

The implemented GNU Hello validation of that direction, including exact
coverage counts, assumptions, candidate-only runtime policy, regional mutation
feedback, and remaining scalability risk, is documented in
[gnu-hello-high-assurance-vertical-slice.md](gnu-hello-high-assurance-vertical-slice.md).

The operator-defined hierarchy, exact machine-boundary derivation, logical
interface proposal model, and residual coverage ledger are documented in
[semantic-component-framework.md](semantic-component-framework.md).

The strict formal Stage A profile remains documented in
[stage-a-architecture.md](stage-a-architecture.md). It defines the authority
and trust boundary for commands that specifically claim formal `pass`; the
meaning of that verdict is not weakened by the high-assurance direction.

Supporting documents:

- [stage-a-relational-v3.md](stage-a-relational-v3.md): implemented v3 proof
  profile, generated graph, and current measured blockers.
- [stage-a-source-equivalence-experiment.md](stage-a-source-equivalence-experiment.md): optional source-relative whole-program theorem experiment and its wider compiler-stack premise.
- [stage-a-internal-equivalence-and-3d-roadmap.md](stage-a-internal-equivalence-and-3d-roadmap.md): forward work from jq to a
  representative 3D application and game under the former mandatory-theorem
  objective; retained as formal-track design history.
