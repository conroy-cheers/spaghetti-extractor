# Semantic-module target baseline (2026-09-02)

This is a non-authorizing comparison snapshot taken after the V2 semantic-module
migrations and the final repository refresh. The content-bound module,
provider, realization, deployment, and observation receipts remain authority
for their own claims. In particular, a passing migration gate does not turn an
incomplete jq module or draft component into a completed candidate.

## Exact linked modules

| Module | Status | Definitions / requirements | Obligations | Frontiers | Holes | Linked-module identity | Transfer-plan identity |
|---|---:|---:|---:|---:|---:|---|---|
| GNU Hello | complete | 8,019 / 8,019 | 109 | 0 | 0 | `a38b8b44ce1bc7fd551a76e811a37328cebeb7413b27dcce11e7995e3e0ba93c` | `8d9d51f62a8d73266b12475d42802224fe6f765e1b9dde5f893b62dd931500fa` |
| jq.exe | incomplete | 4,804 / 4,810 | 89 | 0 | 21 | `44344d08fea0efffa82e5e1a02dcfc6089d1d0aaeca1fd41a2fe951cafc8b2c6` | `581e0111157c58d05ce5c371e8098ebdcc2714c496a8c0aecc03f1109a4dfa76` |
| libjq-1.dll | incomplete | 36,170 / 36,304 | 412 | 0 | 603 | `a81f6c04615225a4bda5d57c627ec3f222e269c0d489110c9881797236fd9f58` | `9496f521628857ec2b69f2b82bb39ec5ece3227d9ef913e5c5c051f948ea05d7` |
| DXBall.exe | complete | 9,269 / 9,269 | 261 | 0 | 0 | `734263ff43f2995372b208b7d94fb14a5146cdcb82ac28fb2461053d2350c5d1` | `42666c993fc088fd738771eedad3576a0f59f3078a5d2123f92a54ba885d105a` |

Hello retains 12,249 active relocations and DX-Ball retains 12,287. The jq
root retains 7,026 active relocations and libjq retains 51,809. Every module
has zero analysis frontiers; the remaining jq incompleteness is represented by
stable semantic holes and residual obligations rather than by pruning the
conservative universe.

## Honest incomplete surfaces

The jq root's 21 holes are nine unresolved checked import-code contracts,
three missing linked import protocols, six may-reachable symbols without a
provider, and three incomplete resolved-environment facts. Libjq's 603 holes
are eight unresolved base-relocation targets, 164 unresolved checked
import-code contracts, 52 missing or ambiguous export call protocols, 65
missing import protocols, eight unresolved may-reachable relocations, 134
may-reachable symbols without providers, 103 incomplete qualified-platform
selections, and 69 incomplete resolved-environment facts.

The exact jq operator view therefore remains incomplete and non-authorizing:
it reports 135 selection/module blockers with view identity
`d10c3a7af9130191e058afe2ed067e49bb62f2df5547c019e48da721e1da1584`.
The complete jq target gate pins the two target-owned modules, their project
edges, and these blockers; it does not claim a deployable jq candidate.

The selected DX-Ball `startup-extended` view is complete with zero blockers
and realization-ready generated-C/runtime ownership. Its non-authorizing view
identity is
`b27229a3a2f46d524093f33b46f70a26c6c719a3be9182d451a0bb21f6ed6adf`.
The draft portable `directdraw-init` overlay remains separately unselected on
the stable `checked_faithful_continuation_portal_state` ownership blocker and
its outcome/internal-effect relations.

The selected Hello `string-pointer-enabled` operator view intentionally stays
incomplete on one unrelated experimental portable-provider qualification,
while its linked module is complete and the faithful plus three required
replacement deployments are independently checked by the target gate.

## Verification and performance

The final exact commands passed:

```sh
nix flake check -L
nix flake check ./targets -L
nix run .#dev -- refresh --check
git diff --check
```

The isolated GNU Hello semantic link remains below the eight-second budget at
approximately 3.7 seconds with peak RSS around 891 MiB. A reversible jq
comment-only invalidation probe completed in 0.83 seconds and executed one
checked-boundary builder; it reused original extraction, ISA qualification,
machine IR, transfer plans, semantic objects, linked modules, Behavioral C,
and runtime artifacts.

## Reproduction

```sh
nix build --no-link --print-out-paths \
  './targets#legacyPackages.x86_64-linux.targets.gnu-hello.diagnostics.candidate-status' \
  './targets#legacyPackages.x86_64-linux.targets.jq.diagnostics.candidate-status' \
  './targets#legacyPackages.x86_64-linux.targets.dxball.diagnostics.candidate-status'
nix build --no-link --print-out-paths \
  './targets#legacyPackages.x86_64-linux.targets.gnu-hello.candidate.linked-semantic-module' \
  './targets#legacyPackages.x86_64-linux.targets.jq.candidate.project.linked-semantic-modules.jq' \
  './targets#legacyPackages.x86_64-linux.targets.jq.candidate.project.linked-semantic-modules.libjq' \
  './targets#legacyPackages.x86_64-linux.targets.dxball.candidate.linked-semantic-module'
```
