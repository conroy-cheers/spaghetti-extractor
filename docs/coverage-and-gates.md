# Coverage And Gates

Dynamic coverage is stored by test ID, observed module, module SHA256 when
resolvable, private RVA block/edge records, and report-facing stable labels.
Standard DynamoRIO `drcov` provides useful bootstrap basic-block coverage only.
The required coverage collector must trace dynamic basic blocks, CFG edges, and
call edges for 32-bit Halo CE processes under Wine.

Objective gates:

- `catalog-complete`: no unknown executable bytes, no unclassified functions, no unlabeled functions/blocks/edges, and no unresolved dynamic module names.
- `coverage-complete`: all included functions, basic blocks, CFG edges, and call edges are dynamically covered or explicitly waived.
- `interface-complete`: every static or dynamically observed platform endpoint has mocks plus success, failure, and error-path tests.
- `data-state-complete`: map/profile/save/packet/config structures and state machines have fixtures, malformed-input tests, transition tests, and round-trip tests where applicable.
- `oracle-complete`: original binaries pass the black-box process suite and private original-code harness suite.
- `mutation-effective`: representative wrong implementations fail the detailed tests.
- `reproducible`: reports include binary hashes, catalog version, tracer version, test IDs, tool versions, Nix/dev-shell provenance, and the exact `nix-haloce` input revision used for private reference/resource material.

Waived blocks remain visible. They are never counted as dynamically covered.
