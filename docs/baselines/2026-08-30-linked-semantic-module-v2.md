# Linked semantic module V2 baseline (2026-08-30)

This checkpoint records the first real GNU Hello vertical through the
non-authorizing `linked-semantic-module-v2` codec. It is evidence for milestone
1 of the authoritative unified plan, not a completion claim for later provider,
realization, deployment, or observation milestones.

## Inputs and output

- V1 migration input:
  `/nix/store/3bvl1p229wxgz2dzc87p2wb3269hdnmm-spaghetti-extractor-gnu-hello-linked-semantic-module-v1/linked-semantic-module.json`
- Nix-built V2 package:
  `/nix/store/3gq6k6c7f03ifrzma17vxbjgq9g1wam5-spaghetti-extractor-gnu-hello-linked-semantic-module-v2`
- V2 identity:
  `59f59622b60d5bde5341815ffa8ff687f02fc816a84918f4a39589dccd6f9346`
- Semantic status: `complete`
- Execution authority: `false`
- V1 fixed-point analysis status retained as diagnostic provenance:
  `incomplete`

## Exact inventory

| Inventory | Count |
| --- | ---: |
| semantic definitions | 8,106 |
| conservative may-realization symbols | 8,106 |
| may-realization relocations | 12,337 |
| transfer-v2 direct control edges bound by hash | 10,404 |
| loader and execution roots | 92 |
| active objects | 7 |
| admitted dispatch/callback domains | 6 |
| semantic holes | 0 |
| residual obligations | 117 |
| non-authorizing analysis frontiers | 63 |

The 63 original fixed-point rows remain visible as 33 external-write
provenance frontiers, 18 code-target provenance frontiers, and 12 callee-summary
binding frontiers. They no longer masquerade as unknown machine semantics.

The residual-obligation inventory contains 83 checked indirect-call sites, 12
guest-only indirect control outcomes, 14 callback-capability publication
sites, six deduplicated external-write validation contracts, and two
deduplicated runtime object/reference binding contracts. The dynamic-dispatch
inventory is larger than the original 18 blockers because the conservative
dispatch domain activates transfers that V1 must-reach analysis never visited.
This widening is intentional and prevents an unsound 4,498-unit implementation
selection.

Indirect calls now use one content-addressed callable union containing all
7,937 guest transfer-entry capabilities and all 75 loader-written IAT targets.
Each external member binds its checked contract and `PhysicalCallFrameV3` by
hash. Runtime selection compares the target word against actual active guest
capability addresses and actual loader-written IAT values; no match or an
ambiguous match is rejected. Indirect control outcomes retain the narrower
guest-entry-only domain. This closes the earlier unsound assumption that every
register-propagated indirect call must target guest code; 13 V1 precision rows
already demonstrated external callthroughs such as `_errno`.

The callback inventory is likewise derived from every may-active transfer,
not copied from V1 target-provenance results. It contains one
`SetUnhandledExceptionFilter`, two `atexit`, two `__setusermatherr`, and nine
`signal` sites over four protocol-specific finite domains. Each site has one
content-addressed effect and one `qualified_runtime` obligation. The codec
checks the relation in both directions. The 95 indirect-dispatch effects have
the same total one-to-one relation with their obligations. Partial V1 callback
capability rows are deliberately absent.

The external-effect catalog is also total over the admitted callable domain:
75 checked callable declarations plus 75 loader-owned IAT cells. Two callable
and two loader-cell rows are checked loader-service declarations; the other
146 rows are ordinary machine-import declarations. Four imports without a
statically named call site (`__p___argv`, `TlsGetValue`, `isspace`, and
`GetProcAddress`) are nevertheless active through the callable-domain hash and
have exact external-environment provider requirements. Keeping the semantic
callable and loader-cell roles distinct prevents a code contract from erasing
the actual IAT datum and its loader-owned identity.

This closes a concrete soundness gap caught by the runtime-domain projection:
the domain admitted all 75 loader-written targets while the earlier semantic
object declared only the 71 seen at static call sites. Semantic-object
construction now declares the entire checked environment catalog once, and
V2 activates exactly each guest and external domain member. Missing or
duplicated domain members fail construction rather than becoming a runtime
trap, analysis frontier, or second external-target model.

The exact transfer-v2 IAT projection is now rebound to V2 may provenance. It
contains 71 code-use effects covering all 321 active external-call relocation
sites; every site binds its active source symbol plus root and admitted-domain
provenance. Removing even one direct code-use site makes the self-contained
codec reject the module. Hello currently has no imported-data use; ambiguous
or inexact data-pointer uses become semantic holes when present.

No effect group is copied from the V1 must-analysis package. V2 construction
now first reduces the transitional checked V1 package to a closed internal
`SemanticLinkFactsV2` carrier containing only bindings, roots, symbols,
relocations, objects, blockers, fixed-point provenance, and analysis policy.
The carrier cannot contain `effects`, a unit test asserts that exact field set,
and the retired-architecture gate rejects any V2 source access to a V1 effect
projection. The five active
runtime primitives each bind their exact qualified-platform provider rule and
definition. All three checked divide-fault transitions are present (V1's
must-reach projection contained one). The lifecycle inventory contains all 41
may-active calls through the five checked `no_return` contracts: three
`_amsg_exit`, 15 `_assert`, two `_exit`, 14 `abort`, and seven `exit` sites.
Each site is cross-checked against the active external-call relocation and its
checked frame. Hello has no exports or nonlocal terminators; code exports use
the existing deterministic EAT/frame projection, while an active nonlocal
terminator remains a semantic hole until a V2 checked outcome protocol binds
it.

## Size and timing observations

- V1 JSON size: 26,550,978 bytes.
- V2 JSON size: 24,243,057 bytes (about 8.7 percent smaller). The increase
  from the first draft is intentional: definitions now bind content hashes
  for dependency contracts instead of worklist-position indexes, and all 95
  dynamic-dispatch plus 14 callback-publication effects now carry their exact
  site contracts. Semantic slices remain reusable across analysis scheduling
  changes.
- Initial transitional construction with duplicate package parsing: 16.254 s.
- Construction after retaining the validated semantic member and removing
  duplicate post-write parsing: 6.345 s on the same host (about 2.6 times
  faster).

RAM was not constrained. The admitted 7,937-entry transfer domain is stored
once and referenced by hash from each dispatch obligation; repeating it in
every obligation was rejected because it increased hashing and serialization
work without adding information.

The 10,404 direct-control rows likewise remain in the canonical transfer-plan
member and are bound once by hash instead of being copied into the V2 manifest.

## Milestone 2 runtime-domain checkpoint

The module-runtime V4 plan now stores each content-addressed admitted guest
domain once and gives each dispatch site only its `domain_sha256`. Generated C
emits one target array per domain and reuses its offset and count at every
site. The former site-expanded runtime-plan representation is retired and an
architecture gate rejects its policy literal.

The direct V2 runtime projection has also been exercised against the packaged
real-Hello module. Its 95 indirect sites reference exactly two runtime-relevant
domains: one callable union used by 83 call sites and one guest-only domain
used by 12 indirect outcomes. Both contain the same 7,937 guest transfer-entry
RVAs, so the runtime plan stores 15,874 target entries rather than expanding
754,015 site-target pairs. This is a 47.5-fold reduction at the dispatch-plan
and generated-table boundary while preserving the exact V2 domain identities.

The callable domain also contains 75 loader-written IAT members. They remain
in the same canonical domain, and every member now has an active checked
semantic definition and external-environment requirement. The next clean cut
must make external callthrough select a unique member by the actual
loader-written target word.

The direct runtime projection now enforces that join rather than merely
carrying the rows through. For every callable-domain member it requires one
active `external_function` symbol, one checked external effect, one matching
physical-frame identity, the callable domain in both provenance lists, and
exactly one `external_environment` provider requirement. The real-Hello gate
projects all 75 external members through the same shared domain and rejects a
fixture with even one disconnected effect. This is still runtime-plan input;
the native external bridge renderer remains the next implementation step.
It must not create a second external-target analysis or choose one import using
the V1 must-provenance result. Callback publication and ingress still consume
the temporary in-memory execution vocabulary, but the vocabulary is now
derived from the validated V2 module and carries the direct V2 domain/effect
payload for runtime lowering. It is not serialized or scheduled.

## Native-ingress V2 reuse checkpoint

Native ingress now accepts a packaged `linked-semantic-module-v2`, sources the
transfer plan, module interface, object authority, and resolved environment
only through its validated semantic-object member, and binds the V2 module
identity directly. It does not manufacture a
`module_execution_closure_sha256` when V2 has no such artifact. The shared
runtime passes its already decoded V2 module into ingress lowering, so the
24-MiB module and its semantic package are decoded only once per realization
process.

The first generous real-Hello V2 ingress run exposed an accidental Cartesian
failure path: 14 callback-publication effects times 7,937 admitted targets
produced 111,121 repeated blockers, an 83-MiB ingress plan, and 58.593 seconds
of wall time. Callback protocol, physical-frame, and lifecycle qualification
are target-independent. They are now checked once per publication effect and
a failed effect is rejected before target materialization.

On the same module and host, the direct V2 ingress now emits 14 causal
blockers, a 32-KiB plan, and completes in 11.201 seconds. Passing the decoded
module onward to the shared-runtime writer preserves the same 14 blockers and
also completes in 11.200 seconds rather than 17.816 seconds. RAM remains
unconstrained; the improvement removes repeated semantic work rather than
trading latency for compactness.

The blockers are honest and actionable:

- 13 publication effects lack checked callback frames for the
  `msvcrt-atexit-handler`, `msvcrt-signal-handler`, and
  `msvcrt-user-math-error-handler` protocols; and
- the checked `win32-unhandled-exception-filter` lifecycle projects
  `borrow.exception-info` onto a boundary value that is not typed as a
  resource.

No callback bridge is emitted for a failed domain. Once those boundary
contracts close, successful domains still need compact domain-based callback
capability materialization; expanding one descriptor per site-target pair is
not the accepted final design.

## Checks run

- Repository-provisioned linked-semantic-module unit gate: 42 tests passed.
- Repository-provisioned semantic-slice, V2 qualification, total-selection,
  and retained V1 provider gate: 25 tests passed.
- Real GNU Hello V2 Nix derivation: built and independently loaded with
  `require_complete=True`.
- Real GNU Hello V2 runtime-domain projection gate: passed with two shared
  domains, 95 sites, 15,874 stored guest targets, and 754,015 equivalent
  expanded site-target pairs.
- The generated-C qualification was rebound to the corrected module at
  `/nix/store/5a314dqvl6c37p9m6h7g919x4bfr19xw-spaghetti-extractor-gnu-hello-semantic-v2-generated-c-provider-v2`.
  It still contains exactly 7,937 definition materializations and 294 unique
  objects; its complete object-hash set is byte-identical to the preceding
  qualification. The four newly active external definitions therefore do not
  invalidate or duplicate faithful generated-C objects.
- The external-environment qualification at
  `/nix/store/y355in28llpxs9agwa6v8k0hmihm4w4y-spaghetti-extractor-gnu-hello-semantic-v2-external-environment-provider-v2`
  contains exactly 150 explicit definition choices.
- Real Hello generated-C and external-environment V2 provider checks passed
  against the current module.
- Full jq and DX-Ball target aggregates passed after the semantic-object
  catalog clean cut; neither target gained invented execution or component
  authority, and their existing blocker meaning is preserved.
- Format registry, generated repository metadata, production Python lint,
  build-infrastructure, and retired-architecture checks: passed.

## Remaining clean-cut work

The V2 Nix producer currently consumes the checked V1 package in memory as an
explicit migration seam. V1 remains the public input for provider selection,
runtime planning, and native realization. Milestone 1 is not complete until:

1. the common semantic-link worklist emits the V2 manifest directly;
2. diagnostics and all semantic-status consumers use the split V2 domains;
3. V2 provider qualification and total selection replace the V1 reducers; and
4. every in-tree V1 consumer is migrated before V1 is retired.

## 2026-08-31 faithful native continuation

The first real GNU Hello faithful realization now closes beyond this baseline:

- `native-realization-v2` is complete and ready for observation with no
  blockers;
- the 62,194,688-byte candidate has SHA-256
  `0bb922eb039f0c72700b80254f879ee00a4da08b07aac1dc55ce48b068a6af78`;
- its exact receipt distinguishes the dynamic
  `msvcrt.dll!___lc_codepage_func` export from ordinary IAT imports and binds
  loader-service contract
  `3f7629809d32db3d4dc3f22610b47a44ff012065ce0079983cdf7e2da6a82a54`;
- the candidate-only headless-Wine receipt passes with exit zero, empty stderr,
  and the original PE's exact `Hello, world!\r\n` stdout bytes; and
- the full GNU Hello target aggregate passes after independent replay learned
  to reconstruct dynamic code exports admitted through loader-service catalogs.

The canonical runtime independently fixes returning external tail transfers
and uses one qualified per-thread private-stack reserve with nested downward
growth. These are generic transfer/runtime semantics, not Hello-specific
adapters. Milestone 2 remains open for the complete synthetic PE32 fixture
matrix and the later deployment-observation gates named by the authoritative
plan.
