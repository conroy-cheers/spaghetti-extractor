# Native ingress and deployable PE32 modules

Native execution authority is expressed by
`spaghetti-extractor-native-ingress-plan-v1`. The plan is derived from an
exact `pe32-module-interface-v2`, behavioral roots, complete checked call
protocols and `PhysicalCallFrameV3` values, lifecycle receipts,
`machine-object-authority-v2`, and checked outcome protocols. It is not an
operator-authored list of jump stubs.

Each ingress has one of five roles: process entry, DLL entry, TLS callback,
export, or callback. The role selects loader lifecycle and failure policy. The
physical frame selects bridge mechanics. Roles for the same logical target with
physically equivalent frames share a stable bridge; unrelated targets retain
distinct addresses. A logical code target reached under incompatible
physical frames is a blocker, preserving native function-pointer equality
instead of manufacturing unequal addresses for the same target.

`machine-object-authority-v2` realizes objects through image RVAs, TLS offsets,
captured stacks, resolved data-import slots, external allocations, or resources.
Every non-executable image section receives a default image-lifetime object;
checked refinements may partition the complete section. EAT data aliases that
refer to the same RVA share one address anchor. Resolution accepts an explicit
authority selector, so overlapping host addresses never fall back to first-match
behavior.

Boundary outcomes are independent of ingress roles.
`checked-boundary-outcome-protocol-v1` admits normal, no-return, exceptional,
and explicitly modelled nonlocal outcomes. `checked-seh-protocol-v1` binds an
exceptional transition, projections, unwind effects, exact handler/resumption
unit RVAs, escape policy, and source-RVA-to-candidate-portal mappings. Observing the
numeric original `ExceptionAddress` or `Eip` blocks completion unless pinned
original-layout authority is supplied.

Linking produces `native-ingress-link-receipt-v1`, which binds every bridge,
SEH registration gateway, and exception recovery portal to an executable
section, and every loader-realized support datum to a non-executable mapped
section, of the linked module at a unique RVA. The composer patches the support
datum to the selected TLS index-cell VA and emits its HIGHLOW relocation.
SafeSEH admits gateway
handlers, never recovery portals. `pe32-loader-surface-receipt-v1` then checks
the decoded candidate entry,
EAT, data anchors, forwarders, combined TLS, imports, delay imports, bound-import
clearing, SafeSEH, and CFG surfaces. Anchor-era compositions are rejected. A
module closes through
`pe32-module-deployment-v1`, binding the original interface, behavioral-C
completion, exact runtime qualification, ingress plan and link receipt,
composition, static assurance, candidate hash, and decoded candidate loader
surface receipt. Project completion v2 accepts these deployments and requires the same
candidate hashes in the candidate-observed load graph.

An ingress plan also carries exact native-runtime feature and private-stack
requirements. The generated backend now emits the exact combined-PE-TLS ABI,
per-thread ingress frame/state arrays, bounded 64 KiB private-stack slices,
table-driven physical-state ingress bridges, capability publication with host
atomics, atomic one-shot admission, replacement publication, checked
resource-event expiration, and x86
exception-registration gateways. The semantic runtime context
is selected from the current loader TLS slot, so independent host threads do not
share its entry lock and same-thread reentry pushes another ingress frame.

A behavioral runtime qualification must bind the same ingress
plan and explicitly qualify PE TLS thread state, host-thread concurrency,
same-thread reentrancy, transactional writeback, loader-lock-safe bootstrap,
the code-capability registry, and (when selected) the SEH gateway. The outgoing
call and typed-x87 frame chains are selected from the same composed PE TLS state;
the generic package no longer emits the singleton process-entry or callback
stack bridges. The SEH gateway performs portal matching, checked handler and
resumption dispatch, RaiseException escape, selective CONTEXT materialization,
continuable host-context recapture, exact guest access-violation parameters,
and unwind-time frame invalidation.

The module interface records complete EAT geometry, lexical name-table order,
holes and aliases, code/data/forwarder classification, TLS template/index and
callback state, stack sizing, imports and delay imports, section permissions, DLL
characteristics, all data directories, and typed SafeSEH/CFG plus later
pointer-bearing load-config fields. Nonempty pointer-bearing directories without
a realization codec are stable blockers.
