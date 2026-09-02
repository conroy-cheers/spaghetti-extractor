# Native ingress and deployable PE32 modules

Native execution authority is expressed by
`spaghetti-extractor-native-ingress-plan-v2`. The plan is derived from an
exact `pe32-module-interface-v2`, behavioral roots, complete checked call
protocols and `PhysicalCallFrameV3` values, lifecycle receipts,
`machine-object-authority-v2`, the exact executable transfer plan, and the
bound `linked-semantic-module-v2`. It is not an operator-authored list of jump
stubs or outcome records. The V2 module supplies conservative domains and
typed runtime obligations directly; ingress does not require or reconstruct a
separate whole-program must-provenance closure.

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

Machine transfer kind, callee outcome, and boundary outcome are independent.
A transfer whose canonical terminator is `outcome_external` is a tail transfer
even when the selected checked external callee returns. Its argument base skips
the continuation already on the captured guest stack. Conversely, an ordinary
call to a no-return callee remains a call. Boundary outcomes are independent of
bridge mechanics. The ingress derivation
projects them from closure-authorized terminal and exceptional behavior for
each causal root; public Nix and CLI interfaces do not accept separately
authored outcome or SEH protocols. Canonical transfer operation metadata plus
the resolved external environment own feasibility, native exception identity,
handler, and terminal dispositions; the semantic object projects them once and
the semantic linker closes their rooted provenance. The resulting
`checked-boundary-outcome-protocol-v1` admits normal, no-return, exceptional,
and explicitly modelled nonlocal outcomes. `checked-seh-protocol-v1` binds an
exceptional transition, projections, unwind effects, exact handler/resumption
unit RVAs, escape policy, and source-RVA-to-candidate-portal mappings. Observing the
numeric original `ExceptionAddress` or `Eip` blocks completion unless pinned
original-layout authority is supplied.

Native realization compiles the selected providers and shared runtime once and
emits `native-realization-build-manifest-v1` as non-authorizing compiler/linker
facts. It binds every bridge, SEH registration gateway, exception recovery
portal, loader support datum, linked section, relocation, and source/object hash
without introducing a second build-plan or link-receipt authority system. The
composer patches loader-visible support data, emits required HIGHLOW
relocations, and regenerates the EAT, data anchors, forwarders, combined TLS,
imports, delay imports, SafeSEH, CFG, and load-config surfaces from those facts.
SafeSEH admits gateway handlers, never recovery portals. The resulting
`native-realization-v2` binds the selected linked semantic module to the exact
candidate hash and decoded loader surface. Project completion consumes only
these realizations and independently observed candidate hashes.

External function addresses have distinct receipt forms. An ordinary loader
import binds its exact IAT RVA. A code export admitted through checked dynamic
resolution instead binds its DLL, name or ordinal, and exact loader-service
contract hash as `loader_resolved_export`; it never receives a fabricated IAT
or linked RVA. Runtime resolution remains subject to the checked admitted
domain and external-environment provider selection.

An ingress plan also carries exact native-runtime feature and private-stack
requirements. The generated backend now emits the exact combined-PE-TLS ABI,
per-thread ingress frame/state arrays, one aligned per-thread private stack at
least as large as the original PE stack reserve,
table-driven physical-state ingress bridges, capability publication with host
atomics, atomic one-shot admission, replacement publication, checked
resource-event expiration, and x86
exception-registration gateways. The semantic runtime context
is selected from the current loader TLS slot, so independent host threads do not
share its entry lock and same-thread reentry pushes another ingress frame.
Nested entry continues downward from the current checked stack pointer; it does
not reserve disjoint slices. The 64-KiB runtime constant is the minimum space
that must remain before admitting an entry, and exhaustion fails
deterministically.

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
