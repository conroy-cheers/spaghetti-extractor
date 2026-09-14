# Reviewed Profiles

This directory contains reusable, authored descriptions of PE32 machine
boundaries. Profiles are input data for static analysis, source rendering, and
candidate runtime generation. They are not target bundles and do not qualify a
candidate by themselves.

`catalog.json` is a closed supported-profile inventory. Its role IDs and the
validator permitted for each role are defined by the typed profile registry;
adding an arbitrary role label or pairing a profile with an unrelated parser is
rejected. Test-only profile fragments belong under `tests/`, and retired
profiles belong in Git history rather than this directory.

## Profile Families

- `pe32-win32-system-dll-abi-policy-v1.json` classifies Win32 import calling
  conventions and machine argument locations.
- `pe32-msvcrt-machine-runtime-v1.json` describes selected MinGW/MSVCRT
  machine-call boundaries used by generated runtimes.
- `pe32-oniguruma-runtime-v1.json` describes reviewed public Oniguruma
  machine-call boundaries shared by targets using the native library.
- `pe32-kernel32-callable-resolvers-v1.json` describes APIs that return callable
  addresses and the lookup identities used to recover them.
- `pe32-kernel32-terminated-byte-read-v1.json` explicitly overrides the ABI-only
  `lstrlenA` entry when selected. Its read-only `terminated_byte_offset` relation
  requires a current terminating span and live readable origin for nonnull
  inputs, and includes a null-input/zero-result outcome. It conservatively
  admits any zero-byte offset inside the span, so it does not prove first-NUL
  length or repeatability. The [Microsoft API contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lstrlena)
  supplies the specification input; selecting the pack does not prove the DLL
  or authorize provider activation. Shared summaries and restricted read
  footprints still need their checked composition rules. The general kernel32
  ABI pack and default target selections remain unchanged.
- `pe32-user32-resource-text-runtime-v1.json` describes `LoadStringA` with a
  positive signed buffer capacity. Its checked `argument_domain` constrains the
  fourth machine word to 1 through `INT32_MAX`, and its writable footprint uses
  that capacity. The profile permits arbitrary buffer bytes and scalar results
  on every outcome; it does not promise termination or unchanged failure bytes.
  The positive capacity follows the [Microsoft API contract](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-loadstringa),
  which excludes zero for the ANSI function. This separate pack lets consumers
  select the resource-text contract without changing their other profile packs.
- `pe32-mingw-win32-function-extraction-v1.json` and
  `pe32-mingw-directx-interface-extraction-v1.json` drive SDK AST extraction for
  Win32 functions and COM-style interfaces.
- `pe32-static-cutpoints-and-paired-callables-v1.json` supplies reviewed static
  cutpoint and indirect-call hints.
- The `*-lockstep-v1.json` files retain machine-level argument, return,
  footprint, callback, allocation, and resource-effect schemas. The historical
  filename is part of their versioned identity; current tooling uses the data
  as external-operation evidence rather than as a whole-program theorem.
- `i686-mingw-freestanding-c0-v1.json` pins a conservative candidate compiler
  profile for generated freestanding C.

## Authority

Profiles may identify an import, describe its ABI words, bound memory reads and
writes, or classify a returned value as an allocation, callback, or opaque
resource. The binary must still contain the named import or call pattern, the
site analysis must recover compatible arguments, and the generated candidate
must pass static assurance plus candidate-only behavioral tests.

Optional `argument_domain` rows contain an `argument_index`, `minimum` and
`maximum`, compared as unsigned 32-bit words. Rows must be ordered and unique.
The domain remains part of the selected behavior identity and exact site
contract. Both the paired oracle and native bridge check the argument before
applying effects or calling the external implementation. Out-of-domain calls
fail closed; a domain declaration alone does not establish caller admission.

An entry may intentionally provide only an ABI template and fixed arity. Such
an entry can support register preservation, stack cleanup, and indirect-target
recovery, but remains incomplete external-site evidence until memory, world,
and callback effects are supplied separately.

Missing calls, unresolved argument sources, unsupported callbacks, ambiguous
footprints, or stale profile bindings remain `incomplete`. A profile never
turns an inferred C prototype or API name into proof of behavior.

Keep profiles generic. Target-specific choices belong under `targets/<id>/intent/`.
