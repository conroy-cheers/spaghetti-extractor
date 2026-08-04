# Reviewed Profiles

This directory contains reusable, authored descriptions of PE32 machine
boundaries. Profiles are input data for static analysis, source rendering, and
candidate runtime generation. They are not target bundles and do not qualify a
candidate by themselves.

## Profile Families

- `pe32-win32-system-dll-abi-policy-v1.json` classifies Win32 import calling
  conventions and machine argument locations.
- `pe32-msvcrt-machine-runtime-v1.json` describes selected MinGW/MSVCRT
  machine-call boundaries used by generated runtimes.
- `pe32-kernel32-callable-resolvers-v1.json` describes APIs that return callable
  addresses and the lookup identities used to recover them.
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

Missing calls, unresolved argument sources, unsupported callbacks, ambiguous
footprints, or stale profile bindings remain `incomplete`. A profile never
turns an inferred C prototype or API name into proof of behavior.

Keep profiles generic. Target-specific choices belong under `targets/<id>/intent/`.
