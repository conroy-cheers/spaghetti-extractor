# XED ISA Catalog Extractor

`xed-isa-catalog` emits the pinned Intel XED instruction-template metadata used
to propose the `pe32-i686-v1` qualification inventory.

The output is untrusted analysis. XED table indices and metadata identify
coverage work and generate test inputs; Lean still decodes exact bytes and
checks every semantic proof used by Stage A. Emulator agreement is veto-only
and cannot authorize a proof.
