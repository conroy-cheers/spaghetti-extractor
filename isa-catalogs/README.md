# ISA qualification catalogs

These files enrich selected entries from the complete pinned XED inventory
with an exact encoding, generic effect descriptors, and defined-output masks.
They are untrusted inputs to the corpus generator. Bochs, Unicorn, and the
authoritative Lean semantics independently execute the generated cases before
the corresponding Lean semantic form can be marked qualified.

`pe32-i686-core-smoke-v1.json` is intentionally small. It validates the full
content-addressed qualification DAG without claiming broad i686 coverage. The
XED campaign artifact keeps every other profile form visible as a frontier.
