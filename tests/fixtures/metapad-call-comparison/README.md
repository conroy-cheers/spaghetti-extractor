# Original Metapad call boundary

`exact/` is emitted by `write_component_exact_c_slice_v1` from the retained
transfer plan with SHA256
`1d1eb428e0fd4a37fc41090ca8904cf83597ce561d3de2be773cf5618c798781`,
selecting only original region 0x5646 as caller root. The existing exact-slice
format retains the direct callee 0x1284 for original provenance. Its bytes must
match the checked supplier's original function, but neither that body nor its
authored object is copied or compiled in the caller proof.

`contract.json` fixes the admitted private-stack span, the four caller words,
actual call edge, outgoing argument/caption/flags, and borrowed result reference.
The private span must not silently grow when a supplier contract changes. Actual
caller reachability, native service table/reference admission, whole cleanup
coverage/progress and MessageBox string safety remain separate obligations.

This directory does not authorize a replacement or declare the full caller
component complete. Source preparation is retained separately in the authored
call fixture; supplier proof material is in the existing resource-text fixture.
