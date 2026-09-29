# Sprite font boundaries, recovered from the pinned DX-Ball executable

No original source is used. The cleanup object representation and lifetime
services are retained unchanged. New metadata accessors name sprite width at
offset 8, height at 12, source rectangle at 20..35, character byte at 36 and
baseline offset at 40, decoded portably from the existing 41-byte metadata.

`font-metrics` owns select (`bd80..bd8a`), lookup (`c660..c6a6`) and measure
(`c760..c80d`). `font-render` owns glyph (`c5a0..c651`), line (`c6b0..c714`)
and centered line (`c720..c752`). These are actual native entries; private
helpers and loop regions do not require extra production component APIs.
Native arguments are cdecl words/pointers. Selection's incidental return word
is unobserved; the remaining operations preserve their exact 32-bit result.

The current font bank is VA `43496c`, spacing is VA `4179f8`, and drawing's
destination surface is VA `434960`. Cleanup's current bank remains `434968`.
Font operations do not mutate the shared tables themselves. Lookup compares
the argument's low byte, starts at slot 1, and uses signed count comparisons;
count zero or negative returns slot 1. Valid positive counts are at most 255,
with live sprites at every inspected slot. Callers can retain slot aliases.
Length is signed; nonpositive lengths read no text. Positive lengths require
that many readable bytes, including embedded NULs. Coordinates, widths,
spacing and returned advances wrap at 32 bits. Half-width uses signed division
rounding towards zero. A line returns its last advance, not total width.

Metrics are a read-only supplier with three operations. Render declares lookup,
measurement and blit services. The source uses the metrics supplier for the
original's duplicated/inlined measurement search. This is tested implementation
composition, not a new claim of formal inlining equivalence.
Graphics blit receives two rectangles and the source surface; the adapter checks
the destination surface, native flags `01008000`, null effects pointer, argument
order and shared state. A controlled blit may change font bank, spacing or glyph
width before returning. Glyph width is reloaded afterwards just as in the binary.
Actual DirectDraw rasterization and failure timing remain outside these cases.

The native consumer is the original line/center path when only metrics is
replaced; the connected selection replaces both units. Cases also dispose the
same live sprite objects using the previously lifted cleanup network. This
connects drawing, object identity and teardown without adding synthetic calls
to any production operation. Application startup and asset loading are not yet
claimed by this boundary. Execution is single-threaded and services return
normally; no arbitrary recursion/concurrency or checked heap summary is claimed.
