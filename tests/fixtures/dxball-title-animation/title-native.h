/* Shared adapter mapping. Pixel storage belongs to the graphics services;
 * message and sine buffers remain borrowed for the whole operation. */
#define TITLE_WORDS(X) \
    X(length, 0x431fa4) X(index, 0x431fb0) X(advance, 0x431fb8) X(glyph_width, 0x431fb4) \
    X(wobble_phase, 0x431fac) X(first_offset, 0x431fa0) X(second_offset, 0x431fbc) \
    X(palette_width, 0x417758) X(palette_phase, 0x41775c) X(palette_offset, 0x431fc0) X(fast, 0x4349c8)
static void title_to_native(void) {
    title_font_to_native(); title_palettes_to_native();
#define PUT(member, address) *word(address) = title.member;
    TITLE_WORDS(PUT)
#undef PUT
    *word(0x434998) = title.flow->windowed;
    *word(0x4349ac) = title_surface_address(title.primary);
    *word(0x41c728) = title_surface_address(title.software);
    *word(0x4349b4) = title_surface_address(title.back);
}
static void title_from_native(void) {
    title_font_from_native(); title_palettes_from_native();
#define GET(member, address) title.member = *word(address);
    TITLE_WORDS(GET)
#undef GET
    title.flow->windowed = *word(0x434998);
    title.primary = title_surface_view(*word(0x4349ac));
    title.software = title_surface_view(*word(0x41c728));
    title.back = title_surface_view(*word(0x4349b4));
}
