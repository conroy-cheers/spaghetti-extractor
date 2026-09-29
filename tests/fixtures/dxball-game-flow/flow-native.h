/* Ordinary adapter transport, shared by controlled and real program consumers.
 * The includer supplies owned object mappings and asset pull/push functions. */
#define FLOW_WORDS(X) \
    X(first_frame, 0x417a00) X(scene, 0x431fd0) X(next_scene, 0x431fc4) \
    X(transition_pending, 0x431fc8) X(windowed, 0x434998) \
    X(refresh_needed, 0x4349a4) X(audio_enabled, 0x42ca10)
static void flow_to_native(void) {
    flow_assets_to_native();
#define PUT(member, address) *word(address) = flow.member;
    FLOW_WORDS(PUT)
#undef PUT
    *word(0x42ca14) = flow_audio_address(flow.audio);
    *word(0x4349ac) = flow_surface_address(flow.primary);
    *word(0x4349b4) = flow_surface_address(flow.back);
    *word(0x431fcc) = flow_surface_address(flow.overlay);
}
static void flow_from_native(void) {
    flow_assets_from_native();
#define GET(member, address) flow.member = *word(address);
    FLOW_WORDS(GET)
#undef GET
    flow.audio = flow_audio_view(*word(0x42ca14));
    flow.primary = flow_surface_view(*word(0x4349ac));
    flow.back = flow_surface_view(*word(0x4349b4));
    flow.overlay = flow_surface_view(*word(0x431fcc));
}
