/* Scene transport extends the same font/palette/flow/animation objects. */
#define SCENE_WORDS(X) \
    X(presentation_mode, 0x417a04) X(no_hardware, 0x417a08) X(low_memory, 0x4349cc) X(refresh_ok, 0x4349c0) \
    X(mouse_x, 0x434970) X(mouse_y, 0x434978) X(cursor_x, 0x431fd8) X(cursor_y, 0x431fdc) \
    X(mouse_buttons, 0x434990) X(scroll_auxiliary, 0x431fa8)
static void scene_to_native(void) {
    scene_parent_to_native();
#define PUT(member, address) *word(address) = scene.member;
    SCENE_WORDS(PUT)
#undef PUT
    *word(0x4349b0) = title_surface_address(scene.flip);
    *word(0x431fcc) = title_surface_address(title.flow->overlay);
    *word(0x431fc8) = title.flow->transition_pending; *word(0x431fc4) = title.flow->next_scene;
    memcpy((void *)0x417650, scene.palette_cycle, sizeof(scene.palette_cycle));
}
static void scene_from_native(void) {
    scene_parent_from_native();
#define GET(member, address) scene.member = *word(address);
    SCENE_WORDS(GET)
#undef GET
    scene.flip = title_surface_view(*word(0x4349b0));
    title.flow->overlay = title_surface_view(*word(0x431fcc));
    title.flow->transition_pending = *word(0x431fc8); title.flow->next_scene = *word(0x431fc4);
    memcpy(scene.palette_cycle, (void *)0x417650, sizeof(scene.palette_cycle));
}
