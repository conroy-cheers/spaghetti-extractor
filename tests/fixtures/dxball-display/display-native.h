/* Parent transport supplies the same application, font and sprite-bank owners. */
static void display_to_native(void) {
    display_parent_to_native();display_state *s=&display;scene_state *scene=s->application->scene;
    *word(0x434974)=shell_handle_address(s->window);*word(0x4349bc)=display_clipper_address(s->clipper);
    *word(0x4179fc)=s->damage->capability;*word(0x43499c)=s->damage->clipped;
    *word(0x417a04)=scene->presentation_mode;*word(0x417a08)=scene->no_hardware;
    *word(0x4349cc)=scene->low_memory;*word(0x4349c8)=scene->animation->fast;
}
static void display_from_native(void) {
    display_parent_from_native();display_state *s=&display;scene_state *scene=s->application->scene;
    s->window=shell_handle_view(*word(0x434974));s->clipper=display_clipper_view(*word(0x4349bc));
    s->damage->capability=*word(0x4179fc);s->damage->clipped=*word(0x43499c);
    scene->presentation_mode=*word(0x417a04);scene->no_hardware=*word(0x417a08);
    scene->low_memory=*word(0x4349cc);scene->animation->fast=*word(0x4349c8);
}
