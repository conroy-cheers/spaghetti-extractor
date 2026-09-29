/* The includer supplies live handle/resource identity maps and word(address). */
static void shell_to_native(void) {
    shell_state *s=&application;scene_state *scene=s->scene;title_state *title=scene->animation;flow_state *flow=title->flow;
    *word(0x43498c)=s->active;*word(0x434994)=s->control;*word(0x434988)=s->shift;*word(0x4349d0)=s->suspended;
    *word(0x434980)=s->cursor.x;*word(0x434984)=s->cursor.y;
    *word(0x434970)=scene->mouse_x;*word(0x434978)=scene->mouse_y;*word(0x434990)=scene->mouse_buttons;
    *word(0x434998)=flow->windowed;*word(0x4349a4)=flow->refresh_needed;*word(0x417a00)=flow->first_frame;
    *word(0x431fd0)=flow->scene;*word(0x431fc4)=flow->next_scene;*word(0x431fc8)=flow->transition_pending;
    *word(0x4349a0)=shell_handle_address(s->instance_lock);*word(0x4349a8)=shell_device_address(s->graphics);
    *word(0x4349b8)=shell_palette_address(s->palette);*word(0x4349ac)=surface_address(title->primary);
    *word(0x4349b4)=surface_address(title->back);*word(0x4349b0)=surface_address(scene->flip);
    memcpy((void *)0x42c148,title->palettes->current,1024);
    flow->primary=title->primary;flow->back=title->back;
}
static void shell_from_native(void) {
    shell_state *s=&application;scene_state *scene=s->scene;title_state *title=scene->animation;flow_state *flow=title->flow;
    s->active=*word(0x43498c);s->control=*word(0x434994);s->shift=*word(0x434988);s->suspended=*word(0x4349d0);
    s->cursor.x=*word(0x434980);s->cursor.y=*word(0x434984);
    scene->mouse_x=*word(0x434970);scene->mouse_y=*word(0x434978);scene->mouse_buttons=*word(0x434990);
    flow->windowed=*word(0x434998);flow->refresh_needed=*word(0x4349a4);flow->first_frame=*word(0x417a00);
    flow->scene=*word(0x431fd0);flow->next_scene=*word(0x431fc4);flow->transition_pending=*word(0x431fc8);
    s->instance_lock=shell_handle_view(*word(0x4349a0));s->graphics=shell_device_view(*word(0x4349a8));
    s->palette=shell_palette_view(*word(0x4349b8));title->primary=surface_view(*word(0x4349ac));
    title->back=surface_view(*word(0x4349b4));scene->flip=surface_view(*word(0x4349b0));
    memcpy(title->palettes->current,(void *)0x42c148,1024);
    flow->primary=title->primary;flow->back=title->back;
}
