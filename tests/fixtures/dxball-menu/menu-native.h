/* Extend the established scene transport with actual dot/timer backing. */
static void menu_to_native(void) {
    scene_to_native();
    *word(0x431cbc) = menu.score; *word(0x434994) = menu.input_ready; *word(0x4331d0) = menu.last_tick;
    for (unsigned i = 0; i < 287; ++i) {
        uint32_t *p = word(0x431fe0+16*i); const menu_dot *d = &menu.dots[i];
        p[0] = d->x; p[1] = d->y; p[2] = d->phase; p[3] = d->kind;
    }
    memcpy((void *)0x4331d8,menu.offsets,sizeof(menu.offsets));
}
static void menu_from_native(void) {
    scene_from_native();
    menu.score = *word(0x431cbc); menu.input_ready = *word(0x434994); menu.last_tick = *word(0x4331d0);
    for (unsigned i = 0; i < 287; ++i) {
        const uint32_t *p = word(0x431fe0+16*i); menu.dots[i] = (menu_dot){p[0],p[1],p[2],p[3]};
    }
    memcpy(menu.offsets,(void *)0x4331d8,sizeof(menu.offsets));
}
