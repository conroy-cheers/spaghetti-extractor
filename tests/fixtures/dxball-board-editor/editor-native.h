/* Extend the existing scene objects with actual editor and board backing. */
static void editor_to_native(void) {
    menu_to_native();
    *word(0x42ca18)=editor.selected_tile; *word(0x42ca54)=editor.index;
    *word(0x435cf4)=editor.region_count; memcpy((void *)0x4349d8,editor.regions,sizeof(editor.regions));
    memcpy((void *)0x42ca60,&editor_boards.current,400); memcpy((void *)0x42cdf8,editor_boards.saved,20000);
    *word(0x434964)=editor_file_address(editor_boards.file);
}
static void editor_from_native(void) {
    menu_from_native();
    editor.selected_tile=*word(0x42ca18); editor.index=*word(0x42ca54);
    editor.region_count=*word(0x435cf4); memcpy(editor.regions,(void *)0x4349d8,sizeof(editor.regions));
    memcpy(&editor_boards.current,(void *)0x42ca60,400); memcpy(editor_boards.saved,(void *)0x42cdf8,20000);
    editor_boards.file=editor_file_view(*word(0x434964));
}
