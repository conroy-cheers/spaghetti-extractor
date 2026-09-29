/* The table and menu views share live objects; copy all owned backing at cuts. */
#define SCREEN_WORDS(X) \
    X(length,0x431f88) X(blink,0x431f8c) X(entering,0x431f90) X(last_tick,0x431f94) \
    X(show_table,0x431f98) X(highlight,0x431f9c) X(shift,0x434988)
static void screen_to_native(void) {
    menu_to_native(); scores_to_native(); memcpy((void *)0x431f60,screen.name,40);
#define PUT(member,address) *word(address)=screen.member;
    SCREEN_WORDS(PUT)
#undef PUT
}
static void screen_from_native(void) {
    menu_from_native(); scores_from_native(); memcpy(screen.name,(void *)0x431f60,40);
#define GET(member,address) screen.member=*word(address);
    SCREEN_WORDS(GET)
#undef GET
}
