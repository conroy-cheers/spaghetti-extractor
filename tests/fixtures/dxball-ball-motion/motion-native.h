/* The caller supplies the existing shared play/font/board transport. */
#define MOTION_WORDS(X) \
    X(ball_count,0x42cbf0) X(gravity,0x42ca38) X(paddle_width,0x431c78) \
    X(paddle_power,0x42cdd0) X(sticky,0x431c8c) X(pierce,0x431c90) \
    X(impact_dx,0x431c34) X(impact_dy,0x431c30)
static void motion_to_native(void) {
    play_to_native();
#define PUT(name,address) *play_word(address)=motion.name;
    MOTION_WORDS(PUT)
#undef PUT
    memcpy((void *)0x42ca60,motion.board,400);
}
static void motion_from_native(void) {
    play_from_native();
#define GET(name,address) motion.name=*play_word(address);
    MOTION_WORDS(GET)
#undef GET
    memcpy(motion.board,(void *)0x42ca60,400);
}
