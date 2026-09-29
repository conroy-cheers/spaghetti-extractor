/* Extend the existing shared scene transport; do not duplicate its destination. */
#define DAMAGE_WORDS(X) \
    X(pending_count,0x42c138) X(page,0x42c13c) X(last_tick,0x42c140) \
    X(clipped,0x43499c) X(capability,0x4179fc)
static void damage_to_native(void) {
    scene_to_native();
#define PUT(member,address) *word(address)=damage.member;
    DAMAGE_WORDS(PUT)
#undef PUT
    *word(0x41a7e0)=title_surface_address(damage.background);
    memcpy((void *)0x41a7e8,damage.keys,sizeof(damage.keys));
    memcpy((void *)0x41c730,damage.pending,sizeof(damage.pending));
    memcpy((void *)0x424430,damage.count,sizeof(damage.count));
    memcpy((void *)0x424438,damage.history,sizeof(damage.history));
}
static void damage_from_native(void) {
    scene_from_native();
#define GET(member,address) damage.member=*word(address);
    DAMAGE_WORDS(GET)
#undef GET
    damage.background=title_surface_view(*word(0x41a7e0));
    memcpy(damage.keys,(void *)0x41a7e8,sizeof(damage.keys));
    memcpy(damage.pending,(void *)0x41c730,sizeof(damage.pending));
    memcpy(damage.count,(void *)0x424430,sizeof(damage.count));
    memcpy(damage.history,(void *)0x424438,sizeof(damage.history));
}
