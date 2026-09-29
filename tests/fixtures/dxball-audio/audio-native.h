/* The owner maps identities and retains sample payload bytes, independently of pointers. */
static void audio_to_native(void) {
    *word(0x42ca10)=audio_device_address(sound.device);
    *word(0x42ca14)=audio_buffer_address(sound.primary);
    for (unsigned i=0;i<50;++i) *word(0x42c948+4*i)=audio_sample_address(sound.slots[i]);
    audio_samples_to_native();
}
static void audio_from_native(void) {
    sound.device=audio_device_view(*word(0x42ca10));sound.primary=audio_buffer_view(*word(0x42ca14));
    for (unsigned i=0;i<50;++i) sound.slots[i]=audio_sample_view(*word(0x42c948+4*i));
    audio_samples_from_native();
}
