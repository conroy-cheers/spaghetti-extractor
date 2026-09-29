#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "win32-platform.h"
#include "audio-runtime.h"
#include "setup-runtime.h"
#include "wave-runtime.h"
#include "flow-runtime.h"

uint32_t setup_create_device(void *u, audio_setup_state *s) {
    (void)u;
    IDirectSound *device = SOUND(s->bank->device);
    HRESULT result = DirectSoundCreate(NULL, &device, NULL);
    s->bank->device = (void *)device;
    return (uint32_t)result;
}
uint32_t setup_cooperative(void *u, audio_setup_state *s, audio_device *device, shell_handle *window, uint32_t flags) {
    (void)u; (void)s; return (uint32_t)IDirectSound_SetCooperativeLevel(SOUND(device), (HWND)window, flags);
}
static uint32_t create_buffer(audio_device *device, uint32_t size, uint32_t flags, uint32_t bytes,
                              uint32_t reserved, const void *format, void *output) {
    DSBUFFERDESC spec = {.dwSize=size, .dwFlags=flags, .dwBufferBytes=bytes,
        .dwReserved=reserved, .lpwfxFormat=(WAVEFORMATEX *)format};
    IDirectSoundBuffer *buffer;
    memcpy(&buffer, output, sizeof(buffer));
    HRESULT result = IDirectSound_CreateSoundBuffer(SOUND(device), &spec, &buffer, NULL);
    memcpy(output, &buffer, sizeof(buffer));
    return (uint32_t)result;
}
uint32_t setup_create_primary(void *u, audio_setup_state *s, audio_device *device, audio_buffer_spec *spec) {
    (void)u;
    return create_buffer(device, spec->size, spec->flags, spec->bytes, spec->reserved, spec->format, &s->bank->primary);
}
uint32_t setup_message(void *u, audio_setup_state *s, shell_handle *window, audio_name *text, audio_name *caption, uint32_t flags) {
    (void)u; (void)s; return (uint32_t)MessageBoxA((HWND)window, text->text, caption->text, flags);
}
void setup_terminate(void *u, audio_setup_state *s, uint32_t code) { (void)u; (void)s; exit((int)code); }
void audio_frequency(void *u, audio_state *s, audio_buffer *buffer, uint32_t value) { (void)u; (void)s; IDirectSoundBuffer_SetFrequency(BUFFER(buffer), value); }
void audio_pan(void *u, audio_state *s, audio_buffer *buffer, uint32_t value) { (void)u; (void)s; IDirectSoundBuffer_SetPan(BUFFER(buffer), (LONG)value); }
void audio_volume(void *u, audio_state *s, audio_buffer *buffer, uint32_t value) { (void)u; (void)s; IDirectSoundBuffer_SetVolume(BUFFER(buffer), (LONG)value); }
void audio_position(void *u, audio_state *s, audio_buffer *buffer, uint32_t value) { (void)u; (void)s; IDirectSoundBuffer_SetCurrentPosition(BUFFER(buffer), value); }
uint32_t audio_play(void *u, audio_state *s, audio_buffer *buffer, uint32_t flags) { (void)u; (void)s; return (uint32_t)IDirectSoundBuffer_Play(BUFFER(buffer), 0, 0, flags); }
void audio_stop(void *u, audio_state *s, audio_buffer *buffer) { (void)u; (void)s; IDirectSoundBuffer_Stop(BUFFER(buffer)); }
uint32_t audio_restore_buffer(void *u, audio_state *s, audio_buffer *buffer) { (void)u; (void)s; return (uint32_t)IDirectSoundBuffer_Restore(BUFFER(buffer)); }
void audio_release_buffer(void *u, audio_state *s, audio_buffer *buffer) { (void)u; (void)s; IDirectSoundBuffer_Release(BUFFER(buffer)); }
void audio_release_device(void *u, audio_state *s, audio_device *device) { (void)u; (void)s; IDirectSound_Release(SOUND(device)); }
void audio_status(void *u, audio_state *s, audio_buffer *buffer, audio_status_word *word) {
    (void)u; (void)s; DWORD status=word->flags; IDirectSoundBuffer_GetStatus(BUFFER(buffer), &status); word->flags=status;
}
uint32_t flow_audio_status(void *u, flow_state *s, flow_audio *buffer) {
    (void)u; (void)s;
    DWORD status;
    if (FAILED(IDirectSoundBuffer_GetStatus(BUFFER(buffer), &status))) {
        fputs("DirectSound status failure needs the original caller's retained status word\n", stderr);
        abort();
    }
    return status;
}
uint32_t wave_create_buffer(void *u, audio_state *s, audio_device *device, audio_sample *sample, wave_buffer_spec *spec) {
    (void)u; (void)s;
    return create_buffer(device, spec->size, spec->flags, spec->bytes, spec->reserved, spec->format, &sample->buffer);
}
uint32_t wave_lock(void *u, audio_state *s, audio_buffer *buffer, uint32_t length, wave_locked *locked) {
    (void)u; (void)s;
    void *first, *second; DWORD first_bytes, second_bytes;
    HRESULT result = IDirectSoundBuffer_Lock(BUFFER(buffer), 0, length, &first, &first_bytes, &second, &second_bytes, 0);
    if (!result) *locked=(wave_locked){first, second, first_bytes, second_bytes};
    return (uint32_t)result;
}
void wave_unlock(void *u, audio_state *s, audio_buffer *buffer, wave_locked *locked) {
    (void)u; (void)s; IDirectSoundBuffer_Unlock(BUFFER(buffer), locked->first, locked->first_bytes, locked->second, locked->second_bytes);
}
void wave_frequency(void *u, audio_state *s, audio_buffer *buffer, wave_word *word) {
    (void)u; (void)s;
    DWORD value; memcpy(&value, word->bytes, 4); IDirectSoundBuffer_GetFrequency(BUFFER(buffer), &value); memcpy(word->bytes, &value, 4);
}
void wave_pan(void *u, audio_state *s, audio_buffer *buffer, wave_word *word) {
    (void)u; (void)s;
    LONG value; memcpy(&value, word->bytes, 4); IDirectSoundBuffer_GetPan(BUFFER(buffer), &value); memcpy(word->bytes, &value, 4);
}
void wave_volume(void *u, audio_state *s, audio_buffer *buffer, wave_word *word) {
    (void)u; (void)s;
    LONG value; memcpy(&value, word->bytes, 4); IDirectSoundBuffer_GetVolume(BUFFER(buffer), &value); memcpy(word->bytes, &value, 4);
}
