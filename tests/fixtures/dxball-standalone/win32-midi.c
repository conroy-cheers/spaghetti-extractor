#include <stdlib.h>
#include <string.h>
#include "win32-platform.h"
#include "mds-storage.h"
#include "mds-stream-runtime.h"

typedef struct {
    MIDIHDR native;
    mds_buffer *buffer, published;
    int initialized;
} midi_header;
typedef struct { uint32_t count; midi_header headers[]; } midi_storage;
_Static_assert(sizeof(MIDIHDR)==64, "original MIDI header ABI");

static midi_header *header_for(mds_info *info, mds_buffer *buffer) {
    midi_storage *storage = dxball_mds_attachment(info);
    if (!storage) abort();
    for (uint32_t i=0; i<storage->count; ++i)
        if (storage->headers[i].buffer == buffer) return &storage->headers[i];
    abort();
}
static void publish_header(midi_header *header) {
    mds_buffer *buffer = header->buffer;
    /* Wine may update its queue links/flags between calls. An unchanged C view
     * is not a request to restore the previous provider state. Keep the baseline
     * from the exact import that constructed that view, as in mds-transport.c. */
#define PUBLISH(field, member, value) \
    if (!header->initialized || buffer->field != header->published.field) header->native.member = (value)
    PUBLISH(event.data, lpData, (LPSTR)buffer->event.data);
    PUBLISH(event.capacity, dwBufferLength, buffer->event.capacity);
    PUBLISH(event.used, dwBytesRecorded, buffer->event.used);
    PUBLISH(owner, dwUser, (DWORD_PTR)buffer->owner);
    PUBLISH(flags, dwFlags, buffer->flags);
    PUBLISH(next, lpNext, buffer->next ? &header_for(buffer->owner, buffer->next)->native : NULL);
#undef PUBLISH
    header->published = *buffer;
    header->initialized = 1;
}
static void read_header(midi_header *header) {
    MIDIHDR observed;
    memcpy(&observed, &header->native, sizeof(observed));
    mds_buffer *buffer = header->buffer;
    buffer->event.data = (unsigned char *)observed.lpData;
    buffer->event.capacity = observed.dwBufferLength;
    buffer->event.used = observed.dwBytesRecorded;
    buffer->owner = (void *)observed.dwUser;
    buffer->flags = observed.dwFlags;
    buffer->next = NULL;
    if (observed.lpNext) {
        midi_storage *storage = dxball_mds_attachment(buffer->owner);
        for (uint32_t i=0; i<storage->count; ++i)
            if (&storage->headers[i].native == observed.lpNext) buffer->next=storage->headers[i].buffer;
        if (!buffer->next) abort();
    }
    header->published = *buffer;
    header->initialized = 1;
}
static void CALLBACK completed(HMIDIOUT stream, UINT message, DWORD_PTR instance, DWORD_PTR first, DWORD_PTR second) {
    (void)stream; (void)instance; (void)second;
    if (message != MOM_DONE) return;
    midi_header *header = (void *)first;
    read_header(header);
    mds_header view = {header->buffer};
    fixture_mds_complete(message, &view);
    publish_header(header);
}
uint32_t stream_open(void *u, mds_info *info, uint32_t device, uint32_t count, uint32_t flags) {
    (void)u;
    if (!dxball_mds_attachment(info)) {
        if (info->count > (SIZE_MAX-sizeof(midi_storage))/sizeof(midi_header)) return MMSYSERR_NOMEM;
        size_t bytes = sizeof(midi_storage)+(size_t)info->count*sizeof(midi_header);
        midi_storage *storage = malloc(bytes);
        if (!storage) return MMSYSERR_NOMEM;
        storage->count=info->count;
        for (uint32_t i=0; i<info->count; ++i) {
            mds_buffer *buffer=&info->buffers->headers[i];
            storage->headers[i]=(midi_header){.buffer=buffer};
            /* The owned parser allocation retains each original 64-byte header
             * before its payload. Carry its private-field history into the SDK
             * attachment instead of introducing a second uninitialized history. */
            memcpy(&storage->headers[i].native, buffer->payload-64, 64);
        }
        dxball_mds_set_attachment(info, storage, free);
    }
    UINT selected=device;
    HMIDISTRM stream=(HMIDISTRM)info->stream;
    MMRESULT result=midiStreamOpen(&stream, &selected, count, (DWORD_PTR)completed, 0, flags);
    info->stream=(uintptr_t)stream;
    return result;
}
uint32_t stream_property(void *u, mds_info *info, uint32_t size, uint32_t division, uint32_t flags) {
    (void)u; MIDIPROPTIMEDIV property={size, division};
    return midiStreamProperty((HMIDISTRM)info->stream, (LPBYTE)&property, flags);
}
#define HEADER_CALL(name, call) \
uint32_t name(void *u, mds_info *info, mds_header *view, uint32_t size) { \
    (void)u; midi_header *header=header_for(info, view->buffer); publish_header(header); \
    MMRESULT result=call; read_header(header); return result; }
HEADER_CALL(stream_prepare, midiOutPrepareHeader((HMIDIOUT)info->stream, &header->native, size))
HEADER_CALL(stream_queue, midiStreamOut((HMIDISTRM)info->stream, &header->native, size))
HEADER_CALL(stream_unprepare, midiOutUnprepareHeader((HMIDIOUT)info->stream, &header->native, size))
#undef HEADER_CALL
uint32_t stream_restart(void *u, mds_info *info) { (void)u; return midiStreamRestart((HMIDISTRM)info->stream); }
uint32_t stream_pause(void *u, mds_info *info) { (void)u; return midiStreamPause((HMIDISTRM)info->stream); }
uint32_t stream_reset(void *u, mds_info *info) { (void)u; return midiOutReset((HMIDIOUT)info->stream); }
uint32_t stream_close(void *u, mds_info *info) { (void)u; return midiStreamClose((HMIDISTRM)info->stream); }
