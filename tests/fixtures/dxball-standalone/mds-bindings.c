#include <stdlib.h>
#include "program-state.h"
#include "mds-storage.h"
#include "music-runtime.h"
#include "mds-loader-runtime.h"
#include "mds-stream-runtime.h"

music_record *music_allocate_record(void *u, music_state *s, uint32_t size) {
    (void)u; (void)s;
    if (size != 8) abort();
    return malloc(sizeof(music_record));
}
void music_free_record(void *u, music_state *s, music_record *record) {
    (void)u; (void)s; free(record);
}
uint32_t music_load(void *u, music_state *s, music_record *record, music_name *name,
                    uint32_t length, uint32_t flags) {
    (void)u;
    /* Load only writes the output on success. Do not interpret an uninitialized
     * incoming pointer merely to preserve the caller's failure-side bytes. */
    mds_output output = {0};
    mds_input input = {(const unsigned char *)name->text};
    uint32_t result = fixture_mds_load(&output, &input, length, flags);
    if (!result) {
        record->stream = (void *)output.value;
        dxball_mds_attach(output.value, DXBALL_OWNER(s, music));
    }
    return result;
}
uint32_t music_start_stream(void *u, music_state *s, music_stream *stream, uint32_t loop) {
    (void)u; (void)s; return fixture_mds_start((void *)stream, loop);
}
uint32_t music_pause_stream(void *u, music_state *s, music_stream *stream) {
    (void)u; (void)s; return fixture_mds_pause((void *)stream);
}
uint32_t music_stop_stream(void *u, music_state *s, music_stream *stream) {
    (void)u; (void)s; return fixture_mds_stop((void *)stream);
}
uint32_t music_release_stream(void *u, music_state *s, music_stream *stream) {
    (void)u; (void)s; return fixture_mds_release((void *)stream);
}
