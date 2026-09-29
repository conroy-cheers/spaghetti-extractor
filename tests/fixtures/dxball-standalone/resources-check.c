/* Run the owned loader/parser/event chain against retained native observations.
 * Entry hooks count calls only; every service is supplied by the assembly. */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "program-state.h"
#include "mds-storage.h"
#include "music-runtime.h"
#include "mds-loader-runtime.h"
#include "mds-parser-runtime.h"
#include "mds-stream-runtime.h"

#define REQUIRE(test) do { if (!(test)) { fprintf(stderr, "resources check: %s:%d: %s\n", __FILE__, __LINE__, #test); exit(1); } } while (0)
static unsigned loaders, parsers, expanders;
void loader_enter(void) { ++loaders; }
void parser_enter(void) { ++parsers; }
void mds_events_enter(void) { ++expanders; }

static unsigned char *read_input(const char *path, uint32_t *length) {
    FILE *file = fopen(path, "rb");
    REQUIRE(file && !fseek(file, 0, SEEK_END));
    long size = ftell(file);
    REQUIRE(size > 0 && (uintmax_t)size <= UINT32_MAX);
    unsigned char *bytes = malloc((size_t)size);
    REQUIRE(bytes && !fseek(file, 0, SEEK_SET));
    REQUIRE(fread(bytes, 1, (size_t)size, file) == (size_t)size);
    REQUIRE(!fclose(file));
    *length = (uint32_t)size;
    return bytes;
}

int main(int argc, char **argv) {
    REQUIRE(argc == 3);
    mds_info *info;
    unsigned char *input_bytes = NULL;
    uint32_t result;
    dxball_program program;
    dxball_program_initialize(&program, NULL);
    music_record *record = NULL;
    int from_file = !strcmp(argv[1], "file");
    if (from_file) {
        record = music_allocate_record(NULL, &program.music, 8);
        REQUIRE(record);
        music_name name = {argv[2]};
        result = music_load(NULL, &program.music, record, &name, 0, 1);
        REQUIRE(!result);
        info = (void *)record->stream;
        REQUIRE(dxball_mds_program(info) == &program);
    } else {
        REQUIRE(!strcmp(argv[1], "memory"));
        uint32_t length;
        input_bytes = read_input(argv[2], &length);
        mds_input input = {input_bytes};
        mds_output output = {0};
        result = fixture_mds_load(&output, &input, length, 2);
        REQUIRE(!result);
        info = output.value;
        REQUIRE(!dxball_mds_program(info));
        /* Parsing must own the expanded bytes, not borrow the input mapping. */
        memset(input_bytes, 0xa5, length);
        free(input_bytes);
    }
    REQUIRE(info && info->buffers && loaders == 1 && parsers == 1);
    printf("{\"result\":%" PRIu32 ",\"info\":[%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIuPTR ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 "],\"expand_calls\":%u,\"buffers\":[",
        result, info->signature, info->division, info->capacity, info->format,
        info->stream, info->flags, info->count, info->pending, expanders);
    for (uint32_t i = 0; i < info->count; ++i) {
        mds_buffer *buffer = &info->buffers->headers[i];
        REQUIRE(buffer->owner == info && !buffer->next);
        REQUIRE(buffer->event.data == buffer->payload);
        REQUIRE(buffer->event.used <= buffer->event.capacity);
        printf("%s{\"capacity\":%" PRIu32 ",\"used\":%" PRIu32 ",\"flags\":%" PRIu32 ",\"payload\":\"",
            i ? "," : "", buffer->event.capacity, buffer->event.used, buffer->flags);
        for (uint32_t j = 0; j < buffer->event.used; ++j) printf("%02x", buffer->event.data[j]);
        fputs("\"}", stdout);
    }
    /* Actual storage services, without inventing a MIDI device for release. */
    mds_memory *memory = stream_allocation(NULL, info->buffers);
    REQUIRE(!stream_unlock(NULL, memory));
    REQUIRE(!stream_free_buffers(NULL, memory));
    REQUIRE(!stream_free_info(NULL, info));
    if (record) music_free_record(NULL, &program.music, record);
    puts("]}");
    return 0;
}
