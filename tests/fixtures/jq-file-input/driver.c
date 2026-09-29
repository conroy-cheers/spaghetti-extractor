#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "portable-component-implementation.h"
#include "file-input.h"
#include "native-entry.h"
#include "allocation-observer.h"

static unsigned calls;
static jv replacement(const char *filename, int raw) {
    spx_file_input_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {filename, raw};
    struct spx_opaque_output_v5 output;
    ++calls;
    lifted_file_input_load(&context, &input, &output);
    return output.value;
}

static unsigned digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    exit(2);
}

static void emit(jv value) {
    allocation_observer_pause(1);
    printf("{\"kind\":%d,\"value\":", jv_get_kind(value));
    if (!jv_is_valid(value)) value = jv_invalid_get_msg(value);
    if (!jv_is_valid(value)) { jv_free(value); value = jv_null(); }
    jv text = jv_dump_string(value, JV_PRINT_SORTED);
    fputs(jv_string_value(text), stdout);
    jv_free(text);
    putchar('}');
    allocation_observer_pause(0);
}

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    int source = !strcmp(argv[1], "source");
    if (source && !spx_install_component_entry((void (*)(void))replacement)) return 85;
    FILE *file = fopen("fixture.bin", "wb");
    if (!file) return 82;
    const char *hex = argv[2];
    if (hex[0] == '@') {
        int json = !strcmp(hex, "@json-utf8");
        if (json) fputc('"', file);
        for (int i = 0; i < (json ? 4094 : 4095); ++i) fputc('a', file);
        hex = !strcmp(hex, "@raw-cr") ? "0d0a62" :
            json ? "f09f9982220d0a" : "f09f99820d0a7a";
    }
    size_t length = strlen(hex);
    if (length % 2) return 2;
    for (size_t i = 0; i < length; i += 2)
        if (fputc((digit(hex[i]) << 4) | digit(hex[i + 1]), file) == EOF) return 82;
    if (fclose(file)) return 82;
    CreateDirectoryA("directory", NULL);
    allocation_observer_begin();
    fputs("{\"values\":[", stdout);
    for (int repeat = 0; repeat < 3; ++repeat) {
        if (repeat) putchar(',');
        emit(jv_load_file(argv[4], atoi(argv[3])));
    }
    fputs("],\"allocation_lifetime\":", stdout);
    allocation_observer_finish(stdout);
    puts("}");
    fprintf(stderr, "authored-file-input-calls=%u\n", calls);
    return source && (calls != 3 || !spx_install_component_entry_intact()) ? 85 : 0;
}
