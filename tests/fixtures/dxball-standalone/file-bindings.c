/* Application paths and typed component views over the standard C file API.
 * A completed transfer retains the component's closed-file identity, just as
 * the original does; it does not grant permission to use the closed stream. */
#include "scores-runtime.h"
#include "board-runtime.h"
#include "program-state.h"
#include "file-storage.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* The stream can close while a component still retains its opaque identity.
 * Keep that token valid until its program owner is disposed. */
struct spx_opaque_scores_file_v5 { struct dxball_program_file file; };
struct spx_opaque_board_file_v5 { struct dxball_program_file file; };

int dxball_file_opened(dxball_program *p, struct dxball_program_file *file, FILE *stream) {
    if (!file) { if (stream) fclose(stream); return 0; }
    if (!stream) { free(file); return 0; }
    file->stream = stream;
    file->next = p->files;
    p->files = file;
    return 1;
}
void dxball_program_dispose_files(dxball_program *p) {
    while (p->files) {
        struct dxball_program_file *file = p->files;
        p->files = file->next;
        if (file->stream) fclose(file->stream);
        free(file);
    }
    p->scores.file = NULL;
    p->boards.file = NULL;
}

scores_file *scores_open(void *u, scores_state *s, uint32_t writing) {
    (void)u;
    scores_file *file = malloc(sizeof(*file));
    FILE *stream = fopen("score.dat", writing ? "wb" : "rb");
    return dxball_file_opened(DXBALL_OWNER(s, scores), file ? &file->file : NULL, stream) ? file : NULL;
}
void scores_read(void *u, scores_state *s, scores_file *file, scores_bytes *bytes) {
    (void)u; (void)s;
    size_t transferred = fread(bytes->data, 1, bytes->size, file->file.stream);
    (void)transferred;
}
void scores_write(void *u, scores_state *s, scores_file *file, scores_bytes *bytes) {
    (void)u; (void)s;
    (void)fwrite(bytes->data, 1, bytes->size, file->file.stream);
}
void scores_close(void *u, scores_state *s, scores_file *file) {
    (void)u; (void)s;
    (void)fclose(file->file.stream);
    file->file.stream = NULL;
}
uint32_t scores_access(void *u, scores_state *s, uint32_t mode) {
    (void)u; (void)s;
    return (uint32_t)access("score.dat", (int)mode);
}
board_file *board_open(void *u, board_set *s, board_name *name, uint32_t writing) {
    (void)u;
    board_file *file = malloc(sizeof(*file));
    FILE *stream = fopen(name->text, writing ? "wb" : "rb");
    return dxball_file_opened(DXBALL_OWNER(s, boards), file ? &file->file : NULL, stream) ? file : NULL;
}
void board_read(void *u, board_set *s, board_file *file, board_bytes *bytes) {
    (void)u; (void)s;
    size_t transferred = fread(bytes->data, 1, bytes->size, file->file.stream);
    (void)transferred;
}
void board_write(void *u, board_set *s, board_file *file, board_bytes *bytes) {
    (void)u; (void)s;
    (void)fwrite(bytes->data, 1, bytes->size, file->file.stream);
}
void board_close(void *u, board_set *s, board_file *file) {
    (void)u; (void)s;
    (void)fclose(file->file.stream);
    file->file.stream = NULL;
}
