/* Windows-1252/CRLF redirected streams and the observed single-writer console
 * text profile on POSIX UTF-8 terminals. Terminal entry is column zero with a
 * fixed winsize. Nonprinting C0/C1/DEL outside BEL/BS/TAB/CR/LF, resizing, other
 * writers and graphical attributes are not covered; see README.md. */
#include "windows-1252.h"
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#endif

typedef struct { unsigned column, width; int wrap_pending; } TargetTerminal;
typedef struct {
    FILE *file;
    unsigned char bytes[4096];
    size_t pending;
    int failed, error;
    TargetTerminal *terminal;
} TargetStream;
static TargetStream target_stdout, target_stderr;
#ifndef _WIN32
static TargetTerminal stdout_terminal, stderr_terminal;

static TargetTerminal *terminal_for(int fd, TargetTerminal *terminal) {
    struct winsize size={0};
    if (!isatty(fd)) return NULL;
    if (!ioctl(fd,TIOCGWINSZ,&size)) terminal->width=size.ws_col;
    return terminal;
}
#endif
static const uint16_t high_controls[32]={
    0x20ac,0x0081,0x201a,0x0192,0x201e,0x2026,0x2020,0x2021,
    0x02c6,0x2030,0x0160,0x2039,0x0152,0x008d,0x017d,0x008f,
    0x0090,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,
    0x02dc,0x2122,0x0161,0x203a,0x0153,0x009d,0x017e,0x0178};

void spx_target_console_init(void) {
    target_stdout.file=stdout; target_stderr.file=stderr;
#ifndef _WIN32
    int saved_errno=errno;
    target_stdout.terminal=terminal_for(STDOUT_FILENO,&stdout_terminal);
    target_stderr.terminal=terminal_for(STDERR_FILENO,&stderr_terminal);
    struct stat out,err;
    if (target_stdout.terminal && target_stderr.terminal && !fstat(STDOUT_FILENO,&out) &&
        !fstat(STDERR_FILENO,&err) && out.st_dev==err.st_dev && out.st_ino==err.st_ino &&
        out.st_rdev==err.st_rdev) target_stderr.terminal=target_stdout.terminal;
    errno=saved_errno;
#endif
    /* The backend owns buffering in target bytes, before CRLF expansion. */
    setvbuf(stdout,NULL,_IONBF,0); setvbuf(stderr,NULL,_IONBF,0);
#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY);
    _setmode(_fileno(stderr), _O_BINARY);
#endif
#ifdef SIGPIPE
    /* Windows reports a failed pipe write through its stream, not SIGPIPE. */
    signal(SIGPIPE, SIG_IGN);
#endif
}

static TargetStream *target_stream(FILE *file) {
    if (file==target_stdout.file) return &target_stdout;
    if (file==target_stderr.file) return &target_stderr;
    errno=EINVAL; return NULL;
}

static void terminal_wrap(TargetTerminal *terminal, unsigned char *text, size_t *count) {
    if (!terminal->wrap_pending) return;
    text[(*count)++]='\r';text[(*count)++]='\n';
    terminal->column=0;terminal->wrap_pending=0;
}

static void terminal_character(TargetTerminal *terminal, uint16_t value,
                               unsigned char *text, size_t *count) {
    if (terminal->wrap_pending) {
        /* Within a console write, CR/BS act on the last occupied column.
         * Completing the write commits the wrap. This distinction is visible
         * when _putws writes its string and trailing newline separately. */
        if (value=='\r' || value=='\b') terminal->wrap_pending=0;
        else terminal_wrap(terminal,text,count);
    }
    if (value>=0x800) {
        text[(*count)++]=(unsigned char)(0xe0|(value>>12));
        text[(*count)++]=(unsigned char)(0x80|((value>>6)&63));
    } else if (value>=0x80) text[(*count)++]=(unsigned char)(0xc0|(value>>6));
    text[(*count)++]=(unsigned char)(value<0x80 ? value : 0x80|(value&63));
    if (value=='\r' || value=='\n') terminal->column=0;
    else if (value=='\b') { if (terminal->column) --terminal->column; }
    else if (value>=0x20 && value!=0x7f) {
        if (terminal->width && terminal->column+1==terminal->width) terminal->wrap_pending=1;
        else ++terminal->column;
    }
}

static int flush(TargetStream *stream, int closing) {
    if (!stream->pending) return 0;
    /* A tab needs at most eight spaces and a preceding/final CRLF wrap. */
    unsigned char text[4096*12+2]; size_t count=0;
    for (size_t i=0;i<stream->pending;++i) {
        uint16_t value=stream->bytes[i];
        if (stream->terminal) {
            if (value=='\t') {
                terminal_wrap(stream->terminal,text,&count);
                unsigned spaces=8-stream->terminal->column%8;
                if (stream->terminal->width && spaces>stream->terminal->width-stream->terminal->column)
                    spaces=stream->terminal->width-stream->terminal->column;
                while (spaces--) terminal_character(stream->terminal,' ',text,&count);
                continue;
            }
            if (value=='\n') terminal_character(stream->terminal,'\r',text,&count);
            if (value>=0x80 && value<0xa0) value=high_controls[value-0x80];
            terminal_character(stream->terminal,value,text,&count);
        } else {
            if (value=='\n') text[count++]='\r';
            text[count++]=(unsigned char)value;
        }
    }
    if (stream->terminal) terminal_wrap(stream->terminal,text,&count);
    stream->pending=0;
    if (fwrite(text,1,count,stream->file)==count) return 0;
    int error=errno;
    /* The pinned MSVCRT reports EINVAL for a failed pipe write. Its first
     * broken-pipe failure during fclose alone is not a close failure. */
    if (error==EPIPE) {
        errno=EINVAL;
        if (closing && !stream->failed) return 0;
        error=EINVAL;
    }
    stream->failed=1; stream->error=error; return EOF;
}

static int emit(FILE *file, unsigned char value) {
    TargetStream *stream=target_stream(file);
    if (!stream) return EOF;
    if (stream->pending==sizeof(stream->bytes) && flush(stream,0)) return EOF;
    stream->bytes[stream->pending++]=value; return value;
}

int spx_target_fprintf(FILE *stream, const char *format, ...) {
    va_list args, copy;
    va_start(args, format); va_copy(copy, args);
    int length = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (length < 0) { va_end(args); return -1; }
    char *text = malloc((size_t)length + 1);
    if (!text) { va_end(args); return -1; }
    vsnprintf(text, (size_t)length + 1, format, args); va_end(args);
    int result = length;
    TargetStream *target=target_stream(stream);
    for (int i = 0; i < length; ++i) {
        if (emit(stream, (unsigned char)text[i]) == EOF) { result = -1; break; }
        /* The selected narrow console formatter writes characters through the
         * unbuffered stream. Its control/wrap boundaries differ from _putws. */
        if (target->terminal && flush(target,0)) { result=-1;break; }
    }
    /* Narrow diagnostic/presentation calls write within the call; wide output
     * retains the target's 4096-byte buffer until full or closed. */
    if (!target || flush(target,0)) result=-1;
    free(text);
    return result;
}

uint32_t spx_target_decode16(uint16_t *output, const unsigned char *input,
                           uint32_t size, unsigned char state[4]) {
    (void)state;
    if (!size) return UINT32_MAX - 1U;
    uint16_t value = *input;
    if (value>=0x80 && value<0xa0) value=high_controls[value-0x80];
    if (output) *output = value;
    return value ? 1U : 0U;
}

int spx_target_put16(FILE *stream, const uint16_t *text) {
    TargetStream *target=target_stream(stream);
    if (!target) return -1;
    int count = 0;
    for (; *text; ++text) {
        uint16_t value=*text;
        if (value>=0x80 && !(value>=0xa0 && value<=0xff)) {
            unsigned i=0;
            while (i<32 && high_controls[i]!=value) ++i;
            if (i==32) { errno=EILSEQ; return -1; }
            value=(uint16_t)(0x80+i);
        }
        if (emit(stream, (unsigned char)value) == EOF) return -1;
        ++count;
    }
    if (target->terminal && flush(target,0)) return -1;
    if (emit(stream, '\n')==EOF) return -1;
    if (target->terminal && flush(target,0)) return -1;
    return count+1;
}

uint32_t spx_target_stream_pending(FILE *stream) {
    TargetStream *target=target_stream(stream);
    return target ? (uint32_t)target->pending : 0;
}

int spx_target_stream_error(FILE *stream) {
    TargetStream *target=target_stream(stream);
    return target ? target->failed : 1;
}

int spx_target_stream_close(FILE *stream) {
    TargetStream *target=target_stream(stream);
    if (!target) return -1;
    flush(target,1);
    int closed=fclose(stream);
    target->file=NULL;
    if (target->failed) { errno=target->error; return -1; }
    return closed;
}

const char *spx_target_basename(const char *name) {
    const char *base = name;
    for (const char *p = name; *p; ++p)
        if (*p == '/' || *p == '\\') base = p + 1;
    return base;
}
