/* Observe a real libvterm UTF-8 terminal; no target output model lives here. */
#include <vterm.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc!=3) return 125;
    int rows=atoi(argv[1]),columns=atoi(argv[2]);
    if (rows<1 || rows>1024 || columns<1 || columns>512) return 125;
    VTerm *terminal=vterm_new(rows,columns);if (!terminal) return 125;
    vterm_set_utf8(terminal,1);VTermScreen *screen=vterm_obtain_screen(terminal);
    vterm_screen_reset(screen,1);
    char bytes[4096];size_t count;
    while ((count=fread(bytes,1,sizeof(bytes),stdin)))
        if (vterm_input_write(terminal,bytes,count)!=count) return 125;
    if (ferror(stdin)) return 125;
    vterm_screen_flush_damage(screen);
    VTermPos cursor;vterm_state_get_cursorpos(vterm_obtain_state(terminal),&cursor);
    printf("{\"cursor\":[%d,%d],\"lines\":[",cursor.col,cursor.row);
    for (int row=0;row<rows;++row) {
        unsigned values[512];int end=0;
        for (int col=0;col<columns;++col) {
            VTermScreenCell cell;
            if (!vterm_screen_get_cell(screen,(VTermPos){row,col},&cell)) return 125;
            /* This observer compares one Unicode scalar per cell. Do not hide
             * combining or double-width output by dropping part of the cell. */
            if (cell.chars[1] || cell.width>1) return 125;
            values[col]=cell.chars[0] ? cell.chars[0] : 32;
            if (values[col]!=32) end=col+1;
        }
        printf("%s[",row ? ",":"");
        for (int col=0;col<end;++col) printf("%s%u",col ? ",":"",values[col]);
        putchar(']');
    }
    printf("]}\n");vterm_free(terminal);return ferror(stdout) ? 125 : 0;
}
