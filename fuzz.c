#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "fline.h"

__AFL_FUZZ_INIT();

int main(int argc, char **argv)
{
    __AFL_INIT();
    unsigned char *input_buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(1000))
    {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len < 1)
            continue;

        /*
         * Byte 0 selects the delimiter:
         *   0xFF -> delim = -1  (skips memchr, reads entire content at once)
         *   else -> delim = byte value (standard delimiter search)
         * Bytes 1..len-1 are the content fed to fline.
         */
        int delim = (input_buf[0] == 0xFF) ? -1 : (int)input_buf[0];
        unsigned char *content     = input_buf + 1;
        int            content_len = len - 1;

        FILE *f1 = fmemopen(content, content_len > 0 ? content_len : 1, "r");
        if (f1 == NULL)
            continue;
        if (content_len == 0)
            fseek(f1, 0, SEEK_END);

        fline_t *state = fline_start(f1);
        if (state == NULL) {
            fclose(f1);
            continue;
        }

        size_t rlen;
        char  *line;

        /* Pass 1: drain all tokens with chosen delimiter */
        while ((line = fline_delim(state, &rlen, delim)) != NULL && rlen > 0)
            ;
        /* Extra call after EOF — covers fline.c:49-52 (in==NULL fast return) */
        fline_delim(state, &rlen, delim);
        fline_remains(state, &rlen);

        /* Pass 2: reuse state with new FILE* and drain using fline() wrapper */
        FILE *f2 = fmemopen(input_buf, len, "r");
        if (f2 != NULL) {
            fline_reuse(state, f2);
            fline_remains(state, &rlen);
            while ((line = fline(state, &rlen)) != NULL && rlen > 0)
                ;
            fline_remains(state, &rlen);
            fclose(f2);
        }

        fline_end(state);
        fclose(f1);
    }

    return 0;
}
