#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "fline.h"


__AFL_FUZZ_INIT();

int main (int argc, char **argv)
{
    __AFL_INIT();
    unsigned char *input_buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10))
    {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        FILE *f1 = fmemopen(input_buf, len, "r");
        fline_t *vip = fline_start(f1);
        size_t vep = (unsigned long)len;
        fline_delim(vip, &vep, len);
        fline(vip, &vep);
        fline_delim(vip, &vep, '\n');
      
    }
    return 0;
}
