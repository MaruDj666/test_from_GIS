#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct node;
void buildHuffmanTree(struct node **tree);
void fillTable(int codeTable[], struct node *tree, int Code);
void invertCodes(int codeTable[], int codeTable2[]);
void compressFile(FILE *input, FILE *output, int codeTable[]);

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    __AFL_INIT();

    unsigned char *input_buf = __AFL_FUZZ_TESTCASE_BUF;

    /* Build tree once outside the loop — it's deterministic and expensive */
    struct node *tree = NULL;
    int codeTable[27], codeTable2[27];
    buildHuffmanTree(&tree);
    fillTable(codeTable, tree, 0);
    invertCodes(codeTable, codeTable2);

    while (__AFL_LOOP(10)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len == 0) continue;

        /*
         * Keep only valid characters for compressFile:
         *   'a'..'z' (97-122) and ' ' (32).
         * Unlike the previous version, invalid bytes are SKIPPED
         * instead of replaced with 'a'. This lets AFL discover all
         * 26 letter code-length variations and the space branch.
         */
        unsigned char *clean_buf = malloc(len + 2);
        if (!clean_buf) continue;
        size_t clean_len = 0;

        for (int i = 0; i < len; ++i) {
            unsigned char c = input_buf[i];
            if ((c >= 'a' && c <= 'z') || c == ' ') {
                clean_buf[clean_len++] = c;
            }
        }

        /* compressFile reads until '\n' — always terminate */
        clean_buf[clean_len++] = '\n';

        FILE *input = fmemopen(clean_buf, clean_len, "r");
        if (!input) {
            free(clean_buf);
            continue;
        }
        FILE *output = fopen("/dev/null", "w");
        if (!output) {
            fclose(input);
            free(clean_buf);
            continue;
        }

        compressFile(input, output, codeTable2);

        fclose(output);
        fclose(input);
        free(clean_buf);
    }

    return 0;
}
