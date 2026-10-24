/* Fixture: emits far more output than any log budget should keep, including
 * NUL bytes and a fake sanitizer banner. Verifies that log capture is bounded
 * and that crash classification is not fooled by target-controlled text. */
#include <stdio.h>
#include <string.h>

int main(void) {
    unsigned char b[64];
    size_t n = fread(b, 1, sizeof b, stdin);

    /* Target-controlled text that mimics a real sanitizer report. The engine
     * must not classify this as a sanitizer finding: it arrives on stdout and
     * the process exits cleanly. */
    printf("==1234==ERROR: AddressSanitizer: heap-use-after-free on address 0x0\n");
    for (int i = 0; i < 20000; i++) {
        printf("line %d padding padding padding\n", i);
        if (i % 1000 == 0) fwrite("\0\0\0\0", 1, 4, stdout);
    }
    fflush(stdout);
    return n > 0 && b[0] == 'Q' ? 3 : 0;
}
