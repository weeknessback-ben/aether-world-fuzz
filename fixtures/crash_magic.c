/* Fixture: nested magic-byte ladder guarding a deliberate abort().
 * Exercises comparison-guided mutation: each gate is a constant compare, so
 * CmpLog substitution should walk the ladder far faster than blind mutation.
 * Reads the whole input from stdin. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    unsigned char b[4096];
    size_t n = fread(b, 1, sizeof b, stdin);
    if (n < 8) return 0;

    unsigned int magic;
    memcpy(&magic, b, 4);
    if (magic != 0xDEADBEEFu) return 1;

    unsigned short ver;
    memcpy(&ver, b + 4, 2);
    if (ver != 0x0203) return 2;

    if (b[6] != 'Z') return 3;
    if (b[7] != '!') return 4;

    /* Known defect: reachable only past all four gates. */
    abort();
}
