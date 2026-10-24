/* Fixture: reads its input from the path given as argv[1] rather than stdin.
 * Exercises file-arg input mode and the @@ placeholder substitution, which no
 * other fixture covers. Crashes on the exact bytes "BOOM" so the two delivery
 * mechanisms can be compared on an identical verdict. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) return 20;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 21;

    unsigned char b[4096];
    size_t n = fread(b, 1, sizeof b, f);
    fclose(f);

    if (n == 4 && !memcmp(b, "BOOM", 4)) abort();
    if (n == 0) return 1;
    return b[0] == 'z' ? 2 : 0;
}
