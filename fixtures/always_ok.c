/* Fixture: always exits 0 and never crashes. A campaign against this target
 * must report zero findings; used as the false-positive control. */
#include <stdio.h>

int main(void) {
    unsigned char b[1024];
    size_t n = fread(b, 1, sizeof b, stdin);
    (void)n;
    return 0;
}
