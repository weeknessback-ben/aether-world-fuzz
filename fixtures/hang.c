/* Fixture: deliberate hang, to exercise timeout handling and child cleanup.
 * Spins rather than sleeping so SIGKILL is the only way out. */
#include <stdio.h>

int main(void) {
    unsigned char b[64];
    size_t n = fread(b, 1, sizeof b, stdin);
    if (n > 0 && b[0] == 'H') {
        volatile unsigned long x = 0;
        for (;;) x++;
    }
    return 0;
}
