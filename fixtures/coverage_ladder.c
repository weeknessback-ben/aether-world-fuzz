/* Fixture: deterministic, measurable coverage gradient with no defect.
 * Each additional correct prefix byte unlocks one more basic block, so edge
 * counts map monotonically onto input quality. Used to verify that coverage
 * feedback and corpus ranking actually track progress. */
#include <stdio.h>

int main(void) {
    unsigned char b[256];
    size_t n = fread(b, 1, sizeof b, stdin);
    const char *key = "AETHER";
    int reached = 0;

    for (size_t i = 0; i < 6; i++) {
        if (i >= n || b[i] != (unsigned char)key[i]) break;
        reached++;
        switch (i) {
            case 0: __asm__ volatile(""); break;
            case 1: __asm__ volatile(""); break;
            case 2: __asm__ volatile(""); break;
            case 3: __asm__ volatile(""); break;
            case 4: __asm__ volatile(""); break;
            case 5: __asm__ volatile(""); break;
        }
    }
    return reached;
}
