/* Fixture: heap buffer overflow, detected only under AddressSanitizer.
 * Length field is trusted past the end of the real allocation. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    unsigned char b[4096];
    size_t n = fread(b, 1, sizeof b, stdin);
    if (n < 4) return 0;
    if (b[0] != 'L' || b[1] != 'E' || b[2] != 'N') return 1;

    size_t claimed = (size_t)b[3];
    unsigned char *heap = (unsigned char *)malloc(16);
    if (!heap) return 1;

    /* Known defect: `claimed` may exceed the 16-byte allocation. */
    memset(heap, 0xAA, claimed);
    int r = heap[0];
    free(heap);
    return r & 1;
}
