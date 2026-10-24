/* Fixture: reference implementation of a tiny decimal parser.
 * Paired with diff_impl_b.c for differential testing. Prints a canonical
 * result line that the differential oracle compares across both binaries. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char b[256];
    size_t n = fread(b, 1, sizeof b - 1, stdin);
    b[n] = 0;

    long acc = 0; int any = 0, neg = 0; size_t i = 0;
    if (b[i] == '-') { neg = 1; i++; }
    for (; b[i]; i++) {
        if (b[i] < '0' || b[i] > '9') break;
        any = 1;
        acc = acc * 10 + (b[i] - '0');
        if (acc > 1000000) { printf("OVERFLOW\n"); return 0; }
    }
    if (!any) { printf("INVALID\n"); return 0; }
    printf("VALUE %ld\n", neg ? -acc : acc);
    return 0;
}
