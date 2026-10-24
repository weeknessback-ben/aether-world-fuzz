/* Fixture: second implementation of the same decimal parser, with a planted
 * divergence: it accepts a leading '+' that implementation A rejects, and it
 * uses a different overflow threshold. The differential oracle should report
 * both as reproducible behavioural differences, not as crashes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char b[256];
    size_t n = fread(b, 1, sizeof b - 1, stdin);
    b[n] = 0;

    long acc = 0; int any = 0, neg = 0; size_t i = 0;
    if (b[i] == '-') { neg = 1; i++; }
    else if (b[i] == '+') { i++; }          /* divergence 1 */
    for (; b[i]; i++) {
        if (b[i] < '0' || b[i] > '9') break;
        any = 1;
        acc = acc * 10 + (b[i] - '0');
        if (acc > 9999999) { printf("OVERFLOW\n"); return 0; }  /* divergence 2 */
    }
    if (!any) { printf("INVALID\n"); return 0; }
    printf("VALUE %ld\n", neg ? -acc : acc);
    return 0;
}
