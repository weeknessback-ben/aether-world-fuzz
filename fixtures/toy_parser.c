/* Fixture: a small type-length-value parser with structural depth.
 * Used for structure-aware and grammar-driven strategies, and to measure
 * input validity (how often a generated input parses at all).
 *
 * Grammar:  record  := 'T' type:u8 len:u8 payload[len]
 *           stream  := "TLV1" record*
 * Exit codes: 0 fully parsed, 10 bad header, 11 truncated, 12 bad type,
 *             13 nesting too deep. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int depth;

static int parse_record(const unsigned char *b, size_t n, size_t *off) {
    if (*off + 3 > n) return 11;
    if (b[*off] != 'T') return 12;
    unsigned char type = b[*off + 1];
    unsigned char len  = b[*off + 2];
    *off += 3;
    if (*off + len > n) return 11;

    switch (type) {
        case 1: /* integer */ break;
        case 2: /* string  */ break;
        case 3: { /* nested stream */
            if (++depth > 4) { depth--; return 13; }
            size_t end = *off + len, inner = *off;
            while (inner < end) {
                int r = parse_record(b, end, &inner);
                if (r) { depth--; return r; }
            }
            depth--;
            break;
        }
        default: return 12;
    }
    *off += len;
    return 0;
}

int main(void) {
    unsigned char b[8192];
    size_t n = fread(b, 1, sizeof b, stdin);
    if (n < 4 || memcmp(b, "TLV1", 4) != 0) return 10;

    size_t off = 4;
    while (off < n) {
        int r = parse_record(b, n, &off);
        if (r) return r;
    }
    return 0;
}
