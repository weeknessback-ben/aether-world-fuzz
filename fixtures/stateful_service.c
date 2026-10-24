/* Fixture: a stateful request/response service driven over stdin.
 * One newline-delimited command per line. The defect is reachable only by a
 * specific ORDER of commands, so single-input mutation cannot find it and the
 * stateful sequence strategy can.
 *
 *   AUTH <token>   -> requires token "letmein", moves NEW -> READY
 *   OPEN <name>    -> READY -> OPEN, records the handle
 *   WRITE <data>   -> allowed in OPEN
 *   CLOSE          -> OPEN -> READY, frees the handle
 *   COMMIT         -> only valid in OPEN; after a CLOSE it touches the freed
 *                     handle, which is the planted use-after-free
 *   QUIT           -> exit
 *
 * Prints a status line per command so response classification has a signal. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum State { ST_NEW, ST_READY, ST_OPEN };

int main(void) {
    char line[512];
    enum State st = ST_NEW;
    char *handle = NULL;
    int closed = 0;

    while (fgets(line, sizeof line, stdin)) {
        size_t L = strlen(line);
        while (L && (line[L - 1] == '\n' || line[L - 1] == '\r')) line[--L] = 0;

        if (!strncmp(line, "AUTH ", 5)) {
            if (st != ST_NEW) { puts("550 bad state"); continue; }
            if (strcmp(line + 5, "letmein")) { puts("530 denied"); continue; }
            st = ST_READY; puts("230 ok");
        } else if (!strncmp(line, "OPEN ", 5)) {
            if (st != ST_READY) { puts("550 bad state"); continue; }
            free(handle);
            handle = strdup(line + 5);
            if (!handle) return 1;
            closed = 0; st = ST_OPEN; puts("250 opened");
        } else if (!strncmp(line, "WRITE ", 6)) {
            if (st != ST_OPEN) { puts("550 bad state"); continue; }
            puts("200 written");
        } else if (!strcmp(line, "CLOSE")) {
            if (st != ST_OPEN) { puts("550 bad state"); continue; }
            free(handle);
            closed = 1;          /* handle deliberately left dangling */
            st = ST_READY; puts("250 closed");
        } else if (!strcmp(line, "COMMIT")) {
            /* Known defect: COMMIT does not re-check the handle's lifetime,
             * so AUTH / OPEN / CLOSE / COMMIT reads freed memory. */
            if (closed && handle) {
                printf("226 commit %c\n", handle[0]);
                abort();
            }
            if (st != ST_OPEN) { puts("550 bad state"); continue; }
            puts("226 commit");
        } else if (!strcmp(line, "QUIT")) {
            puts("221 bye"); break;
        } else {
            puts("500 unknown");
        }
    }
    free(handle);
    return 0;
}
