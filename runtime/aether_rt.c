/*
 * AETHER coverage runtime.
 *
 * Linked into a target that was compiled with
 *   -fsanitize-coverage=trace-pc-guard[,trace-cmp]
 * It provides the SanitizerCoverage callbacks that clang/gcc emit calls to,
 * records AFL-style edge coverage plus comparison operands into a shared
 * memory region, and optionally serves an AETHER fork server so the engine
 * can spawn runs without paying execve() for every input.
 *
 * Deliberately dependency-free (libc only) and safe to run standalone: with
 * no AETHER_SHM_PATH in the environment the callbacks fall back to a private
 * in-process map, so an instrumented binary still behaves like a normal
 * program when run by hand.
 */
#define _GNU_SOURCE
#include "aether_rt.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* ---------------------------------------------------------------------- */
/* State                                                                   */
/* ---------------------------------------------------------------------- */

static AetherShm *g_shm;          /* shared with the engine, or private     */
static int        g_shm_is_shared;
static uint8_t   *g_map;          /* == g_shm->map, cached                  */
static uint32_t   g_guard_next = 1; /* guard 0 is reserved as "unassigned"  */

/* AFL-style previous location, shifted, for edge (not block) coverage. */
static __thread uint32_t g_prev_loc;

/* Set once the fork server is serving; used to avoid re-entering it. */
static int g_in_forkserver_child;

/* ---------------------------------------------------------------------- */
/* Shared memory setup                                                     */
/* ---------------------------------------------------------------------- */

/* Fall back to a private region so an instrumented binary runs standalone. */
static void aether_map_private(void)
{
    void *p = mmap(NULL, sizeof(AetherShm), PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        /* Without a map the callbacks must stay inert rather than crash. */
        g_shm = NULL;
        g_map = NULL;
        return;
    }
    g_shm = (AetherShm *)p;
    g_shm->hdr.magic = AETHER_SHM_MAGIC;
    g_shm->hdr.version = AETHER_SHM_VERSION;
    g_shm->hdr.map_size = AETHER_MAP_SIZE;
    g_shm->hdr.cmp_cap = AETHER_CMP_CAP;
    g_map = g_shm->map;
    g_shm_is_shared = 0;
}

static void aether_shm_init(void)
{
    if (g_shm) return;

    const char *path = getenv("AETHER_SHM_PATH");
    if (!path || !*path) {
        aether_map_private();
        return;
    }

    int fd = open(path, O_RDWR, 0600);
    if (fd < 0) {
        aether_map_private();
        return;
    }
    if (ftruncate(fd, (off_t)sizeof(AetherShm)) != 0) {
        /* The engine normally sizes the file; tolerate a read-only failure. */
    }
    void *p = mmap(NULL, sizeof(AetherShm), PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) {
        aether_map_private();
        return;
    }

    g_shm = (AetherShm *)p;
    g_shm->hdr.magic = AETHER_SHM_MAGIC;
    g_shm->hdr.version = AETHER_SHM_VERSION;
    g_shm->hdr.map_size = AETHER_MAP_SIZE;
    g_shm->hdr.cmp_cap = AETHER_CMP_CAP;
    g_map = g_shm->map;
    g_shm_is_shared = 1;

    if (getenv("AETHER_CMPLOG")) g_shm->hdr.flags |= AETHER_FLAG_CMPLOG_ON;
}

/* ---------------------------------------------------------------------- */
/* SanitizerCoverage: edge tracing                                         */
/* ---------------------------------------------------------------------- */

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop)
{
    aether_shm_init();
    if (start == stop || *start) return;
    for (uint32_t *g = start; g < stop; g++) *g = g_guard_next++;
    if (g_shm) g_shm->hdr.guard_count = g_guard_next - 1;
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard)
{
    if (!g_map) return;
    uint32_t cur = *guard;
    if (!cur) return;

    /* AFL's edge approximation: hash (prev, cur) into the map, then keep a
     * shifted copy of cur so A->B and B->A land in different buckets. */
    uint32_t idx = (cur ^ g_prev_loc) & AETHER_MAP_MASK;
    g_prev_loc = cur >> 1;

    /* Saturating 8-bit hit counter; the engine buckets these log2-style. */
    uint8_t v = g_map[idx];
    if (v != 255) g_map[idx] = (uint8_t)(v + 1);
}

/* gcc's -fsanitize-coverage=trace-pc emits this instead of the guard form. */
void __sanitizer_cov_trace_pc(void)
{
    if (!g_map) return;
    uint32_t cur = (uint32_t)(uintptr_t)__builtin_return_address(0);
    cur = (cur >> 4) ^ (cur << 8);
    uint32_t idx = (cur ^ g_prev_loc) & AETHER_MAP_MASK;
    g_prev_loc = cur >> 1;
    uint8_t v = g_map[idx];
    if (v != 255) g_map[idx] = (uint8_t)(v + 1);
}

/* ---------------------------------------------------------------------- */
/* SanitizerCoverage: comparison tracing (input-to-state / CmpLog)         */
/* ---------------------------------------------------------------------- */

static inline void aether_record_cmp(uint64_t v0, uint64_t v1, uint8_t width,
                                     uint8_t is_const, void *pc)
{
    if (!g_shm) return;
    if (!(g_shm->hdr.flags & AETHER_FLAG_CMPLOG_ON)) return;
    /* Equal operands carry no information for substitution. */
    if (v0 == v1) return;

    uint32_t n = g_shm->hdr.cmp_len;
    if (n >= AETHER_CMP_CAP) {
        g_shm->hdr.flags |= AETHER_FLAG_CMP_OVERFLOW;
        return;
    }

    uintptr_t p = (uintptr_t)pc;
    AetherCmpEntry *e = &g_shm->cmp[n];
    e->v0 = v0;
    e->v1 = v1;
    e->pc_hash = (uint32_t)((p >> 4) ^ (p << 7));
    e->width = width;
    e->is_const = is_const;
    e->_pad[0] = e->_pad[1] = 0;
    g_shm->hdr.cmp_len = n + 1;
}

#define AETHER_CMP_FN(name, type, width, is_const)                       \
    void name(type a, type b)                                            \
    {                                                                    \
        aether_record_cmp((uint64_t)a, (uint64_t)b, width, is_const,     \
                          __builtin_return_address(0));                  \
    }

AETHER_CMP_FN(__sanitizer_cov_trace_cmp1, uint8_t,  1, 0)
AETHER_CMP_FN(__sanitizer_cov_trace_cmp2, uint16_t, 2, 0)
AETHER_CMP_FN(__sanitizer_cov_trace_cmp4, uint32_t, 4, 0)
AETHER_CMP_FN(__sanitizer_cov_trace_cmp8, uint64_t, 8, 0)

/* The const_* variants guarantee the first operand is a literal, which is
 * exactly what we want to splice into the input. */
AETHER_CMP_FN(__sanitizer_cov_trace_const_cmp1, uint8_t,  1, 1)
AETHER_CMP_FN(__sanitizer_cov_trace_const_cmp2, uint16_t, 2, 1)
AETHER_CMP_FN(__sanitizer_cov_trace_const_cmp4, uint32_t, 4, 1)
AETHER_CMP_FN(__sanitizer_cov_trace_const_cmp8, uint64_t, 8, 1)

void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases)
{
    /* cases[0] = case count, cases[1] = operand bit width, then the labels. */
    if (!cases) return;
    uint64_t n = cases[0];
    uint8_t width = (uint8_t)(cases[1] / 8);
    if (width == 0 || width > 8) width = 8;
    if (n > 32) n = 32; /* bound the work on jump tables */
    for (uint64_t i = 0; i < n; i++)
        aether_record_cmp(cases[2 + i], val, width, 1,
                          __builtin_return_address(0));
}

/* Division and GEP hooks: accepted so that fully-instrumented objects link,
 * but the operands are not useful for substitution, so they are dropped. */
void __sanitizer_cov_trace_div4(uint32_t v) { (void)v; }
void __sanitizer_cov_trace_div8(uint64_t v) { (void)v; }
void __sanitizer_cov_trace_gep(uintptr_t v) { (void)v; }

/* ---------------------------------------------------------------------- */
/* Fork server                                                             */
/* ---------------------------------------------------------------------- */
/*
 * Protocol (all words are 4-byte host-endian):
 *   target -> status pipe : AETHER_FS_HELLO
 *   repeat:
 *     engine -> ctl pipe  : any word (a request to fork)
 *     target -> status    : child pid
 *     target -> status    : waitpid() status
 *
 * The engine resets the coverage map before writing the fork request, so the
 * map a run produces belongs to that run alone. On a timeout the engine
 * SIGKILLs the reported pid and still reads the status word, which keeps the
 * two sides in lockstep.
 */

static int aether_read_exact(int fd, void *buf, size_t n)
{
    uint8_t *p = (uint8_t *)buf;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r > 0) { p += r; n -= (size_t)r; continue; }
        if (r == 0) return -1;              /* engine closed the pipe */
        if (errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int aether_write_exact(int fd, const void *buf, size_t n)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (n) {
        ssize_t r = write(fd, p, n);
        if (r > 0) { p += r; n -= (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

__attribute__((constructor(1000))) static void aether_forkserver_init(void)
{
    aether_shm_init();

    if (g_in_forkserver_child) return;
    if (!getenv("AETHER_FORKSRV")) return;

    uint32_t hello = AETHER_FS_HELLO;
    if (aether_write_exact(AETHER_FORKSRV_ST_FD, &hello, 4) != 0) {
        /* No engine on the other end: run as an ordinary process. */
        return;
    }

    for (;;) {
        uint32_t cmd;
        if (aether_read_exact(AETHER_FORKSRV_CTL_FD, &cmd, 4) != 0) _exit(0);

        pid_t pid = fork();
        if (pid < 0) _exit(1);

        if (pid == 0) {
            /* Child: shed the fork server and continue into main().
             * setpgid makes the child its own process-group leader, so an
             * engine-side timeout can signal the whole group and reap
             * anything the target spawned without touching the fork server. */
            g_in_forkserver_child = 1;
            g_prev_loc = 0;
            setpgid(0, 0);
            close(AETHER_FORKSRV_CTL_FD);
            close(AETHER_FORKSRV_ST_FD);
            return;
        }

        uint32_t wpid = (uint32_t)pid;
        if (aether_write_exact(AETHER_FORKSRV_ST_FD, &wpid, 4) != 0) _exit(0);

        int status = 0;
        while (waitpid(pid, &status, 0) < 0) {
            if (errno != EINTR) { status = -1; break; }
        }

        uint32_t st = (uint32_t)status;
        if (aether_write_exact(AETHER_FORKSRV_ST_FD, &st, 4) != 0) _exit(0);
    }
}

/* ---------------------------------------------------------------------- */
/* Per-run bookkeeping                                                     */
/* ---------------------------------------------------------------------- */

__attribute__((destructor(1000))) static void aether_run_done(void)
{
    if (g_shm) __atomic_add_fetch(&g_shm->hdr.exec_count, 1, __ATOMIC_RELAXED);
    if (g_shm && !g_shm_is_shared && getenv("AETHER_PRINT_COVERAGE")) {
        /* Standalone diagnostic path; never used during a campaign. */
        uint32_t covered = 0;
        for (uint32_t i = 0; i < AETHER_MAP_SIZE; i++)
            if (g_shm->map[i]) covered++;
        char buf[128];
        int n = snprintf(buf, sizeof buf,
                         "[aether] edges=%u guards=%u\n",
                         covered, g_shm->hdr.guard_count);
        if (n > 0) (void)!write(2, buf, (size_t)n);
    }
}
