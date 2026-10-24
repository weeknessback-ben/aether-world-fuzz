/*
 * AETHER coverage runtime - shared memory ABI.
 *
 * This header is the contract between the AETHER engine (Rust) and the
 * instrumented target process (C). Both sides must agree on it exactly;
 * the engine refuses to use a region whose magic/version/sizes disagree.
 */
#ifndef AETHER_RT_H
#define AETHER_RT_H

#include <stdint.h>

#define AETHER_SHM_MAGIC    0xAE12E401u
#define AETHER_SHM_VERSION  1u

/* Edge map size. Power of two so the engine can mask instead of modulo. */
#define AETHER_MAP_SIZE     65536u
#define AETHER_MAP_MASK     (AETHER_MAP_SIZE - 1u)

/* Capacity of the comparison-operand ring buffer. */
#define AETHER_CMP_CAP      4096u

/* Fork server control/status descriptors, inherited across exec. */
#define AETHER_FORKSRV_CTL_FD 198
#define AETHER_FORKSRV_ST_FD  199

/* Fork server handshake word written by the target to the status pipe. */
#define AETHER_FS_HELLO     0x41455448u /* "AETH" */

/* Values for AetherShmHeader.flags, set by the runtime. */
#define AETHER_FLAG_CMPLOG_ON   0x1u
#define AETHER_FLAG_CMP_OVERFLOW 0x2u

/* One recorded comparison. `is_const` marks operand `v0` as a compile-time
 * constant, which makes the pair usable for input-to-state substitution. */
typedef struct {
    uint64_t v0;
    uint64_t v1;
    uint32_t pc_hash;
    uint8_t  width;    /* operand width in bytes: 1,2,4,8 */
    uint8_t  is_const;
    uint8_t  _pad[2];
} AetherCmpEntry;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t map_size;
    uint32_t cmp_cap;
    uint64_t exec_count;   /* incremented by the runtime on each target run */
    uint32_t cmp_len;      /* entries written into cmp[] this run */
    uint32_t flags;
    uint32_t guard_count;  /* instrumented edges registered by the module(s) */
    uint32_t _pad;
} AetherShmHeader;

/* Full region layout: header, then the edge map, then the cmp ring. */
typedef struct {
    AetherShmHeader hdr;
    uint8_t         map[AETHER_MAP_SIZE];
    AetherCmpEntry  cmp[AETHER_CMP_CAP];
} AetherShm;

#endif /* AETHER_RT_H */
