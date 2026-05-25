// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright (c) 2026 Yousef Mahmoud
 * <yosefkhalil610@gmail.com>
 *
 * SPSC ring over mmap'd shm. producer: DR client, consumer: rust engine.
 * head/tail on separate cache lines. 32 byte v3 events. */

#ifndef RTMAP_BRIDGE_H
#define RTMAP_BRIDGE_H

#include <stdint.h>
#include <stdatomic.h>
#include <string.h>

#define RTMAP_CACHE_LINE    64
#define RTMAP_MAGIC         0x52544D4150425200ULL  /* "RTMAPBR\0" */
#define RTMAP_PROTO_VERSION 3
#define RTMAP_SHM_ENV       "RTMAP_SHM_PATH"

/*hash me baby*/
#define _MV_FNV(h, v) do { \
    uint32_t _v = (uint32_t)(v); \
    for (int _i = 0; _i < 4; _i++) { \
        (h) ^= (_v >> (_i * 8)) & 0xFF; \
        (h) *= 0x01000193u; \
    } \
} while(0)

#define RTMAP_EVENT_WRITE    0
#define RTMAP_EVENT_READ     1
#define RTMAP_EVENT_CALL     2
#define RTMAP_EVENT_RETURN   3
#define RTMAP_EVENT_OVERFLOW 4
#define RTMAP_EVENT_REG_SNAPSHOT 5
#define RTMAP_EVENT_CACHE_MISS   6
#define RTMAP_EVENT_MODULE_LOAD  7
#define RTMAP_EVENT_TAIL_CALL    8
#define RTMAP_EVENT_ALLOC        9
#define RTMAP_EVENT_FREE        10
#define RTMAP_EVENT_BB_ENTRY    11
#define RTMAP_EVENT_RELOAD      12
#define RTMAP_EVENT_PROCESS_FORK 13
#define RTMAP_EVENT_SHARED_MAP   14

#define RTMAP_REG_SNAPSHOT_SLOTS 7

#define RTMAP_REG_RAX    0
#define RTMAP_REG_RBX    1
#define RTMAP_REG_RCX    2
#define RTMAP_REG_RDX    3
#define RTMAP_REG_RSI    4
#define RTMAP_REG_RDI    5
#define RTMAP_REG_RBP    6
#define RTMAP_REG_RSP    7
#define RTMAP_REG_R8     8
#define RTMAP_REG_R9     9
#define RTMAP_REG_R10   10
#define RTMAP_REG_R11   11
#define RTMAP_REG_R12   12
#define RTMAP_REG_R13   13
#define RTMAP_REG_R14   14
#define RTMAP_REG_R15   15
#define RTMAP_REG_RIP   16
#define RTMAP_REG_RFLAGS 17
#define RTMAP_REG_COUNT 18

#define RTMAP_BP_LOW_WATER   3
#define RTMAP_BP_SHED_READS  6  /* 6/8: shed reads + bb_entry */
#define RTMAP_BP_SHED_WRITES 7  /* 7/8: shed non-bloom writes */

#define RTMAP_BLOOM_U64S    512   /* 4KB = 32768 bits */
#define RTMAP_BLOOM_BITS    (RTMAP_BLOOM_U64S * 64)

#define RTMAP_RAW_TLS_SLOTS     8
#define RTMAP_RAW_SLOT_RING     0
#define RTMAP_RAW_SLOT_HEAD     1
#define RTMAP_RAW_SLOT_SEQ      2
#define RTMAP_RAW_SLOT_TID      3
#define RTMAP_RAW_SLOT_BP       4
#define RTMAP_RAW_SLOT_SCRATCH  5
#define RTMAP_RAW_SLOT_RDBUF    6
#define RTMAP_RAW_SLOT_GUARD    7

#define RTMAP_HEAD_FLUSH_MASK  0x3F

/* two cache lines per thread: hot path + ambient stats */
typedef struct __attribute__((aligned(RTMAP_CACHE_LINE))) {
    /* cl0: hot */
    uint64_t scratch[2];
    uint64_t ring_data;
    uint32_t ring_mask;
    uint32_t nesting_level;
    uint64_t stat_reentrant_drops;
    uint64_t stat_truncated_writes;
    uint64_t _cl0_reserved[2];
    /* cl1: stats */
    uint64_t stat_inline_writes;
    uint64_t stat_reads;
    uint64_t stat_reloads;
    uint64_t stat_calls;
    uint64_t stat_returns;
    uint64_t stat_tail_calls;
    uint64_t stat_dropped;
    uint64_t ccc_audit_ctr;
} rtmap_scratch_pad_t;

_Static_assert(sizeof(rtmap_scratch_pad_t) == 2 * RTMAP_CACHE_LINE, "");

/* v2 event (compat) */
typedef struct __attribute__((aligned(32))) {
    uint64_t addr;
    uint32_t size;
    uint16_t thread_id;
    uint16_t seq;
    uint64_t value;
    uint64_t kind_flags;
} rtmap_event_t;

_Static_assert(sizeof(rtmap_event_t) == 32, "");

/* v3 event. 32 bit seq wraps ~86s at 50M ev/s; use modular arithmetic. */
typedef struct __attribute__((aligned(32))) {
    uint64_t addr;
    uint32_t size;
    uint16_t thread_id;
    uint16_t seq_lo;
    uint64_t value;
    uint32_t kind_flags;  /* kind:8 | flags:8 | seq_hi:16 */
    uint32_t rip_lo;      /* app PC offset from module base */
} rtmap_event_v3_t;

_Static_assert(sizeof(rtmap_event_v3_t) == 32, "");

static inline uint8_t rtmap_v3_kind(const rtmap_event_v3_t *e) {
    return (uint8_t)(e->kind_flags & 0xFF);
}
static inline uint32_t rtmap_v3_seq(const rtmap_event_v3_t *e) {
    return (uint32_t)e->seq_lo | ((uint32_t)(e->kind_flags >> 16) << 16);
}
static inline uint32_t rtmap_v3_make_kf(uint8_t kind, uint8_t flags, uint16_t seq_hi) {
    return (uint32_t)kind | ((uint32_t)flags << 8) | ((uint32_t)seq_hi << 16);
}

static inline uint8_t rtmap_event_kind(const rtmap_event_t *e) {
    return (uint8_t)(e->kind_flags & 0xFF);
}
static inline uint8_t rtmap_event_flags(const rtmap_event_t *e) {
    return (uint8_t)((e->kind_flags >> 8) & 0xFF);
}
static inline uint64_t rtmap_make_kind_flags(uint8_t kind, uint8_t flags) {
    return (uint64_t)kind | ((uint64_t)flags << 8);
}

#define RTMAP_FLAG_DROP_ON_FULL  0x0
#define RTMAP_FLAG_SPIN_ON_FULL  0x1

/* per-event flags (bits 8-15 of kind_flags) */
#define RTMAP_FLAG_TRUNCATED     0x80
#define RTMAP_FLAG_COMPOUND      0x40  /* header of multi-slot wide write */
#define RTMAP_FLAG_CONTINUATION  0x20  /* continuation slot of compound write */
#define RTMAP_COMPOUND_MAX_SLOTS 8     /* header + 7 continuations = 64B max */

/* ring lifecycle status (ring_header.status) */
#define MV_STATUS_ACTIVE          0
#define MV_STATUS_TERMINAL        1

typedef struct {
    uint64_t magic;
    uint32_t capacity;
    uint32_t entry_size;
    uint64_t flags;
    _Atomic uint32_t backpressure;
    uint32_t proto_version;
    _Atomic uint32_t status;
    uint8_t  _pad0[RTMAP_CACHE_LINE - 36];
    _Alignas(RTMAP_CACHE_LINE) _Atomic uint64_t head;
    uint8_t  _pad1[RTMAP_CACHE_LINE - sizeof(_Atomic uint64_t)];
    _Alignas(RTMAP_CACHE_LINE) _Atomic uint64_t tail;
    uint8_t  _pad2[RTMAP_CACHE_LINE - sizeof(_Atomic uint64_t)];
} rtmap_ring_header_t;

_Static_assert(sizeof(rtmap_ring_header_t) == 3 * RTMAP_CACHE_LINE, "");

static inline rtmap_event_t *rtmap_ring_data(rtmap_ring_header_t *hdr) {
    return (rtmap_event_t *)((uint8_t *)hdr + sizeof(rtmap_ring_header_t));
}

static inline rtmap_event_v3_t *rtmap_ring_data_v3(rtmap_ring_header_t *hdr) {
    return (rtmap_event_v3_t *)((uint8_t *)hdr + sizeof(rtmap_ring_header_t));
}

static inline size_t rtmap_shm_size(uint32_t capacity) {
    return sizeof(rtmap_ring_header_t) + (size_t)capacity * sizeof(rtmap_event_v3_t);
}

/* must match engine-side rtmap_abi_hash() */
static inline uint32_t rtmap_build_hash_compute(void) {
    uint32_t h = 0x811c9dc5u;
    _MV_FNV(h, sizeof(rtmap_event_v3_t));
    _MV_FNV(h, offsetof(rtmap_event_v3_t, addr));
    _MV_FNV(h, offsetof(rtmap_event_v3_t, value));
    _MV_FNV(h, offsetof(rtmap_event_v3_t, kind_flags));
    _MV_FNV(h, offsetof(rtmap_event_v3_t, rip_lo));
    _MV_FNV(h, sizeof(rtmap_ring_header_t));
    _MV_FNV(h, offsetof(rtmap_ring_header_t, head));
    _MV_FNV(h, offsetof(rtmap_ring_header_t, tail));
    _MV_FNV(h, offsetof(rtmap_ring_header_t, status));
    _MV_FNV(h, sizeof(rtmap_scratch_pad_t));
    _MV_FNV(h, offsetof(rtmap_scratch_pad_t, nesting_level));
    _MV_FNV(h, offsetof(rtmap_scratch_pad_t, stat_reentrant_drops));
    _MV_FNV(h, offsetof(rtmap_scratch_pad_t, stat_truncated_writes));
    return h;
}

static inline int rtmap_push_ex_flags(rtmap_ring_header_t *ring,
                                        uint64_t addr, uint32_t size,
                                        uint64_t value, uint8_t kind,
                                        uint8_t flags,
                                        uint16_t thread_id, uint32_t seq)
{
    const uint32_t mask = ring->capacity - 1;
    rtmap_event_v3_t *data = rtmap_ring_data_v3(ring);
    uint64_t h = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint64_t t = atomic_load_explicit(&ring->tail, memory_order_acquire);

    if (h - t >= ring->capacity) {
        if (!(ring->flags & RTMAP_FLAG_SPIN_ON_FULL))
            return -1;
        while (h - t >= ring->capacity) {
            __builtin_ia32_pause();
            t = atomic_load_explicit(&ring->tail, memory_order_acquire);
        }
    }

    uint64_t idx = h & mask;
    data[idx].addr       = addr;
    data[idx].size       = size;
    data[idx].thread_id  = thread_id;
    data[idx].seq_lo     = (uint16_t)(seq & 0xFFFF);
    data[idx].value      = value;
    data[idx].kind_flags = rtmap_v3_make_kf(kind, flags, (uint16_t)(seq >> 16));
    data[idx].rip_lo     = 0;

    atomic_store_explicit(&ring->head, h + 1, memory_order_release);
    return 0;
}

static inline int rtmap_push_ex(rtmap_ring_header_t *ring,
                                  uint64_t addr, uint32_t size,
                                  uint64_t value, uint8_t kind,
                                  uint16_t thread_id, uint32_t seq)
{
    return rtmap_push_ex_flags(ring, addr, size, value, kind, 0, thread_id, seq);
}

/* alloc/free with caller RIP for alloc-site type oracle */
static inline int rtmap_push_alloc(rtmap_ring_header_t *ring,
                                     uint64_t ptr, uint32_t size_lo,
                                     uint64_t size_full, uint8_t kind,
                                     uint16_t thread_id, uint32_t seq,
                                     uint32_t caller_rip_lo)
{
    const uint32_t mask = ring->capacity - 1;
    rtmap_event_v3_t *data = rtmap_ring_data_v3(ring);
    uint64_t h = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint64_t t = atomic_load_explicit(&ring->tail, memory_order_acquire);

    if (h - t >= ring->capacity) {
        if (!(ring->flags & RTMAP_FLAG_SPIN_ON_FULL))
            return -1;
        while (h - t >= ring->capacity) {
            __builtin_ia32_pause();
            t = atomic_load_explicit(&ring->tail, memory_order_acquire);
        }
    }

    uint64_t idx = h & mask;
    data[idx].addr       = ptr;
    data[idx].size       = size_lo;
    data[idx].thread_id  = thread_id;
    data[idx].seq_lo     = (uint16_t)(seq & 0xFFFF);
    data[idx].value      = size_full;
    data[idx].kind_flags = rtmap_v3_make_kf(kind, 0, (uint16_t)(seq >> 16));
    data[idx].rip_lo     = caller_rip_lo;

    atomic_store_explicit(&ring->head, h + 1, memory_order_release);
    return 0;
}

static inline int rtmap_push(rtmap_ring_header_t *ring,
                               uint64_t addr, uint32_t size, uint64_t value,
                               uint16_t thread_id, uint32_t seq)
{
    return rtmap_push_ex(ring, addr, size, value, RTMAP_EVENT_WRITE, thread_id, seq);
}

static inline int rtmap_push_reg_snapshot(rtmap_ring_header_t *ring,
                                            uint64_t insn_counter,
                                            const uint64_t regs[RTMAP_REG_COUNT],
                                            uint16_t thread_id, uint32_t seq)
{
    const uint32_t mask = ring->capacity - 1;
    rtmap_event_v3_t *data = rtmap_ring_data_v3(ring);

    uint64_t h = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint64_t t = atomic_load_explicit(&ring->tail, memory_order_acquire);
    if (h - t + RTMAP_REG_SNAPSHOT_SLOTS > ring->capacity)
        return -1;

    uint16_t seq_lo = (uint16_t)(seq & 0xFFFF);
    uint16_t seq_hi = (uint16_t)(seq >> 16);
    uint32_t kf = rtmap_v3_make_kf(RTMAP_EVENT_REG_SNAPSHOT, 0, seq_hi);
    uint64_t idx = h & mask;
    data[idx] = (rtmap_event_v3_t){ insn_counter, 0, thread_id, seq_lo, 0, kf, 0 };
    for (int s = 0; s < 6; s++) {
        idx = (h + 1 + s) & mask;
        data[idx] = (rtmap_event_v3_t){ regs[s*3], (uint32_t)regs[s*3+1], thread_id, 0,
                                          regs[s*3+2], kf, 0 };
    }

    atomic_store_explicit(&ring->head, h + RTMAP_REG_SNAPSHOT_SLOTS, memory_order_release);
    return 0;
}

static inline int rtmap_push_cache_miss(rtmap_ring_header_t *ring,
                                          uint64_t miss_addr,
                                          uint32_t cache_level,
                                          uint64_t sample_ip,
                                          uint16_t thread_id, uint32_t seq)
{
    return rtmap_push_ex(ring, miss_addr, cache_level, sample_ip,
                          RTMAP_EVENT_CACHE_MISS, thread_id, seq);
}

static inline int rtmap_pop(rtmap_ring_header_t *ring,
                              rtmap_event_v3_t *out_event)
{
    const uint32_t mask = ring->capacity - 1;
    rtmap_event_v3_t *data = rtmap_ring_data_v3(ring);
    uint64_t t = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    uint64_t h = atomic_load_explicit(&ring->head, memory_order_acquire);
    if (t == h) return -1;
    *out_event = data[t & mask];
    atomic_store_explicit(&ring->tail, t + 1, memory_order_release);
    return 0;
}

#define RTMAP_IS_POW2(x) ((x) != 0 && ((x) & ((x) - 1)) == 0)

static inline void rtmap_ring_init(rtmap_ring_header_t *ring,
                                     uint32_t capacity, uint64_t flags)
{
    if (!RTMAP_IS_POW2(capacity)) {
        memset(ring, 0, sizeof(rtmap_ring_header_t));
        return;
    }
    memset(ring, 0, sizeof(rtmap_ring_header_t));
    ring->magic         = RTMAP_MAGIC;
    ring->capacity      = capacity;
    ring->entry_size    = sizeof(rtmap_event_v3_t);
    ring->flags         = flags;
    ring->proto_version = RTMAP_PROTO_VERSION;
    atomic_store_explicit(&ring->head, 0, memory_order_relaxed);
    atomic_store_explicit(&ring->tail, 0, memory_order_relaxed);
}

static inline uint32_t rtmap_ring_fill_eighths(rtmap_ring_header_t *ring)
{
    uint64_t h = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint64_t t = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    return (uint32_t)(((h - t) << 3) / ring->capacity);
}

/* shed reads and bb_entry under backpressure; lifecycle events always land */
static inline int rtmap_push_sampled(rtmap_ring_header_t *ring,
                                       uint64_t addr, uint32_t size,
                                       uint64_t value, uint8_t kind,
                                       uint16_t thread_id, uint32_t seq)
{
    if ((kind == RTMAP_EVENT_READ || kind == RTMAP_EVENT_BB_ENTRY) &&
        atomic_load_explicit(&ring->backpressure, memory_order_relaxed))
        return 1;
    return rtmap_push_ex(ring, addr, size, value, kind, thread_id, seq);
}

static inline void rtmap_push_overflow(rtmap_ring_header_t *ring,
                                         uint64_t insn_counter,
                                         uint16_t thread_id, uint32_t seq)
{
    rtmap_push_ex(ring, insn_counter, 0, 0, RTMAP_EVENT_OVERFLOW, thread_id, seq);
}

/* ctl ring: thread discovery */

#define RTMAP_CTL_SHM_NAME     "/rtmap_ctl"
#define RTMAP_CTL_SHM_FMT      "/rtmap_ctl_%u"
#define RTMAP_RING_SHM_FMT     "/rtmap_ring_%u_%u"  /* pid, tid */
#define RTMAP_CTL_MAGIC        0x5254435430303032ULL  /* "RTCT0002" */
#define RTMAP_MAX_THREADS      256
#define RTMAP_RING_NAME_LEN    48

#define RTMAP_THREAD_RING_CAPACITY  (1u << 20)
_Static_assert(RTMAP_IS_POW2(RTMAP_THREAD_RING_CAPACITY), "ring capacity must be power-of-two");

#define RTMAP_THREAD_STATE_EMPTY        0
#define RTMAP_THREAD_STATE_ACTIVE       1
#define RTMAP_THREAD_STATE_DEAD         2
#define RTMAP_THREAD_STATE_INITIALIZING 3

typedef struct {
    _Atomic uint32_t state;
    uint16_t thread_id;
    uint16_t _reserved;
    char     shm_name[RTMAP_RING_NAME_LEN];
} rtmap_thread_entry_t;

_Static_assert(sizeof(rtmap_thread_entry_t) == 56, "thread entry sizing");

typedef struct {
    uint64_t magic;
    uint32_t proto_version;
    _Atomic uint32_t thread_count;
    uint32_t max_threads;
    uint32_t build_hash;
    uint32_t target_pid;
    uint32_t parent_pid;        /* 0 for root process */
    _Atomic uint32_t tripwire_hit;  /* tracer sets to 1 on tripwire entry */
    uint32_t _ctl_reserved;
    uint64_t priority_bloom[RTMAP_BLOOM_U64S];
    rtmap_thread_entry_t threads[RTMAP_MAX_THREADS];
} rtmap_ctl_header_t;

static inline uint32_t rtmap_bloom_h1(uint64_t addr) {
    uint32_t h = 0x811c9dc5u;
    for (int i = 0; i < 8; i++) { h ^= (uint8_t)(addr >> (i * 8)); h *= 0x01000193u; }
    return h % RTMAP_BLOOM_BITS;
}
static inline uint32_t rtmap_bloom_h2(uint64_t addr) {
    uint32_t h = 0x01000193u;
    for (int i = 0; i < 8; i++) { h ^= (uint8_t)(addr >> (i * 8)); h *= 0x811c9dc5u; }
    return h % RTMAP_BLOOM_BITS;
}
static inline void rtmap_bloom_insert(uint64_t *bloom, uint64_t addr) {
    uint32_t b1 = rtmap_bloom_h1(addr);
    uint32_t b2 = rtmap_bloom_h2(addr);
    bloom[b1 / 64] |= (1ULL << (b1 % 64));
    bloom[b2 / 64] |= (1ULL << (b2 % 64));
}
static inline int rtmap_bloom_query(const uint64_t *bloom, uint64_t addr) {
    uint32_t b1 = rtmap_bloom_h1(addr);
    uint32_t b2 = rtmap_bloom_h2(addr);
    return (bloom[b1 / 64] & (1ULL << (b1 % 64))) &&
           (bloom[b2 / 64] & (1ULL << (b2 % 64)));
}

static inline size_t rtmap_ctl_shm_size(void) {
    return sizeof(rtmap_ctl_header_t);
}

static inline void rtmap_ctl_init(rtmap_ctl_header_t *ctl) {
    memset(ctl, 0, sizeof(rtmap_ctl_header_t));
    ctl->magic = RTMAP_CTL_MAGIC;
    ctl->proto_version = RTMAP_PROTO_VERSION;
    ctl->build_hash = rtmap_build_hash_compute();
    ctl->max_threads = RTMAP_MAX_THREADS;
    atomic_store_explicit(&ctl->thread_count, 0, memory_order_relaxed);
}

static inline int rtmap_ctl_register_thread(rtmap_ctl_header_t *ctl,
                                               uint16_t thread_id,
                                               const char *ring_shm_name)
{
    /* reclaim DEAD slot via CAS -> INITIALIZING -> populate -> ACTIVE */
    for (uint32_t i = 0; i < ctl->max_threads; i++) {
        uint32_t expected = RTMAP_THREAD_STATE_DEAD;
        if (atomic_compare_exchange_strong_explicit(
                &ctl->threads[i].state, &expected,
                RTMAP_THREAD_STATE_INITIALIZING,
                memory_order_acq_rel, memory_order_relaxed)) {
            ctl->threads[i].thread_id = thread_id;
            strncpy(ctl->threads[i].shm_name, ring_shm_name, RTMAP_RING_NAME_LEN - 1);
            ctl->threads[i].shm_name[RTMAP_RING_NAME_LEN - 1] = '\0';
            atomic_store_explicit(&ctl->threads[i].state,
                                  RTMAP_THREAD_STATE_ACTIVE, memory_order_release);
            return (int)i;
        }
    }
    uint32_t idx = atomic_fetch_add_explicit(&ctl->thread_count, 1, memory_order_acq_rel);
    if (idx >= ctl->max_threads) {
        atomic_fetch_sub_explicit(&ctl->thread_count, 1, memory_order_relaxed);
        return -1;
    }
    rtmap_thread_entry_t *entry = &ctl->threads[idx];
    entry->thread_id = thread_id;
    strncpy(entry->shm_name, ring_shm_name, RTMAP_RING_NAME_LEN - 1);
    entry->shm_name[RTMAP_RING_NAME_LEN - 1] = '\0';
    atomic_store_explicit(&entry->state, RTMAP_THREAD_STATE_ACTIVE, memory_order_release);
    return (int)idx;
}

static inline void rtmap_ctl_mark_dead(rtmap_ctl_header_t *ctl, uint32_t idx) {
    if (idx < ctl->max_threads)
        atomic_store_explicit(&ctl->threads[idx].state, RTMAP_THREAD_STATE_DEAD, memory_order_release);
}

#endif /* RTMAP_BRIDGE_H */
