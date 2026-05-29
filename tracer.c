/* SPDX-License-Identifier: Apache-2.0 */


/* Ghost v3 tracer. Inline writes, clean call control flow */

#include <stddef.h>

#include "rtmap_bridge.h"

#define OFF_PAD_SCRATCH0       ((int)offsetof(rtmap_scratch_pad_t, scratch[0]))
#define OFF_PAD_SCRATCH1       ((int)offsetof(rtmap_scratch_pad_t, scratch[1]))
#define OFF_PAD_RING_MASK      ((int)offsetof(rtmap_scratch_pad_t, ring_mask))
#define OFF_PAD_RING_DATA      ((int)offsetof(rtmap_scratch_pad_t, ring_data))
#define OFF_PAD_STAT_INLINE    ((int)offsetof(rtmap_scratch_pad_t, stat_inline_writes))
#define OFF_PAD_STAT_READS     ((int)offsetof(rtmap_scratch_pad_t, stat_reads))
#define OFF_PAD_STAT_RELOADS   ((int)offsetof(rtmap_scratch_pad_t, stat_reloads))
#define OFF_PAD_STAT_CALLS     ((int)offsetof(rtmap_scratch_pad_t, stat_calls))
#define OFF_PAD_STAT_RETURNS   ((int)offsetof(rtmap_scratch_pad_t, stat_returns))
#define OFF_PAD_STAT_DROPPED   ((int)offsetof(rtmap_scratch_pad_t, stat_dropped))
#define OFF_PAD_AUDIT_CTR      ((int)offsetof(rtmap_scratch_pad_t, ccc_audit_ctr))
#define OFF_PAD_NESTING        ((int)offsetof(rtmap_scratch_pad_t, nesting_level))
#define OFF_PAD_REENTRANT      ((int)offsetof(rtmap_scratch_pad_t, stat_reentrant_drops))
#define OFF_PAD_TRUNCATED      ((int)offsetof(rtmap_scratch_pad_t, stat_truncated_writes))

_Static_assert(offsetof(rtmap_scratch_pad_t, scratch[0]) ==  0, "pad.scratch[0] drift");
_Static_assert(offsetof(rtmap_scratch_pad_t, ring_data)  == 16, "pad.ring_data drift");
_Static_assert(offsetof(rtmap_scratch_pad_t, ring_mask)  == 24, "pad.ring_mask drift");
_Static_assert(offsetof(rtmap_scratch_pad_t, nesting_level) == 28, "pad.nesting drift");
_Static_assert(offsetof(rtmap_scratch_pad_t, stat_reentrant_drops) == 32, "pad.reentrant drift");
_Static_assert(offsetof(rtmap_scratch_pad_t, stat_truncated_writes) == 40, "pad.truncated drift");
_Static_assert(offsetof(rtmap_scratch_pad_t, stat_inline_writes) == 64, "pad.stat_inline drift");
_Static_assert(sizeof(rtmap_scratch_pad_t) == 128, "pad size drift");

#define OFF_EV3_ADDR       ((int)offsetof(rtmap_event_v3_t, addr))
#define OFF_EV3_SIZE       ((int)offsetof(rtmap_event_v3_t, size))
#define OFF_EV3_THREAD_ID  ((int)offsetof(rtmap_event_v3_t, thread_id))
#define OFF_EV3_SEQ_LO     ((int)offsetof(rtmap_event_v3_t, seq_lo))
#define OFF_EV3_VALUE      ((int)offsetof(rtmap_event_v3_t, value))
#define OFF_EV3_KIND_FLAGS ((int)offsetof(rtmap_event_v3_t, kind_flags))
#define OFF_EV3_RIP_LO     ((int)offsetof(rtmap_event_v3_t, rip_lo))

_Static_assert(offsetof(rtmap_event_v3_t, addr)       ==  0, "ev3.addr drift");
_Static_assert(offsetof(rtmap_event_v3_t, size)       ==  8, "ev3.size drift");
_Static_assert(offsetof(rtmap_event_v3_t, thread_id)  == 12, "ev3.thread_id drift");
_Static_assert(offsetof(rtmap_event_v3_t, seq_lo)     == 14, "ev3.seq_lo drift");
_Static_assert(offsetof(rtmap_event_v3_t, value)      == 16, "ev3.value drift");
_Static_assert(offsetof(rtmap_event_v3_t, kind_flags) == 24, "ev3.kind_flags drift");
_Static_assert(offsetof(rtmap_event_v3_t, rip_lo)     == 28, "ev3.rip_lo drift");
_Static_assert(sizeof(rtmap_event_v3_t)               == 32, "ev3 size drift");

#define OFF_RING_HEAD      ((int)offsetof(rtmap_ring_header_t, head))
#define OFF_RING_TAIL      ((int)offsetof(rtmap_ring_header_t, tail))

_Static_assert(offsetof(rtmap_ring_header_t, head) == 1 * RTMAP_CACHE_LINE, "ring.head drift");
_Static_assert(offsetof(rtmap_ring_header_t, tail) == 2 * RTMAP_CACHE_LINE, "ring.tail drift");

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drwrap.h"
#include "drsyms.h"
#include "dr_ir_macros_x86.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

/* #define RTMAP_CCC_AUDIT */
#define RTMAP_CCC_AUDIT_INTERVAL 1

#ifdef RTMAP_CCC_AUDIT
static _Atomic uint64_t g_ccc_audit_checks = 0;
static _Atomic uint64_t g_ccc_audit_pass   = 0;
static _Atomic uint64_t g_ccc_audit_fail   = 0;
#endif

static rtmap_ctl_header_t *g_ctl     = NULL;
static int                  g_ctl_fd  = -1;
static uint32_t             g_process_pid = 0;
static char                 g_ctl_shm_name[RTMAP_RING_NAME_LEN];

static _Atomic uint64_t g_insn_counter  = 0;

static _Atomic uint64_t g_stat_reads        = 0;
static _Atomic uint64_t g_stat_calls        = 0;
static _Atomic uint64_t g_stat_returns      = 0;
static _Atomic uint64_t g_stat_dropped      = 0;
static _Atomic uint64_t g_stat_reg_snaps    = 0;
static _Atomic uint64_t g_stat_rdbuf_flushes = 0;
static _Atomic uint64_t g_stat_inline_writes = 0;
static _Atomic uint64_t g_stat_reloads       = 0;
static _Atomic uint64_t g_stat_tail_calls    = 0;
static _Atomic uint64_t g_stat_allocs        = 0;
static _Atomic uint64_t g_stat_frees         = 0;
static _Atomic uint64_t g_stat_gpr_captures  = 0;
static _Atomic uint64_t g_stat_clean_reads   = 0;
static _Atomic uint64_t g_stat_read_vals     = 0;
static _Atomic uint64_t g_stat_priority_reads = 0;
static _Atomic uint64_t g_stat_shed_reads     = 0;
static _Atomic uint64_t g_stat_reentrant_drops = 0;
static _Atomic uint64_t g_stat_truncated_writes = 0;

/* JIT-time site counters */
static _Atomic uint64_t g_jit_gpr_sites      = 0;
static _Atomic uint64_t g_jit_clean_sites    = 0;
static _Atomic uint64_t g_jit_imm_sites      = 0;

static _Atomic uint16_t g_next_thread_id    = 0;

static uint64_t g_module_base = 0;
static uint64_t g_module_end  = 0;
static _Atomic int g_module_base_phase = 0;

/* phase-delayed JIT hydration: skip instrumentation during init,
 * activate when RIP hits tripwire (e.g. aeMain). */
#define PHASE_BOOT  0
#define PHASE_TRACE 1
static volatile int g_phase = PHASE_TRACE;  /* default: full trace (no tripwire) */
static uint64_t g_tripwire_offset = 0;      /* ELF offset from client argv */
static void tripwire_hit(void);

/* This is custom arena/pool sub allocators (e.g. ngx_palloc, palloc, do_item_alloc etc.).
 * Its parsed from client argv after the tripwire offset; resolved to func_pc at main-module load. */
#define ARENA_MAX 16
typedef struct {
    uint64_t offset;   
    int      size_arg; 
    app_pc   func_pc;  
} arena_spec_t;
static arena_spec_t g_arena_specs[ARENA_MAX];
static int g_arena_spec_count = 0;

/* sidecar module table: written to /dev/shm/rtmap_modules_<pid> */
#define MODTAB_MAX 64
static struct { uint64_t base; char path[256]; } g_modtab[MODTAB_MAX];
static int g_modtab_count = 0;
static void *g_modtab_lock = NULL;

#define TLS_SLOT_GUARD     0
#define TLS_SLOT_THREAD_ID 1
#define TLS_SLOT_SEQ       2
#define TLS_SLOT_RING      3
#define TLS_SLOT_CTL_IDX   4
#define TLS_SLOT_RDBUF     5
#define TLS_SLOT_COUNT     6

#define RDBUF_CAP 16
typedef struct {
    uint32_t count;
    uint32_t _pad;
    struct { uint64_t addr; uint64_t value; uint32_t size; uint32_t _p; } entries[RDBUF_CAP];
} read_buf_t;

static int g_tls_idx[TLS_SLOT_COUNT];

static reg_id_t g_raw_tls_seg;
static uint     g_raw_tls_off;
#define RAW_TLS(slot) (g_raw_tls_off + (slot) * sizeof(void *))

static inline void *raw_tls_get(void *drcontext, uint off) {
    void **base = (void **)dr_get_dr_segment_base(g_raw_tls_seg);
    return *(void **)((char *)base + off);
}
static inline void raw_tls_set(void *drcontext, uint off, void *val) {
    void **base = (void **)dr_get_dr_segment_base(g_raw_tls_seg);
    *(void **)((char *)base + off) = val;
}
static inline rtmap_scratch_pad_t *tls_pad(void *drcontext) {
    return (rtmap_scratch_pad_t *)raw_tls_get(drcontext, RAW_TLS(RTMAP_RAW_SLOT_SCRATCH));
}

static void
map_ctl_ring(uint32_t parent_pid)
{
    g_process_pid = (uint32_t)dr_get_process_id();
    dr_snprintf(g_ctl_shm_name, sizeof(g_ctl_shm_name),
                RTMAP_CTL_SHM_FMT, (unsigned)g_process_pid);

    size_t sz = rtmap_ctl_shm_size();
    g_ctl_fd = shm_open(g_ctl_shm_name, O_CREAT | O_RDWR, 0600);
    DR_ASSERT(g_ctl_fd >= 0);
    if (ftruncate(g_ctl_fd, (off_t)sz) != 0)
        DR_ASSERT(false);
    g_ctl = (rtmap_ctl_header_t *)mmap(
        NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, g_ctl_fd, 0);
    DR_ASSERT(g_ctl != MAP_FAILED);
    if (g_ctl->magic != RTMAP_CTL_MAGIC)
        rtmap_ctl_init(g_ctl);
    g_ctl->target_pid = g_process_pid;
    g_ctl->parent_pid = parent_pid;

    /* legacy symlink: root process also creates /rtmap_ctl for v3 engines */
    if (parent_pid == 0) {
        shm_unlink(RTMAP_CTL_SHM_NAME);
        int legacy_fd = shm_open(RTMAP_CTL_SHM_NAME, O_CREAT | O_RDWR, 0600);
        if (legacy_fd >= 0) {
            if (ftruncate(legacy_fd, (off_t)sz) == 0) {
                rtmap_ctl_header_t *lctl = (rtmap_ctl_header_t *)mmap(
                    NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, legacy_fd, 0);
                if (lctl != MAP_FAILED) {
                    /* share same content by copying header; engine attaches here */
                    memcpy(lctl, g_ctl, sizeof(rtmap_ctl_header_t));
                    munmap(lctl, sz);
                }
            }
            close(legacy_fd);
        }
    }
}

/* per BB instrumentation state; reg_addr lives across the app store */
typedef struct {
    reg_id_t reg_addr;
    reg_id_t src_reg;
    uint32_t write_sz;
    bool     has_reads;
    bool     value_inline;
    bool     value_is_imm;
    bool     wide_write;
    bool     bb_emitted;
} instru_data_t;

static _Atomic uint64_t g_stat_bb_entries = 0;

/* fully inline BB_ENTRY (kind 11). no clean call, no EA; PC is JIT-time const. */
static void
emit_bb_entry(void *drcontext, instrlist_t *bb, instr_t *where, app_pc bb_pc)
{
    if (g_module_base == 0)
        return;
    uint64_t pc64 = (uint64_t)(ptr_uint_t)bb_pc;
    if (pc64 < g_module_base || pc64 >= g_module_end)
        return;
    uint32_t rip_offset = (uint32_t)(pc64 - g_module_base);
    atomic_fetch_add_explicit(&g_stat_bb_entries, 1, memory_order_relaxed);

    reg_id_t scratch;
    if (drreg_reserve_register(drcontext, bb, where, NULL, &scratch) != DRREG_SUCCESS)
        return;
    reg_id_t scratch2;
    if (drreg_reserve_register(drcontext, bb, where, NULL, &scratch2) != DRREG_SUCCESS) {
        drreg_unreserve_register(drcontext, bb, where, scratch);
        return;
    }

    instr_t *skip_label = INSTR_CREATE_label(drcontext);
    instr_t *no_flush   = INSTR_CREATE_label(drcontext);

    drreg_reserve_aflags(drcontext, bb, where);

    /* runtime phase gate: skip all BB_ENTRY traffic during BOOT.
     * cmp [&g_phase], PHASE_TRACE; jne skip; 2 insns, predicted taken post transition */
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_cmp(drcontext,
            opnd_create_abs_addr((void *)&g_phase, OPSZ_4),
            OPND_CREATE_INT32(PHASE_TRACE)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_jne, opnd_create_instr(skip_label)));

    /* ring null check */
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_RING))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_test(drcontext,
            opnd_create_reg(scratch), opnd_create_reg(scratch)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_jz, opnd_create_instr(skip_label)));

    /* backpressure check */
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_BP))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_test(drcontext,
            opnd_create_reg(scratch), opnd_create_reg(scratch)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_jnz, opnd_create_instr(skip_label)));

    /* scratch = pad ptr */
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_SCRATCH))));

    /* slot = ring_data + (head & mask) * 32 */
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch2),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_HEAD))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_and(drcontext,
            opnd_create_reg(scratch2),
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_RING_MASK)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_shl(drcontext,
            opnd_create_reg(scratch2),
            OPND_CREATE_INT8(5)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_add(drcontext,
            opnd_create_reg(scratch2),
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_RING_DATA)));

    /* scratch2 = slot ptr. write event fields. */
    /* addr = bb_pc (64-bit imm via two 32-bit stores) */
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(scratch2, DR_REG_NULL, 0, OFF_EV3_ADDR, OPSZ_4),
            OPND_CREATE_INT32((int)(uint32_t)(pc64 & 0xFFFFFFFFULL))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(scratch2, DR_REG_NULL, 0, OFF_EV3_ADDR + 4, OPSZ_4),
            OPND_CREATE_INT32((int)(uint32_t)(pc64 >> 32))));

    /* size = 0 */
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(scratch2, DR_REG_NULL, 0, OFF_EV3_SIZE, OPSZ_4),
            OPND_CREATE_INT32(0)));

    /* thread_id | seq_lo packed into 4 bytes at offset 12 */
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_SEQ))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_shl(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT8(16)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_or(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_TID))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(scratch2, DR_REG_NULL, 0, OFF_EV3_THREAD_ID, OPSZ_4),
            opnd_create_reg(reg_64_to_32(scratch))));

    /* kind_flags = BB_ENTRY | (seq_hi << 16) */
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_SEQ))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_shr(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT8(16)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_shl(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT8(16)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_or(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT32(RTMAP_EVENT_BB_ENTRY)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(scratch2, DR_REG_NULL, 0, OFF_EV3_KIND_FLAGS, OPSZ_4),
            opnd_create_reg(reg_64_to_32(scratch))));

    /* rip_lo */
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(scratch2, DR_REG_NULL, 0, OFF_EV3_RIP_LO, OPSZ_4),
            OPND_CREATE_INT32((int)rip_offset)));

    /* value = 0 */
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(scratch2, DR_REG_NULL, 0, OFF_EV3_VALUE, OPSZ_4),
            OPND_CREATE_INT32(0)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(scratch2, DR_REG_NULL, 0, OFF_EV3_VALUE + 4, OPSZ_4),
            OPND_CREATE_INT32(0)));

    /* seq++ */
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_SEQ))));
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_add(drcontext,
            opnd_create_reg(scratch), OPND_CREATE_INT32(1)));
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_store(drcontext,
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_SEQ)),
            opnd_create_reg(scratch)));

    /* head++ */
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_HEAD))));
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_add(drcontext,
            opnd_create_reg(scratch), OPND_CREATE_INT32(1)));
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_store(drcontext,
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_HEAD)),
            opnd_create_reg(scratch)));

    /* conditional head flush */
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_test(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT32(RTMAP_HEAD_FLUSH_MASK)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_jnz, opnd_create_instr(no_flush)));
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch2),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_RING))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            OPND_CREATE_MEMPTR(scratch2, OFF_RING_HEAD),
            opnd_create_reg(scratch)));

    instrlist_meta_preinsert(bb, where, no_flush);
    instrlist_meta_preinsert(bb, where, skip_label);

    drreg_unreserve_aflags(drcontext, bb, where);
    drreg_unreserve_register(drcontext, bb, where, scratch2);
    drreg_unreserve_register(drcontext, bb, where, scratch);
}

static void
emit_pre_write(void *drcontext, instrlist_t *bb, instr_t *where,
               reg_id_t reg_addr, reg_id_t scratch,
               uint32_t sz, app_pc app_pc_val,
               reg_id_t src_reg, bool has_imm, uint64_t imm_val,
               bool *value_captured, bool wide_write)
{
    uint32_t rip_offset = (uint32_t)((uint64_t)(ptr_uint_t)app_pc_val
                                     - g_module_base);
    /* JIT-time constant: kind byte + flags byte (COMPOUND if wide) */
    uint32_t kind_or = (uint32_t)RTMAP_EVENT_WRITE
                     | (wide_write ? ((uint32_t)RTMAP_FLAG_COMPOUND << 8) : 0);

    instr_t *skip_label     = INSTR_CREATE_label(drcontext);
    instr_t *reentrant_skip = INSTR_CREATE_label(drcontext);

    drreg_reserve_aflags(drcontext, bb, where);

    /* runtime phase gate: skip write instrumentation during BOOT.
     * single cmp+jne on g_phase; predicted-taken after transition. */
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_cmp(drcontext,
            opnd_create_abs_addr((void *)&g_phase, OPSZ_4),
            OPND_CREATE_INT32(PHASE_TRACE)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_jne, opnd_create_instr(skip_label)));

    /* EA -> pad.scratch[0] */
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_SCRATCH))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH0),
            opnd_create_reg(reg_addr)));

    /* signal re-entrancy guard: if nesting_level != 0, torn event; drop */
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_cmp(drcontext,
            opnd_create_base_disp(scratch, DR_REG_NULL, 0,
                OFF_PAD_NESTING, OPSZ_4),
            OPND_CREATE_INT32(0)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_jnz, opnd_create_instr(reentrant_skip)));

    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(reg_addr),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_RING))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_test(drcontext,
            opnd_create_reg(reg_addr), opnd_create_reg(reg_addr)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_jz, opnd_create_instr(skip_label)));

    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(reg_addr),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_BP))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_test(drcontext,
            opnd_create_reg(reg_addr), opnd_create_reg(reg_addr)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_jnz, opnd_create_instr(skip_label)));

    /* slot = ring_data + (head & mask) * 32 */
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(reg_addr),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_HEAD))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_and(drcontext,
            opnd_create_reg(reg_addr),
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_RING_MASK)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_shl(drcontext,
            opnd_create_reg(reg_addr),
            OPND_CREATE_INT8(5)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_add(drcontext,
            opnd_create_reg(reg_addr),
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_RING_DATA)));

    /* recover EA; reg_addr now holds slot ptr */
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_SCRATCH))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_ld(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH0)));

    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            OPND_CREATE_MEMPTR(reg_addr, OFF_EV3_ADDR),
            opnd_create_reg(scratch)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(reg_addr, DR_REG_NULL, 0,
                OFF_EV3_SIZE, OPSZ_4),
            OPND_CREATE_INT32((int)sz)));

    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_SEQ))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_shl(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT8(16)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_or(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_TID))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(reg_addr, DR_REG_NULL, 0,
                OFF_EV3_THREAD_ID, OPSZ_4),
            opnd_create_reg(reg_64_to_32(scratch))));

    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_SEQ))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_shr(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT8(16)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_shl(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT8(16)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_or(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT32((int)kind_or)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(reg_addr, DR_REG_NULL, 0,
                OFF_EV3_KIND_FLAGS, OPSZ_4),
            opnd_create_reg(reg_64_to_32(scratch))));

    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(reg_addr, DR_REG_NULL, 0,
                OFF_EV3_RIP_LO, OPSZ_4),
            OPND_CREATE_INT32((int)rip_offset)));

    /* imm value: written inline at JIT time */
    if (has_imm) {
        uint32_t lo = (uint32_t)(imm_val & 0xFFFFFFFFULL);
        uint32_t hi = (uint32_t)(imm_val >> 32);
        instrlist_meta_preinsert(bb, where,
            INSTR_CREATE_mov_st(drcontext,
                opnd_create_base_disp(reg_addr, DR_REG_NULL, 0,
                    OFF_EV3_VALUE, OPSZ_4),
                OPND_CREATE_INT32((int)lo)));
        instrlist_meta_preinsert(bb, where,
            INSTR_CREATE_mov_st(drcontext,
                opnd_create_base_disp(reg_addr, DR_REG_NULL, 0,
                    OFF_EV3_VALUE + 4, OPSZ_4),
                OPND_CREATE_INT32((int)hi)));
    }

    /* slot ptr -> pad.scratch[1] for post-write */
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_SCRATCH))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH1),
            opnd_create_reg(reg_addr)));

    /* arm nesting guard; post-write will clear */
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(scratch, DR_REG_NULL, 0,
                OFF_PAD_NESTING, OPSZ_4),
            OPND_CREATE_INT32(1)));

    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_ld(drcontext,
            opnd_create_reg(reg_addr),
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH0)));

    instr_t *done_label = INSTR_CREATE_label(drcontext);
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jmp(drcontext, opnd_create_instr(done_label)));

    /* reentrant skip: bump stat, fall through to normal skip */
    instrlist_meta_preinsert(bb, where, reentrant_skip);
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_SCRATCH))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_add(drcontext,
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_REENTRANT),
            OPND_CREATE_INT32(1)));

    /* skip: zero scratch[1], restore EA */
    instrlist_meta_preinsert(bb, where, skip_label);
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_SCRATCH))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_xor(drcontext,
            opnd_create_reg(reg_addr), opnd_create_reg(reg_addr)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH1),
            opnd_create_reg(reg_addr)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_ld(drcontext,
            opnd_create_reg(reg_addr),
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH0)));

    instrlist_meta_preinsert(bb, where, done_label);

    drreg_unreserve_aflags(drcontext, bb, where);
}

#ifdef RTMAP_CCC_AUDIT
/* shadow audit: re-reads [EA] and compares against slot->value */
static void
ccc_audit_verify(uint32_t size)
{
    void *drcontext = dr_get_current_drcontext();
    rtmap_scratch_pad_t *pad = tls_pad(drcontext);
    if (!pad) return;
    pad->ccc_audit_ctr++;
    if ((pad->ccc_audit_ctr & (RTMAP_CCC_AUDIT_INTERVAL - 1)) != 0)
        return;
    uint64_t addr = pad->scratch[0];
    rtmap_event_v3_t *slot = (rtmap_event_v3_t *)(uintptr_t)pad->scratch[1];
    if (!slot) return;
    uint64_t ground_truth = 0;
    if (size <= 8) {
        DR_TRY_EXCEPT(drcontext, {
            memcpy(&ground_truth, (void *)(uintptr_t)addr, size);
        }, { /* fault: ground_truth stays 0 */ });
    }
    uint64_t mask = (size >= 8) ? ~0ULL : ((1ULL << (size * 8)) - 1);
    uint64_t inline_val = slot->value & mask;
    ground_truth &= mask;
    atomic_fetch_add_explicit(&g_ccc_audit_checks, 1, memory_order_relaxed);
    if (inline_val == ground_truth) {
        atomic_fetch_add_explicit(&g_ccc_audit_pass, 1, memory_order_relaxed);
    } else {
        atomic_fetch_add_explicit(&g_ccc_audit_fail, 1, memory_order_relaxed);
        dr_printf("rtmap: CCC AUDIT FAIL addr=%p sz=%u "
                  "inline=0x%llx truth=0x%llx rip_lo=0x%x\n",
                  (void *)(uintptr_t)addr, size,
                  (unsigned long long)inline_val,
                  (unsigned long long)ground_truth,
                  (unsigned)slot->rip_lo);
    }
}
#endif

#ifdef RTMAP_CCC_AUDIT
static void ccc_count_gpr(void) {
    atomic_fetch_add_explicit(&g_stat_gpr_captures, 1, memory_order_relaxed);
}
static void ccc_count_clean(void) {
    atomic_fetch_add_explicit(&g_stat_clean_reads, 1, memory_order_relaxed);
}
#endif

static void
safe_read_into_slot(uint64_t addr, uint32_t size, rtmap_event_v3_t *slot)
{
    uint64_t val = 0;
    if (size <= 8) {
        DR_TRY_EXCEPT(dr_get_current_drcontext(), {
            memcpy(&val, (void *)(uintptr_t)addr, size);
        }, { /* fault: val stays 0 */ });
    }
    slot->value = val;
}

/* compound wide write: fill continuation slots after the inline header.
 * header slot (slot[0]) already has value = low 8B, flags = COMPOUND.
 * this writes slots 1..N-1 with CONTINUATION flag + next 8B chunks.
 * called from post write path for wide_write && !ccc_force_clean. */
static void
compound_fill_continuations(uint32_t write_size)
{
    void *drcontext = dr_get_current_drcontext();
    rtmap_scratch_pad_t *pad = tls_pad(drcontext);
    if (!pad) return;

    uint64_t ea = pad->scratch[0];
    rtmap_event_v3_t *header = (rtmap_event_v3_t *)(uintptr_t)pad->scratch[1];
    if (!header) return;

    uint32_t total_slots = (write_size + 7) / 8;
    if (total_slots > RTMAP_COMPOUND_MAX_SLOTS)
        total_slots = RTMAP_COMPOUND_MAX_SLOTS;
    if (total_slots <= 1) return;

    uint32_t cont_count = total_slots - 1;
    uint16_t tid = header->thread_id;
    uint32_t kf_cont = rtmap_v3_make_kf(RTMAP_EVENT_WRITE,
                                          RTMAP_FLAG_CONTINUATION, 0);

    for (uint32_t k = 0; k < cont_count; k++) {
        rtmap_event_v3_t *slot = header + 1 + k;
        uint64_t chunk_ea = ea + (uint64_t)(k + 1) * 8;
        uint32_t chunk_sz = write_size - (k + 1) * 8;
        if (chunk_sz > 8) chunk_sz = 8;

        uint64_t val = 0;
        DR_TRY_EXCEPT(drcontext, {
            memcpy(&val, (void *)(uintptr_t)chunk_ea, chunk_sz);
        }, { /* fault: val stays 0 */ });

        slot->addr       = chunk_ea;
        slot->size       = chunk_sz;
        slot->thread_id  = tid;
        slot->seq_lo     = 0;
        slot->value      = val;
        slot->kind_flags = kf_cont;
        slot->rip_lo     = 0;
    }

    /* advance head by cont_count additional slots */
    uint64_t *head_cache = (uint64_t *)raw_tls_get(drcontext,
                                RAW_TLS(RTMAP_RAW_SLOT_HEAD));
    /* head_cache is the value, not a pointer; use raw TLS directly */
    void **base = (void **)dr_get_dr_segment_base(g_raw_tls_seg);
    uintptr_t cur = (uintptr_t)*(void **)((char *)base + RAW_TLS(RTMAP_RAW_SLOT_HEAD));
    *(void **)((char *)base + RAW_TLS(RTMAP_RAW_SLOT_HEAD)) = (void *)(cur + cont_count);

    pad->stat_truncated_writes += 1;
}

static void
emit_post_write(void *drcontext, instrlist_t *bb, instr_t *where,
                reg_id_t reg_addr, uint32_t sz, bool value_inline,
                bool value_is_imm, reg_id_t src_reg, bool wide_write)
{
    reg_id_t scratch;
    if (drreg_reserve_register(drcontext, bb, where, NULL, &scratch) != DRREG_SUCCESS) {
        DR_ASSERT(false);
        return;
    }

    instr_t *skip_label     = INSTR_CREATE_label(drcontext);
    instr_t *val_done       = INSTR_CREATE_label(drcontext);
    instr_t *no_flush_label = INSTR_CREATE_label(drcontext);

    drreg_reserve_aflags(drcontext, bb, where);

    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_SCRATCH))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_cmp(drcontext,
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH1),
            OPND_CREATE_INT32(0)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_jz, opnd_create_instr(skip_label)));

    if (!value_inline && (sz <= 8 || wide_write)) {
        /* vector 7: inline EA re-read (8B prefix for wide writes) */
        atomic_fetch_add_explicit(&g_jit_gpr_sites, 1, memory_order_relaxed);

        instrlist_meta_preinsert(bb, where,
            XINST_CREATE_load(drcontext,
                opnd_create_reg(scratch),
                dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                    RAW_TLS(RTMAP_RAW_SLOT_SCRATCH))));
        instrlist_meta_preinsert(bb, where,
            INSTR_CREATE_mov_ld(drcontext,
                opnd_create_reg(reg_addr),
                OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH0)));
        instrlist_meta_preinsert(bb, where,
            XINST_CREATE_load(drcontext,
                opnd_create_reg(scratch),
                dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                    RAW_TLS(RTMAP_RAW_SLOT_SCRATCH))));
        instrlist_meta_preinsert(bb, where,
            INSTR_CREATE_mov_ld(drcontext,
                opnd_create_reg(scratch),
                OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH1)));

        /* read [EA] low 8B into header slot; compound path fills continuations */
        instrlist_meta_preinsert(bb, where,
            INSTR_CREATE_mov_ld(drcontext,
                opnd_create_reg(reg_addr),
                OPND_CREATE_MEMPTR(reg_addr, 0)));
        instrlist_meta_preinsert(bb, where,
            INSTR_CREATE_mov_st(drcontext,
                OPND_CREATE_MEMPTR(scratch, OFF_EV3_VALUE),
                opnd_create_reg(reg_addr)));

        if (wide_write) {
            /* fill continuation slots via clean call; advances head by N-1 */
            dr_insert_clean_call(drcontext, bb, where,
                (void *)compound_fill_continuations, false, 1,
                OPND_CREATE_INT32((int)sz));
        }
#ifdef RTMAP_CCC_AUDIT
        if (!wide_write)
            dr_insert_clean_call(drcontext, bb, where,
                (void *)ccc_count_gpr, false, 0);
#endif
    } else if (!value_inline) {
        /* sz > 8 non-wide (REP/LOCK): clean-call fallback */
        atomic_fetch_add_explicit(&g_jit_clean_sites, 1, memory_order_relaxed);
        instrlist_meta_preinsert(bb, where,
            INSTR_CREATE_mov_ld(drcontext,
                opnd_create_reg(reg_addr),
                OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH0)));
        instrlist_meta_preinsert(bb, where,
            INSTR_CREATE_mov_ld(drcontext,
                opnd_create_reg(scratch),
                OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH1)));

        dr_insert_clean_call(drcontext, bb, where,
            (void *)safe_read_into_slot, false, 3,
            opnd_create_reg(reg_addr),
            OPND_CREATE_INT32((int)sz),
            opnd_create_reg(scratch));
#ifdef RTMAP_CCC_AUDIT
        dr_insert_clean_call(drcontext, bb, where,
            (void *)ccc_count_clean, false, 0);
#endif
    } else {
        atomic_fetch_add_explicit(&g_jit_imm_sites, 1, memory_order_relaxed);
    }

#ifdef RTMAP_CCC_AUDIT
    if (!value_is_imm) {
        dr_insert_clean_call(drcontext, bb, where,
            (void *)ccc_audit_verify, false, 1,
            OPND_CREATE_INT32((int)sz));
    }
#endif

    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_SCRATCH))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_add(drcontext,
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_STAT_INLINE),
            OPND_CREATE_INT32(1)));

    instrlist_meta_preinsert(bb, where, val_done);

    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_SEQ))));
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_add(drcontext,
            opnd_create_reg(scratch), OPND_CREATE_INT32(1)));
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_store(drcontext,
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_SEQ)),
            opnd_create_reg(scratch)));

    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_HEAD))));
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_add(drcontext,
            opnd_create_reg(scratch), OPND_CREATE_INT32(1)));
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_store(drcontext,
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_HEAD)),
            opnd_create_reg(scratch)));

    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_test(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT32(RTMAP_HEAD_FLUSH_MASK)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_jnz, opnd_create_instr(no_flush_label)));

    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(reg_addr),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_RING))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            OPND_CREATE_MEMPTR(reg_addr, OFF_RING_HEAD),
            opnd_create_reg(scratch)));

    instrlist_meta_preinsert(bb, where, no_flush_label);
    instrlist_meta_preinsert(bb, where, skip_label);

    /* disarm nesting guard unconditionally; harmless if never armed */
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(reg_addr),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(RTMAP_RAW_SLOT_SCRATCH))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(reg_addr, DR_REG_NULL, 0,
                OFF_PAD_NESTING, OPSZ_4),
            OPND_CREATE_INT32(0)));

    drreg_unreserve_aflags(drcontext, bb, where);

    if (drreg_unreserve_register(drcontext, bb, where, scratch) != DRREG_SUCCESS)
        DR_ASSERT(false);
}

static void
flush_head_cache(void *drcontext)
{
    rtmap_ring_header_t *ring = (rtmap_ring_header_t *)raw_tls_get(
        drcontext, RAW_TLS(RTMAP_RAW_SLOT_RING));
    if (!ring) return;
    uint64_t cached_head = (uint64_t)(uintptr_t)raw_tls_get(
        drcontext, RAW_TLS(RTMAP_RAW_SLOT_HEAD));
    atomic_store_explicit(&ring->head, cached_head, memory_order_release);
}

static void
sync_head_cache(void *drcontext)
{
    rtmap_ring_header_t *ring = (rtmap_ring_header_t *)raw_tls_get(
        drcontext, RAW_TLS(RTMAP_RAW_SLOT_RING));
    if (!ring) return;
    uint64_t real_head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    raw_tls_set(drcontext, RAW_TLS(RTMAP_RAW_SLOT_HEAD), (void *)(uintptr_t)real_head);
}

static rtmap_ring_header_t *
alloc_thread_ring(const char *shm_name)
{
    uint32_t capacity = RTMAP_THREAD_RING_CAPACITY;
    size_t sz = rtmap_shm_size(capacity);
    int fd = shm_open(shm_name, O_CREAT | O_RDWR, 0600);
    if (fd < 0) return NULL;
    if (ftruncate(fd, (off_t)sz) != 0) { close(fd); return NULL; }
    rtmap_ring_header_t *ring = (rtmap_ring_header_t *)mmap(
        NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (ring == MAP_FAILED) return NULL;
    rtmap_ring_init(ring, capacity, RTMAP_FLAG_DROP_ON_FULL);
    return ring;
}

static rtmap_scratch_pad_t *
alloc_scratch_pad(void *drcontext, rtmap_ring_header_t *ring)
{
    rtmap_scratch_pad_t *pad = (rtmap_scratch_pad_t *)dr_thread_alloc(
        drcontext, sizeof(rtmap_scratch_pad_t));
    memset(pad, 0, sizeof(rtmap_scratch_pad_t));
    if (ring) {
        pad->ring_data = (uint64_t)(uintptr_t)rtmap_ring_data(ring);
        pad->ring_mask = ring->capacity - 1;
    }
    return pad;
}

static void
unmap_ctl_ring(void)
{
    if (g_ctl && g_ctl != (void *)MAP_FAILED) {
        munmap(g_ctl, rtmap_ctl_shm_size());
        g_ctl = NULL;
    }
    if (g_ctl_fd >= 0) {
        close(g_ctl_fd);
        g_ctl_fd = -1;
    }
    /* Unlink ctl names: the engine already has the ctl mapped by the time
     * we exit. Ring names are NOT unlinked here; the engine needs them
     * to discover and mmap thread rings (short-lived process race).
     * The engine's cleanup_shm_for_pid() unlinks rings after draining. */
    if (g_ctl_shm_name[0])
        shm_unlink(g_ctl_shm_name);
    shm_unlink(RTMAP_CTL_SHM_NAME);
}

static inline uint16_t tls_thread_id(void *drcontext) {
    return (uint16_t)(uintptr_t)drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_THREAD_ID]);
}

/* 32-bit seq split across seq_lo (low 16) and kind_flags (high 16) */
static inline uint32_t tls_next_seq(void *drcontext) {
    uint32_t s = (uint32_t)(uintptr_t)drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_SEQ]);
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_SEQ], (void *)(uintptr_t)(s + 1));
    return s;
}

static inline rtmap_ring_header_t *tls_ring(void *drcontext) {
    return (rtmap_ring_header_t *)drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_RING]);
}

static void flush_modtab(void);

static inline void maybe_emit_module_load(void *drcontext, rtmap_ring_header_t *ring) {
    int phase = atomic_load_explicit(&g_module_base_phase, memory_order_acquire);
    if (phase != 1) return;
    if (!atomic_compare_exchange_strong_explicit(&g_module_base_phase, &phase, 2,
                                                  memory_order_acq_rel, memory_order_relaxed))
        return;
    uint16_t tid = tls_thread_id(drcontext);
    uint32_t seq = tls_next_seq(drcontext);
    rtmap_push_ex(ring, g_module_base, 0, 0, RTMAP_EVENT_MODULE_LOAD, tid, seq);
    sync_head_cache(drcontext);
    dr_printf("rtmap: emitted MODULE_LOAD base=0x%llx (tid=%u seq=%u)\n",
              (unsigned long long)g_module_base, (unsigned)tid, (unsigned)seq);
}

static inline uint64_t safe_read_value(uint64_t addr, uint32_t size) {
    uint64_t val = 0;
    if (size <= 8) {
        DR_TRY_EXCEPT(dr_get_current_drcontext(), {
            memcpy(&val, (void *)(uintptr_t)addr, size);
        }, { /* fault: leave val=0 */ });
    }
    return val;
}

static void
at_mem_read_buf(uint64_t addr, uint32_t size)
{
    if (g_phase == PHASE_BOOT) return;
    void *drcontext = dr_get_current_drcontext();
    rtmap_ring_header_t *ring = tls_ring(drcontext);
    if (ring && atomic_load_explicit(&ring->backpressure, memory_order_relaxed)) {
        if (g_ctl && rtmap_bloom_query(g_ctl->priority_bloom, addr)) {
            atomic_fetch_add_explicit(&g_stat_priority_reads, 1, memory_order_relaxed);
        } else {
            atomic_fetch_add_explicit(&g_stat_shed_reads, 1, memory_order_relaxed);
            return;
        }
    }
    read_buf_t *buf = (read_buf_t *)drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_RDBUF]);
    if (!buf || buf->count >= RDBUF_CAP) return;
    uint32_t idx = buf->count++;
    buf->entries[idx].addr = addr;
    buf->entries[idx].size = size;
    buf->entries[idx].value = safe_read_value(addr, size);
    if (buf->entries[idx].value != 0)
        atomic_fetch_add_explicit(&g_stat_read_vals, 1, memory_order_relaxed);
}

static void flush_read_buf(void);

static void
flush_read_buf_if_needed(int needed)
{
    if (g_phase == PHASE_BOOT) return;
    void *drcontext = dr_get_current_drcontext();
    read_buf_t *buf = (read_buf_t *)drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_RDBUF]);
    if (!buf || (int)buf->count + needed <= RDBUF_CAP) return;
    flush_read_buf();
}

static void
flush_read_buf(void)
{
    if (g_phase == PHASE_BOOT) return;
    void *drcontext = dr_get_current_drcontext();
    void *guard = drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD]);
    if (guard != NULL) return;
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], (void *)(uintptr_t)1);

    read_buf_t *buf = (read_buf_t *)drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_RDBUF]);
    if (!buf || buf->count == 0) {
        drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
        return;
    }
    rtmap_ring_header_t *ring = tls_ring(drcontext);
    if (!ring) {
        buf->count = 0;
        drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
        return;
    }
    uint16_t tid = tls_thread_id(drcontext);
    rtmap_scratch_pad_t *pad = tls_pad(drcontext);
    uint32_t n = buf->count;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t seq = tls_next_seq(drcontext);
        int rc = rtmap_push_sampled(ring, buf->entries[i].addr,
                                      buf->entries[i].size,
                                      buf->entries[i].value,
                                      RTMAP_EVENT_READ, tid, seq);
        if (rc == 0 && pad)
            pad->stat_reads++;
        else if (rc == 1 && pad)
            pad->stat_dropped++;
    }
    buf->count = 0;
    sync_head_cache(drcontext);
    atomic_fetch_add_explicit(&g_stat_rdbuf_flushes, 1, memory_order_relaxed);
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
}

static void
at_call(uint64_t callee_pc, uint64_t frame_base)
{
    if (g_phase == PHASE_BOOT) return;
    void *drcontext = dr_get_current_drcontext();
    void *guard = drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD]);
    if (guard != NULL) return;
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], (void *)(uintptr_t)1);

    rtmap_ring_header_t *ring = tls_ring(drcontext);
    if (!ring) { drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL); return; }
    maybe_emit_module_load(drcontext, ring);
    uint16_t tid = tls_thread_id(drcontext);
    uint32_t seq = tls_next_seq(drcontext);
    rtmap_push_ex(ring, callee_pc, 0, frame_base, RTMAP_EVENT_CALL, tid, seq);
    sync_head_cache(drcontext);
    rtmap_scratch_pad_t *pad = tls_pad(drcontext);
    if (pad) pad->stat_calls++;
    uint64_t ic = atomic_fetch_add_explicit(&g_insn_counter, 8, memory_order_relaxed);

    dr_mcontext_t mc;
    mc.size = sizeof(mc);
    mc.flags = DR_MC_INTEGER | DR_MC_CONTROL;
    if (dr_get_mcontext(drcontext, &mc)) {
        uint64_t regs[RTMAP_REG_COUNT];
        regs[RTMAP_REG_RAX]    = (uint64_t)mc.rax;
        regs[RTMAP_REG_RBX]    = (uint64_t)mc.rbx;
        regs[RTMAP_REG_RCX]    = (uint64_t)mc.rcx;
        regs[RTMAP_REG_RDX]    = (uint64_t)mc.rdx;
        regs[RTMAP_REG_RSI]    = (uint64_t)mc.rsi;
        regs[RTMAP_REG_RDI]    = (uint64_t)mc.rdi;
        regs[RTMAP_REG_RBP]    = (uint64_t)mc.rbp;
        regs[RTMAP_REG_RSP]    = (uint64_t)mc.rsp;
        regs[RTMAP_REG_R8]     = (uint64_t)mc.r8;
        regs[RTMAP_REG_R9]     = (uint64_t)mc.r9;
        regs[RTMAP_REG_R10]    = (uint64_t)mc.r10;
        regs[RTMAP_REG_R11]    = (uint64_t)mc.r11;
        regs[RTMAP_REG_R12]    = (uint64_t)mc.r12;
        regs[RTMAP_REG_R13]    = (uint64_t)mc.r13;
        regs[RTMAP_REG_R14]    = (uint64_t)mc.r14;
        regs[RTMAP_REG_R15]    = (uint64_t)mc.r15;
        regs[RTMAP_REG_RIP]    = (uint64_t)mc.pc;
        regs[RTMAP_REG_RFLAGS] = (uint64_t)mc.xflags;
        uint32_t rseq = tls_next_seq(drcontext);
        rtmap_push_reg_snapshot(ring, ic + 8, regs, tid, rseq);
        sync_head_cache(drcontext);
        atomic_fetch_add_explicit(&g_stat_reg_snaps, 1, memory_order_relaxed);
    }

    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
}

static void
at_reload(uint64_t src_addr, uint32_t size, uint32_t dest_reg_idx)
{
    if (g_phase == PHASE_BOOT) return;
    void *drcontext = dr_get_current_drcontext();
    void *guard = drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD]);
    if (guard != NULL) return;
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], (void *)(uintptr_t)1);

    rtmap_ring_header_t *ring = tls_ring(drcontext);
    if (!ring) { drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL); return; }
    uint16_t tid = tls_thread_id(drcontext);
    uint32_t seq = tls_next_seq(drcontext);
    uint64_t val = safe_read_value(src_addr, size);
    uint8_t flags = (uint8_t)(dest_reg_idx & 0xFF);
    rtmap_push_ex_flags(ring, src_addr, size, val,
                         RTMAP_EVENT_RELOAD, flags, tid, seq);
    sync_head_cache(drcontext);
    { rtmap_scratch_pad_t *pad = tls_pad(drcontext); if (pad) pad->stat_reloads++; }

    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
}

static int
dr_reg_to_rtmap_idx(reg_id_t reg)
{
    reg = reg_to_pointer_sized(reg);
    switch (reg) {
    case DR_REG_RAX: return RTMAP_REG_RAX;
    case DR_REG_RBX: return RTMAP_REG_RBX;
    case DR_REG_RCX: return RTMAP_REG_RCX;
    case DR_REG_RDX: return RTMAP_REG_RDX;
    case DR_REG_RSI: return RTMAP_REG_RSI;
    case DR_REG_RDI: return RTMAP_REG_RDI;
    case DR_REG_RBP: return RTMAP_REG_RBP;
    case DR_REG_RSP: return RTMAP_REG_RSP;
    case DR_REG_R8:  return RTMAP_REG_R8;
    case DR_REG_R9:  return RTMAP_REG_R9;
    case DR_REG_R10: return RTMAP_REG_R10;
    case DR_REG_R11: return RTMAP_REG_R11;
    case DR_REG_R12: return RTMAP_REG_R12;
    case DR_REG_R13: return RTMAP_REG_R13;
    case DR_REG_R14: return RTMAP_REG_R14;
    case DR_REG_R15: return RTMAP_REG_R15;
    default: return -1;
    }
}

static bool
is_dwarf_reload_candidate(reg_id_t reg)
{
    reg = reg_to_pointer_sized(reg);
    return reg == DR_REG_RBX || reg == DR_REG_RBP ||
           reg == DR_REG_R12 || reg == DR_REG_R13 ||
           reg == DR_REG_R14 || reg == DR_REG_R15;
}

static void
at_return(uint64_t retaddr)
{
    if (g_phase == PHASE_BOOT) return;
    void *drcontext = dr_get_current_drcontext();
    void *guard = drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD]);
    if (guard != NULL) return;
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], (void *)(uintptr_t)1);

    rtmap_ring_header_t *ring = tls_ring(drcontext);
    if (!ring) { drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL); return; }
    uint16_t tid = tls_thread_id(drcontext);
    uint32_t seq = tls_next_seq(drcontext);
    rtmap_push_ex(ring, retaddr, 0, 0, RTMAP_EVENT_RETURN, tid, seq);
    sync_head_cache(drcontext);
    { rtmap_scratch_pad_t *pad = tls_pad(drcontext); if (pad) pad->stat_returns++; }

    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
}

static void
at_tail_call(uint64_t target_pc, uint64_t frame_base)
{
    if (g_phase == PHASE_BOOT) return;
    void *drcontext = dr_get_current_drcontext();
    void *guard = drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD]);
    if (guard != NULL) return;
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], (void *)(uintptr_t)1);

    rtmap_ring_header_t *ring = tls_ring(drcontext);
    if (!ring) { drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL); return; }
    uint16_t tid = tls_thread_id(drcontext);
    uint32_t seq = tls_next_seq(drcontext);
    rtmap_push_ex(ring, target_pc, 0, frame_base, RTMAP_EVENT_TAIL_CALL, tid, seq);
    sync_head_cache(drcontext);
    { rtmap_scratch_pad_t *pad = tls_pad(drcontext); if (pad) pad->stat_tail_calls++; }

    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
}

static dr_emit_flags_t
event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating, void **user_data)
{
    (void)tag; (void)for_trace; (void)translating;
    instru_data_t *data = (instru_data_t *)dr_thread_alloc(drcontext, sizeof(*data));
    data->reg_addr = DR_REG_NULL;
    data->src_reg = DR_REG_NULL;
    data->write_sz = 0;
    data->has_reads = false;
    data->value_is_imm = false;
    data->wide_write = false;
    data->value_inline = false;
    data->bb_emitted = false;
    for (instr_t *i = instrlist_first_app(bb); i != NULL; i = instr_get_next_app(i)) {
        if (instr_reads_memory(i)) { data->has_reads = true; break; }
    }
    *user_data = (void *)data;
    return DR_EMIT_DEFAULT;
}

static void
handle_pending_post_write(void *drcontext, instrlist_t *bb, instr_t *where,
                          instru_data_t *data)
{
    if (data->reg_addr == DR_REG_NULL)
        return;
    emit_post_write(drcontext, bb, where, data->reg_addr, data->write_sz,
                    data->value_inline, data->value_is_imm, data->src_reg,
                    data->wide_write);
    if (drreg_unreserve_register(drcontext, bb, where, data->reg_addr) != DRREG_SUCCESS)
        DR_ASSERT(false);
    data->reg_addr = DR_REG_NULL;
    data->src_reg = DR_REG_NULL;
    data->value_inline = false;
    data->value_is_imm = false;
}

static dr_emit_flags_t
event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                bool for_trace, bool translating, void *user_data)
{
    (void)tag; (void)for_trace; (void)translating;
    instru_data_t *data = (instru_data_t *)user_data;

    if (!data->bb_emitted) {
        data->bb_emitted = true;

        /* tripwire: emit clean call at the target BB during BOOT.
         * only one BB matches; after tripwire_hit flips g_phase,
         * the runtime phase gates in emit_bb_entry/emit_pre_write
         * activate all instrumentation. */
        if (g_tripwire_offset != 0 && g_module_base != 0) {
            uint64_t bb_off = (uint64_t)(ptr_uint_t)instr_get_app_pc(instr) - g_module_base;
            if (bb_off == g_tripwire_offset) {
                dr_insert_clean_call(drcontext, bb, instr,
                                     (void *)tripwire_hit, false, 0);
            }
        }

        /* always emit BB_ENTRY; runtime phase gate inside skips during BOOT */
        emit_bb_entry(drcontext, bb, instr, instr_get_app_pc(instr));
    }

    /* all instrumentation emitted unconditionally; runtime g_phase checks
     * inside clean calls and inline paths gate actual event production. */

    handle_pending_post_write(drcontext, bb, instr, data);

    if (instr_is_call_direct(instr)) {
        dr_insert_clean_call(drcontext, bb, instr,
                             (void *)flush_head_cache, false, 0);
        app_pc target = instr_get_branch_target_pc(instr);
        dr_insert_clean_call(drcontext, bb, instr,
                             (void *)at_call, false, 2,
                             OPND_CREATE_INT64((uint64_t)(ptr_uint_t)target),
                             opnd_create_reg(DR_REG_XSP));
    }

    if (instr_is_return(instr)) {
        dr_insert_clean_call(drcontext, bb, instr,
                             (void *)flush_head_cache, false, 0);
        dr_insert_clean_call(drcontext, bb, instr,
                             (void *)at_return, false, 1,
                             OPND_CREATE_INT64((uint64_t)(ptr_uint_t)
                                 instr_get_app_pc(instr)));
    }

    /* tail-call heuristic: end-of-BB JMP, target >4KB away */
    if (instr_is_ubr(instr) && !instr_is_call(instr) &&
        drmgr_is_last_instr(drcontext, instr) && g_module_base != 0) {
        app_pc target = instr_get_branch_target_pc(instr);
        app_pc here   = instr_get_app_pc(instr);
        if (target != NULL && (ptr_uint_t)target >= g_module_base) {
            ptr_uint_t dist = (ptr_uint_t)target > (ptr_uint_t)here
                ? (ptr_uint_t)target - (ptr_uint_t)here
                : (ptr_uint_t)here - (ptr_uint_t)target;
            if (dist > 4096) {
                dr_insert_clean_call(drcontext, bb, instr,
                                     (void *)flush_head_cache, false, 0);
                dr_insert_clean_call(drcontext, bb, instr,
                                     (void *)at_tail_call, false, 2,
                                     OPND_CREATE_INT64((uint64_t)(ptr_uint_t)target),
                                     opnd_create_reg(DR_REG_XSP));
            }
        }
    }

    /* inline write path; main module only */
    if (instr_writes_memory(instr)) {
        app_pc pc = instr_get_app_pc(instr);
        bool in_main = g_module_base != 0 &&
                       (uint64_t)(ptr_uint_t)pc >= g_module_base &&
                       (uint64_t)(ptr_uint_t)pc <  g_module_end;
        if (!in_main)
            goto after_write;
    }
    if (instr_writes_memory(instr)) {
        bool seen_memref = false;
        for (int i = 0; i < instr_num_dsts(instr); i++) {
            opnd_t dst = instr_get_dst(instr, i);
            if (!opnd_is_memory_reference(dst))
                continue;
            if (seen_memref)
                break;
            seen_memref = true;

            uint32_t sz = opnd_size_in_bytes(opnd_get_size(dst));
            app_pc write_pc = instr_get_app_pc(instr);

            reg_id_t reg_addr, reg_scratch;
            if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg_addr) !=
                    DRREG_SUCCESS)
                break;
            if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg_scratch) !=
                    DRREG_SUCCESS) {
                drreg_unreserve_register(drcontext, bb, instr, reg_addr);
                break;
            }

            if (opnd_uses_reg(dst, reg_addr))
                drreg_get_app_value(drcontext, bb, instr, reg_addr, reg_addr);
            if (opnd_uses_reg(dst, reg_scratch))
                drreg_get_app_value(drcontext, bb, instr, reg_scratch, reg_scratch);

            bool ok = drutil_insert_get_mem_addr(
                drcontext, bb, instr, dst, reg_addr, reg_scratch);

            drreg_unreserve_register(drcontext, bb, instr, reg_scratch);

            if (ok) {
                reg_id_t pre_scratch;
                if (drreg_reserve_register(drcontext, bb, instr, NULL, &pre_scratch) !=
                        DRREG_SUCCESS) {
                    drreg_unreserve_register(drcontext, bb, instr, reg_addr);
                    break;
                }

                reg_id_t ccc_src_reg = DR_REG_NULL;
                bool     ccc_has_imm = false;
                uint64_t ccc_imm_val = 0;
                bool     ccc_force_clean = false;

                if (instr_is_rep_string_op(instr) ||
                    instr_get_prefix_flag(instr, PREFIX_LOCK)) {
                    ccc_force_clean = true;
                }

                if (!ccc_force_clean) {
                    bool is_rmw = false;
                    for (int si = 0; si < instr_num_srcs(instr); si++) {
                        opnd_t src = instr_get_src(instr, si);
                        if (opnd_is_memory_reference(src)) {
                            is_rmw = true;
                            break;
                        }
                    }

                    if (!is_rmw) {
                        reg_id_t skip_a = reg_to_pointer_sized(reg_addr);
                        reg_id_t skip_b = reg_to_pointer_sized(pre_scratch);
                        for (int si = 0; si < instr_num_srcs(instr); si++) {
                            opnd_t src = instr_get_src(instr, si);
                            if (opnd_is_reg(src)) {
                                reg_id_t sr = opnd_get_reg(src);
                                if (opnd_uses_reg(dst, sr))
                                    continue;
                                sr = reg_to_pointer_sized(sr);
                                if (sr == skip_a || sr == skip_b)
                                    continue;
                                if (sr >= DR_REG_RAX && sr <= DR_REG_R15) {
                                    ccc_src_reg = sr;
                                    break;
                                }
                            } else if (opnd_is_immed_int(src)) {
                                ccc_has_imm = true;
                                ccc_imm_val = (uint64_t)opnd_get_immed_int(src);
                                break;
                            }
                        }
                    }
                }

                bool vi = ccc_has_imm;
                bool is_wide = (sz > 8) && !ccc_force_clean;

                emit_pre_write(drcontext, bb, instr,
                               reg_addr, pre_scratch, sz, write_pc,
                               ccc_src_reg, ccc_has_imm, ccc_imm_val,
                               &vi, is_wide);

                drreg_unreserve_register(drcontext, bb, instr, pre_scratch);

                data->reg_addr = reg_addr;
                data->src_reg  = ccc_src_reg;
                data->write_sz = sz;
                data->value_inline = vi;
                data->value_is_imm = ccc_has_imm;
                data->wide_write = is_wide;
            } else {
                drreg_unreserve_register(drcontext, bb, instr, reg_addr);
            }
        }
    }
after_write:

    if (drmgr_is_last_instr(drcontext, instr)) {
        handle_pending_post_write(drcontext, bb, instr, data);
        dr_insert_clean_call(drcontext, bb, instr,
                             (void *)flush_head_cache, false, 0);
        dr_thread_free(drcontext, data, sizeof(instru_data_t));
    }

    if (instr_reads_memory(instr)) {
        bool reload_handled = false;
        if (instr_num_dsts(instr) == 1 && opnd_is_reg(instr_get_dst(instr, 0))) {
            reg_id_t dst_reg = opnd_get_reg(instr_get_dst(instr, 0));
            if (is_dwarf_reload_candidate(dst_reg)) {
                for (int i = 0; i < instr_num_srcs(instr); i++) {
                    opnd_t src = instr_get_src(instr, i);
                    if (!opnd_is_memory_reference(src)) continue;
                    reg_id_t reg1, reg2;
                    if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg1) != DRREG_SUCCESS)
                        break;
                    if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg2) != DRREG_SUCCESS) {
                        drreg_unreserve_register(drcontext, bb, instr, reg1);
                        break;
                    }
                    bool ok = drutil_insert_get_mem_addr(drcontext, bb, instr, src, reg1, reg2);
                    uint32_t rd_sz = opnd_size_in_bytes(opnd_get_size(src));
                    int midx = dr_reg_to_rtmap_idx(dst_reg);
                    drreg_unreserve_register(drcontext, bb, instr, reg2);
                    if (ok && midx >= 0) {
                        dr_insert_clean_call(drcontext, bb, instr,
                                             (void *)at_reload, false, 3,
                                             opnd_create_reg(reg1),
                                             OPND_CREATE_INT32((int)rd_sz),
                                             OPND_CREATE_INT32(midx));
                        reload_handled = true;
                    }
                    drreg_unreserve_register(drcontext, bb, instr, reg1);
                    break;
                }
            }
        }

        if (!reload_handled) {
            int rd_ops = 0;
            for (int i = 0; i < instr_num_srcs(instr); i++) {
                if (opnd_is_memory_reference(instr_get_src(instr, i))) rd_ops++;
            }
            if (rd_ops > 0) {
                dr_insert_clean_call(drcontext, bb, instr,
                                     (void *)flush_read_buf_if_needed, false, 1,
                                     OPND_CREATE_INT32(rd_ops));
            }
            for (int i = 0; i < instr_num_srcs(instr); i++) {
                opnd_t src = instr_get_src(instr, i);
                if (!opnd_is_memory_reference(src))
                    continue;
                reg_id_t reg1, reg2;
                if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg1) != DRREG_SUCCESS)
                    continue;
                if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg2) != DRREG_SUCCESS) {
                    drreg_unreserve_register(drcontext, bb, instr, reg1);
                    continue;
                }
                bool ok = drutil_insert_get_mem_addr(drcontext, bb, instr, src, reg1, reg2);
                uint32_t rd_sz = opnd_size_in_bytes(opnd_get_size(src));
                if (ok) {
                    dr_insert_clean_call(drcontext, bb, instr,
                                         (void *)at_mem_read_buf, false, 2,
                                         opnd_create_reg(reg1),
                                         OPND_CREATE_INT32((int)rd_sz));
                }
                drreg_unreserve_register(drcontext, bb, instr, reg2);
                drreg_unreserve_register(drcontext, bb, instr, reg1);
            }
        }
    }

    if (data->has_reads && instr_get_next_app(instr) == NULL) {
        dr_insert_clean_call(drcontext, bb, instr,
                             (void *)flush_read_buf, false, 0);
    }

    return DR_EMIT_DEFAULT;
}

static void
wrap_malloc_pre(void *wrapctx, void **user_data)
{
    *user_data = (void *)drwrap_get_arg(wrapctx, 0);
}

static void
wrap_arena_alloc_pre(void *wrapctx, void **user_data)
{
    app_pc f = drwrap_get_func(wrapctx);
    int size_arg = 0;
    for (int i = 0; i < g_arena_spec_count; i++) {
        if (g_arena_specs[i].func_pc == f) {
            size_arg = g_arena_specs[i].size_arg;
            break;
        }
    }
    *user_data = (void *)(uintptr_t)drwrap_get_arg(wrapctx, size_arg);
}

static void
wrap_malloc_post(void *wrapctx, void *user_data)
{
    void *ret = drwrap_get_retval(wrapctx);
    if (ret == NULL) return;
    uint64_t ptr  = (uint64_t)(uintptr_t)ret;
    uint64_t size = (uint64_t)(uintptr_t)user_data;
    uint32_t caller = (uint32_t)(uintptr_t)drwrap_get_retaddr(wrapctx);

    void *drcontext = drwrap_get_drcontext(wrapctx);
    rtmap_ring_header_t *ring = tls_ring(drcontext);
    if (!ring) return;
    uint16_t tid = tls_thread_id(drcontext);
    uint32_t seq = tls_next_seq(drcontext);
    rtmap_push_alloc(ring, ptr, (uint32_t)size, size,
                      RTMAP_EVENT_ALLOC, tid, seq, caller);
    sync_head_cache(drcontext);
    atomic_fetch_add_explicit(&g_stat_allocs, 1, memory_order_relaxed);
}

static void
wrap_calloc_pre(void *wrapctx, void **user_data)
{
    size_t nmemb = (size_t)drwrap_get_arg(wrapctx, 0);
    size_t sz    = (size_t)drwrap_get_arg(wrapctx, 1);
    *user_data = (void *)(uintptr_t)(nmemb * sz);
}

static void
wrap_realloc_pre(void *wrapctx, void **user_data)
{
    void *old_ptr  = drwrap_get_arg(wrapctx, 0);
    size_t new_sz  = (size_t)drwrap_get_arg(wrapctx, 1);
    *user_data = old_ptr;
    void *drcontext = drwrap_get_drcontext(wrapctx);
    /* free old_ptr now, alloc in post */
    if (old_ptr != NULL) {
        rtmap_ring_header_t *ring = tls_ring(drcontext);
        if (ring) {
            uint16_t tid = tls_thread_id(drcontext);
            uint32_t seq = tls_next_seq(drcontext);
            rtmap_push_ex(ring, (uint64_t)(uintptr_t)old_ptr, 0, 0,
                           RTMAP_EVENT_FREE, tid, seq);
            sync_head_cache(drcontext);
            atomic_fetch_add_explicit(&g_stat_frees, 1, memory_order_relaxed);
        }
    }
    *user_data = (void *)(uintptr_t)new_sz;
}

static void
wrap_realloc_post(void *wrapctx, void *user_data)
{
    void *ret = drwrap_get_retval(wrapctx);
    if (ret == NULL) return;
    uint64_t ptr  = (uint64_t)(uintptr_t)ret;
    uint64_t size = (uint64_t)(uintptr_t)user_data;
    uint32_t caller = (uint32_t)(uintptr_t)drwrap_get_retaddr(wrapctx);

    void *drcontext = drwrap_get_drcontext(wrapctx);
    rtmap_ring_header_t *ring = tls_ring(drcontext);
    if (!ring) return;
    uint16_t tid = tls_thread_id(drcontext);
    uint32_t seq = tls_next_seq(drcontext);
    rtmap_push_alloc(ring, ptr, (uint32_t)size, size,
                      RTMAP_EVENT_ALLOC, tid, seq, caller);
    sync_head_cache(drcontext);
    atomic_fetch_add_explicit(&g_stat_allocs, 1, memory_order_relaxed);
}

static void
wrap_free_pre(void *wrapctx, void **user_data)
{
    void *ptr = drwrap_get_arg(wrapctx, 0);
    if (ptr == NULL) return;

    void *drcontext = drwrap_get_drcontext(wrapctx);
    rtmap_ring_header_t *ring = tls_ring(drcontext);
    if (!ring) return;
    uint16_t tid = tls_thread_id(drcontext);
    uint32_t seq = tls_next_seq(drcontext);
    rtmap_push_ex(ring, (uint64_t)(uintptr_t)ptr, 0, 0,
                   RTMAP_EVENT_FREE, tid, seq);
    sync_head_cache(drcontext);
    atomic_fetch_add_explicit(&g_stat_frees, 1, memory_order_relaxed);
    *user_data = NULL;
}

/* 0=malloc 1=free 2=calloc 3=realloc */
static void
try_wrap_one(const module_data_t *mod, const char *sym, int kind)
{
    size_t offset;
    drsym_error_t err = drsym_lookup_symbol(
        mod->full_path, sym, &offset, DRSYM_DEFAULT_FLAGS);
    if (err != DRSYM_SUCCESS) return;
    app_pc func_pc = mod->start + offset;
    switch (kind) {
    case 0: drwrap_wrap(func_pc, wrap_malloc_pre, wrap_malloc_post); break;
    case 1: drwrap_wrap(func_pc, wrap_free_pre, NULL); break;
    case 2: drwrap_wrap(func_pc, wrap_calloc_pre, wrap_malloc_post); break;
    case 3: drwrap_wrap(func_pc, wrap_realloc_pre, wrap_realloc_post); break;
    }
    dr_printf("rtmap: wrapped %s @ %p\n", sym, (void *)func_pc);
}

/* Known application-level allocator wrappers (same ABI as libc).
 * wrapping these in addition to libc gives us the outermost caller RIP;
 * e.g. dictAddRaw instead of zmalloc internals. drwrap fires
 * inner-to-outer for nested wrappers, so the outermost event's rip_lo
 * wins in the engine (last-write-wins on same ptr). */
static const char *g_app_alloc_prefixes[] = {
    "zmalloc", "zfree", "zcalloc", "zrealloc",
    "ztrymalloc", "ztryrealloc",
    "g_malloc", "g_free", "g_realloc",
    "xmalloc", "xfree", "xrealloc", "xcalloc",
    NULL
};

static int
alloc_kind_from_name(const char *sym)
{
    if (strstr(sym, "realloc")) return 3;
    if (strstr(sym, "calloc"))  return 2;
    if (strstr(sym, "free"))    return 1;
    return 0; /* malloc / alloc */
}

static void
wrap_alloc_funcs(const module_data_t *mod)
{
    try_wrap_one(mod, "malloc",  0);
    try_wrap_one(mod, "free",    1);
    try_wrap_one(mod, "calloc",  2);
    try_wrap_one(mod, "realloc", 3);
}

/* foreign allocator prefixes (same ABI) */
static void
wrap_alloc_funcs_foreign(const module_data_t *mod, const char *tag)
{
    try_wrap_one(mod, "je_malloc",  0);
    try_wrap_one(mod, "je_free",    1);
    try_wrap_one(mod, "je_calloc",  2);
    try_wrap_one(mod, "je_realloc", 3);
    try_wrap_one(mod, "tc_malloc",  0);
    try_wrap_one(mod, "tc_free",    1);
    try_wrap_one(mod, "tc_calloc",  2);
    try_wrap_one(mod, "tc_realloc", 3);
    try_wrap_one(mod, "mi_malloc",  0);
    try_wrap_one(mod, "mi_free",    1);
    try_wrap_one(mod, "mi_calloc",  2);
    try_wrap_one(mod, "mi_realloc", 3);
    try_wrap_one(mod, "malloc",  0);
    try_wrap_one(mod, "free",    1);
    try_wrap_one(mod, "calloc",  2);
    try_wrap_one(mod, "realloc", 3);
    dr_printf("rtmap: scanned foreign allocator module '%s'\n", tag);
}

/* flush module table to /dev/shm sidecar; engine reads after ctl attach */
static void
flush_modtab(void)
{
    char path[128];
    dr_snprintf(path, sizeof(path), "/dev/shm/rtmap_modules_%u", g_process_pid);
    file_t f = dr_open_file(path, DR_FILE_WRITE_OVERWRITE);
    if (f == INVALID_FILE) return;
    for (int i = 0; i < g_modtab_count; i++) {
        char line[320];
        dr_snprintf(line, sizeof(line), "%llx %s\n",
                    (unsigned long long)g_modtab[i].base, g_modtab[i].path);
        dr_write_file(f, line, strlen(line));
    }
    dr_close_file(f);
}

static int
is_system_module(const char *name)
{
    return (strstr(name, "vdso") != NULL ||
            strstr(name, "ld-linux") != NULL ||
            strstr(name, "libpthread") != NULL ||
            strstr(name, "librtmap") != NULL ||
            strstr(name, "libdynamorio") != NULL ||
            strstr(name, "libdr") != NULL);
}

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    (void)drcontext; (void)loaded;
    const char *name = dr_module_preferred_name(info);

    if (name && (strstr(name, "libc") != NULL)) {
        wrap_alloc_funcs(info);
    } else if (name && (strstr(name, "jemalloc") != NULL ||
                        strstr(name, "tcmalloc") != NULL ||
                        strstr(name, "mimalloc") != NULL)) {
        wrap_alloc_funcs_foreign(info, name);
    } else if (name && !is_system_module(name)) {
        /* scan non-system modules for application-level allocator wrappers */
        for (const char **p = g_app_alloc_prefixes; *p; p++) {
            size_t offset;
            drsym_error_t err = drsym_lookup_symbol(
                info->full_path, *p, &offset, DRSYM_DEFAULT_FLAGS);
            if (err != DRSYM_SUCCESS) continue;
            app_pc func_pc = info->start + offset;
            int kind = alloc_kind_from_name(*p);
            switch (kind) {
            case 0: drwrap_wrap(func_pc, wrap_malloc_pre, wrap_malloc_post); break;
            case 1: drwrap_wrap(func_pc, wrap_free_pre, NULL); break;
            case 2: drwrap_wrap(func_pc, wrap_calloc_pre, wrap_malloc_post); break;
            case 3: drwrap_wrap(func_pc, wrap_realloc_pre, wrap_realloc_post); break;
            }
            dr_printf("rtmap: wrapped app allocator %s @ %p (kind=%d) in %s\n",
                      *p, (void *)func_pc, kind, name);
        }
    }

    /* record all non-system modules in sidecar table */
    if (name && info->full_path[0] != '\0' && !is_system_module(name) &&
        strstr(name, "libc") == NULL) {
        dr_mutex_lock(g_modtab_lock);
        if (g_modtab_count < MODTAB_MAX) {
            g_modtab[g_modtab_count].base = (uint64_t)(uintptr_t)info->start;
            strncpy(g_modtab[g_modtab_count].path, info->full_path, 255);
            g_modtab[g_modtab_count].path[255] = '\0';
            g_modtab_count++;
            flush_modtab();
        }
        dr_mutex_unlock(g_modtab_lock);
    }

    if (atomic_load_explicit(&g_module_base_phase, memory_order_relaxed) == 0 &&
        info->full_path[0] != '\0') {
        if (name && !is_system_module(name) && strstr(name, "libc") == NULL) {
            g_module_base = (uint64_t)(uintptr_t)info->start;
            g_module_end  = (uint64_t)(uintptr_t)info->end;
            atomic_store_explicit(&g_module_base_phase, 1, memory_order_release);
            dr_printf("rtmap: main module '%s' base=0x%llx\n",
                      name, (unsigned long long)g_module_base);

            /* resolve + wrap custom arena sub-allocators by ELF offset.
             * func_pc = main module base + offset. share wrap_malloc_post. */
            for (int i = 0; i < g_arena_spec_count; i++) {
                app_pc fpc = info->start + g_arena_specs[i].offset;
                g_arena_specs[i].func_pc = fpc;
                drwrap_wrap(fpc, wrap_arena_alloc_pre, wrap_malloc_post);
                dr_printf("rtmap: wrapped arena allocator @ ELF+0x%llx (size_arg=%d) in %s\n",
                          (unsigned long long)g_arena_specs[i].offset,
                          g_arena_specs[i].size_arg, name);
            }
        }
    }
}

/* fork: child inherits parent's g_ctl mmap (stale). re-create own ctl + ring.
 * DR guarantees this fires in the child before any instrumented code runs. */
static void
event_fork_init(void *drcontext)
{
    uint32_t parent = g_process_pid;
    uint32_t child  = (uint32_t)dr_get_process_id();

    /* detach from parent's ctl (inherited mmap) */
    if (g_ctl && g_ctl != (void *)MAP_FAILED) {
        munmap(g_ctl, rtmap_ctl_shm_size());
        g_ctl = NULL;
    }
    if (g_ctl_fd >= 0) {
        close(g_ctl_fd);
        g_ctl_fd = -1;
    }

    /* reset thread counter; fork child starts with one thread */
    atomic_store_explicit(&g_next_thread_id, 0, memory_order_relaxed);

    map_ctl_ring(parent);

    /* re-create this thread's ring under the child's namespace */
    uint16_t tid = atomic_fetch_add_explicit(&g_next_thread_id, 1, memory_order_relaxed);
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_THREAD_ID], (void *)(uintptr_t)tid);

    /* unmap parent's ring (inherited) */
    rtmap_ring_header_t *old_ring = tls_ring(drcontext);
    if (old_ring) {
        munmap(old_ring, rtmap_shm_size(old_ring->capacity));
    }

    char name[RTMAP_RING_NAME_LEN];
    dr_snprintf(name, sizeof(name), RTMAP_RING_SHM_FMT,
                (unsigned)g_process_pid, (unsigned)tid);
    rtmap_ring_header_t *ring = alloc_thread_ring(name);
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_RING], (void *)ring);

    /* update raw TLS and pad */
    rtmap_scratch_pad_t *pad = tls_pad(drcontext);
    if (pad && ring) {
        pad->ring_data = (uint64_t)(uintptr_t)rtmap_ring_data(ring);
        pad->ring_mask = ring->capacity - 1;
    }
    raw_tls_set(drcontext, RAW_TLS(RTMAP_RAW_SLOT_RING), (void *)ring);
    raw_tls_set(drcontext, RAW_TLS(RTMAP_RAW_SLOT_HEAD), (void *)(uintptr_t)0);
    raw_tls_set(drcontext, RAW_TLS(RTMAP_RAW_SLOT_SEQ), (void *)(uintptr_t)0);
    raw_tls_set(drcontext, RAW_TLS(RTMAP_RAW_SLOT_TID), (void *)(uintptr_t)tid);

    int ctl_idx = -1;
    if (ring && g_ctl)
        ctl_idx = rtmap_ctl_register_thread(g_ctl, tid, name);
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_CTL_IDX], (void *)(uintptr_t)(ctl_idx + 1));

    /* emit PROCESS_FORK into child's ring so engine discovers us */
    if (ring) {
        rtmap_push_ex(ring, (uint64_t)child, 0, (uint64_t)parent,
                       RTMAP_EVENT_PROCESS_FORK, tid, 0);
        atomic_store_explicit(&ring->head,
            atomic_load_explicit(&ring->head, memory_order_relaxed),
            memory_order_release);
    }

    dr_printf("rtmap: fork child pid=%u parent=%u ring @ %p (%s)\n",
              (unsigned)child, (unsigned)parent, (void *)ring, name);
}

static void
event_thread_init(void *drcontext)
{
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
    uint16_t tid = atomic_fetch_add_explicit(&g_next_thread_id, 1, memory_order_relaxed);
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_THREAD_ID], (void *)(uintptr_t)tid);
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_SEQ], (void *)(uintptr_t)0);

    char name[RTMAP_RING_NAME_LEN];
    dr_snprintf(name, sizeof(name), RTMAP_RING_SHM_FMT,
                (unsigned)g_process_pid, (unsigned)tid);
    rtmap_ring_header_t *ring = alloc_thread_ring(name);
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_RING], (void *)ring);

    read_buf_t *rdbuf = (read_buf_t *)dr_thread_alloc(drcontext, sizeof(read_buf_t));
    memset(rdbuf, 0, sizeof(read_buf_t));
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_RDBUF], (void *)rdbuf);

    rtmap_scratch_pad_t *pad = alloc_scratch_pad(drcontext, ring);
    raw_tls_set(drcontext, RAW_TLS(RTMAP_RAW_SLOT_RING), (void *)ring);
    raw_tls_set(drcontext, RAW_TLS(RTMAP_RAW_SLOT_HEAD), (void *)(uintptr_t)0);
    raw_tls_set(drcontext, RAW_TLS(RTMAP_RAW_SLOT_SEQ), (void *)(uintptr_t)0);
    raw_tls_set(drcontext, RAW_TLS(RTMAP_RAW_SLOT_TID), (void *)(uintptr_t)tid);
    raw_tls_set(drcontext, RAW_TLS(RTMAP_RAW_SLOT_BP), (void *)(uintptr_t)0);
    raw_tls_set(drcontext, RAW_TLS(RTMAP_RAW_SLOT_SCRATCH), (void *)pad);
    raw_tls_set(drcontext, RAW_TLS(RTMAP_RAW_SLOT_RDBUF), (void *)rdbuf);
    raw_tls_set(drcontext, RAW_TLS(RTMAP_RAW_SLOT_GUARD), NULL);

    int ctl_idx = -1;
    if (ring && g_ctl)
        ctl_idx = rtmap_ctl_register_thread(g_ctl, tid, name);
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_CTL_IDX], (void *)(uintptr_t)(ctl_idx + 1));

    dr_printf("rtmap: thread %u ring @ %p pad @ %p (%s)\n",
              (unsigned)tid, (void *)ring, (void *)pad, name);
}

/* flush cached head to shared ring before blocking syscalls; mark terminal on exit */
static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    rtmap_ring_header_t *ring = (rtmap_ring_header_t *)raw_tls_get(
        drcontext, RAW_TLS(RTMAP_RAW_SLOT_RING));
    if (!ring) return true;

    uint64_t cached = (uint64_t)(uintptr_t)raw_tls_get(
        drcontext, RAW_TLS(RTMAP_RAW_SLOT_HEAD));
    uint64_t published = atomic_load_explicit(&ring->head, memory_order_relaxed);
    if (cached != published)
        atomic_store_explicit(&ring->head, cached, memory_order_release);

    if (sysnum == SYS_exit || sysnum == SYS_exit_group)
        atomic_store_explicit(&ring->status, MV_STATUS_TERMINAL, memory_order_release);

    return true;
}

/* in-band shared mapping detection: intercept mmap/munmap to push
 * EVENT_SHARED_MAP synchronously, eliminating /proc/maps TOCTOU. */
static bool
event_filter_syscall(void *drcontext, int sysnum)
{
    (void)drcontext;
    return (sysnum == SYS_mmap || sysnum == SYS_munmap);
}

static void
event_post_syscall(void *drcontext, int sysnum)
{
    if (g_phase == PHASE_BOOT) return;
    if (sysnum == SYS_mmap) {
        uint64_t ret = (uint64_t)dr_syscall_get_result(drcontext);
        /* mmap returns -errno on failure (top bits set) */
        if ((int64_t)ret < 0 && (int64_t)ret >= -4096) return;
        int flags = (int)dr_syscall_get_param(drcontext, 3);
        if (!(flags & MAP_SHARED)) return;
        size_t length = (size_t)dr_syscall_get_param(drcontext, 1);
        int fd = (int)dr_syscall_get_param(drcontext, 4);
        rtmap_ring_header_t *ring = tls_ring(drcontext);
        if (!ring) return;
        uint16_t tid = tls_thread_id(drcontext);
        uint32_t seq = tls_next_seq(drcontext);
        /* addr=map_addr, size=fd, value=length; engine decodes */
        rtmap_push_ex(ring, ret, (uint32_t)(fd & 0xFFFFFFFF), length,
                       RTMAP_EVENT_SHARED_MAP, tid, seq);
        sync_head_cache(drcontext);
    } else if (sysnum == SYS_munmap) {
        uint64_t addr = (uint64_t)dr_syscall_get_param(drcontext, 0);
        size_t length = (size_t)dr_syscall_get_param(drcontext, 1);
        uint64_t ret = (uint64_t)dr_syscall_get_result(drcontext);
        if ((int64_t)ret != 0) return;
        rtmap_ring_header_t *ring = tls_ring(drcontext);
        if (!ring) return;
        uint16_t tid = tls_thread_id(drcontext);
        uint32_t seq = tls_next_seq(drcontext);
        /* addr=unmap_addr, size=0xFFFFFFFF (sentinel), value=length */
        rtmap_push_ex(ring, addr, 0xFFFFFFFF, length,
                       RTMAP_EVENT_SHARED_MAP, tid, seq);
        sync_head_cache(drcontext);
    }
}

static void
event_thread_exit(void *drcontext)
{
    /* terminal flush: publish any remaining cached events */
    rtmap_ring_header_t *ring_hdr = (rtmap_ring_header_t *)raw_tls_get(
        drcontext, RAW_TLS(RTMAP_RAW_SLOT_RING));
    if (ring_hdr) {
        flush_head_cache(drcontext);
        atomic_store_explicit(&ring_hdr->status, MV_STATUS_TERMINAL, memory_order_release);
    }

    int ctl_idx = (int)(uintptr_t)drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_CTL_IDX]) - 1;
    if (ctl_idx >= 0 && g_ctl)
        rtmap_ctl_mark_dead(g_ctl, (uint32_t)ctl_idx);

    rtmap_ring_header_t *ring = tls_ring(drcontext);
    if (ring) {
        size_t sz = rtmap_shm_size(ring->capacity);
        munmap(ring, sz);
        /* Do NOT shm_unlink here. The engine needs the name to discover
         * and mmap the ring after the tracer exits. The engine's
         * cleanup_shm_for_pid() will unlink after draining. */
    }
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_RING], NULL);

    rtmap_scratch_pad_t *pad = (rtmap_scratch_pad_t *)raw_tls_get(
        drcontext, RAW_TLS(RTMAP_RAW_SLOT_SCRATCH));
    if (pad) {
        atomic_fetch_add_explicit(&g_stat_inline_writes, pad->stat_inline_writes, memory_order_relaxed);
        atomic_fetch_add_explicit(&g_stat_reads,         pad->stat_reads,          memory_order_relaxed);
        atomic_fetch_add_explicit(&g_stat_reloads,       pad->stat_reloads,        memory_order_relaxed);
        atomic_fetch_add_explicit(&g_stat_calls,         pad->stat_calls,          memory_order_relaxed);
        atomic_fetch_add_explicit(&g_stat_returns,       pad->stat_returns,        memory_order_relaxed);
        atomic_fetch_add_explicit(&g_stat_tail_calls,    pad->stat_tail_calls,     memory_order_relaxed);
        atomic_fetch_add_explicit(&g_stat_dropped,       pad->stat_dropped,        memory_order_relaxed);
        atomic_fetch_add_explicit(&g_stat_reentrant_drops, pad->stat_reentrant_drops, memory_order_relaxed);
        atomic_fetch_add_explicit(&g_stat_truncated_writes, pad->stat_truncated_writes, memory_order_relaxed);
        dr_thread_free(drcontext, pad, sizeof(rtmap_scratch_pad_t));
    }

    read_buf_t *rdbuf = (read_buf_t *)drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_RDBUF]);
    if (rdbuf) {
        dr_thread_free(drcontext, rdbuf, sizeof(read_buf_t));
        drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_RDBUF], NULL);
    }
}

static void
event_exit(void)
{
    dr_printf("rtmap: --- Producer Stats (ambient per-thread) ---\n");
    dr_printf("rtmap:   wr_fast: %llu\n", (unsigned long long)atomic_load(&g_stat_inline_writes));
    dr_printf("rtmap:   reads:   %llu\n", (unsigned long long)atomic_load(&g_stat_reads));
    dr_printf("rtmap:   calls:   %llu\n", (unsigned long long)atomic_load(&g_stat_calls));
    dr_printf("rtmap:   returns: %llu\n", (unsigned long long)atomic_load(&g_stat_returns));
    dr_printf("rtmap:   tcalls:  %llu\n", (unsigned long long)atomic_load(&g_stat_tail_calls));
    dr_printf("rtmap:   reloads: %llu\n", (unsigned long long)atomic_load(&g_stat_reloads));
    dr_printf("rtmap:   dropped: %llu\n", (unsigned long long)atomic_load(&g_stat_dropped));
    dr_printf("rtmap:   regsnap: %llu\n", (unsigned long long)atomic_load(&g_stat_reg_snaps));
    dr_printf("rtmap:   rdflush: %llu\n", (unsigned long long)atomic_load(&g_stat_rdbuf_flushes));
    dr_printf("rtmap:   allocs:  %llu\n", (unsigned long long)atomic_load(&g_stat_allocs));
    dr_printf("rtmap:   frees:   %llu\n", (unsigned long long)atomic_load(&g_stat_frees));
    dr_printf("rtmap:   threads: %u\n", (unsigned)atomic_load(&g_next_thread_id));
    dr_printf("rtmap:   bb_entr: %llu\n", (unsigned long long)atomic_load(&g_stat_bb_entries));
    dr_printf("rtmap:   rd_vals: %llu\n", (unsigned long long)atomic_load(&g_stat_read_vals));
    dr_printf("rtmap:   rd_prio: %llu\n", (unsigned long long)atomic_load(&g_stat_priority_reads));
    dr_printf("rtmap:   rd_shed: %llu\n", (unsigned long long)atomic_load(&g_stat_shed_reads));
    dr_printf("rtmap:   reentry: %llu\n", (unsigned long long)atomic_load(&g_stat_reentrant_drops));
    dr_printf("rtmap:   wr_trunc:%llu\n", (unsigned long long)atomic_load(&g_stat_truncated_writes));
    dr_printf("rtmap: --- JIT site breakdown ---\n");
    dr_printf("rtmap:   imm_sites:   %llu\n", (unsigned long long)atomic_load(&g_jit_imm_sites));
    dr_printf("rtmap:   gpr_sites:   %llu\n", (unsigned long long)atomic_load(&g_jit_gpr_sites));
    dr_printf("rtmap:   clean_sites: %llu\n", (unsigned long long)atomic_load(&g_jit_clean_sites));
#ifdef RTMAP_CCC_AUDIT
    dr_printf("rtmap: --- CCC shadow audit ---\n");
    dr_printf("rtmap:   checks:      %llu\n", (unsigned long long)atomic_load(&g_ccc_audit_checks));
    dr_printf("rtmap:   pass:        %llu\n", (unsigned long long)atomic_load(&g_ccc_audit_pass));
    dr_printf("rtmap:   fail:        %llu\n", (unsigned long long)atomic_load(&g_ccc_audit_fail));
    dr_printf("rtmap:   rt_gpr:      %llu\n", (unsigned long long)atomic_load(&g_stat_gpr_captures));
    dr_printf("rtmap:   rt_clean:    %llu\n", (unsigned long long)atomic_load(&g_stat_clean_reads));
#endif

    /* sidecar module table left for engine to read + clean up */
    dr_mutex_destroy(g_modtab_lock);

    unmap_ctl_ring();
    drmgr_unregister_bb_insertion_event(event_bb_insert);
    for (int i = 0; i < TLS_SLOT_COUNT; i++)
        drmgr_unregister_tls_field(g_tls_idx[i]);
    dr_raw_tls_cfree(g_raw_tls_off, RTMAP_RAW_TLS_SLOTS);
    drwrap_exit();
    drsym_exit();
    drreg_exit();
    drutil_exit();
    drmgr_exit();
}

static void tripwire_hit(void)
{
    if (g_phase != PHASE_BOOT) return;
    g_phase = PHASE_TRACE;
    if (g_ctl)
        atomic_store_explicit(&g_ctl->tripwire_hit, 1, memory_order_release);
    dr_printf("rtmap: TRIPWIRE HIT — phase transition BOOT->TRACE (no flush)\n");
    /* runtime phase gates: all instrumentation was emitted at JIT time,
     * gated by cmp [&g_phase], PHASE_TRACE; jne skip. flipping g_phase
     * activates every existing fragment instantly — zero recompilation. */
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    (void)id;

    /* parse client args: argv[0] is client lib path, argv[1..] are our args.
     * argv[1] is hex tripwire ELF offset (0 = disabled).
     * argv[2..] are arena allocator specs formatted "<hex_offset>:<size_arg>"
     * (e.g. "3a2b0:1" for ngx_palloc(pool, size)). */
    if (argc >= 2 && argv[1] != NULL) {
        char *end = NULL;
        uint64_t off = (uint64_t)strtoull(argv[1], &end, 16);
        if (end != argv[1] && off != 0) {
            g_tripwire_offset = off;
            g_phase = PHASE_BOOT;
            dr_printf("rtmap: tripwire armed at ELF+0x%llx (PHASE_BOOT)\n",
                      (unsigned long long)off);
        }
    }
    for (int ai = 2; ai < argc && argv[ai] != NULL; ai++) {
        if (g_arena_spec_count >= ARENA_MAX) {
            dr_printf("rtmap: WARNING: too many arena allocator specs (max %d)\n",
                      ARENA_MAX);
            break;
        }
        char *colon = NULL;
        uint64_t aoff = (uint64_t)strtoull(argv[ai], &colon, 16);
        if (colon == argv[ai] || *colon != ':') {
            dr_printf("rtmap: WARNING: malformed arena spec '%s' (want <hexoff>:<argidx>)\n",
                      argv[ai]);
            continue;
        }
        int sarg = (int)strtol(colon + 1, NULL, 10);
        if (sarg < 0 || sarg > 8) sarg = 0;
        g_arena_specs[g_arena_spec_count].offset   = aoff;
        g_arena_specs[g_arena_spec_count].size_arg = sarg;
        g_arena_specs[g_arena_spec_count].func_pc  = NULL;
        g_arena_spec_count++;
        dr_printf("rtmap: arena allocator spec: ELF+0x%llx size_arg=%d\n",
                  (unsigned long long)aoff, sarg);
    }

    dr_set_client_name("rtmap tracer", "https://github.com/abokhalill/rtmap");

    drmgr_init();
    drutil_init();
    drreg_options_t drreg_ops = { sizeof(drreg_ops), 8, false };
    drreg_init(&drreg_ops);
    drwrap_init();
    drsym_init(0);

    if (!dr_raw_tls_calloc(&g_raw_tls_seg, &g_raw_tls_off,
                            RTMAP_RAW_TLS_SLOTS, 0))
        DR_ASSERT_MSG(false, "dr_raw_tls_calloc failed");

    for (int i = 0; i < TLS_SLOT_COUNT; i++) {
        g_tls_idx[i] = drmgr_register_tls_field();
        DR_ASSERT(g_tls_idx[i] != -1);
    }

    /* stale cleanup: legacy names + pid-scoped from prior runs */
    shm_unlink(RTMAP_CTL_SHM_NAME);
    {
        uint32_t my_pid = (uint32_t)dr_get_process_id();
        char stale_ctl[RTMAP_RING_NAME_LEN];
        dr_snprintf(stale_ctl, sizeof(stale_ctl), RTMAP_CTL_SHM_FMT, (unsigned)my_pid);
        shm_unlink(stale_ctl);
        for (unsigned i = 0; i < RTMAP_MAX_THREADS; i++) {
            char stale[RTMAP_RING_NAME_LEN];
            dr_snprintf(stale, sizeof(stale), "/rtmap_ring_%u", i);
            shm_unlink(stale);
            dr_snprintf(stale, sizeof(stale), RTMAP_RING_SHM_FMT, (unsigned)my_pid, i);
            shm_unlink(stale);
        }
    }

    g_modtab_lock = dr_mutex_create();

    map_ctl_ring(0);

    drmgr_register_module_load_event(event_module_load);
    drmgr_register_exit_event(event_exit);
    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);
    drmgr_register_pre_syscall_event(event_pre_syscall);
    drmgr_register_filter_syscall_event(event_filter_syscall);
    drmgr_register_post_syscall_event(event_post_syscall);
    dr_register_fork_init_event(event_fork_init);

    drmgr_register_bb_instrumentation_event(event_bb_analysis,
                                            event_bb_insert, NULL);

    dr_printf("rtmap: Ghost v3 tracer attached, macro-trampoline inline writes\n");
    dr_printf("rtmap: raw TLS seg=%d off=0x%x, ctl @ %p\n",
              (int)g_raw_tls_seg, g_raw_tls_off, (void *)g_ctl);
}
