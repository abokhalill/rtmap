# Tracer

The tracer is a DynamoRIO client written in C (`tracer.c`). It runs inside the
target process's address space and instruments every basic block to capture
memory writes, reads, function calls, returns, tail calls, and register
reloads. Events are pushed into per-thread SPSC ring buffers over POSIX
shared memory.

This document covers the tracer's instrumentation strategy, thread-local
storage layout, event emission, and performance characteristics. All claims
are derived from the current `tracer.c` and `rtmap_bridge.h`.

## Initialization

The tracer entry point is `dr_client_main()`. It performs the following steps:

1. Initializes DynamoRIO extension libraries: `drmgr`, `drutil`, `drreg`,
   `drwrap`, `drsyms`.
2. Registers 6 drmgr TLS fields via `drmgr_register_tls_field`. The returned
   indices are stored in `g_tls_idx[]`.
3. Registers 8 raw TLS slots via `drmgr_tls_field_request_raw`.
4. Creates the PID-scoped control ring shared memory (`/rtmap_ctl_<pid>`).
   Root processes also create a legacy `/rtmap_ctl` for backward compat.
5. Registers callbacks: module load, thread init/exit, process exit,
   fork init (`dr_register_fork_init_event`), BB analysis, and BB insertion.
6. If a tripwire ELF offset was passed by the engine (first argument to the
   client), arms the tripwire breakpoint via `dr_register_bb_event` filtering.

### Tripwire mechanism (runtime phase gate)

The tracer supports a **runtime phase gate** for server-mode targets.
The engine resolves a tripwire symbol (e.g., `ngx_epoll_process_events`,
`aeProcessEvents`) to an ELF offset and passes it as the first client
argument. The tracer operates in two phases:

| Phase | Name | Behavior |
|---|---|---|
| `PHASE_BOOT` | DBI startup | All instrumentation is **emitted at JIT time** but **gated at runtime** by an inline `cmp [g_phase], PHASE_TRACE; jne skip` at the top of each instrumented path. Only ALLOC/FREE (via clean-call hooks that check `g_phase` at entry) pass through. |
| `PHASE_TRACE` | Full tracing | The runtime gate falls through (predicted-taken). All event types flow. No code cache invalidation occurs. |

The transition occurs in `tripwire_hit()`:

1. Guard: if `g_phase != PHASE_BOOT`, return (idempotent).
2. Set `g_phase = PHASE_TRACE` (relaxed store; the inline compare will
   observe the new value on the next BB entry).
3. Atomically set `g_ctl->tripwire_hit = 1` with release semantics.

**No code cache flush.** Because all instrumentation was emitted during
PHASE_BOOT (gated by the runtime check), the transition from BOOT→TRACE
requires zero JIT recompilation. This eliminates the multi-second code cache
flush storm that previously occurred on tripwire fire in large binaries
(e.g., Redis with ~15K basic blocks).

The engine reads `tripwire_hit` from the shared ctl header (relaxed load)
to arm its idle timeout. This prevents premature exit during the startup
pause before the server's event loop begins.

### drmgr TLS fields

DynamoRIO assigns TLS field indices dynamically. The tracer stores them in
`g_tls_idx[]` and accesses them by symbolic slot index:

| Slot | Name | Purpose |
|---|---|---|
| 0 | `TLS_SLOT_GUARD` | Reentrancy guard (prevents recursive clean calls) |
| 1 | `TLS_SLOT_THREAD_ID` | Logical thread ID (u16, assigned sequentially) |
| 2 | `TLS_SLOT_SEQ` | Per-thread event sequence counter (u32, stored as `uintptr_t`) |
| 3 | `TLS_SLOT_RING` | Pointer to this thread's ring header |
| 4 | `TLS_SLOT_CTL_IDX` | Index in the control ring's thread array |
| 5 | `TLS_SLOT_RDBUF` | Pointer to the per-thread read buffer |

### Raw TLS slots

The raw TLS slots are used by inline JIT instrumentation (no clean call):

| Slot | Name | Purpose |
|---|---|---|
| 0 | `RTMAP_RAW_SLOT_RING` | Ring header pointer (for inline head flush) |
| 1 | `RTMAP_RAW_SLOT_HEAD` | Cached head counter (deferred release store) |
| 2 | `RTMAP_RAW_SLOT_SEQ` | Cached sequence counter (inline increment) |
| 3 | `RTMAP_RAW_SLOT_TID` | Thread ID (inline event metadata) |
| 4 | `RTMAP_RAW_SLOT_BP` | Backpressure flag mirror (inline check) |
| 5 | `RTMAP_RAW_SLOT_SCRATCH` | Pointer to `rtmap_scratch_pad_t` |
| 6 | `RTMAP_RAW_SLOT_RDBUF` | Read buffer pointer (inline overflow check) |
| 7 | `RTMAP_RAW_SLOT_GUARD` | Inline reentrancy guard |

Raw TLS is accessed via segment base + offset (`dr_raw_tls_opnd`), which
compiles to a single `MOV` through `gs:` or `fs:` segment override — no
function call overhead.

## Instrumentation

DynamoRIO calls the tracer twice for each basic block:

1. **Analysis pass** (`event_bb_analysis`). Scans the BB for memory read
   instructions. Sets a boolean flag (`has_reads`) controlling whether a
   read buffer flush is inserted at the end of the BB. Also allocates
   `instru_data_t` for cross-instruction state.

2. **Insertion pass** (`event_bb_insert`). Called once per instruction.
   Inserts instrumentation based on instruction type. The pass also handles
   **deferred post-write** completion: if the previous instruction had a
   pending `emit_post_write`, it is emitted at the start of the current
   instruction's insertion callback.

### Writes (hybrid inline/clean-call)

The write path is the most performance-critical and uses a two-phase
inline/clean-call hybrid. This is the **only proven-stable approach** under
DynamoRIO's execution model. Six alternative inline value capture strategies
were tested and all failed (see Design Decisions below).

**Phase 1: `emit_pre_write` (fully inline, BEFORE the store)**

1. Reserve two scratch registers via `drreg` (`reg_addr`, `scratch`).
2. Compute effective address (EA) via `drutil_insert_get_mem_addr` into
   `reg_addr`.
3. Save EA to `pad.scratch[0]` via raw TLS (EA may become stale after
   the store — e.g., PUSH decrements RSP before writing).
4. Check ring null → skip if no ring allocated.
5. Check backpressure → skip if active.
6. Compute slot pointer: `ring_data + (head & mask) * 32`.
7. Write metadata into slot fields inline:
   - `addr` = EA
   - `size` = write size (JIT-time constant)
   - `thread_id` = from raw TLS
   - `seq_lo` = from raw TLS
   - `kind_flags` = `RTMAP_EVENT_WRITE | (wide_write ? RTMAP_FLAG_TRUNCATED << 8 : 0) | (seq_hi << 16)`
   - `rip_lo` = app PC offset from module base (JIT-time constant)
8. Save slot pointer to `pad.scratch[1]` (0 if skipped).
9. Unreserve `scratch`. Keep `reg_addr` reserved across the app store.

**Phase 2: `emit_post_write` (inline + clean call, AFTER the store)**

1. Load `pad.scratch[1]`. If 0 → skip (pre-write was skipped).
2. **Value capture** (three tiers, selected at JIT time):
   - **Cat-A (imm)**: value already written in pre-write. No action.
   - **Cat-B (vector 7, generalized)**: inline EA re-read for writes
     where `sz ≤ 8`. Load EA from `pad.scratch[0]` via raw TLS, 8-byte
     `mov_ld` from `[EA]`, store into `slot->value`. Engine masks to
     actual size via `ev.size`. All meta-instructions — bypasses drreg
     entirely. ~10 cycles. Covers GPR-sourced, RMW, LOCK, and all other
     ≤ 8-byte stores. The app just committed to `[EA]` so the cache
     line is hot.
   - **Cat-B wide (compound multi-slot)**: for writes where `sz > 8` and
     no REP/LOCK prefix (`!ccc_force_clean`). Header event reads the low
     8 bytes inline (vector 7) with `RTMAP_FLAG_COMPOUND` in `kind_flags`.
     A clean call to `compound_fill_continuations` then writes N-1
     continuation events (each with `RTMAP_FLAG_CONTINUATION`, 8B chunk
     value, chunk EA) into consecutive ring slots and advances the cached
     head. Max 8 slots (64B). Engine reassembles full value per-chunk —
     no data loss, no zero-poisoning. Bumps `pad->stat_truncated_writes`.
   - **Cat-B fallback**: clean call to `safe_read_into_slot(EA, size, slot)`.
     `DR_TRY_EXCEPT`-guarded `memcpy`. ~100 cycles. Only used for
     REP MOVS/STOS and LOCK-prefixed wide writes (`ccc_force_clean`).
     These retain `RTMAP_FLAG_TRUNCATED` and the engine zero-poisons.
3. Increment `pad->stat_inline_writes` inline. (Wide writes also increment
   `pad->stat_truncated_writes` in the vector 7 path.)
4. Increment per-thread `seq` counter (raw TLS).
5. Increment cached `head` counter (raw TLS).
6. Conditional head flush: if `head & 0x3F == 0`, flush to `ring->head`
   (release store).
7. Unreserve `reg_addr`.

**Why `drreg_get_app_value` is unsound for value capture**: six attempts
plus a seventh (post-write position) all fail. drreg's lazy spill/restore
is resolved during the mangler phase; `drreg_get_app_value` reads from
spill slots that may contain stale pre-instruction values. The manual EA
re-read (vector 7) bypasses drreg entirely by reading from application
memory via raw-TLS-derived pointers. CCC audit verified: 0 failures
across 2M single-threaded events.

**BB-exit head flush**: At the end of every basic block, a clean call to
`flush_head_cache` unconditionally stores the cached head to `ring->head`
with release ordering. This ensures the consumer sees events even from
threads that produce fewer than 64 writes per BB.

### BB_ENTRY (Kind 11)

Emitted once at the head of every basic block, fully inline — no clean
call, no EA computation. The BB start PC is a JIT-time constant embedded
as two 32-bit immediate stores. Uses the same raw TLS seq/head/flush
machinery as writes.

Fields: `addr` = BB start PC, `size` = 0, `value` = 0, `rip_lo` =
PC offset from module base. Only emitted for BBs within the main module
address range.

~30 meta-instructions per BB entry. Engine-side: `world.record_bb_entry(rip_lo)`
increments per-BB hit counter and `insn_counter`.

### Calls

For each direct `call` instruction:

```
flush_head_cache()    // ensure consumer sees prior writes
at_call(callee_pc, RSP)
```

The `at_call` function:
- Checks the reentrancy guard. Returns immediately if set.
- Sets the reentrancy guard.
- Calls `maybe_emit_module_load` (at most once per process, via CAS).
- Pushes a `CALL` event with callee PC and frame base (RSP).
- Increments `pad->stat_calls`.
- Increments `g_insn_counter` by 8 (relaxed).
- Snapshots all 18 registers via `dr_get_mcontext` and pushes a 7-slot
  `REG_SNAPSHOT` via `rtmap_push_reg_snapshot`.
- Clears the reentrancy guard.

### Returns

For each `ret` instruction:

```
flush_head_cache()
at_return(instr_pc)
```

Pushes a `RETURN` event with the return address. Increments
`pad->stat_returns`.

### Tail calls

Detected heuristically at the end of each BB:

```
if instr_is_ubr(instr) && !instr_is_call(instr) && is_last_instr:
    target = branch_target_pc
    if target >= module_base && distance(target, here) > 4096:
        flush_head_cache()
        at_tail_call(target_pc, RSP)
```

The 4KB threshold filters out intra-function branches (if/else, loops) while
catching function-to-function tail calls emitted by `-O2`/`-O3`. Pushes a
`TAIL_CALL` event (kind 8) with callee PC and frame base.

### Reloads

Selective detection of callee-saved register reloads:

```
if instr is MOV reg, [mem]:
    if reg in {RBX, RBP, R12, R13, R14, R15}:
        at_reload(src_addr, size, dest_reg_idx)
```

Only callee-saved registers are instrumented — these are the registers that
DWARF promotes variables into at `-O3`. The reload event encodes the
destination register index in the `flags` byte of `kind_flags`, allowing the
Shadow Register File in the engine to update its confidence tracking.

### Reads

Memory reads use a buffered strategy to reduce clean_call overhead:

1. Before each read instruction, if the buffer might overflow, a
   `flush_read_buf_if_needed(needed)` call is inserted.
2. Each read source operand gets a clean_call to `at_mem_read_buf`, which
   appends the address and size to the per-thread read buffer (capacity 16).
   No ring push occurs here.
3. At the last application instruction of the BB, a `flush_read_buf` call is
   inserted. This iterates the buffer and pushes all buffered reads into the
   ring via `rtmap_push_sampled` (which sheds reads under backpressure).

A BB with 10 read instructions produces 10 fast `at_mem_read_buf` calls (no
ring interaction) plus 1 `flush_read_buf` call (pushes up to 10 events).

### Allocator hooks (`drwrap`)

When `event_module_load` detects a module whose name contains `"libc"`, it
calls `wrap_alloc_funcs(info)` to install `drwrap` pre/post callbacks on four
allocator functions:

| Function | Pre callback | Post callback |
|---|---|---|
| `malloc` | Stashes `size` arg in `user_data` | Emits ALLOC(`ptr`, `size`) |
| `free` | Emits FREE(`ptr`) | — |
| `realloc` | Emits FREE(`old_ptr`) if non-NULL, stashes `new_size` | Emits ALLOC(`new_ptr`, `new_size`) |
| `calloc` | Stashes `nmemb * size` in `user_data` | Emits ALLOC(`ptr`, `total_size`) |

ALLOC events encode the allocation size in the `size` field (32-bit) and the
returned pointer in `addr`. FREE events encode the freed pointer in `addr`.

Global counters `g_stat_allocs` and `g_stat_frees` track totals (relaxed
atomics, printed at process exit).

## Thread lifecycle

### Thread init (`event_thread_init`)

1. Sets the reentrancy guard to NULL (inactive).
2. Assigns a sequential thread ID via `atomic_fetch_add` on
   `g_next_thread_id`.
3. Initializes the per-thread sequence counter to 0.
4. Allocates a per-thread ring via `shm_open` (name:
   `/rtmap_ring_<pid>_<tid>`). Ring is initialized with `rtmap_ring_init`
   (sets magic, capacity, proto_version).
5. Allocates a `rtmap_scratch_pad_t` (128 bytes) via `dr_thread_alloc`.
   Populates `ring_data` and `ring_mask` from the ring header.
6. Allocates a per-thread read buffer (capacity 16) via `dr_thread_alloc`.
7. Initializes raw TLS slots: ring pointer, head=0, seq=0, tid, bp=0,
   scratch pad pointer.
8. Registers the thread in the control ring via
   `rtmap_ctl_register_thread` (CAS reclaim or fresh allocation).

### Thread exit (`event_thread_exit`)

1. Flushes the cached head to the ring header (release store).
2. Drains per-thread pad stats into global atomics via
   `atomic_fetch_add_explicit`.
3. Marks the thread as `DEAD` in the control ring (`rtmap_ctl_mark_dead`).
4. Unmaps and unlinks the per-thread ring shared memory.
5. Frees the scratch pad and read buffer via `dr_thread_free`.

## Module load detection

The tracer communicates the target binary's runtime base address to the engine
via a two-phase atomic protocol:

```
Phase 0 (initial):     g_module_base_phase = 0
Phase 1 (base set):    event_module_load stores g_module_base, then
                        stores g_module_base_phase = 1 (release)
Phase 2 (emitted):     first at_call reads phase with acquire,
                        CAS 1 → 2, emits MODULE_LOAD event
```

The `event_module_load` callback filters out system libraries (vdso, ld-linux,
libc, libpthread, libdynamorio) and captures the first non-system module as
the main executable. The CAS ensures exactly one thread emits the event.

## Reentrancy guard

The inline write path uses `pad->nesting_level` (per-thread, in
`rtmap_scratch_pad_t`) to detect reentrant writes. `emit_pre_write`
increments `nesting_level` before writing event metadata; `emit_post_write`
decrements it after. If `nesting_level > 0` at entry, the write is dropped
and `pad->stat_reentrant_drops` is incremented.

Clean-call functions (except `at_mem_read_buf`) also check `TLS_SLOT_GUARD`.
NULL = inactive, non-NULL = clean call in progress.

DynamoRIO delivers signals at basic block boundaries, so the nesting guard
rarely fires in practice. The chaos monkey validates stability under 50µs
signal storms (42K+ signals delivered, zero crashes).

## Pre-syscall flush

`event_pre_syscall` is registered via `drmgr_register_pre_syscall_event`. On
every syscall, if the cached head is dirty (non-zero), it is flushed to
`ring->head` with release ordering. On `SYS_exit` and `SYS_exit_group`, the
ring status is set to `MV_STATUS_TERMINAL` before the flush. This ensures the
engine sees all pending events before the thread vanishes.

## Terminal handshake

`event_thread_exit` performs a belt-and-suspenders terminal flush:
1. Flushes cached head to `ring->head` (release store).
2. Sets `ring->status = MV_STATUS_TERMINAL` (release store).
3. Drains per-thread pad stats into global atomics.
4. Marks the thread `DEAD` in the control ring.
5. Unmaps and unlinks the ring shared memory.

The engine's `batch_drain` checks for terminal status after consuming events.
A terminal ring with `head == tail` (fully drained) is retired.

## Statistics

Stats use a two-tier architecture for zero-contention hot-path counting:

### Per-thread pad stats (hot path, zero atomics)

| Field | Meaning |
|---|---|
| `pad->nesting_level` | Inline reentrancy nesting depth |
| `pad->stat_reentrant_drops` | Writes dropped due to nesting |
| `pad->stat_truncated_writes` | Wide writes (>8B) with truncated prefix |
| `pad->stat_inline_writes` | Write events emitted via inline path |
| `pad->stat_reads` | Read events pushed to ring |
| `pad->stat_reloads` | Reload events emitted |
| `pad->stat_calls` | Call events pushed |
| `pad->stat_returns` | Return events pushed |
| `pad->stat_tail_calls` | Tail-call events emitted |
| `pad->stat_dropped` | Events dropped (ring full or backpressure) |

### Global atomics (drained at thread exit)

| Counter | Meaning |
|---|---|
| `g_stat_inline_writes` | Sum of all threads' inline write counts |
| `g_stat_reads` | Sum of all threads' read counts |
| `g_stat_reloads` | Sum of all threads' reload counts |
| `g_stat_calls` | Sum of all threads' call counts |
| `g_stat_returns` | Sum of all threads' return counts |
| `g_stat_dropped` | Sum of all threads' dropped counts |
| `g_stat_reentrant_drops` | Sum of all threads' reentrant drop counts |
| `g_stat_truncated_writes` | Sum of all threads' truncated write counts |
| `g_stat_reg_snaps` | Register snapshots pushed (global, per-call) |
| `g_stat_rdbuf_flushes` | Read buffer flushes performed (global) |

All global counters use `atomic_fetch_add` with relaxed ordering. They are
printed at process exit via `dr_printf`.

## Design decisions

### Value capture: vector 7 (inline EA re-read)

Six inline value capture approaches were tested and failed under DynamoRIO's
block builder (drreg lazy-restore corruption, block truncation, encoder
ambiguity). The 23x write count drop (14K→631) is the diagnostic signal of
silent block truncation.

**Vector 7** bypasses drreg entirely: after the app store, load EA from
`pad.scratch[0]` via raw TLS, 8-byte `mov_ld` from `[EA]`, store into
`slot->value`. All meta-instructions — mangler-invisible. Works for all
writes where `sz ≤ 8` (GPR-sourced, RMW, LOCK, etc). The `sz > 8` case
(REP MOVS/STOS) falls back to `safe_read_into_slot` clean call.

CCC audit verified: 0 failures across 2M single-threaded events. Multi-threaded
failures (0.025%) are cross-thread TOCTOU on shared memory, not capture bugs.

## Performance characteristics

- **Inline metadata**: ~13 meta-instructions per write (pre-write). No clean
  call, no context save/restore.
- **Value capture**: ~6 meta-instructions (vector 7, post-write) for `sz ≤ 8`.
  Clean call fallback only for `sz > 8`.
- **Head caching**: release store deferred to every 64th event or BB exit.
- **Read buffering**: amortizes clean-call overhead to 1-per-BB-flush.
- **BB_ENTRY**: ~30 meta-instructions per BB head. Fully inline, no clean call.
  PC is JIT-time constant (two imm32 stores). Same seq/head/flush tail as writes.
- **Backpressure**: relaxed load, same cache line as ring metadata.
- **Ring push**: 1 relaxed load (head) + 1 acquire load (tail) + plain stores
  + 1 release store (head). TSO: release store is a plain `mov`.
