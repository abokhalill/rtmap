# Ring Protocol

This document specifies the shared memory ring buffer protocol used for
communication between the rtmap tracer (producer) and engine (consumer).
The protocol is defined in `rtmap_bridge.h`. Protocol version: **3**.

## Design goals

1. **Zero-copy.** Events are written directly into shared memory. No
   serialization, no syscalls in the hot path.
2. **Lock-free.** The SPSC (single-producer, single-consumer) design requires
   no mutexes or CAS operations in the data path.
3. **Cache-line conscious.** The head and tail cursors occupy separate 64-byte
   cache lines to eliminate false sharing between the producer and consumer
   cores.
4. **Bounded.** Each ring has a fixed power-of-two capacity. Full rings either
   drop events or spin, depending on a per-ring flag.
5. **Versioned.** Both ring headers and the control ring carry a
   `proto_version` field. The consumer validates this on attach and rejects
   mismatched versions.

## Event formats

Two event struct layouts are defined. Both are 32 bytes, 32-byte aligned.

### v2 format (`rtmap_event_t`)

Used by `rtmap_push_ex`, `rtmap_push_reg_snapshot`, and the ring data
accessor functions:

```c
typedef struct __attribute__((aligned(32))) {
    uint64_t addr;        // byte 0:  address (memory addr, callee PC, etc.)
    uint32_t size;        // byte 8:  size in bytes (for W/R events)
    uint16_t thread_id;   // byte 12: logical thread ID (0-based)
    uint16_t seq;         // byte 14: per-thread sequence number (wraps at 2^16)
    uint64_t value;       // byte 16: payload (written value, frame base, etc.)
    uint64_t kind_flags;  // byte 24: kind (low 8 bits) | flags (bits 8-15)
} rtmap_event_t;
```

### v3 format (`rtmap_event_v3_t`)

Used by the inline write path for extended sequence numbers and RIP tracking:

```c
typedef struct __attribute__((aligned(32))) {
    uint64_t addr;        // byte 0:  effective address
    uint32_t size;        // byte 8:  write size in bytes
    uint16_t thread_id;   // byte 12: logical thread ID
    uint16_t seq_lo;      // byte 14: sequence number, low 16 bits
    uint64_t value;       // byte 16: post-write value (captured via clean call)
    uint32_t kind_flags;  // byte 24: kind:8 | flags:8 | seq_hi:16
    uint32_t rip_lo;      // byte 28: app PC offset from module base
} rtmap_event_v3_t;
```

Both are `sizeof == 32` (compile-time asserted).

**Sequence number encoding** (v3): The full 32-bit sequence is reconstructed as:

```c
uint32_t seq = (uint32_t)seq_lo | ((uint32_t)(kind_flags >> 16) << 16);
```

At 50M events/sec (typical DBI throughput), 32-bit wrap occurs every ~86
seconds. Consumers MUST use modular arithmetic for ordering:
`(int32_t)(a - b) > 0`. The sequence is per-thread; cross-thread ordering uses
`(thread_id, seq)` pairs.

**ABI compatibility note**: On little-endian, the low 4 bytes of a v2
`kind_flags` (u64) at offset 24 occupy the same position as the v3
`kind_flags` (u32). The consumer currently reads events through the v2 layout
and extracts `kind` via `kind_flags & 0xFF`, which produces correct results
for both formats.

### Event kinds

| Kind | Value | `addr` | `size` | `value` | Notes |
|---|---|---|---|---|---|
| `WRITE` | 0 | Memory address | Byte count | Post-write value | `rip_lo` set (v3) |
| `READ` | 1 | Memory address | Byte count | 0 | Shed under backpressure |
| `CALL` | 2 | Callee PC | 0 | Frame base (RSP) | Triggers REG_SNAPSHOT |
| `RETURN` | 3 | Return address | 0 | 0 | |
| `OVERFLOW` | 4 | Instruction counter | 0 | 0 | Ring was full (diagnostic) |
| `REG_SNAPSHOT` | 5 | Instruction counter | 0 | 0 | 7 consecutive slots |
| `CACHE_MISS` | 6 | Miss address | Cache level | Sample IP | |
| `MODULE_LOAD` | 7 | Runtime base addr | 0 | 0 | Emitted exactly once |
| `TAIL_CALL` | 8 | Callee PC | 0 | Frame base (RSP) | JMP >4KB, main module |
| `ALLOC` | 9 | Pointer returned | Alloc size (bytes) | (unused) | `drwrap` post-malloc/calloc/realloc |
| `FREE` | 10 | Pointer freed | 0 | 0 | `drwrap` pre-free / pre-realloc(old) |
| `BB_ENTRY` | 11 | BB start PC | 0 | 0 | Fully inline, main module only. Shed under backpressure. |
| `RELOAD` | 12 | Source address | Load size | Register index | MOV to callee-saved |
| `PROCESS_FORK` | 13 | Child PID | 0 | Parent PID | Emitted by child after `fork()` |
| `SHARED_MAP` | 14 | Map address | Map length | Flags (MAP/UNMAP) | In-band `mmap`/`munmap` notification |

### Backpressure levels

The ring protocol defines three backpressure levels, communicated from engine
to tracer via the `bp_level` field in the per-thread ring header:

| Level | Threshold | Behavior |
|---|---|---|
| 0 (normal) | Ring < 6/8 full | All events emitted |
| 1 (shed reads) | Ring ≥ 6/8 full | READ and BB_ENTRY events suppressed |
| 2 (shed non-bloom) | Ring ≥ 7/8 full | All events suppressed EXCEPT: ALLOC, FREE, and writes whose `(addr + field_offset)` is present in the per-ring bloom filter |

Hysteresis: backpressure clears only when occupancy drops below 3/8.

The bloom filter is populated by the engine when it stamps a heap allocation:
for each field in the type projection, `bloom_insert(alloc_base + field_offset)`.
This ensures that initialization writes to freshly-typed heap memory survive
even the highest backpressure level.

### Compound wide writes

A compound wide write captures the full value of a memory store >8 bytes by
occupying multiple consecutive ring slots. The protocol mirrors the register
snapshot pattern (atomic multi-slot run).

**Header event** (slot 0):

| Field | Value |
|---|---|
| `kind` | `WRITE` (0) |
| `flags` | `RTMAP_FLAG_COMPOUND` (0x40) |
| `addr` | Effective address of the write |
| `size` | Full write size in bytes (e.g. 16, 32, 64) |
| `value` | Low 8 bytes of the written value |
| `rip_lo` | App PC offset from module base |
| `seq_lo` / `seq_hi` | Per-thread sequence number |

**Continuation events** (slots 1..N-1):

| Field | Value |
|---|---|
| `kind` | `WRITE` (0) |
| `flags` | `RTMAP_FLAG_CONTINUATION` (0x20) |
| `addr` | `EA + k*8` (chunk effective address) |
| `size` | `min(8, remaining_bytes)` |
| `value` | 8-byte chunk at that offset |
| `rip_lo` | 0 |
| `seq_lo` | 0 |

**Slot count**: `ceil(write_size / 8)`, capped at `RTMAP_COMPOUND_MAX_SLOTS`
(8). A 64-byte AVX-512 / cache-line write uses all 8 slots (header + 7
continuations). Writes >64 bytes capture the first 64 bytes.

**Atomicity**: `consume_batch` treats compound writes the same as register
snapshots — if the full run does not fit in the remaining batch capacity, the
batch ends before the header. This guarantees compound writes are never split
across batch boundaries.

**Engine processing**: Each continuation event flows through `process_event` as
an independent `WRITE` with correct `addr`, `size`, and `value`. Continuations
skip `shadow_regs.observe_write` and cross-thread coherence checks (they carry
no meaningful sequence number). The header event's value is real data (not
zero-poisoned).

**Tracer emission**: The header slot is written inline (vector 7 path). A clean
call to `compound_fill_continuations` writes the continuation slots with
`DR_TRY_EXCEPT`-guarded reads and advances the cached head by the continuation
count.

**Flag definitions** (`rtmap_bridge.h`):

```c
#define RTMAP_FLAG_COMPOUND      0x40  /* header of multi-slot wide write */
#define RTMAP_FLAG_CONTINUATION  0x20  /* continuation slot of compound write */
#define RTMAP_COMPOUND_MAX_SLOTS 8     /* header + 7 continuations = 64B max */
```

**Distinction from TRUNCATED**: `RTMAP_FLAG_TRUNCATED` (0x80) is retained for
REP MOVS/STOS and LOCK-prefixed wide writes that use the `safe_read_into_slot`
clean-call fallback. Those events carry only the low 8 bytes and the engine
zero-poisons their values. Compound writes replace truncation for all other
wide stores.

### Register snapshots

A register snapshot occupies 7 consecutive event slots. The first slot is the
header (kind = `REG_SNAPSHOT`, `addr` = instruction counter). The next 6 slots
each carry 3 register values packed into `addr`, `size`, and `value`:

```
slot 0: header         { insn_counter, 0, tid, seq, 0, REG_SNAPSHOT }
slot 1: regs[0..2]     { regs[0],  (u32)regs[1],  tid, 0, regs[2],  REG_SNAPSHOT }
slot 2: regs[3..5]     { regs[3],  (u32)regs[4],  tid, 0, regs[5],  REG_SNAPSHOT }
slot 3: regs[6..8]     { regs[6],  (u32)regs[7],  tid, 0, regs[8],  REG_SNAPSHOT }
slot 4: regs[9..11]    { regs[9],  (u32)regs[10], tid, 0, regs[11], REG_SNAPSHOT }
slot 5: regs[12..14]   { regs[12], (u32)regs[13], tid, 0, regs[14], REG_SNAPSHOT }
slot 6: regs[15..17]   { regs[15], (u32)regs[16], tid, 0, regs[17], REG_SNAPSHOT }
```

Register indices follow the rtmap layout (not DWARF numbering):

| Index | Register | Index | Register |
|---|---|---|---|
| 0 | RAX | 9 | R9 |
| 1 | RBX | 10 | R10 |
| 2 | RCX | 11 | R11 |
| 3 | RDX | 12 | R12 |
| 4 | RSI | 13 | R13 |
| 5 | RDI | 14 | R14 |
| 6 | RBP | 15 | R15 |
| 7 | RSP | 16 | RIP |
| 8 | R8 | 17 | RFLAGS |

The producer checks that 7 slots are available before writing a snapshot. If
there is insufficient space, the entire snapshot is dropped.

**Recording**: `EventRecorder::record_reg_snapshot` writes the same 7-event
layout to disk. The offline replayer (`rtmap-diff`, `rtmap --replay`)
detects the header, reads 6 continuations, and reconstructs the 18-register
array for `ShadowRegisterFile` population.

## Ring header

The ring header is a 192-byte (3 cache lines) struct:

```
Byte offset   Size   Field            Cache line
-----------   ----   -----            ----------
0             8      magic            CL 0
8             4      capacity
12            4      entry_size
16            8      flags
24            4      backpressure     (atomic)
28            4      proto_version
32            4      status           (atomic, MV_STATUS_{ACTIVE,TERMINAL})
36            24     padding

64            8      head             CL 1 (atomic, producer-owned)
72            56     padding

128           8      tail             CL 2 (atomic, consumer-owned)
136           56     padding
```

Static assert: `sizeof(rtmap_ring_header_t) == 192` (3 × `RTMAP_CACHE_LINE`).

The event data array begins immediately after the header, at byte offset 192.

### Fields

- **`magic`** (u64): `0x52544D4150425200` (ASCII "RTMAPBR"). Validated by both
  tracer (on init) and consumer (on attach).
- **`capacity`** (u32): Number of event slots. **Must be a power of two.**
  Enforced at runtime by `rtmap_ring_init` — a non-power-of-two capacity
  causes the ring to be zero-initialized and left invalid. Default:
  `RTMAP_THREAD_RING_CAPACITY = 1 << 20` (1,048,576). Compile-time asserted
  via `RTMAP_IS_POW2`.
- **`entry_size`** (u32): `sizeof(rtmap_event_t)` = 32.
- **`flags`** (u64): Bitfield. Bit 0 (`RTMAP_FLAG_SPIN_ON_FULL`): if set, the
  producer spins when the ring is full instead of dropping the event.
- **`backpressure`** (atomic u32): Set to 1 by the consumer when ring fill
  exceeds 6/8 capacity. Cleared when fill drops below 3/8. The producer checks
  this flag and sheds `READ` events when backpressure is active.
- **`proto_version`** (u32): `RTMAP_PROTO_VERSION` (currently 3). Written by
  `rtmap_ring_init`. The consumer validates this on attach and rejects
  mismatched versions with a diagnostic message to stderr.
- **`status`** (atomic u32): Ring lifecycle state. `MV_STATUS_ACTIVE` (0) is
  the initial state. The tracer sets `MV_STATUS_TERMINAL` (1) on thread exit
  or on `SYS_exit`/`SYS_exit_group` via the pre-syscall hook. The engine
  checks this after each `batch_drain`: a terminal ring with `head == tail`
  is retired (set `alive = false`), implementing the last-gasp drain.
- **`head`** (atomic u64): Write cursor. Owned by the producer. Monotonically
  increasing (wraps at 2^64, masked to capacity for indexing).
- **`tail`** (atomic u64): Read cursor. Owned by the consumer. Monotonically
  increasing.

### Indexing

Both `head` and `tail` are unbounded 64-bit counters. The actual array index is
computed as:

```
index = counter & (capacity - 1)
```

This requires `capacity` to be a power of two. The number of events currently
in the ring is `head - tail` (unsigned subtraction handles wrap correctly).

### Head caching

The tracer caches the head pointer in raw TLS (`RTMAP_RAW_SLOT_HEAD`) to
avoid an atomic store on every event. The cached head is flushed to the ring
header's atomic `head` field in two cases:

1. **Conditional flush**: Every 64 events (`head & RTMAP_HEAD_FLUSH_MASK ==
   0`, where `RTMAP_HEAD_FLUSH_MASK = 0x3F`).
2. **BB-exit flush**: Unconditionally at the end of every basic block. This
   ensures the consumer sees events even from threads that produce fewer than
   64 writes per BB before blocking.

The flush is a single release store to `ring->head`.

## Memory ordering

The ring uses a standard SPSC acquire-release protocol:

### Producer (tracer, single thread per ring)

```
1. Load head      (relaxed)       — only this thread writes head
2. Load tail      (acquire)       — synchronizes with consumer's tail store
3. Check: head - tail < capacity  — if full, drop or spin
4. Write event data to slot[head & mask]  (plain stores, no atomics)
5. Store head+1   (release)       — publishes the event data
```

The release store at step 5 guarantees that the event data written in step 4 is
visible to any thread that loads `head` with acquire ordering.

**Note**: The inline write path defers step 5 via head caching (see above). The
actual release store occurs at the flush point, not on every event.

### Consumer (engine, single thread)

```
1. Load tail      (relaxed)       — only this thread writes tail
2. Load head      (acquire)       — synchronizes with producer's head store
3. Check: tail == head            — if equal, ring is empty
4. Read event data from slot[tail & mask]  (volatile read)
5. Store tail+1   (release)       — frees the slot for reuse
```

### Batch operations

The engine's `batch_pop` reads up to N events in a single pass:

```
1. Load tail      (relaxed)
2. Load head      (acquire)
3. avail = head - tail
4. n = min(avail, max_batch)
5. For i in 0..n: read slot[(tail + i) & mask]  (volatile read)
6. Store tail + n (release)       — frees all n slots at once
```

This amortizes the atomic overhead from 2 atomics per event to 2 atomics per
batch. With `max_batch = 20,000` and 6 rings, a single drain cycle can return
up to 120,000 events with only 12 atomic operations total.

## Backpressure

The consumer monitors ring fill levels and communicates backpressure to the
producer through the `backpressure` field in the ring header:

```
Fill >= 6/8 capacity:  consumer stores backpressure = 1  (release)
Fill <  3/8 capacity:  consumer stores backpressure = 0  (release)
```

The producer checks `backpressure` with a relaxed load. When backpressure is
active, `rtmap_push_sampled()` silently drops `READ` and `BB_ENTRY` events
(returns 1 instead of 0). `WRITE`, `CALL`, `RETURN`, `TAIL_CALL`, `ALLOC`,
`FREE`, `RELOAD`, `MODULE_LOAD`, and `REG_SNAPSHOT` are **never** dropped by
backpressure.

This mechanism degrades gracefully under load: read and BB_ENTRY events are
low-priority observability data (reads carry no post-read values; BB_ENTRY
affects only coverage counters, not topology). Shedding them reduces ring
pressure without losing writes, lifecycle events, or control events.

## Spin-on-full

If the ring's `flags` field has bit 0 set (`RTMAP_FLAG_SPIN_ON_FULL`), the
producer spins instead of dropping events when the ring is full:

```c
while (head - tail >= capacity) {
    __builtin_ia32_pause();
    tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
}
```

The `pause` intrinsic reduces the rate of cache-line acquisitions on the
consumer's `tail` line. The default policy is `RTMAP_FLAG_DROP_ON_FULL`
(flags = 0), which drops events rather than stalling the target program.

## Control ring

The control ring is a PID-scoped shared memory object (`/rtmap_ctl_<pid>`)
used for thread discovery. The root process also creates a legacy
`/rtmap_ctl` for backward compatibility. It contains a fixed-size array of
256 thread entries:

```c
typedef struct {
    uint64_t magic;                              // 0x5254435430303032 ("RTCT0002")
    uint32_t proto_version;                      // RTMAP_PROTO_VERSION (3)
    _Atomic uint32_t thread_count;               // high-water mark of allocated slots
    uint32_t max_threads;                        // 256
    uint32_t build_hash;                         // structural ABI hash (FNV-1a)
    uint32_t target_pid;                         // PID of instrumented process
    uint32_t parent_pid;                         // 0 for root process
    _Atomic uint32_t tripwire_hit;               // tracer sets to 1 on tripwire entry (release)
    uint32_t _ctl_reserved;                      // padding for 8-byte alignment before bloom
    uint64_t priority_bloom[RTMAP_BLOOM_U64S];  // address-level priority filter
    rtmap_thread_entry_t threads[256];
} rtmap_ctl_header_t;
```

Each thread entry is 56 bytes:

```c
typedef struct {
    _Atomic uint32_t state;       // EMPTY=0, ACTIVE=1, DEAD=2
    uint16_t thread_id;
    uint16_t _reserved;
    char shm_name[48];            // e.g. "/rtmap_ring_12345_0"
} rtmap_thread_entry_t;
```

### Thread registration protocol

When a new thread starts in the target process, `rtmap_ctl_register_thread`
executes a two-pass allocation:

**Pass 1: Dead-slot reclamation (CAS scan)**

```
for i in 0..max_threads:
    CAS(threads[i].state, DEAD → ACTIVE, acq_rel)
    if success: reuse slot i, return
```

This reclaims slots from exited threads without incrementing the high-water
mark. The CAS ensures exactly one thread wins each dead slot.

**Pass 2: Fresh allocation (fetch_add)**

```
idx = atomic_fetch_add(&thread_count, 1, acq_rel)
if idx >= max_threads: undo fetch_add, return -1
write thread_id and shm_name into threads[idx]
store threads[idx].state = ACTIVE (release)
```

The engine polls the control ring every drain cycle:

1. Load `thread_count` with acquire ordering.
2. For each slot (0..thread_count):
   - Load `state` with acquire ordering.
   - If `ACTIVE` and not already tracked: open the shared memory by name,
     validate magic + proto_version, add ring to orchestrator.
3. For all tracked rings: check for `DEAD` state transitions and mark
   inactive.

### Thread teardown

When a thread exits:

1. The tracer's pre-syscall hook flushes the cached head on every syscall.
   On `SYS_exit`/`SYS_exit_group`, it also sets `ring->status =
   MV_STATUS_TERMINAL`.
2. `event_thread_exit` performs a terminal flush (belt-and-suspenders):
   flushes cached head, sets `status = MV_STATUS_TERMINAL`, then marks
   the thread `DEAD` in the control ring.
3. The tracer unmaps and unlinks the shared memory ring.
4. The engine's `batch_drain` consumes remaining events from the ring.
   After consuming, if `is_terminal()` and `head == tail` (fully drained),
   the ring is retired (`alive = false`). This is the last-gasp drain.
5. The engine detects the `DEAD` state on its next poll.

### Protocol version handshake

Both the ring header and control ring header carry `proto_version`:

- `rtmap_ring_init` sets `ring->proto_version = RTMAP_PROTO_VERSION`.
- `rtmap_ctl_init` sets `ctl->proto_version = RTMAP_PROTO_VERSION`.
- The engine's `ThreadRing::from_shm` validates `proto_version` on ring
  attach and rejects mismatches.
- The engine's `try_attach_ctl` validates `proto_version` on ctl attach
  and rejects mismatches.

### Structural ABI hash

The control ring header carries `build_hash` (u32), computed by
`rtmap_build_hash_compute()`. This is a deterministic FNV-1a over
`sizeof`/`offsetof` of the three ABI-critical structs:
`rtmap_event_v3_t`, `rtmap_ring_header_t`, and `rtmap_scratch_pad_t`.

The engine computes the same hash via `rtmap_abi_hash()` and compares
on ctl attach. If the hashes differ, the engine refuses to connect and
prints a diagnostic:

```
rtmap: ABI MISMATCH: tracer hash=0x..., engine hash=0x...
rtmap: rebuild both tracer and engine from the same rtmap_bridge.h
```

This prevents silent data corruption when the tracer and engine are built
against different versions of `rtmap_bridge.h`.

## Shared memory lifecycle

| Phase | Actor | Action |
|---|---|---|
| Startup | Engine | Best-effort cleanup of stale `/dev/shm/rtmap_*` (legacy + PID-scoped) |
| Startup | Tracer | Creates `/rtmap_ctl_<pid>` (+ legacy `/rtmap_ctl` for root), inits header (magic + proto + abi_hash + target_pid + parent_pid) |
| Thread init | Tracer | Creates `/rtmap_ring_<pid>_<tid>`, registers via CAS reclaim or alloc |
| Attach | Engine | Opens `/rtmap_ctl_<pid>` (or legacy `/rtmap_ctl`), validates magic + proto + abi_hash |
| Discovery | Engine | Opens `/rtmap_ring_<pid>_<tid>`, validates magic + proto |
| Fork | Tracer | `event_fork_init`: detach inherited SHM, create child-scoped ctl + ring, emit PROCESS_FORK event |
| Fork | Engine | `ChildProcessTracker`: discovers child ctl via `try_attach_ctl_pid`, drains child rings |
| Runtime | Both | Producer writes events, consumer drains them (parent + child orchestrators) |
| Thread exit | Tracer | Terminal flush, marks DEAD in ctl. Ring SHM persists for post-mortem drain |
| Shutdown | Tracer | Unmaps and unlinks `/rtmap_ctl_<pid>` (+ legacy) |
| Shutdown | Engine | Unmaps all rings |

All shared memory objects are created with mode 0600 (owner read/write only).
