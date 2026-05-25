# Architecture

Authoritative reference for the rtmap system architecture. All claims are
derived from the current implementation in `tracer.c`, `rtmap_bridge.h`, and
`engine/src/`. Protocol version: **3**.

## System overview

rtmap consists of two cooperating OS processes connected by POSIX shared
memory, plus offline analysis tools that operate on recorded traces:

```
 ┌───────────────────────────┐   /dev/shm/    ┌───────────────────────────────────┐
 │         TRACER            │ =============> │             ENGINE                │
 │  (DynamoRIO client, C)    │  SPSC rings    │        (Rust, 4 binaries)         │
 │                           │  control ring  │                                   │
 │  tracer.c                 │                │  rtmap       main.rs  (live)     │
 │  rtmap_bridge.h          │                │  rtmap-lint  lint.rs  (static)   │
 │                           │                │  rtmap-diff  diff.rs  (offline)  │
 │  inline pre/post write    │                │  rtmap-check check.rs (CI/CD)    │
 │  clean-call value capture │                │                                   │
 │  per-thread raw TLS       │                │  reconciler.rs  (event dispatch)  │
 │  adaptive backpressure    │                │  config.rs     (configuration)    │
 │  tail-call detection      │                │  record.rs      (recording I/O)   │
 │  selective reload detect  │                │  topology.rs    (JSONL streaming) │
 │  allocator hooks (drwrap) │                │  dwarf.rs       (DWARF + ELF+CFI) │
 │                           │                │  ring.rs        (SHM consumer)    │
 │                           │                │  index.rs       (interval map)     │
 │                           │                │  world.rs       (STM, RTR, ASan)  │
 │                           │                │  shadow_regs.rs (shadow registers) │
 │                           │                │  heap_graph.rs  (heap object discovery) │
 └───────────────────────────┘                └───────────────────────────────────┘
       runs inside target's                         separate process(es)
       address space (DBI)
```

The **tracer** is a shared library (`librtmap_tracer.so`) loaded into the
target by DynamoRIO. The **engine** is a Rust crate producing four binaries:

| Binary | Entry point | Purpose |
|---|---|---|
| `rtmap` | `main.rs` | CLI shell with subcommands (`setup`, `init`, `record`, `replay`, `attach`; default: instrument+run headless). `RunConfig` carries `--live`, `--no-bb`, `--tripwire`, `--coverage`, `--topology`, `--heatmap`, `--min-events`, record path, `server_mode`. |
| `rtmap-lint` | `lint.rs` | Static cacheline lint: struct analysis, divergence report, diff mode |
| `rtmap-diff` | `diff.rs` | Replay two `.bin` traces, diff ASLR-invariant topology |
| `rtmap-check` | `check.rs` | Evaluate `.assertions` against JSONL topology |

## Components

### Tracer (`tracer.c`, `rtmap_bridge.h`)

The tracer is a DynamoRIO client. It uses a **hybrid inline/clean-call**
strategy. See [Tracer](tracer.md) for the full specification.

Summary of instrumented event types:

| Event | Strategy | Description |
|---|---|---|
| Memory writes | Two-phase inline + clean call | Metadata inline, value via `safe_read_into_slot` |
| Memory reads | Buffered clean call | Per-BB flush of 16-entry buffer |
| Direct calls | Clean call | CALL event + 7-slot REG_SNAPSHOT (18 registers) |
| Returns | Clean call | RETURN event |
| Tail calls | Heuristic (JMP >4KB) | TAIL_CALL event |
| Reloads | Selective (callee-saved) | RELOAD event |
| Allocations | `drwrap` hooks | ALLOC/FREE events for malloc/free/realloc/calloc |
| Fork | `dr_register_fork_init_event` | PROCESS_FORK event (kind 13) |

Each thread gets its own SPSC ring buffer via `shm_open(3)`. Thread metadata
is published to a PID-scoped control ring (`/rtmap_ctl_<pid>`). The root
process also creates a legacy `/rtmap_ctl` for backward compatibility.
See [Ring Protocol](ring-protocol.md).

#### Runtime phase gate

The tracer operates in two phases (`g_phase`):

| Phase | Name | Behavior |
|---|---|---|
| `PHASE_BOOT` | DBI startup | All instrumentation is **emitted at JIT time** but **gated at runtime** via an inline `cmp [g_phase], PHASE_TRACE; jne skip` at the top of `emit_bb_entry` and `emit_pre_write`. Only ALLOC/FREE (clean-call hooks check `g_phase` at entry) pass through. |
| `PHASE_TRACE` | Full tracing | The runtime gate falls through (predicted-taken). All event types flow. **No code cache invalidation occurs.** |

Transition in `tripwire_hit()`: set `g_phase = PHASE_TRACE` (relaxed store),
then `g_ctl->tripwire_hit = 1` (release). Zero code cache flush — the inline
gate observes the new phase on the next BB entry without recompilation.

#### Tiered backpressure

Three levels communicated from engine to tracer via the ring header's
`bp_level` field:

| Level | Threshold | Behavior |
|---|---|---|
| 0 | Ring < 6/8 full | All events emitted |
| 1 | Ring ≥ 6/8 full | READ and BB_ENTRY suppressed |
| 2 | Ring ≥ 7/8 full | Only ALLOC, FREE, and bloom-gated writes survive |

Hysteresis: clears at 3/8. The bloom filter is populated per stamped
allocation's fields (`alloc_base + field_offset`), ensuring initialization
writes to typed heap survive BP=2.

#### In-band syscall hooks

`EVENT_SHARED_MAP` (kind 14) emits mmap/munmap notifications in-band via
`drmgr_register_filter_syscall_event` + `drmgr_register_post_syscall_event`.
Eliminates races from polling `/proc/<pid>/maps` for shared region discovery.

### Engine (`engine/`)

The engine is the consumer process. Its subsystems are organized into library
modules re-exported from `lib.rs`, with four binary entry points.

#### Core modules

| File | Module | Role |
|---|---|---|
| `reconciler.rs` | `reconciler` | Event dispatch: `process_event`, `populate_globals`, `warm_scan` (legacy one-shot), `WarmScanner` (continuous BFS with `seed()`/`step(budget)`) |
| `config.rs` | `config` | Configuration resolution: `.rtmap` project profiles, `~/.config/rtmap/config`, `TargetProfile` (tripwire, args, export paths), auto-detect |
| `dwarf.rs` | `dwarf` | DWARF parser + ELF symtab fallback + CFI table + JIT deep resolution: globals, functions, locals, types, type_registry, `.eh_frame` |
| `ring.rs` | `ring` | SHM mapping, ring consumer, orchestrator, `new_offline()` for replay |
| `index.rs` | `index` | Two-tier interval map. O(log N) address-to-variable lookup |
| `world.rs` | `world` | WorldState, STM, RTR, HeapAllocTracker, Visual ASan, CoW snapshots |
| `shadow_regs.rs` | `shadow_regs` | Shadow Register File, 7 confidence tiers (incl. `CfiVerified`), piece assembler |
| `heap_graph.rs` | `heap_graph` | Heap object discovery, field value storage, pointer edges, type inference |
| `record.rs` | `record` | EventRecorder (write), EventPlayer (read), compound REG_SNAPSHOT I/O |
| `topology.rs` | `topology` | JSONL topology streamer: STAMP, LINK, HAZARD, COLD_*, PROCESS_FORK, CROSS_PROCESS_WRITE, SUMMARY, TYPE_SCHISM, TYPE_EPOCH_CLOSE |
| `proc_maps.rs` | `proc_maps` | `/proc/<pid>/maps` parser, shared region detection via `(dev, inode)` matching |
| `tui.rs` | `tui` | ratatui TUI: 6 panels, keybindings, event filters, time-travel |
| `lib.rs` | — | Crate root. Re-exports all modules |

#### Binary entry points

| File | Binary | Role |
|---|---|---|
| `main.rs` | `rtmap` | CLI shell with subcommands (`setup`, `init`, `record`, `replay`, `attach`; default: instrument+run headless). `RunConfig` carries `--live`, `--no-bb`, `--tripwire`, `--coverage`, `--topology`, `--heatmap`, `--min-events`, record path, `server_mode`. |
| `lint.rs` | `rtmap-lint` | Static cacheline lint: struct analysis, divergence report, diff mode |
| `diff.rs` | `rtmap-diff` | Replay two `.bin` traces, diff ASLR-invariant topology |
| `check.rs` | `rtmap-check` | Evaluate `.assertions` against JSONL topology |

#### Engine subsystem summary

1. **DWARF parsing** (`dwarf.rs`). Parses `.debug_info` via `gimli` (0.33).
   Extracts globals, functions, locals, type information. Struct field
   extraction is depth-capped at 8 levels via `extract_struct_fields`; type
   resolution (`resolve_type_at`) is depth-capped at 16 levels. Types
   truncated by the depth cap are marked `shallow: true` on `TypeInfo`.
   Builds `type_registry` mapping struct names to `TypeInfo`. Supports
   location tables, `DW_OP_piece` fragments, and a stack-machine evaluator.
   Tracks `DW_TAG_volatile_type` and `DW_TAG_atomic_type` qualifiers
   (`is_volatile`, `is_atomic` on `TypeInfo`) and `DW_AT_alignment` on
   struct members (`alignment` on `FieldInfo`).
   **ELF symtab fallback**: globals with `DW_AT_specification` but no
   `DW_AT_location` have addresses resolved from the ELF symbol table.
   **DT_NEEDED library merge**: `merge_needed_libs` parses the target ELF's
   `.dynamic` section for `DT_NEEDED` sonames, resolves them via standard
   linker search paths (`LD_LIBRARY_PATH`, binary directory, system defaults),
   and merges type information from libraries with `.debug_info`. Works
   entirely from on-disk files — no live process required, immune to
   DynamoRIO's private loader. Prefers debug-info-bearing copies when
   multiple candidates exist for a soname.
   **DWARF5 name acceleration**: `NameAccelerator::build()` parses the
   `.debug_names` section at startup, building a `HashMap<String,
   Vec<(cu_offset, die_offset)>>` for struct/union/class tags.
   `resolve_deep` uses this for O(1) name→DIE lookup; falls back to full
   CU scan for DWARF4 binaries. `resolve_deep_at` jumps directly to a
   CU+DIE via `Dwarf::unit_header()`.

2. **CFI table** (`dwarf.rs`). `parse_eh_frame` reads the `.eh_frame` section
   via gimli and builds a `CfiTable` — a list of `CfiEntry` structs, each
   mapping a PC range (`start_pc..end_pc`) to the set of callee-saved register
   indices preserved in that frame. `saved_regs_at(pc)` performs a linear
   scan to find the entry covering a given PC. The table is populated during
   `parse_elf` and stored as `DwarfInfo.cfi`.

3. **JIT DWARF resolution** (`dwarf.rs`). On-demand deep type resolution for
   types marked `shallow: true` by the initial parse. Two strategies:
   - `patch_shallow_fields(ti)`: walks a `TypeInfo`'s field tree and replaces
     any field-embedded shallow types with their full version from
     `type_registry`. This handles the common case where each struct has a
     top-level DWARF DIE and was resolved at depth 0 in the registry.
   - `resolve_deep(type_name)`: re-reads the ELF binary from `elf_path` and
     re-parses the named type with raised depth caps (struct fields: 32,
     type resolution: 64). Updates `type_registry` in place. Fallback for
     types that only exist as nested fields with no standalone DIE.
   The reconciler's STM stamp path clones the registry type, calls
   `patch_shallow_fields`, then stamps with the patched version.

4. **Event reconciler** (`reconciler.rs`). Extracted from `main.rs` for
   library consumption by `rtmap-diff`. Contains `process_event` (central
   dispatch for all 14 event types including PROCESS_FORK),
   `populate_globals`, and `warm_scan`. `process_event` takes
   `dwarf_info: &mut Option<DwarfInfo>` to allow mutable access for
   `resolve_deep` and `patch_shallow_fields`.

   **Dual-domain sequence tracking**: the tracer uses two independent
   per-thread sequence counters — raw TLS for JIT-inlined events (WRITE,
   BB_ENTRY) and drmgr TLS for clean-call events (READ, CALL, RET, ALLOC,
   FREE, REG_SNAPSHOT). The engine classifies events via `seq_domain()` and
   tracks `expected_seq` per `(thread_id, domain)`, eliminating false-positive
   gap reports that occurred when both domains' counters were conflated.

5. **Warm-scan** (`reconciler.rs`). `WarmScanner`: persistent incremental BFS
   over `/proc/<pid>/mem`. `seed(&mut DwarfInfo, delta, heap_oracle, topo, stm,
   alloc_tracker)` calls `ensure_type` on each global's type to fully
   materialize depth-truncated structs (e.g. `redisServer` with 487 fields),
   rebuilds global `TypeInfo` from the now-deep registry, patches shallow
   fields, then enqueues globals via `scan_ptr_fields`. `step(budget)`
   processes up to `budget` reads per call, yielding on exhaustion and
   resuming on the next invocation. Depth-limited (12). Initial seed at
   100K events; periodic re-seed every 200K events (event-count based,
   works identically in TUI and headless modes regardless of wall-clock
   processing speed). Budget per step: 2000 reads. Emits COLD_STAMP and
   COLD_LINK to topology stream. `scan_ptr_fields` uses
   `DwarfInfo.container_of_map` for intrusive container discovery: when
   following a pointer to an embedded struct (e.g. `list_head*`), also
   enqueues the container base (`ptr - field_offset`) with the container
   type. The `**T` alloc gate is relaxed via `heap_oracle.is_heap()` to
   handle targets whose alloc events were lost to ring overflow. Legacy
   one-shot `warm_scan` retained for replay.

6. **Ring orchestration** (`ring.rs`). Attaches to control ring with protocol
   handshake. Discovers per-thread data rings. Batch pops up to 20,000
   events per ring per cycle (2 atomics per ring per batch).
   `new_offline()` creates a dummy orchestrator for replay without SHM.

7. **Shadow Type Map** (`world.rs`). Maps heap addresses to DWARF type
   projections. Four stamp paths: direct stamp, field propagation
   (`propagate_field_write`, returns `bool`), indirect element registration
   (`**T` field writes register the target allocation's element type; the
   written `*T` pointer is then stamped as `T` via `indirect_lookup`), and
   retrospective scan. Counters: `indirect_stamps`, `indirect_registrations`.
   `purge_range` on FREE.

   **Pool/arena reuse classification**: `stamp_type` returns a `StampResult`
   enum (`New`, `Replaced`, `PoolReuse`). Addresses with 2+ type schisms
   (different type overwrites) are classified as `PoolReuse` — the address
   is being recycled by an allocator, not genuinely type-confused. The
   topology stream emits `pool_reuse` events (distinct from `schism`
   events). Verified: nginx 1811 pool_reuse vs 38 schisms; Redis 119,922
   pool_reuse vs 195 schisms.

8. **Retrospective Type Reconciliation** (`world.rs`). Bounded BFS (fuel=64)
   from freshly-stamped addresses through HeapGraph pointer fields. Candidates
   sorted by field name for deterministic discovery order across runs.

9. **Visual ASan** (`world.rs`). OutOfBounds and HeapHole detection with
   symbolic intent. Each `HeapHazard` carries `pc` and `reg_snapshot`
   (18 registers from `ShadowRegisterFile::values()`).

10. **Shadow Register File** (`shadow_regs.rs`). Per-thread tracking of 18
    x86-64 registers with provenance, confidence, and memory-source coherence.
    Seven confidence tiers (ordered low to high):

    | Tier | Label | Source |
    |---|---|---|
    | `Unknown` | `???` | No information |
    | `Stale` | `STALE` | Invalidated by memory write to source |
    | `Speculative` | `spec` | Heuristic inference |
    | `WriteBack` | `wb` | Value written back to known memory source |
    | `AbiInferred` | `abi` | ABI convention (callee-saved on CALL) |
    | `CfiVerified` | `cfi` | CFI `.eh_frame` confirms preservation |
    | `Observed` | `obs` | Direct `REG_SNAPSHOT` from tracer |

    Key methods: `on_call`, `on_return`, `on_return_cfi` (promotes
    callee-saved registers to `CfiVerified` when CFI data is available),
    `on_reload`, `on_snapshot`, `check_coherence`. `callee_pc()` returns
    the current top-of-stack callee PC for CFI lookup.

11. **Event recording** (`record.rs`). `EventRecorder::record()` writes
    32-byte events. `record_reg_snapshot()` writes header + 6 continuation
    events carrying 18 register values. `EventPlayer` reads them back. File
    format: 24-byte header (magic + proto + count) followed by packed 32-byte
    events.

12. **Topology streaming** (`topology.rs`). JSONL emitter for structural graph
    deltas: ALLOC, FREE, STAMP, LINK, COLD_STAMP, COLD_LINK, HAZARD,
    FALSE_SHARE, PROCESS_FORK, CROSS_PROCESS_WRITE, TYPE_SCHISM,
    TYPE_EPOCH_CLOSE, SEQ_GAP, SUMMARY. `TYPE_SCHISM` events carry a
    `pool_reuse` boolean distinguishing allocator recycling from genuine
    type confusion. Consumed by `rtmap-check`.

16. **Cross-process topology** (`main.rs`, `proc_maps.rs`).
    `ChildProcessTracker` manages fork-discovered child processes:
    - `register_fork(pid)`: queues child PID from PROCESS_FORK event.
    - `discover()`: attempts `try_attach_ctl_pid` for pending PIDs,
      creates child `RingOrchestrator`s, refreshes shared region map.
    - `refresh_shared_regions()`: calls `proc_maps::detect_shared_regions`
      across all PIDs to find file-backed mappings sharing `(dev, inode)`.
    - `is_shared_addr(addr)`: O(regions × mappings) lookup for cross-process
      write detection; returns region path on hit.
    - `batch_drain()`: drains child orchestrators into the parent's event
      buffer for unified processing.

    `proc_maps` module parses `/proc/<pid>/maps` lines into `MapEntry`
    structs with `DevInode` keys. `detect_shared_regions` returns regions
    mapped by 2+ distinct PIDs (anonymous mappings filtered by inode == 0).

13. **Differential topology** (`diff.rs`). Replays two `.bin` recordings
    through `reconciler::process_event` with `RingOrchestrator::new_offline()`.
    Checkpoints at configurable intervals. Comparison features:
    - Canonical stamps: `(source, type_name, type_size, field_count)`.
    - Common stamp mask: filters discovery-order noise from intermediate diffs.
    - Steady-state type histogram: order-invariant final-checkpoint comparison.
    - Hazard register context: PC + RAX/RDI/RSI/RDX/RSP per hazard.

14. **World state** (`world.rs`). CoW snapshots via `Arc<WorldInner>`.
    Circular snapshot ring (512 entries) for time-travel. Cache-line
    contention tracker with per-writer counts and observation-bias
    correction (`contention_score_weighted`). Longjmp-aware shadow stacks
    (`pop_return_checked`, `non_local_jumps` counter). Live register file.

15. **Rendering** (`tui.rs`, `main.rs`). Interactive ratatui TUI at 20 Hz
    with six panels.

### Headless exit path

The engine exits headless mode via two conditions:

1. **Tracer death**: `TRACER_EXITED` flag (set by `waitpid` thread).
   Bypasses arming — triggers immediate final drain and exit.
2. **Idle timeout**: consecutive poll rounds with zero events.

| Mode | Idle limit | Armed when |
|---|---|---|
| Normal | 50 rounds (~5s) | `total > 0` (any events received) |
| Server | 200 rounds (~20s) | `ctl.tripwire_hit == 1` or `stm.len() > 0` |

In server mode, the engine reads the `tripwire_hit` atomic flag from the
shared ctl header. The tracer sets this flag (release store) when the
tripwire function is entered. This prevents premature exit during
DynamoRIO's JIT compilation phase, where startup ALLOC/FREE events are
followed by a multi-second pause before the server's event loop begins.

On exit, the engine performs a final `poll_new_rings()` sweep to discover
rings from short-lived threads that spawned and died between poll
intervals, drains all remaining events, then renders the final snapshot.

### Shared memory protocol (`rtmap_bridge.h`)

See [Ring Protocol](ring-protocol.md) for the full specification. Summary:

- **v3 event format**: 32 bytes. `kind_flags` (u32: kind:8|flags:8|seq_hi:16)
  + `rip_lo` (u32: app PC offset). Extended 32-bit sequence numbers.
- **Ring header**: 192 bytes (3 cache lines). Head and tail on separate lines.
- **Control ring**: 256 thread slots. Dead-slot reclamation via CAS.
- **Build hash**: structural FNV-1a over `sizeof`/`offsetof` of `rtmap_event_v3_t`, `rtmap_ring_header_t`, and `rtmap_scratch_pad_t`. Engine refuses to attach on mismatch.

## Data flow

### Live path (target write → screen)

```
 target executes: *ptr = 42;
         │
         ▼
 [1] DynamoRIO intercepts BB containing the store
         │
         ▼
 [2] emit_pre_write (inline, BEFORE store):
     reserves drreg scratch, computes EA, saves to pad.scratch[0],
     reserves ring slot, writes metadata (addr, size, tid, seq, kind, rip)
         │
         ▼
 [3] target store executes
         │
         ▼
 [4] emit_post_write (inline + clean call, AFTER store):
     reloads EA from pad.scratch[0], clean call safe_read_into_slot,
     bumps seq + cached head, conditional flush (1/64 events)
         │
         ▼
 [5] BB exit: unconditional head flush → ring.head (release store)
         │
         ▼
 [6] ring.rs:batch_pop: load head (acquire), read ≤20K events,
     store tail (release) — 2 atomics per ring per batch
         │
         ▼
 [7] reconciler::process_event (EVENT_WRITE path):
     a. cl_tracker.record_write(addr, tid)
     b. shadow_regs.check_coherence(addr, value, size, seq)
     c. if heap: heap_graph → stm.propagate → RTR → check_write_bounds
     d. addr_index.lookup → world.update_value + update_edge
     e. if pointer to heap: clone type from registry,
        patch_shallow_fields, stm.stamp_type + retrospective_scan
         │
         ▼
 [8] recorder.record(ev) or recorder.record_reg_snapshot(ev, regs)
     [optional: writes to .bin file]
         │
         ▼
 [9] world.snapshot() → Arc<WorldInner> (ref-count bump)
     TUI renders at 20 Hz
```

### RETURN path (CFI-hardened, longjmp-aware)

```
 [1] reconciler::process_event (EVENT_RETURN):
         │
         ▼
 [2] srf.callee_pc() → look up CfiTable
         │
     ┌───┴───────────────────────────┐
     │ CFI data available            │ No CFI data
     ▼                               ▼
 [3a] srf.on_return_cfi(saved)   [3b] srf.on_return()
      restores callee-saved,          restores callee-saved,
      promotes to CfiVerified         retains prior confidence
         │
         ▼
 [4] shadow_stack.pop_return()
     (or pop_return_checked for longjmp detection:
      if return_pc ≠ top.callee_pc, scan stack for
      matching frame, unwind intermediate frames,
      increment non_local_jumps)
```

### Recording path (live → `.bin` → replay)

```
 live run (rtmap record -o trace.bin ./target)
         │
         ▼
 EventRecorder writes events to .bin (32 bytes each)
 REG_SNAPSHOT: header + 6 continuations = 7 events (18 registers)
         │
         ▼
 offline replay (rtmap replay trace.bin [--no-bb])
   or    offline diff (rtmap-diff --baseline a.bin --subject b.bin)
         │
         ▼
 EventPlayer reads events → reconciler::process_event
 REG_SNAPSHOT reconstructed from 7 consecutive events
```

### Warm-scan path (cold discovery)

```
 initial seed at 100K events; re-seed every 200K events
         │
         ▼
 WarmScanner::seed(&mut info) calls ensure_type on globals,
   rebuilds type_info from deep registry, enqueues via scan_ptr_fields
 WarmScanner::step(2000) reads /proc/<pid>/mem, budget-bounded BFS
         │
         ├─ scan_ptr_fields follows pointer fields
         │   ├─ if pointee type has container_of entries:
         │   │   enqueue container base (ptr - offset) with container type
         │   └─ enqueue pointee with pointee type
         ▼
 COLD_STAMP + COLD_LINK events → topology stream
 stm.stamp_type for each discovered allocation
```

## Address space layout

```
# Root process (PID-scoped + legacy for backward compat)
/dev/shm/rtmap_ctl           Legacy control ring (root process only)
/dev/shm/rtmap_ctl_<pid>     PID-scoped control ring (~14 KB)
/dev/shm/rtmap_ring_<pid>_0  Thread 0 data ring (1M entries, ~32 MB)
/dev/shm/rtmap_ring_<pid>_1  Thread 1 data ring
...
/dev/shm/rtmap_ring_<pid>_N  Thread N data ring (max N = 255)

# Forked child process (PID-scoped only, no legacy)
/dev/shm/rtmap_ctl_<child_pid>
/dev/shm/rtmap_ring_<child_pid>_0
...
```

Each data ring is `sizeof(rtmap_ring_header_t) + capacity * 32` bytes.
Default capacity: 2^20 (1,048,576 entries), ~32 MB per ring.

## Shared memory lifecycle

| Phase | Actor | Action |
|---|---|---|
| Startup | Engine | Best-effort cleanup of stale `/dev/shm/rtmap_*` (legacy + PID-scoped) |
| Startup | Tracer | Creates `/rtmap_ctl_<pid>` (+ legacy `/rtmap_ctl` for root), inits header (magic + proto + abi_hash + parent_pid) |
| Thread init | Tracer | Creates `/rtmap_ring_<pid>_<tid>`, registers via CAS reclaim or alloc |
| Attach | Engine | Opens `/rtmap_ctl` (legacy) or `/rtmap_ctl_<pid>`, validates magic + proto + abi_hash |
| Discovery | Engine | Opens `/rtmap_ring_<pid>_<tid>`, validates magic + proto |
| Fork | Tracer | `event_fork_init`: detach inherited SHM, create child-scoped ctl + ring, emit PROCESS_FORK event |
| Fork | Engine | `ChildProcessTracker`: discovers child ctl via `try_attach_ctl_pid`, polls child rings, detects shared regions |
| Runtime | Both | Producer writes events, consumer drains them (parent + child orchestrators) |
| Pre-syscall | Tracer | Flushes cached head; marks terminal on exit/exit_group |
| Thread exit | Tracer | Terminal flush: sets `status = MV_STATUS_TERMINAL`, marks DEAD, unmaps/unlinks |
| Ring drain | Engine | `batch_drain`: consumes events, retires terminal rings when `head == tail` |
| Shutdown | Tracer | Unmaps and unlinks `/rtmap_ctl` |
| Shutdown | Engine | Unmaps all rings |

All shared memory objects: mode 0600 (owner read/write only).

## Relocation

PIE binaries load at a random base (ASLR). DWARF uses ELF virtual addresses.

```
delta = runtime_module_base - elf_base_vaddr
```

The tracer emits `MODULE_LOAD` (kind 7) with the runtime base. The engine
re-populates global addresses by adding the delta. The tracer's
`event_module_load` detects libc (for `drwrap` hooks) and captures the first
non-system module as the main executable.

## Concurrency model

No shared mutable state. All communication via SPSC ring buffers.

- **Producer** (tracer thread): owns `head`. Relaxed load, release store.
- **Consumer** (engine): owns `tail`. Relaxed load, release store.
- Cross-cursor reads: acquire ordering.

No mutex, spinlock, or CAS in the hot path. CAS only in:
- `rtmap_ctl_register_thread` (once per thread lifetime).
- `g_module_base_phase` CAS 1→2 (once per process lifetime).

### Head caching

Cached in raw TLS (`RTMAP_RAW_SLOT_HEAD`). Flushed to ring header:
- Every 64 events (`head & 0x3F == 0`): conditional inline flush.
- Every BB exit: unconditional flush.

## Dependencies

| Component | Dependency | Version | Purpose |
|---|---|---|---|
| Tracer | DynamoRIO | 11.91+ | Dynamic binary instrumentation |
| Tracer | drmgr | (bundled) | Multi-callback management |
| Tracer | drutil | (bundled) | Memory operand analysis |
| Tracer | drreg | (bundled) | Register reservation |
| Tracer | drwrap | (bundled) | Function wrapping (allocator hooks) |
| Tracer | drsyms | (bundled) | Symbol lookup (allocator resolution) |
| Engine | gimli | 0.33 | DWARF parsing + `.eh_frame` CFI + `.debug_names` acceleration |
| Engine | object | 0.36 | ELF parsing (including symtab fallback) |
| Engine | ratatui | 0.29 | Terminal UI |
| Engine | crossterm | 0.28 | Terminal I/O |
| Engine | libc | 0.2 | POSIX shared memory, `/proc/<pid>/mem` access |

## Build

### Docker

```sh
DOCKER_BUILDKIT=1 docker build -t rtmap .
docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v /path/to/my_program:/app/my_program \
    rtmap /app/my_program
```

`--cap-add=SYS_PTRACE` required for DynamoRIO process attachment.

### Manual

```sh
# tracer (requires DynamoRIO SDK)
cmake -B build -DDynamoRIO_DIR=/path/to/DynamoRIO/cmake
cmake --build build -j$(nproc)

# engine (produces rtmap, rtmap-lint, rtmap-diff, rtmap-check)
cd engine && cargo build --release
```

## Invocation

```sh
# default: headless instrumentation, print snapshot, exit on 500ms idle
rtmap <target> [args...]

# interactive TUI (20 Hz)
rtmap <target> --live

# explicit DWARF source
rtmap <target> --dwarf <elf>

# record events for offline analysis
rtmap record -o trace.bin <target>

# replay (with optional --no-bb filter)
rtmap replay trace.bin [--no-bb] [--dwarf <elf>]

# attach to running tracer
rtmap attach [--dwarf <elf>] [--live]

# export topology, heatmap, BB coverage
rtmap <target> --topology topo.jsonl --heatmap heat.tsv --coverage cov.tsv

# skip BB_ENTRY events (reduces volume, no topology impact)
rtmap <target> --no-bb

# static cacheline lint
rtmap-lint <binary> --struct <name>
rtmap-lint <binary> --struct <name> --heatmap heat.tsv

# differential comparison (--dwarf optional)
rtmap-diff --baseline a.bin --subject b.bin [--dwarf <elf>] \
    [--interval N] [--output diff.jsonl]

# structural assertions (CI/CD)
rtmap-check <topology.jsonl> <assertions.txt>
```

Legacy flags `--once`, `--record`, `--replay`, `--consumer-only` are accepted
via compatibility shims.

| Variable | Purpose |
|---|---|
| `DYNAMORIO_HOME` | Path to DynamoRIO installation directory |
| `RTMAP_DRRUN` | Explicit path to `drrun` binary |
| `RTMAP_TRACER` | Explicit path to `librtmap_tracer.so` |
