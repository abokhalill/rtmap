# Engine

The engine is a Rust crate (`engine/`) that produces four binaries:

| Binary | Entry point | Purpose |
|---|---|---|
| `rtmap` | `main.rs` | Live instrumentation (TUI/headless), event recording, event replay |
| `rtmap-lint` | `lint.rs` | Static cacheline false-sharing detector with divergence report |
| `rtmap-diff` | `diff.rs` | Offline ASLR-invariant differential topology comparison |
| `rtmap-check` | `check.rs` | CI/CD structural assertion engine over JSONL topology files |

All four share the same library modules via `lib.rs`. This document covers
each subsystem. All claims are derived from the current `engine/src/` source.

## Subsystems

```
                       +------------------+
                       |    DWARF parser  |  (startup, one-shot)
                       |    dwarf.rs      |
                       |  + ELF symtab    |
                       +--------+---------+
                                |
                      DwarfInfo + type_registry
                                |
                                v
+------------------+   +------------------+   +------------------+
|  Ring            |-->|  Reconciler      |-->|  World state     |
|  orchestrator    |   |  reconciler.rs   |   |    world.rs      |
|  ring.rs         |   |  process_event   |   |  Arc<WorldInner> |
+------------------+   |  warm_scan       |   +--------+---------+
         |             +---+---------+----+            |
   EventPlayer              |         |          CoW snapshot
   record.rs         AddressIndex  ShadowRegs          |
         |           index.rs     shadow_regs.rs       v
         v                  |         |       +------------------+
   rtmap-diff       HeapGraph    HeapOracle  |  Renderer        |
   diff.rs           heap_graph.rs            |  tui.rs (TUI)    |
         |                  |                 |  main.rs (text)  |
   rtmap-check      ShadowTypeMap (STM)      +------------------+
   check.rs          HeapAllocTracker                  |
         |           Visual ASan               EventRecorder
   topology.jsonl    world.rs                  record.rs
   topology.rs                                        |
                                               TopologyStream
                                               topology.rs
```

## DWARF parser (`dwarf.rs`)

The DWARF parser runs once at startup. It reads the target ELF binary and
extracts four categories of information, then merges type information from
shared libraries via `DT_NEEDED` resolution.

### Globals

A global variable is a `DW_TAG_variable` with a `DW_AT_location` attribute
that resolves to a fixed address (`DW_OP_addr`). The parser extracts name,
address, size, type information, and location table. Struct field
decomposition follows the same depth caps as type resolution (8 levels for
field extraction, 16 for type resolution). Globals are stored as `GlobalVar`
structs.

**ELF symtab fallback**: Globals with `DW_AT_specification` but no
`DW_AT_location` (common in C++ and large C programs like Redis) have their
addresses resolved from the ELF symbol table via `try_extract_spec_global`.
This recovers globals that would otherwise be invisible to the STM and
warm-scan.

### Functions

A function is a `DW_TAG_subprogram` or `DW_TAG_inlined_subroutine` with
`DW_AT_low_pc` and `DW_AT_high_pc`. The parser extracts name, PC range,
frame base convention (CFA or register), and local variables with location
tables.

### Type resolution

`resolve_type_at` follows `DW_AT_type` through typedefs, const/volatile/atomic
qualifiers, pointers, structs, unions, and arrays. Peels up to 16 levels of
type indirection. Struct field extraction (`extract_struct_fields`) is
depth-capped at 8 levels. Types whose fields were truncated by the depth cap
are marked `shallow: true`.

Qualifier tracking: `DW_TAG_volatile_type` and `DW_TAG_atomic_type` set
`is_volatile` / `is_atomic` on the resolved `TypeInfo` instead of discarding
the qualifier. This provides ground-truth write-intent signals to downstream
consumers (e.g., `rtmap-lint`).

```rust
pub struct TypeInfo {
    pub name: String,
    pub byte_size: u64,
    pub is_pointer: bool,
    pub is_volatile: bool,  // DW_TAG_volatile_type in type chain
    pub is_atomic: bool,    // DW_TAG_atomic_type (C11 _Atomic)
    pub shallow: bool,      // true if fields truncated by depth cap
    pub fields: Vec<FieldInfo>,
}

pub struct FieldInfo {
    pub name: String,
    pub byte_offset: u64,
    pub byte_size: u64,
    pub type_info: TypeInfo,
    pub alignment: u64,     // DW_AT_alignment on member, 0 if absent
}
```

### Type registry

After parsing, `register_recursive` builds a `HashMap<String, TypeInfo>`
mapping struct/union names to their full `TypeInfo`. Only non-empty,
non-pointer types with `byte_size > 0` are registered. This registry is
used by the Shadow Type Map and RTR to resolve pointee types at runtime.

Top-level registry entries are resolved at depth 0 and have full field
trees. The `shallow` flag only appears on field-embedded `TypeInfo` that
was resolved recursively from a parent struct and hit the depth-8 cap.

### Container-of inference

`build_container_of_map(registry)` scans the type registry for structs
that embed other named structs at non-zero offsets — the intrusive
container pattern (e.g., `list_head` embedded at offset 16 within
`task_struct`). Produces a `HashMap<String, Vec<ContainerOfEntry>>`
mapping embedded type names to their enclosing containers:

```rust
pub struct ContainerOfEntry {
    pub container_type: String,
    pub field_name: String,
    pub field_offset: u64,
}
```

Filtering rules:
- **Skip offset 0**: a field at offset 0 is not intrusive — it is the
  first field of the containing struct.
- **Skip pointers**: pointer fields are not embedded structs.
- **Skip anonymous/empty types**: `<anon>` and types with no fields are
  excluded.
- **Require registry presence**: the embedded type must itself be a
  known struct in the type registry.

The map is stored as `DwarfInfo.container_of_map` and consumed by
`scan_ptr_fields` during warm-scan BFS. When the scanner follows a
pointer to an embedded struct (e.g., `list_head*`), it also enqueues
the container base address (`ptr - field_offset`) with the container
type, enabling discovery of the full enclosing object.

### DT_NEEDED library merge

`merge_needed_libs` runs at the end of `parse_elf`. It parses the target
ELF's `.dynamic` section for `DT_NEEDED` sonames, resolves them to on-disk
shared libraries via standard linker search paths, and merges type
information from any that contain `.debug_info`.

**Resolution order** (first match wins, debug-info copies preferred):
1. `LD_LIBRARY_PATH` directories
2. Target binary's parent directory (handles libtool `.libs/` pattern)
3. `/usr/local/lib`, `/usr/local/lib/x86_64-linux-gnu`
4. `/usr/lib/x86_64-linux-gnu`, `/usr/lib`
5. `/lib/x86_64-linux-gnu`, `/lib`

For each candidate, the resolver checks for `.debug_info` presence and
prefers debug-info-bearing copies. Only types are merged (no address
relocation) — type stamps require structural layout, not absolute addresses.

This approach is deterministic and works post-mortem. It is immune to
DynamoRIO's private loader hiding target libraries from `/proc/<pid>/maps`.

### DWARF5 name acceleration

`NameAccelerator::build()` parses the `.debug_names` section (DWARF5) at
`parse_elf` time. It builds a `HashMap<String, Vec<(cu_offset, die_offset)>>`
for `DW_TAG_structure_type`, `DW_TAG_union_type`, and `DW_TAG_class_type`
entries. `resolve_deep` uses this for O(1) name→DIE lookup instead of
scanning all compilation units. Falls back to full CU scan for DWARF4
binaries (no `.debug_names` section). `resolve_deep_at` jumps directly to
a CU+DIE via `Dwarf::unit_header()`.

### CFI table

`parse_eh_frame` reads the `.eh_frame` section via gimli and builds a
`CfiTable` — a vector of `CfiEntry` structs, each mapping a PC range
(`start_pc..end_pc`) to the set of callee-saved register indices preserved
in that frame. `saved_regs_at(pc)` finds the entry covering a given PC.
The table is populated during `parse_elf` and stored as `DwarfInfo.cfi`.

### JIT DWARF resolution

On-demand deep type resolution for types marked `shallow: true`. Two
strategies, applied in order by the reconciler's STM stamp path:

1. **`patch_shallow_fields(ti)`**: walks a `TypeInfo`'s field tree and
   replaces field-embedded shallow types with their full version from
   `type_registry`. O(1) per field. Handles the common case where each
   struct has a top-level DWARF DIE resolved at depth 0 in the registry.

2. **`resolve_deep(type_name)`**: re-reads the ELF from `elf_path` and
   re-parses the named type with raised depth caps (struct fields: 32,
   type resolution: 64 via `extract_struct_fields_deep` and
   `resolve_type_at_deep`). Updates `type_registry` in place. Fallback
   for types that only exist as nested fields with no standalone DIE.

`DwarfInfo` stores `elf_path: String` to enable on-demand re-parsing.

### Location tables

DWARF location descriptions can be simple or PC-qualified. The parser supports
both via `LocationTable`:

```rust
pub struct LocationTable {
    pub entries: Vec<(Range, LocationPiece)>,
}
```

Supported `LocationPiece` variants:

| Variant | DWARF equivalent | Meaning |
|---|---|---|
| `Address(u64)` | `DW_OP_addr` | Fixed memory address |
| `FrameBaseOffset(i64)` | `DW_OP_fbreg` | Frame base + offset |
| `Register(u16)` | `DW_OP_reg*` | Value lives in a register |
| `RegisterOffset(u16, i64)` | `DW_OP_breg*` | Register + offset |
| `ImplicitValue(u64)` | `DW_OP_implicit_value` | Compile-time constant |
| `CFA` | `DW_OP_call_frame_cfa` | Canonical frame address |
| `Expr(DwarfExprOp)` | Complex expression | Stack machine or pattern match |

### Expression evaluator

`DwarfExprOp` has three fast-path patterns plus a general stack machine:

- **`DerefRegOffset`**: `DW_OP_breg + DW_OP_deref` (returns pre-deref addr).
- **`RegPlusReg`**: Two register+offset values added.
- **`StackMachine`**: Full evaluator supporting arithmetic, bitwise, stack
  manipulation (`Drop`, `Pick`, `Swap`, `Rot`), `DW_OP_piece`, and
  `DW_OP_stack_value`. Cannot dereference target memory (separate address
  space), so `DW_OP_deref` preserves the address on the stack.

DWARF-to-rtmap register mapping is defined in `DWARF_TO_REGFILE[17]`,
translating DWARF register numbers (0=RAX, 1=RDX, 2=RCX, 3=RBX, ...) to
rtmap indices (0=RAX, 1=RBX, 2=RCX, 3=RDX, ...).

## Ring orchestrator (`ring.rs`)

The orchestrator manages all shared memory connections to the tracer.

### Structures

- **`MappedShm`**: RAII wrapper around `shm_open` + `mmap`/`munmap`.
- **`ThreadRing`**: A single thread's ring buffer. Exposes `pop_n` and
  `consume_batch` (snapshot-atomic: a REG_SNAPSHOT header is never returned
  without its 6 continuations).
- **`RingOrchestrator`**: Manages the control ring and a vector of
  `ThreadRing`s. Provides `try_attach_ctl`, `poll_new_rings`,
  `batch_drain`, `merge_pop`, `total_fill`, and `update_backpressure`.

### Protocol version + ABI hash handshake

On attach, `try_attach_ctl` validates:
1. `magic` matches the expected constant.
2. `proto_version == RTMAP_PROTO_VERSION` (currently 3).
3. `build_hash == rtmap_abi_hash()` — structural ABI hash over `sizeof`/`offsetof`
   of `Event`, `RingHeader`, and scratch pad offsets. Mismatches are rejected
   with `ABI MISMATCH` diagnostic and the engine refuses to attach.

`ThreadRing::from_shm` validates magic + proto_version on ring attach.

### Batch drain

The primary drain method is `batch_drain(per_ring, buf)`:

1. Iterates all rings from the current round-robin index.
2. Per ring: loads `tail` (relaxed) and `head` (acquire) once, reads up
   to `per_ring` events via `read_volatile`, stores `tail + n` (release).
3. After consuming events from each ring, checks `is_terminal()` and
   whether `head == tail` (fully drained). If both, retires the ring
   (`alive = false`). This is the last-gasp drain: the normal consume
   reads remaining events, and the terminal check retires only after all
   events are consumed.
4. Appends `(ring_index, event)` pairs to the output buffer.

With `per_ring = 20,000` and 6 rings, a single call can return up to
120,000 events with 12 atomic operations total.

### Backpressure

After each drain: computes fill in eighths per ring. Sets `backpressure = 1`
(release) when fill >= 6/8, clears when fill < 3/8. The tracer reads this
with relaxed ordering and sheds `READ` events.

## Address index (`index.rs`)

Two-tier sorted interval map resolving addresses to named variables in O(log N).

### Tier 1: Static globals

Inserted once after DWARF parsing and relocation into a sorted
`Vec<Interval>`. Binary search for O(log N) lookup. Never removed.

### Tier 2: Dynamic locals

Inserted on CALL, removed on RETURN. Stored in
`HashMap<FrameId, Vec<Interval>>` for O(1) frame removal. Scanned linearly
on lookup (typically <10 frames, <5 locals each).

### MRU cache

8-slot MRU cache shared across both tiers with LRU promotion. Each entry
is either `Static { lo, hi, idx }` or `Dynamic { lo, hi, frame_id, local_idx }`.

### Lookup priority

On overlapping intervals, `lookup(addr)` prefers:
1. Locals over fields over globals.
2. Narrower intervals over wider intervals (within the same tier).

### Finalization

`finalize()` re-sorts the static interval vector. Deferred to end of each
batch drain cycle (not per-event) to amortize sorting cost.

## Shadow Register File (`shadow_regs.rs`)

Per-thread register tracking with provenance and coherence.

### Confidence tiers

Each of the 18 tracked registers carries a `Confidence` level (ordered
low to high):

| Tier | Label | Bar | Source |
|---|---|---|---|
| `Unknown` | `???` | 0/10 | No information |
| `Stale` | `STALE` | 2/10 | Invalidated by a memory write to the source |
| `Speculative` | `spec` | 5/10 | Heuristic inference |
| `WriteBack` | `wb` | 7/10 | Value written back to known memory source |
| `AbiInferred` | `abi` | 8/10 | ABI convention (callee-saved on CALL) |
| `CfiVerified` | `cfi` | 9/10 | CFI `.eh_frame` confirms register preservation |
| `Observed` | `obs` | 10/10 | Direct `REG_SNAPSHOT` from tracer |

The TUI renders a 10-segment confidence bar per register with color coding.
`CfiVerified` is rendered as `LightGreen`.

### Coherence checking

On every write event, `check_coherence(addr, value, size, seq)` scans all
registers. For each register with a known memory source (`src_addr`,
`src_size`), it checks for interval overlap:

```
overlap = addr < (src_addr + src_size) && (addr + write_size) > src_addr
```

If the write overlaps the register's source and the value differs, the
register is marked `Stale`. This detects cross-thread coherence violations
and same-thread overwrites of spilled register values.

### Event handlers

- **`on_snapshot(regs)`**: Sets all 18 registers to `Observed` confidence.
- **`on_call(callee_pc, rsp, seq)`**: Pushes a `ShadowFrame` saving all
  register states. Sets RSP to `Observed`. Promotes callee-saved registers
  (RBX, RBP, R12-R15) to `AbiInferred`. Marks caller-saved registers
  (RAX, RCX, RDX, RSI, RDI, R8-R11) as `Speculative`.
- **`on_return(seq, pc)`**: Pops the `ShadowFrame` and restores callee-saved
  registers to their pre-call state. Sets RAX to `Speculative` (return
  value). Restores other caller-saved registers from the saved frame.
- **`on_return_cfi(seq, pc, cfi_saved)`**: Calls `on_return`, then promotes
  callee-saved registers that appear in the CFI saved set and have
  confidence between `Speculative` and `Observed` (exclusive) to
  `CfiVerified`. This is the CFI-hardened return path.
- **`callee_pc()`**: Returns the PC of the current top-of-stack callee,
  used by the reconciler to query `CfiTable.saved_regs_at(pc)`.
- **`on_reload(reg, value, src_addr, src_size, seq, rip)`**: Sets register
  to `Observed` with known memory source for future coherence checking.

### Piece assembler

`PieceAssembler` reconstructs `DW_OP_piece`-fragmented variables. It parses
a sequence of `ExprStep`s into `PieceFragment`s, each with a byte offset,
size, and source (`Register`, `Memory`, or `Implicit`). The `assemble`
method reads fragment values from the SRF and produces an `AssembledValue`
with per-fragment confidence tracking.

## Heap graph (`heap_graph.rs`)

Autonomous heap object discovery from the write event stream.

### HeapOracle

Classifies addresses as heap, stack, or module:
- **Module**: Falls within any `(base, base+size)` range from loaded modules.
- **Stack**: Falls within any thread's `(min_rsp, max_rsp + 128KB)` range.
- **Heap**: Plausible userspace pointer (>=0x1000, <0x0000_8000_0000_0000)
  that is neither module nor stack.

### Object discovery via clustering

`process_write` maintains a sliding window of recent writes
(`CLUSTER_WINDOW = 64`). When >=3 writes fall within `CLUSTER_RADIUS = 256`
bytes of each other and target heap addresses, a new `HeapObject` is created
with the minimum address as base and the span as inferred size.

### Field value storage

Each `HeapObject` stores a `BTreeMap<u64, HeapFieldInfo>` mapping field
offsets to their last-known values, sizes, write counts, and pointer flags.
This is the data source for Retrospective Type Reconciliation — RTR reads
`last_value` from these fields to discover pointer chains without additional
tracer events.

### Pointer edge tracking

Fields where `size == 8` and the value is a plausible pointer are tagged as
pointer fields. `HeapEdge`s track source->target relationships with write
counts.

### Type inference

Periodically (`TYPE_INFERENCE_INTERVAL = 10,000` events), `run_type_inference`
matches observed field layouts against DWARF struct definitions. Each
candidate is scored by field-offset/size match ratio with a 10% bonus for
exact size match. Objects with score >=0.5 get a type annotation.

### Lifecycle integration

`on_free(addr, size)` removes all objects whose base address falls within
the freed range, and purges their entries from `addr_to_base`.

### Garbage collection

`gc_stale(current_seq, max_age)` evicts objects not written within `max_age`
sequence numbers. Called every 65,536 events with `max_age = 500,000`.

## Shadow Type Map (`world.rs`)

The STM is a `HashMap<u64, TypeProjection>` mapping heap addresses to
authoritative DWARF type projections. Each projection stores:

```rust
pub struct TypeProjection {
    pub base_addr: u64,
    pub type_info: TypeInfo,
    pub source_name: String,
    pub stamp_seq: u64,
}
```

### Stamp paths

1. **Direct stamp** (`stamp_type`): When a DWARF-typed pointer global or
   local writes a non-zero value to a heap address, the pointee's struct
   type is looked up in `type_registry` and stamped. Returns a `StampResult`
   enum:

   | Variant | Meaning |
   |---|---|
   | `New` | First stamp at this address |
   | `Replaced` | Overwrites a same-type or first-time different-type stamp |
   | `PoolReuse` | Address has 2+ schisms (recycled by allocator) |

   The caller uses `StampResult` to decide whether to trigger RTR (`New`)
   and whether to emit a `TYPE_SCHISM` or `pool_reuse` topology event.

2. **Field propagation** (`propagate_field_write`): When a write hits an
   address covered by an existing STM projection, and the written field is
   a pointer whose pointee type exists in `type_registry`, the engine stamps
   the written value with the pointee type. Returns `bool` indicating whether
   a new stamp was created. Includes a freshness guard: skips propagation if
   the covering projection predates the current allocation epoch.

3. **Indirect element registration**: When `propagate_field_write` encounters
   a `**T` field (pointer-to-pointer), it registers the target allocation's
   element type as `T` via `register_indirect(alloc_base, element_ti)`. Future
   writes into that allocation (e.g., bucket array stores) are stamped via
   `indirect_lookup` without requiring a covering STM projection on the bucket
   array itself. Counters: `indirect_registrations` (registrations created),
   `indirect_stamps` (stamps applied via indirect path).

4. **Size-validation sentinel** (`HeapAllocTracker::check_size`): Before
   stamping, if the type's `byte_size` exceeds the known allocation size,
   a `SizeMismatch` is recorded but the stamp still proceeds (last-write-wins).

### Pool/arena reuse classification

Addresses that oscillate between types (e.g., jemalloc slab reuse, nginx
pool recycling) are classified as `PoolReuse` rather than genuine type
confusion. The STM tracks a per-address schism counter. On the second
type overwrite at the same address, all future stamps are `PoolReuse`.

The topology stream emits:
- `TYPE_SCHISM` with `"pool_reuse": true` — allocator recycling noise.
- `TYPE_SCHISM` with `"pool_reuse": false` — genuine structural confusion.
- `TYPE_EPOCH_CLOSE` — the old type's reign at this address ended.

Verified: nginx 1811 pool_reuse vs 38 schisms; Redis 119,922 pool_reuse
vs 195 schisms.

### Purge

`purge_range(addr, size)` removes all projections whose `base_addr` falls
within `[addr, addr + size)`. Called on every confirmed FREE event.

## Retrospective Type Reconciliation (`world.rs`)

`ShadowTypeMap::retrospective_scan` performs a bounded BFS from a
freshly-stamped address:

```
queue = [seed_addr]
stamped = 0
while queue not empty AND stamped < 64:
    base = queue.pop_front()
    proj = stm.get(base)           // must be stamped
    obj  = heap_graph.find(base)   // must have observed fields
    candidates = []
    for each pointer field in proj.type_info.fields:
        val = obj.fields[field.byte_offset].last_value
        if val != 0 AND val not in stm AND val in live_allocs:
            pointee_type = type_registry[field.type_info.name.strip_prefix('*')]
            candidates.push((field.name, val, pointee_type))
    candidates.sort_by(field_name)          // deterministic order
    for (name, val, type) in candidates:
        stm.stamp(val, type, name, seq)
        stamped += 1
        queue.push_back(val)
```

The fuel budget (64 nodes) prevents latency spikes on large graphs.
**Deterministic BFS**: candidates are sorted by field name before pushing to
the queue, ensuring identical discovery order across ASLR'd runs. The BFS
uses `find_object_base` on the HeapGraph to handle cases where the STM stamp
address differs from the HeapGraph's clustering base, adjusting field offsets
by the delta.

**Effect**: The instant a global pointer is assigned to the head of a linked
list, RTR discovers and types every reachable node in the chain — even if
the list was built before tracing began.

## Type Stability Monitor (`world.rs`)

`TypeStabilityMonitor` validates every write to an STM-stamped heap region
against the projected type's field layout. On the WRITE hot path, the
reconciler reuses the `covering()` result already computed for the field
heatmap — no additional O(N) scan.

### SIMD-scaled tail tolerance

The `check_write` function applies a **write-size-scaled tail tolerance**
before reporting Spanning violations. This eliminates false positives from
AVX2/AVX-512 coalesced stores that spill past the last declared field:

| Write size | Tolerance | Rationale |
|---|---|---|
| ≥ 64 bytes | 56 bytes | AVX-512: 64B store across last 8B field → 56B overshoot |
| ≥ 32 bytes | 24 bytes | AVX2: 32B store across last 8B field → 24B overshoot |
| ≥ 16 bytes | 8 bytes | SSE: 16B store across last 8B field → 8B overshoot |
| < 16 bytes | 0 bytes | Scalar: no tolerance (exact field match required) |

The tolerance is applied only to the **last field** of a struct (tail spill).
Interior field boundary violations are always reported regardless of write size.

### Violation classes

| Kind | Condition | Signal |
|---|---|---|
| **Interstitial** | Write offset matches no field (padding, tail, or corruption) | Structural violation: write to a byte the type doesn't declare |
| **Spanning** | Write starts within a field but extends past its boundary | Type confusion: wrong-size access or cross-field overwrite |

Aligned writes (offset and size match a field exactly) are tallied but
not flagged.

### Hot-path contract

```
check_write(write_addr, write_size, projection, pc) → bool
  offset = write_addr - projection.base_addr
  if fields is empty → false (opaque type)
  field = fields.find(offset ∈ [f.byte_offset, f.byte_offset + f.byte_size))
  if field is None → Interstitial violation
  if offset + write_size > field.byte_offset + field.byte_size → Spanning violation
  else → aligned, no violation
```

Per-type tallies (`TypeStabilityTally`) are keyed by type name in a
`HashMap`. Violation details are stored in a capped `Vec<TypeViolation>`
(max 128) for the headless summary; the tally is always accurate
regardless of cap.

### Output

- **Headless summary**: per-type tally table (aligned/interstitial/spanning)
  + top 20 violation details with write address, offset, type, field, and PC.
- **Topology stream**: `TYPE_VIOLATION` JSONL events emitted on each
  violation with kind, write geometry, type name, field name, and PC.
- **Clean bill**: if checked > 0 and violations == 0, prints confirmation.

### Design rationale

The monitor detects the class of bug that survives for decades: a struct
field written at the wrong offset due to slab reuse, union aliasing, or
stale type casts. These writes are spatially valid (within allocation
bounds) and temporally valid (allocation is live), but semantically wrong.
ASan and Valgrind cannot detect them because they operate below the type
layer. Static analyzers cannot detect them because the aliasing depends
on runtime allocator behavior.

## Allocator lifecycle (`world.rs`)

`HeapAllocTracker` tracks live allocations in a `BTreeMap<u64, u64>` (addr
to size), enabling O(log N) range queries via `containing_alloc`.

### Event handling

- **ALLOC** (kind 9): `on_alloc(ptr, size)` inserts the allocation.
  Size is read from `ev.size` (32-bit field).
- **FREE** (kind 10): `on_free(ptr)` removes the allocation and returns
  the old size. If no matching ALLOC exists (orphan free), the counter
  `orphan_frees` is incremented but the STM is **not** purged.

### Orphan free policy

Orphan frees occur when the ALLOC event was dropped due to ring backpressure.
Purging the STM on an orphan free would cause "type blindness" — typed nodes
silently vanishing from the output. The conservative policy (count but don't
purge) preserves type information until the address is overwritten or freed
with a matching allocation.

### Headless output

The status line includes allocation metrics:
```
allocs {total_allocs}/{total_frees} live {live_count} [orphan_free={orphan_frees}]
```

## Visual ASan (`world.rs`)

On every heap write, `check_write_bounds(addr, write_size, stm)` checks
whether the write stays within a live allocation boundary.

### Hazard classification

```rust
pub enum HazardKind {
    OutOfBounds,  // write starts in alloc, extends past end
    HeapHole,     // write addr between allocations (UAF / wild write)
}
```

### Symbolic intent

For OOB hazards, the engine looks up the STM projection covering the write
address. If found, it reports the type name and specific field name, enabling
output like:

```
OOB  0x...40 +8B exceeds alloc [0x...20..+24] by 8B (intended for node_t.next)
```

### HeapHole grace period

HeapHole hazards are suppressed within **256 events** of the last ALLOC event
(`world.total_event_count - world.last_alloc_event_count <= 256`). This
eliminates false-positive HeapHole reports caused by cross-thread ring
reordering: when thread A's ALLOC and thread B's WRITE to the freshly-
allocated memory are consumed in WRITE-first order, the engine would
otherwise report a HeapHole (write to unallocated memory) that is merely
an artifact of ring consumption order.

**OOB hazards are never suppressed** — they reference a known allocation
boundary and cannot be caused by reordering.

The grace period is zero-allocation, zero-copy, and branch-predicted-taken
(HeapHoles are rare in correct programs). Fields:
- `world.total_event_count`: incremented at the top of `process_event`.
- `world.last_alloc_event_count`: stamped on every ALLOC event.

### Heap-hole filtering

HeapHole hazards are only reported if the write address falls within the
span `[min_alloc_addr, max_alloc_addr + max_alloc_size)`. This prevents
false positives from globals and stack addresses that `HeapOracle` loosely
classifies as heap.

### Register context

Each `HeapHazard` carries two additional fields populated at creation time
in `reconciler::process_event`:

- **`pc`** (`u64`): faulting program counter from `ev.rip_lo` (module-relative).
- **`reg_snapshot`** (`Option<[u64; 18]>`): full register values from the
  per-thread `ShadowRegisterFile::values()` at hazard time.

The diff output extracts a compact `HazardRegContext` with `pc`, `rax`,
`rdi`, `rsi`, `rdx`, `rsp` for each hazard.

### Deduplication

Hazards are deduplicated by `write_addr` — if a previous hazard exists for
the same address, the new one is suppressed. Total hazard count is capped
at 64 to bound memory usage.

## World state (`world.rs`)

The engine's in-memory model of the target program's observable state.

### WorldState

```rust
pub struct WorldState {
    inner: Arc<WorldInner>,
    pub cl_tracker: CacheLineTracker,
    pub stm: ShadowTypeMap,
    pub heap_allocs: HeapAllocTracker,
    pub hazards: Vec<HeapHazard>,
}
```

### WorldInner

```rust
pub struct WorldInner {
    pub nodes: BTreeMap<NodeId, Node>,
    pub edges: BTreeMap<NodeId, PointerEdge>,
    pub insn_counter: u64,
    pub reg_file: LiveRegisterFile,
    pub cache_heat: CacheHeatmap,
}
```

Note: `cl_tracker`, `stm`, `heap_allocs`, and `hazards` are on `WorldState`
(mutable), not `WorldInner` (snapshotted). This is intentional — these
structures are only needed by the event processor, not the renderer.

### Node IDs

```rust
pub enum NodeId {
    Global(u32),
    Field(u32, u16),
    Local(FrameId, u16),
}
```

### Copy-on-write snapshots

`WorldState` wraps `WorldInner` in an `Arc`. `snapshot()` is a ref-count
bump (1 atomic). `cow()` calls `Arc::make_mut` — no-op if refcount is 1,
clones if a snapshot is held by the renderer.

### Pointer edge tracking

When a tracked pointer variable is written:
1. `addr_index.lookup(pointer_value)` resolves the pointee.
2. If tracked: `PointerEdge` links source to target.
3. If untracked: edge marked `is_dangling = true`.
4. If NULL: edge removed.

### Cache-line contention tracking

`CacheLineTracker` monitors which threads write to each 64-byte cache line.
Each `ClSlot` stores a `per_writer: [u16; 16]` array indexed by
`thread_id & 15`, enabling observation-bias correction.

- **`contention_score(addr)`**: Raw distinct writer count (bitmask popcount).
  Susceptible to noise from threads that wrote once due to backpressure
  asymmetry.
- **`contention_score_weighted(addr, min_frac)`**: Bias-corrected score.
  Only counts threads whose write fraction exceeds `min_frac` of total
  writes to the cache line. `min_frac=0.01` means a thread must account
  for ≥1% of writes. Filters out backpressure artifacts.
- **`writer_breakdown(addr)`**: Returns `Vec<(u8, u16)>` of (thread_idx,
  write_count) pairs for diagnostic output.

The TUI annotates cache lines with `FALSE_SHARE T=N` when N > 1.

`tick()` halves all `per_writer` counts and `write_count`, then evicts
slots where `write_count` decayed to zero. Writers whose `per_writer`
count drops to zero are removed from the `writers` bitmask. Called every
4,096 events alongside `cache_heat_tick()`.

### Shadow stacks

Per-thread shadow stacks mirror the target's call stack:

```rust
pub struct ShadowStack {
    pub frames: Vec<ShadowFrame>,
    pub mismatches: u64,
    pub non_local_jumps: u64,
    pub max_depth: usize,
}
```

- **CALL**: Push frame with ID, callee PC, function name.
- **RETURN**: Pop frame. Remove locals from index. Queue nodes for deferred
  removal (32-frame delay for renderer visibility).
- **`pop_return_checked(return_pc)`**: Longjmp-aware return. If `return_pc`
  matches the top frame's `callee_pc`, normal pop. If not, scans the stack
  downward for a frame whose `callee_pc` matches — if found, unwinds all
  frames above it (non-local jump) and increments `non_local_jumps`. If
  not found, falls back to normal pop and increments `mismatches`.
  Returns `(Option<ShadowFrame>, frames_unwound)`.
  **Not wired**: the live `EVENT_RETURN` path uses plain `pop_return`;
  `pop_return_checked` is unit-tested only. Wiring it requires resolving
  the PC-semantics mismatch (RETURN events carry the ret instruction's PC,
  not the call target).
- **Mismatch**: Incremented when RETURN has empty stack or `return_pc` is
  not on the stack at all (missed CALL, indirect calls).
- **Non-local jump**: Incremented when `pop_return_checked` detects a
  `longjmp`/`setjmp` return — `return_pc` matches a frame deeper than
  the top of stack.

### Snapshot ring

Circular buffer of 512 `Arc<WorldInner>` snapshots for time-travel:

```rust
pub struct SnapshotRing {
    buf: Vec<SnapEntry>,
    cap: usize,
    write_pos: usize,
    len: usize,
}
```

Each entry: snapshot + instruction counter + render tick + event sequence.

### SnapshotDelta

Temporal self-diff between two `SnapshotRing` entries. Compares `WorldInner`
snapshots by index and reports:

- **`node_delta`**: `newer.nodes.len() as i64 - older.nodes.len() as i64`
- **`edge_delta`**: `newer.edges.len() as i64 - older.edges.len() as i64`
- **`added_nodes`**: node IDs present in newer but absent in older.
- **`removed_nodes`**: node IDs present in older but absent in newer.
- **`changed_edges`**: edges where the target address differs.
- **`value_changes`**: nodes where `last_value` differs between snapshots.

`SnapshotRing::delta(older_idx, newer_idx)` returns `None` if either index is
out of bounds. Five unit tests cover identity, known mutation, wraparound,
node removal, and OOB.

### BB coverage

Per-basic-block hit counters tracked in `WorldState`. `record_bb_entry(rip_lo)`
increments the counter for the given RIP offset and bumps `insn_counter`.

Headless output includes a `BB COVERAGE` section with unique block count, total
hits, and top-10 hottest blocks by hit count. `--coverage <file>` exports the
full map as TSV (`rip_offset\thits`).

The `--no-bb` flag filters `EVENT_BB_ENTRY` events in both live and replay
paths, suppressing coverage tracking without affecting topology correctness.

## Event reconciler (`reconciler.rs`)

Extracted from `main.rs` into a library module for consumption by both the
live engine and `rtmap-diff`. Public API:

- **`process_event`**: Central dispatch for all event types.
- **`populate_globals`**: Inserts DWARF globals into the address index.
- **`warm_scan`**: Legacy one-shot BFS over `/proc/<pid>/mem` (retained for replay).
- **`WarmScanner`**: Persistent incremental BFS (see Warm-scan section below).
- **`apply_reg_snapshot`**: Processes 7-slot register snapshot runs.

### Event dispatch table

| Event | Action |
|---|---|
| `WRITE` (0) | `cl_tracker.record_write`. **Compound writes**: COMPOUND header carries real low 8B; continuation events carry subsequent 8B chunks with their own `addr`/`size`/`value`, processed as independent writes. Continuations skip `shadow_regs.observe_write` and cross-thread coherence (no meaningful seq). **TRUNCATED gate** (REP/LOCK fallback only): `val` zero-poisoned to prevent phantom pointer chasing. Normal path: `shadow_regs.check_coherence`. If heap: `heap_graph.process_write`, `stm.propagate_field_write` (+ RTR on new stamp), `heap_allocs.check_write_bounds` (Visual ASan, populates `pc` + `reg_snapshot` on hazard). `addr_index.lookup` → `world.update_value` + `world.update_edge`. If pointer to heap: clone type from registry, `patch_shallow_fields`, `stm.stamp_type` + RTR scan. |
| `READ` (1) | Journal only (no state mutation). |
| `CALL` (2) | DWARF function lookup (relocated PC). Push shadow frame. Insert locals into index. |
| `RETURN` (3) | Look up callee PC via `srf.callee_pc()`. If CFI data exists in `DwarfInfo.cfi` for that PC: `srf.on_return_cfi(saved)` (promotes callee-saved to `CfiVerified`). Otherwise: `srf.on_return()`. Pop shadow frame. Remove locals. Queue deferred node removal. |
| `REG_SNAPSHOT` (5) | Handled by caller via `reconciler::apply_reg_snapshot` over the drained 7-slot run. `process_event`'s arm is a no-op. `ring::consume_batch` enforces snapshot atomicity so the run never straddles a batch. |
| `CACHE_MISS` (6) | `addr_index.lookup`. Record miss in `cache_heat`. |
| `MODULE_LOAD` (7) | Compute relocation delta. Re-populate globals with relocated addresses. Register heap oracle module range. |
| `TAIL_CALL` (8) | Like CALL but does not push a new shadow frame (replaces current). |
| `ALLOC` (9) | `heap_allocs.on_alloc(ptr, size)`. Size read from `ev.size` (32-bit). Stamps `world.last_alloc_event_count = world.total_event_count` for HeapHole grace period. |
| `FREE` (10) | `heap_allocs.on_free(ptr)`. If matched: `stm.purge_range` + `heap_graph.on_free`. If orphan: count only, no purge. |
| `RELOAD` (12) | `shadow_regs.on_reload(reg, value, src_addr, size, seq, rip)`. |
| `PROCESS_FORK` (13) | Log child/parent PID. `ChildProcessTracker::register_fork(child_pid)`. |
| `SHARED_MAP` (14) | Log mmap/munmap address and length. Used by `ChildProcessTracker` to refresh shared region map without polling `/proc/<pid>/maps`. |

### Inline-aware caller_pcs enrichment

In the `ALLOC` handler, after building `caller_pcs` from `ev.rip_lo` and
the shadow stack, the reconciler enriches the set with inlined subroutine
PCs. For each caller PC, it queries `dwarf_info.functions` (a `BTreeMap<u64,
FunctionMeta>`) for overlapping inlined subroutines. If the caller PC falls
within an inlined function's `[low_pc, high_pc)` range, that function's
`low_pc` is added to `caller_pcs`.

This closes the AllocSiteOracle blind spot under `-O3` aggressive inlining:
when a function is inlined, no CALL event (and thus no shadow stack frame)
exists for it. Without enrichment, the oracle cannot match the allocation
signature. With enrichment, the inlined caller's low_pc appears in
`caller_pcs` and the oracle matches correctly.

**Impact**: Redis at `-O3` achieves 46 STM projections with enrichment vs
~12 without (type coverage gap from inlined allocator wrappers like
`zmalloc` → `malloc`).

Returns `true` if the event was "interesting" (tracked write or control
event). Untracked writes return `false` and are not journaled (~90% of
writes in typical workloads).

### Dual-domain sequence tracking

The tracer uses two independent per-thread sequence counters:

| Domain | Counter | Events |
|---|---|---|
| JIT (0) | raw TLS `RTMAP_RAW_SLOT_SEQ` | WRITE, BB_ENTRY |
| Clean-call (1) | drmgr TLS `TLS_SLOT_SEQ` | READ, CALL, RETURN, TAIL_CALL, ALLOC, FREE, REG_SNAPSHOT, RELOAD |

The engine classifies events via `seq_domain(ev_kind)` and tracks
`expected_seq` as a `HashMap<(thread_id, domain), u32>`. This eliminates
false-positive gap reports that occurred when both domains' counters were
conflated into a single per-thread tracker. Compound events (REG_SNAPSHOT,
compound wide writes) consume multiple ring slots but increment the
sequence counter only once.

### Warm-scan

#### `WarmScanner` (continuous, production path)

Persistent incremental BFS over `/proc/<pid>/mem`. Used in both TUI and
headless loops.

```rust
pub struct WarmScanner {
    mem: File,                                    // /proc/<pid>/mem
    queue: VecDeque<(u64, TypeInfo, String, u32)>, // (addr, type, source, depth)
    visited: HashSet<u64>,
    pub stats: WarmScanStats,
    pub passes: u32,
    max_depth: u32,                               // 12 in production
    pub seeded: bool,
}
```

- **`seed(&mut info, delta, heap_oracle, topo, stm, alloc_tracker)`**: Calls
  `ensure_type` on each global's type to fully materialize depth-truncated
  structs (e.g. `redisServer` with 487 fields) before traversal. Rebuilds
  global `TypeInfo` from the now-deep registry via a two-pass collect-then-
  apply pattern (avoids borrow conflict on `info.globals` vs `info.type_registry`).
  Calls `patch_shallow_fields` on each global. Enqueues all DWARF globals with
  pointer fields. Reads pointer values from `/proc/<pid>/mem` via
  `scan_ptr_fields`. Increments `passes`.
- **`step(budget, info, world, heap_oracle, topo)`**: Processes up to `budget`
  reads from the queue. On each item: skip if depth > `max_depth` or already
  visited, stamp via `stm.stamp_type`, emit `COLD_STAMP`/`COLD_LINK`, recurse
  via `scan_ptr_fields`. Returns stamp count. If budget exhausted, remaining
  items stay in queue for the next call.
- **`is_idle()`**: `seeded && queue.is_empty()`.

Initial seed at 100K events (after library globals are relocated). Periodic
re-seed every 200K events thereafter (event-count based via `last_reseed_total`,
works identically in TUI and headless modes regardless of wall-clock speed).
Budget per step: 2000 reads. Scanner is lazily initialized on first trigger.

**Queue cap**: `WARM_SCAN_QUEUE_CAP = 50_000`. Enqueues beyond this limit are
dropped and counted in `stats.dropped`. Prevents unbounded memory growth on
targets with deep pointer graphs (e.g., Redis with 400K+ reachable objects).

**Visited pre-filter**: `scan_ptr_fields` checks `visited.contains(addr)`
before cloning `TypeInfo` and enqueuing. This eliminates redundant TypeInfo
clones on dense graphs where many pointers converge on the same object,
reducing peak memory by ~40% on Redis workloads.

`scan_ptr_fields` accepts the `container_of_map` from `DwarfInfo`. When a
pointer field's pointee type has container-of entries, the scanner also
enqueues the container base address (`ptr - field_offset`) with the container
type. This enables discovery of full enclosing objects when following intrusive
links (e.g., `list_head*` → `task_struct`). The `container_of_stamps` stat
tracks how many objects were discovered via this path.

The `**T` alloc gate in `scan_ptr_fields` is relaxed: when the pointee
address is not in `alloc_tracker` (alloc event lost to ring overflow),
`heap_oracle.is_heap()` is used as a fallback. This ensures indirect
pointer targets are still enqueued and stamped under backpressure.

#### `warm_scan` (legacy one-shot)

Retained for replay and backward compatibility. Runs the full BFS in a single
call with no budget limit.

Both paths emit `COLD_STAMP` and `COLD_LINK` to the topology stream.
Stats: globals scanned, reads, null pointers, missing pointee types, stamps,
max depth, read errors, non-heap pointers, container_of_stamps, enqueued.

### Periodic maintenance

Every 4,096 events (`total & 0xFFF == 0`):
- `world.cache_heat_tick()` — decay cache miss counts.
- `world.cl_tracker_tick()` — decay contention tracking, evict dead entries.

Every 65,536 events (`total & 0xFFFF == 0`):
- `heap_graph.gc_stale(total, 500_000)` — evict old heap objects.

Heap type inference runs when `heap_graph.needs_type_inference()` returns
true (every 10,000 heap events with objects present).

### Sequence tracking

Each event carries a per-thread 32-bit sequence number (seq_lo in the wire
field, seq_hi in kind_flags[16..31]; reconstructed via `Event::seq32()`).
The engine tracks the expected next sequence per thread and increments
`seq_gaps` on mismatches. Gaps indicate dropped events (ring overflow) and
are displayed in the TUI header.

## Rendering

### Interactive mode (TUI, `tui.rs`)

ratatui with crossterm backend. 20 Hz refresh. Six drawn regions; three are
focusable panels (Memory, Events, Registers — `Panel` enum, Tab to cycle):

1. **Header bar.** Instruction counter, event count, node count, edge count,
   ring count, LAG metric, allocation stats, time-travel indicator, pause
   indicator, gap warnings.
2. **Memory map** (top-left, 55%). Variables grouped by cache line. Addresses,
   sizes, type names, values with recency coloring (red <100 events, yellow
   <1K, white <10K, gray older). Pointer values show pointee name. Struct
   fields indented under parent. `FALSE_SHARE T=N` on multi-writer cache
   lines. STM-typed heap regions shown in HEAP TYPES section.
3. **Events** (bottom-left, 45%). Filterable journal. Kind labels: W, R,
   CALL, RET, OVF, REG, CMIS, MLOAD, TCAL, RLOD. Thread ID. Address, size,
   value. Auto-scrolls to bottom unless user has scrolled.
4. **Shadow Registers** (top-right, 40%). 18 registers with hex values,
   10-segment confidence bar (color-coded by tier), stale warnings.
5. **Call Stacks** (mid-right, 30%). Per-thread shadow stacks. Top 4 frames
   shown (newest first). Idle threads show max depth.
6. **Heap Objects** (bottom-right, 30%). Object count, edge count. Top 8 by
   recency: base address, inferred size, type name, confidence %, field
   count, edge count.

### Event filters

Active when Events panel is focused:

| Key | Filter |
|---|---|
| `w` | Writes only (kind 0) |
| `r` | Hide reads (kind 1) |
| `0-9` | Filter by thread ID (toggle) |
| `x` | Clear all filters |

Filter state shown in panel title: `Events [W only, T3]`.

### Time travel

- `<-`/`h`: Step backward through snapshot ring. Auto-pauses.
- `->`/`l`: Step forward. Returns to live when past latest snapshot.
- `End`: Jump to live (exit time-travel).

### Headless mode (`--once`)

Plain-text output to stdout. Exits via two conditions:

1. **Tracer death**: `TRACER_EXITED` flag set by the `waitpid` thread.
   Bypasses arming — triggers immediate final drain and exit.
2. **Idle timeout**: consecutive poll rounds (100ms each) with zero events
   drained, subject to arming:

| Mode | Idle limit | Armed when |
|---|---|---|
| Normal | 50 rounds (~5s) | `total > 0` (any events received) |
| Server | 200 rounds (~20s) | `ctl.tripwire_hit == 1` or `stm.len() > 0` |

Server mode is activated by `--tripwire` or a `.rtmap` profile with a
tripwire symbol. The engine reads the `tripwire_hit` atomic flag from the
shared ctl header to determine arming. This prevents premature exit during
DynamoRIO's multi-second JIT compilation pause.

On exit, the engine performs a **final ring discovery sweep**
(`poll_new_rings`) followed by a drain loop to capture any remaining
events from short-lived threads that spawned and died between poll
intervals, then renders the final snapshot and exports artifacts.

Headless output sections:
1. **Status line**: insn count, events, nodes, edges, rings, LAG, alloc stats.
2. **Memory map**: variables grouped by cache line.
3. **HEAP TYPES**: STM projections with field decomposition.
4. **Size mismatches**: warnings from size-validation sentinel.
5. **Heap hazards**: OOB and heap-hole detections with symbolic intent.
6. **Pointer edges**: resolved and dangling pointer relationships.
7. **Event journal**: last 12 events.

### LAG metric

| LAG | Color | Meaning |
|---|---|---|
| 0-1,000 | Green | Consumer keeping up |
| 1,001-50,000 | Yellow | Falling behind |
| >50,000 | Red | Significant lag |

Displayed with K/M suffixes.

## Event recording (`record.rs`)

### File format

```
Bytes 0..8:    magic  = 0x52544D4150524300 ("RTMAPRC")
Bytes 8..12:   proto_version (u32) = 3
Bytes 12..20:  event_count (u64, backpatched on close)
Bytes 20..24:  reserved (u32, zero)
Bytes 24..:    packed events, 32 bytes each
```

Each event on disk: `addr(8) + size(4) + tid(2) + seq(2) + value(8) + kind_flags(4) + rip_lo(4) = 32 bytes`.

### Compound REG_SNAPSHOT recording

`EventRecorder::record_reg_snapshot(header, regs)` writes 7 consecutive events:

- Event 0: header (kind = REG_SNAPSHOT)
- Events 1-6: continuation, each packing 3 register values:
  - `addr` = `regs[i*3]`
  - `size` = `regs[i*3+1]` (truncated to u32)
  - `value` = `regs[i*3+2]`

This mirrors the ring protocol layout. The replayer (`rtmap-diff`) detects
the header, reads 6 continuations, reconstructs the 18-register array, and
calls `world.update_regs` + `srf.apply_snapshot`.

### EventPlayer

`EventPlayer::open(path)` validates magic and proto_version. `next_event()`
reads one event. `read_batch(buf, max)` reads up to `max` events into a
pre-allocated buffer, returning the count read.

## Topology streaming (`topology.rs`)

JSONL emitter for structural graph deltas. Activated by `--export-topology`.
Each line is a self-contained JSON object.

| Event type | Fields | Emitted when |
|---|---|---|
| `ALLOC` | seq, tid, addr, size | `on_alloc` |
| `FREE` | seq, tid, addr, size | `on_free` (confirmed) |
| `STAMP` | seq, addr, type_name, type_size, source, fields | STM stamp |
| `LINK` | seq, from, from_addr, to_addr, pointee_type, edge | Pointer edge |
| `COLD_STAMP` | addr, type_name, type_size, source, fields, depth | Warm-scan discovery |
| `COLD_LINK` | from, from_addr, to_addr, pointee_type, edge | Warm-scan pointer |
| `HAZARD` | seq, kind, write_addr, write_size, alloc_base, alloc_size, overflow, type_name, field_name | Visual ASan |
| `FALSE_SHARE` | seq, cl_addr, threads, names[] | Cache-line contention |
| `SUMMARY` | total_events, nodes, edges, stm_projections, live_allocs, hazards | End of run |

Consumed by `rtmap-check` for structural assertions.

## Differential topology (`diff.rs`, `rtmap-diff`)

Replays two `.bin` recordings through `reconciler::process_event` with
`RingOrchestrator::new_offline()`, checkpoints ASLR-invariant topology at
configurable intervals, and reports structural divergence.

### Usage

```sh
rtmap-diff --baseline a.bin --subject b.bin [--dwarf <elf>] \
    [--interval N] [--output diff.jsonl]
```

`--dwarf` is optional. Without it, the diff still compares alloc counts,
hazard counts, and raw topology, but type stamps will be empty.

### Canonical stamps

Each topology checkpoint captures a `BTreeSet<CanonicalStamp>`:

```rust
struct CanonicalStamp {
    source: String,      // symbolic: "server.db", not "0x7f..."
    type_name: String,   // DWARF type name
    type_size: u64,
    field_count: usize,
}
```

Sources come from `TypeProjection::source_name` in the STM. These are
already symbolic (e.g., `server.db`, `shared.ok`), not address-based.
ASLR has no effect on stamp identity.

### Common stamp mask

Stamps present in both final checkpoints are filtered from intermediate
diffs. This eliminates discovery-order noise (warm-scan timing, BFS
non-determinism) while preserving intentional structural divergence.

### Steady-state type histogram

Final checkpoints are compared using an order-invariant `BTreeMap<type_name, count>`.
This is immune to both ASLR and discovery order. Output shows `+N` deltas per type.

### Hazard register context

Each `CanonicalHazard` carries `pc` (from `ev.rip_lo`). The diff output
includes a `HazardRegContext` with `pc`, `rax`, `rdi`, `rsi`, `rdx`, `rsp`
from the `ShadowRegisterFile` at hazard time. JSONL output:

```json
{"hazard":"HOLE","write_size":8,"type":"?","field":"?","pc":"0x8c3cf","rax":"0x75d474c03b00",...}
```

### REG_SNAPSHOT replay

The replayer detects REG_SNAPSHOT headers in the event stream, reads 6
consecutive continuation events, reconstructs the 18-register array, and
calls `world.update_regs` + `srf.apply_snapshot`. This provides full CPU
context for hazard analysis during offline replay.

## Structural assertions (`check.rs`, `rtmap-check`)

Reads a JSONL topology file and a `.assertions` file. Evaluates invariants
against the recorded structural events. Intended for CI/CD integration.

```sh
rtmap-check topo.jsonl assertions.txt
```

Exit code 0 = all assertions pass. Non-zero = at least one failure.

### Assertion DSL

Each line in the `.assertions` file is either blank, a comment (`#`), or
an assertion of the form `assert <predicate>`. Supported predicates:

| Assertion | Syntax | Semantics |
|---|---|---|
| `NoHazards` | `assert no_hazards` | Zero `HAZARD` events in topology |
| `LiveAllocsLt` | `assert live_allocs < N` | Fewer than N live allocations at SUMMARY |
| `StmProjectionsGt` | `assert stm_projections > N` | More than N STM projections at SUMMARY |
| `MaxChain` | `assert max_chain(type("T"), "field") < N` | Longest pointer chain via `T.field` is < N |
| `TypeStable` | `assert type_stable(global("src"), "T")` | All stamps from source `src` have type `T` |
| `NoFalseSharing` | `assert no_false_sharing("A", "B")` | Variables A and B do not share a cacheline |
| `AllocBeforeStamp` | `assert alloc_before_stamp` | Every heap STAMP has a preceding ALLOC at the same address |
| `NoUseAfterFree` | `assert no_use_after_free` | No STAMP or LINK targets a freed address (compares STAMP seq against FREE seq, not ALLOC seq) |
| `MonotonicSeq` | `assert monotonic_seq` | ALLOC, STAMP, and LINK sequences are each monotonically increasing |
| `StampBeforeLink` | `assert stamp_before_link` | Every LINK target was stamped before the link event |

**`no_use_after_free` implementation note**: `AllocEvent` tracks both
`seq` (ALLOC event sequence) and `free_seq` (FREE event sequence). The
assertion compares STAMP/LINK `seq` against `free_seq`, not `seq`. This
prevents false positives where a STAMP occurs after ALLOC but before FREE.

## Static cacheline lint (`lint.rs`, `rtmap-lint`)

`rtmap-lint` is a pure static analysis tool. It reads DWARF from a compiled
binary and maps struct fields to cacheline boundaries, warning on layouts
likely to cause false-sharing.

### Recursive sub-struct flattening

Nested structs and unions are recursively expanded into leaf fields with
dotted paths (e.g., `bstate.timeout`, `pending_cmds.head`). Union variants
are emitted at the same offset. Depth-capped at 8 to match the DWARF
parser's `extract_struct_fields` cap.

### Three-tier structural intent analysis

When no annotation file is provided, the linter classifies fields using
three tiers ordered by certainty:

| Tier | Signal | Source | Severity |
|---|---|---|---|
| 1 | `is_volatile` / `is_atomic` | `DW_TAG_volatile_type`, `DW_TAG_atomic_type` | Warning |
| 2 | `alignment >= cacheline_size` | `DW_AT_alignment` on member | Warning |
| 3a | Lock-keyword name match | Field name contains `lock`, `mutex`, etc. | Warning |
| 3b | Scalar adjacent to pointer | Small scalar shares CL with pointer field | Info |

Tier 1 is compiler ground truth. Tier 2 detects alignment-intent violations
(developer intended isolation but other fields leaked onto the line). Tier 3
is a heuristic fallback. Earlier tiers short-circuit via `continue`.

### Union overlap check

Fields at identical offsets (union variants) with conflicting volatile/atomic
qualifiers are flagged as type-confused contention.

### Annotation support

An annotation file maps fields to writer groups (`field = group`, one per
line). When annotations are present, the linter warns on cachelines where
multiple writer groups collide. Annotation lookup tries the full dotted
path first, then falls back to the leaf field name.

### Divergence report (`--heatmap`)

Overlays lint predictions with runtime observations from a heatmap TSV
(exported by `rtmap --export-heatmap`). Classifies each cacheline:

| Class | Lint | Heatmap | Meaning |
|---|---|---|---|
| **Confirmed** | Flagged | Multi-thread writes observed | Ship the fix |
| **Silent Killer** | Clean | Multi-thread writes observed | Needs annotation or qualifier |
| **False Alarm** | Flagged | No cross-thread writes | Safe to suppress |

### CLI

```sh
rtmap-lint <binary> --struct <name>           # single struct analysis
rtmap-lint <binary> --all                     # all structs with warnings
rtmap-lint <binary> --list                    # list available struct types
rtmap-lint <binary> --struct <name> --json    # JSON output for CI/CD
rtmap-lint <old> <new> --struct <name> --diff # field migration diff
rtmap-lint <binary> --struct <name> --heatmap heat.tsv  # divergence report
rtmap-lint <binary> --struct <name> --annotations ann.txt --cacheline 64
```

Exit code 1 if any warnings are emitted (CI/CD gatekeeper).

## Startup sequence

Full startup when the user runs `rtmap <target>`:

1. Parse CLI: subcommand routing (`setup`, `init`, `record`, `replay`,
   `attach`, or default `run`). Legacy flags (`--once`, `--record`,
   `--replay`, `--consumer-only`) accepted via compat shims.
   `parse_common_flags` builds a `RunConfig` struct carrying `once`
   (default true; `--live` sets false), `no_bb`, `tripwire_symbol`,
   `server_mode`, `min_events`, `record_path`, `topo_path`, `heatmap_path`,
   `coverage_path`.
2. Load configuration: `resolve_config()` merges global config
   (`~/.config/rtmap/config`) with project config (`.rtmap` found by
   walking cwd upward). `resolve_target_profile` matches the target
   binary name to a `TargetProfile` and applies tripwire, args, topology,
   heatmap, coverage, no_bb settings (CLI flags take precedence).
3. If `replay`: spawn replay thread, call `run_replay(no_bb)`. No tracer.
4. If `attach`: spawn consumer thread, attach to existing tracer.
5. Otherwise (launch mode):
   a. Locate `drrun` (via config `paths.dynamorio_home`, `DYNAMORIO_HOME`,
      `RTMAP_DRRUN`, `--dr-home`, or glob auto-detect).
   b. Locate `librtmap_tracer.so` (via `RTMAP_TRACER` or relative to binary).
   c. Resolve tripwire symbol to ELF offset via `resolve_elf_symbol_offset`.
   d. Clean up stale `/dev/shm/rtmap_*` from previous runs.
   e. Install signal handlers (SIGINT, SIGTERM) to forward to the tracer.
   f. Spawn: `drrun -c librtmap_tracer.so [tripwire_offset_hex] -- <target> [args]`.
6. Parse DWARF from the target ELF binary (globals, functions, locals, types,
   type_registry). ELF symtab fallback for `DW_AT_specification` globals.
7. Poll for `/rtmap_ctl` (up to 30 seconds, validating magic + proto).
8. Discover the first thread ring and attach (validating magic + proto).
9. Spawn the consumer on a 64 MB stack thread (deep DWARF resolution).
10. Consumer enters the main event loop (TUI or headless).
11. Warm-scan: initial seed at 100K events; periodic re-seed every 200K events
    (event-count based). Calls `ensure_type` on globals, reads `/proc/<pid>/mem`.
12. If `--record`: `EventRecorder` writes events (compound REG_SNAPSHOT).
13. If `--topology`: `TopologyStream` writes JSONL.
14. On exit: finalize recorder/topology/heatmap, send SIGTERM to tracer, reap
    child, unmap all rings.
