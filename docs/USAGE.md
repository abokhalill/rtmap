# Usage

Full flag reference and invocation examples for all rtmap binaries.

## First-time setup

```sh
rtmap setup
```

Auto-detects DynamoRIO, locates `drrun` and `librtmap_tracer.so`, and
writes `~/.config/rtmap/config`. Run once after installation.

## Project profiles

```sh
rtmap init /path/to/my_server
```

Creates a `.rtmap` file in the current directory with auto-detected settings
for the target binary. Auto-detects the tripwire symbol (event-loop function)
for servers, and enables topology + heatmap export by default.

The `.rtmap` file is a flat key-value config:

```ini
target.nginx.tripwire = ngx_epoll_process_events
target.nginx.topology = nginx.topo.jsonl
target.nginx.heatmap = nginx.heatmap.tsv
# target.nginx.args = -p /tmp/nginx-install -c nginx.conf
# target.nginx.no_bb = false
```

Resolution order: **CLI flags > `.rtmap` project > `~/.config/rtmap/config` > auto-detect**.

## rtmap

### Instrument and run

```sh
# headless (default): print snapshot to stdout, exit on idle
rtmap ./my_program [-- target_args...]

# interactive TUI (20 Hz refresh, time-travel, 3 focusable panels)
rtmap ./my_program --live

# server mode: defer tracing until event loop starts, auto-exit after traffic
rtmap --tripwire aeProcessEvents ./redis-server -- --port 6399

# with project profile (reads .rtmap, no flags needed)
rtmap ./my_server

# override profile args on CLI
rtmap ./my_server -- --port 7399

# record events for offline analysis
rtmap record -o trace.bin ./my_program

# export topology, heatmap, and BB coverage
rtmap ./my_program --topology topo.jsonl --heatmap heat.tsv --coverage cov.tsv

# skip BB_ENTRY events (reduces ring volume, no topology impact)
rtmap ./my_program --no-bb
```

### Replay

```sh
rtmap replay trace.bin --dwarf ./my_program
rtmap replay trace.bin --no-bb
```

### Attach to running tracer

```sh
rtmap attach --dwarf ./my_program
rtmap attach --live
```

### Flags

| Flag | Description |
|---|---|
| `--tripwire <sym>` | Defer tracing until `<sym>` is entered; implies server mode |
| `--live` | Interactive TUI instead of headless |
| `--topology <file>` | Export topology graph as JSONL |
| `--heatmap <file>` | Export field write heatmap as TSV |
| `--coverage <file>` | Export basic-block coverage map as TSV |
| `--record <file>` | Record events to `.bin` file |
| `--no-bb` | Skip BB_ENTRY events (reduces volume) |
| `--min-events <N>` | Minimum events before snapshot (default: 1) |
| `--dwarf <elf>` | Explicit DWARF source |
| `--dr-home <path>` | Explicit DynamoRIO installation (overrides config/env) |
| `-o, --output <file>` | Output file (for record) |

### Server mode idle timeout

When `--tripwire` is set (or resolved from `.rtmap`), the engine enters
server mode. The idle timeout is armed only after the tracer confirms the
tripwire has fired (via an atomic `tripwire_hit` flag in the shared ctl
header). This prevents premature exit during DynamoRIO's JIT compilation
phase.

| Mode | Idle timeout | Armed when |
|---|---|---|
| Normal | 50 rounds (~5s) | Any events received (`total > 0`) |
| Server | 200 rounds (~20s) | `ctl.tripwire_hit == 1` or STM has projections |

Tracer death always triggers immediate exit regardless of arming state.

## rtmap-diff

Offline differential topology comparison of two recorded traces.

```sh
rtmap-diff --baseline a.bin --subject b.bin --dwarf ./my_program \
    --interval 500000 --output diff.jsonl

# --dwarf is optional; without it, diff compares alloc/hazard topology only
rtmap-diff --baseline a.bin --subject b.bin --interval 50000
```

## rtmap-check

CI/CD structural assertion engine over JSONL topology files.

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
| `NoUseAfterFree` | `assert no_use_after_free` | No STAMP or LINK targets a freed address (compares against FREE seq) |
| `MonotonicSeq` | `assert monotonic_seq` | ALLOC, STAMP, and LINK sequences are each monotonically increasing |
| `StampBeforeLink` | `assert stamp_before_link` | Every LINK target was stamped before the link event |

Example `.assertions` file:

```
# Ensure no heap hazards detected
assert no_hazards

# All heap accesses must be preceded by allocation
assert alloc_before_stamp

# No use-after-free violations
assert no_use_after_free

# Node chain length bounded
assert max_chain(type("node"), "next") < 100

# Global variable type stability
assert type_stable(global("head"), "node*")

# No false sharing between hot counters
assert no_false_sharing("counter_a", "counter_b")
```

## rtmap-lint

Static cacheline false-sharing detector.

```sh
# analyze a single struct
rtmap-lint ./my_program --struct my_struct

# all structs with warnings
rtmap-lint ./my_program --all

# list available struct types
rtmap-lint ./my_program --list

# field migration diff between two builds
rtmap-lint ./old_binary ./new_binary --struct my_struct --diff

# divergence report: overlay lint predictions with runtime heatmap
rtmap-lint ./my_program --struct my_struct --heatmap heat.tsv

# annotation-based analysis
rtmap-lint ./my_program --struct my_struct --annotations ann.txt --cacheline 64

# JSON output for CI/CD
rtmap-lint ./my_program --struct my_struct --json
```

Exit code 1 if any warnings are emitted.

## Environment variables

| Variable | Purpose |
|---|---|
| `DYNAMORIO_HOME` | DynamoRIO installation directory |
| `RTMAP_DRRUN` | Explicit path to `drrun` binary |
| `RTMAP_TRACER` | Explicit path to `librtmap_tracer.so` |

## TUI keybindings

| Key | Action |
|---|---|
| `q` / `Ctrl+C` | Quit |
| `Tab` | Cycle focus: Memory → Events → Registers |
| `Space` | Pause / resume event consumption |
| `↑↓` / `jk` | Scroll focused panel |
| `PgUp` / `PgDn` | Page scroll |
| `Home` | Scroll to top |
| `←→` / `hl` | Time-travel scrub through snapshot history |
| `End` | Jump to live (exit time-travel) |
| `w` | Toggle writes-only filter (Events panel) |
| `r` | Toggle hide-reads filter (Events panel) |
| `0-9` | Filter by thread ID (Events panel) |
| `x` | Clear all event filters |

## Docker

```sh
DOCKER_BUILDKIT=1 docker build -t rtmap .
docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v /path/to/my_program:/app/my_program \
    rtmap /app/my_program
```

`--cap-add=SYS_PTRACE` and `--security-opt seccomp=unconfined` are required
for DynamoRIO's process injection inside the container.
