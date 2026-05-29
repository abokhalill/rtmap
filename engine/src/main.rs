// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering as AtomicOrdering};
use std::{env, thread, time};

use rtmap::dwarf::{self, DwarfInfo};
use rtmap::heap_graph::{HeapGraph, HeapOracle};
use rtmap::index::{AddressIndex, FrameId, NodeId};
use rtmap::proc_maps::{self, SharedRegion};
use rtmap::reconciler::{self, EVENT_BB_ENTRY, EVENT_CALL, EVENT_PROCESS_FORK, EVENT_REG_SNAPSHOT};
use rtmap::record::{EventPlayer, EventRecorder};
use rtmap::ring::{Event, RingOrchestrator};
use rtmap::shadow_regs::ShadowRegisterFile;
use rtmap::topology::TopologyStream;
use rtmap::tui::{self, AppState, JournalEntry};
use rtmap::world::{ShadowStack, SnapshotRing, WorldState};

struct RunConfig {
    once: bool,
    server_mode: bool,
    record_path: Option<String>,
    topo_path: Option<String>,
    heatmap_path: Option<String>,
    coverage_path: Option<String>,
    no_bb: bool,
    tripwire_symbol: Option<String>,
    alloc_fns: Vec<(String, u32)>,
}

#[inline(always)]
fn seq_domain(ev_kind: u8) -> u8 {
    match ev_kind {
        0 | 11 => 0, // WRITE, BB_ENTRY -> JIT raw-TLS seq domain
        _ => 1,       // READ, CALL, RET, ALLOC, FREE, REG_SNAPSHOT, etc. -> clean-call drmgr seq domain
    }
}

struct SharedIntervalMap {
    /// sorted by start address; non-overlapping after merge
    intervals: Vec<(u64, u64, usize)>,
}

impl SharedIntervalMap {
    fn new() -> Self {
        Self { intervals: Vec::new() }
    }

    fn rebuild(&mut self, regions: &[SharedRegion]) {
        self.intervals.clear();
        for (ri, r) in regions.iter().enumerate() {
            for &(_pid, start, end) in &r.mappings {
                self.intervals.push((start, end, ri));
            }
        }
        self.intervals.sort_unstable_by_key(|&(s, _, _)| s);
    }

    #[inline]
    fn lookup(&self, addr: u64) -> Option<usize> {
        let idx = self.intervals.partition_point(|&(s, _, _)| s <= addr);
        if idx == 0 {
            return None;
        }
        let (start, end, ri) = self.intervals[idx - 1];
        if addr >= start && addr < end {
            Some(ri)
        } else {
            None
        }
    }
}

/// tracks child processes discovered via PROCESS_FORK events
struct ChildProcessTracker {
    pending_pids: Vec<u32>,
    pending_since: Vec<std::time::Instant>,
    child_orchs: Vec<RingOrchestrator>,
    child_empty_ticks: Vec<u32>,
    shared_regions: Vec<SharedRegion>,
    shared_interval_map: SharedIntervalMap,
    shared_regions_stale: bool,
    root_pid: Option<u32>,
}

const PENDING_PID_TTL_SECS: u64 = 30;
const CHILD_EMPTY_TICK_RETIRE: u32 = 150; // ~30s at 200ms ticks

impl ChildProcessTracker {
    fn new() -> Self {
        Self {
            pending_pids: Vec::new(),
            pending_since: Vec::new(),
            child_orchs: Vec::new(),
            child_empty_ticks: Vec::new(),
            shared_regions: Vec::new(),
            shared_interval_map: SharedIntervalMap::new(),
            shared_regions_stale: false,
            root_pid: None,
        }
    }

    fn set_root_pid(&mut self, pid: u32) {
        self.root_pid = Some(pid);
    }

    fn register_fork(&mut self, child_pid: u32) {
        if !self.pending_pids.contains(&child_pid) {
            self.pending_pids.push(child_pid);
            self.pending_since.push(std::time::Instant::now());
            self.shared_regions_stale = true;
        }
    }

    fn discover(&mut self) {
        let had_pending = !self.pending_pids.is_empty();
        let now = std::time::Instant::now();
        let ttl = std::time::Duration::from_secs(PENDING_PID_TTL_SECS);
        // expire stale pending PIDs (TIER 3.1)
        let mut i = 0;
        while i < self.pending_pids.len() {
            if now.duration_since(self.pending_since[i]) > ttl {
                eprintln!(
                    "rtmap: pending child pid {} expired after {}s (ctl never appeared)",
                    self.pending_pids[i], PENDING_PID_TTL_SECS
                );
                self.pending_pids.swap_remove(i);
                self.pending_since.swap_remove(i);
            } else {
                i += 1;
            }
        }
        // try to attach remaining pending PIDs
        let mut attached_new = false;
        let mut j = 0;
        while j < self.pending_pids.len() {
            let pid = self.pending_pids[j];
            let mut orch = RingOrchestrator::new();
            if orch.try_attach_ctl_pid(pid) {
                eprintln!("rtmap: child process {} ctl attached", pid);
                self.child_orchs.push(orch);
                self.child_empty_ticks.push(0);
                self.pending_pids.swap_remove(j);
                self.pending_since.swap_remove(j);
                attached_new = true;
            } else {
                j += 1;
            }
        }
        // retire dead child orchestrators (TIER 3.2)
        let mut k = 0;
        while k < self.child_orchs.len() {
            let pid_gone = self.child_orchs[k]
                .target_pid()
                .map(|p| !std::path::Path::new(&format!("/proc/{}", p)).exists())
                .unwrap_or(false);
            if pid_gone && self.child_empty_ticks[k] >= CHILD_EMPTY_TICK_RETIRE {
                let pid = self.child_orchs[k].target_pid().unwrap_or(0);
                eprintln!(
                    "rtmap: retiring dead child orchestrator pid={} after {} empty ticks",
                    pid, self.child_empty_ticks[k]
                );
                self.child_orchs.swap_remove(k);
                self.child_empty_ticks.swap_remove(k);
                self.shared_regions_stale = true;
            } else {
                k += 1;
            }
        }
        for co in &mut self.child_orchs {
            co.poll_new_rings();
        }
        // refresh shared regions after new child attached or child retired
        if (had_pending || attached_new) && self.shared_regions_stale {
            self.refresh_shared_regions();
        }
    }

    fn refresh_shared_regions(&mut self) {
        let mut all_pids: Vec<u32> = Vec::new();
        if let Some(root) = self.root_pid {
            all_pids.push(root);
        }
        for co in &self.child_orchs {
            if let Some(pid) = co.target_pid() {
                all_pids.push(pid);
            }
        }
        if all_pids.len() < 2 {
            self.shared_regions.clear();
            self.shared_interval_map.rebuild(&[]);
            self.shared_regions_stale = false;
            return;
        }
        match proc_maps::detect_shared_regions(&all_pids) {
            Ok(regions) => {
                if !regions.is_empty() {
                    eprintln!(
                        "rtmap: detected {} shared regions across {} processes",
                        regions.len(),
                        all_pids.len()
                    );
                    for r in &regions {
                        eprintln!(
                            "rtmap:   inode={} path='{}' mappings={}",
                            r.dev_inode.inode,
                            r.path,
                            r.mappings.len()
                        );
                    }
                }
                self.shared_interval_map.rebuild(&regions);
                self.shared_regions = regions;
            }
            Err(e) => {
                eprintln!("rtmap: shared region detection failed: {}", e);
            }
        }
        self.shared_regions_stale = false;
    }

    /// O(log N) check if addr falls in a shared region; returns the region path if so
    #[inline]
    fn is_shared_addr(&self, addr: u64) -> Option<&str> {
        self.shared_interval_map
            .lookup(addr)
            .map(|ri| self.shared_regions[ri].path.as_str())
    }

    fn batch_drain(&mut self, limit: usize, buf: &mut Vec<(usize, Event)>) -> usize {
        let mut total = 0;
        for (ci, co) in self.child_orchs.iter_mut().enumerate() {
            if total >= limit {
                break;
            }
            let got = co.batch_drain(limit - total, buf);
            if got == 0 {
                if ci < self.child_empty_ticks.len() {
                    self.child_empty_ticks[ci] = self.child_empty_ticks[ci].saturating_add(1);
                }
            } else if ci < self.child_empty_ticks.len() {
                self.child_empty_ticks[ci] = 0;
            }
            total += got;
        }
        total
    }

    fn update_backpressure(&mut self) {
        for co in &mut self.child_orchs {
            co.update_backpressure();
        }
    }

    fn child_count(&self) -> usize {
        self.child_orchs.len()
    }
}

fn run(mut orch: RingOrchestrator, mut dwarf_info: Option<DwarfInfo>, cfg: RunConfig) {
    let once = cfg.once;
    let server_mode = cfg.server_mode;
    let no_bb = cfg.no_bb;
    let record_path = cfg.record_path;
    let topo_path = cfg.topo_path;
    let heatmap_path = cfg.heatmap_path;
    let coverage_path = cfg.coverage_path;
    let mut addr_index = AddressIndex::new();
    let mut world = WorldState::new();
    let mut stacks: HashMap<u16, ShadowStack> = HashMap::new();
    let mut next_frame_id: FrameId = 1;
    let mut total: u64 = 0;
    let mut journal: VecDeque<JournalEntry> = VecDeque::with_capacity(1024);
    let mut relocation_delta: Option<u64> = None;
    let mut returned_frames: VecDeque<FrameId> = VecDeque::with_capacity(64);
    // seq gap tracking: two domains per thread; JIT (WRITE/READ/BB_ENTRY)
    // and clean-call (CALL/RET/ALLOC/FREE/REG_SNAPSHOT/etc.) use separate
    // monotonic seq counters in the tracer (raw TLS vs drmgr TLS).
    let mut expected_seq: HashMap<(u16, u8), u32> = HashMap::new();
    let mut seq_gaps: u64 = 0;
    let mut shadow_regs: HashMap<u16, ShadowRegisterFile> = HashMap::new();
    let mut heap_graph = HeapGraph::new();
    let mut heap_oracle = HeapOracle::new();
    let mut lib_globals_done = false;

    if let Some(ref info) = dwarf_info {
        reconciler::populate_globals(info, 0, &mut addr_index, &mut world);
        heap_graph.init_candidates(info);
    }

    let mut recorder: Option<EventRecorder> =
        record_path
            .as_ref()
            .and_then(|p| match EventRecorder::create(std::path::Path::new(p)) {
                Ok(r) => {
                    eprintln!("rtmap: recording to {}", p);
                    Some(r)
                }
                Err(e) => {
                    eprintln!("rtmap: failed to create recording: {}", e);
                    None
                }
            });

    let mut topo: Option<TopologyStream> =
        topo_path
            .as_ref()
            .and_then(|p| match TopologyStream::create(std::path::Path::new(p)) {
                Ok(t) => {
                    eprintln!("rtmap: topology stream → {}", p);
                    Some(t)
                }
                Err(e) => {
                    eprintln!("rtmap: failed to create topology stream: {}", e);
                    None
                }
            });

    if once {
        run_headless(
            &mut orch,
            &mut dwarf_info,
            server_mode,
            &mut addr_index,
            &mut world,
            &mut stacks,
            &mut next_frame_id,
            &mut total,
            &mut journal,
            &mut relocation_delta,
            &mut returned_frames,
            &mut shadow_regs,
            &mut heap_graph,
            &mut heap_oracle,
            &mut recorder,
            &mut topo,
            no_bb,
        );
        eprintln!("rtmap: indirect registrations={} stamps={} map_size={}",
            world.stm.indirect_registrations, world.stm.indirect_stamps, world.stm.indirect_len());
        if let Some(ref mut ts) = topo {
            ts.emit_summary(
                total,
                world.node_count(),
                world.edge_count(),
                world.stm.len(),
                world.heap_allocs.live_count(),
                world.hazards.len(),
            );
        }
        if let Some(rec) = recorder {
            match rec.finish() {
                Ok(n) => eprintln!("rtmap: recorded {} events", n),
                Err(e) => eprintln!("rtmap: recording finalize error: {}", e),
            }
        }
        if let Some(ts) = topo {
            match ts.finish() {
                Ok(n) => eprintln!("rtmap: topology: {} lines", n),
                Err(e) => eprintln!("rtmap: topology finalize error: {}", e),
            }
        }
        if let Some(ref hp) = heatmap_path {
            match world.field_heatmap.export_tsv(std::path::Path::new(hp)) {
                Ok(()) => eprintln!("rtmap: heatmap exported to {}", hp),
                Err(e) => eprintln!("rtmap: heatmap export error: {}", e),
            }
        }
        if let Some(ref cp) = coverage_path {
            export_bb_coverage(std::path::Path::new(cp), &world.bb_hits);
        }
        return;
    }

    let mut terminal = match tui::init_terminal() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("rtmap: failed to init terminal: {}", e);
            return;
        }
    };
    let mut app = AppState::new();
    let mut snap_ring = SnapshotRing::new(512);
    let mut tick: u64 = 0;
    let refresh = time::Duration::from_millis(50);
    let mut last_render = time::Instant::now();
    let mut last_discovery = time::Instant::now();
    let mut batch_buf: Vec<(usize, rtmap::ring::Event)> = Vec::with_capacity(128_000);
    let mut warm_scanner: Option<reconciler::WarmScanner> = None;
    let mut last_reseed_total: u64 = 0;
    let mut child_tracker = ChildProcessTracker::new();

    loop {
        tui::handle_input(&mut app);
        if app.quit {
            break;
        }

        let now_disc = time::Instant::now();
        if now_disc.duration_since(last_discovery) >= time::Duration::from_millis(200) {
            orch.poll_new_rings();
            if child_tracker.root_pid.is_none() {
                if let Some(pid) = orch.target_pid() {
                    child_tracker.set_root_pid(pid);
                }
            }
            if world.proc_mem.is_none() {
                if let Some(pid) = orch.target_pid() {
                    if let Ok(f) = std::fs::File::open(format!("/proc/{}/mem", pid)) {
                        world.proc_mem = Some(f);
                    }
                }
            }
            child_tracker.discover();
            last_discovery = now_disc;
        }

        if !app.paused {
            let mut need_finalize = false;
            let mut tick_events = 0usize;
            const TICK_BUDGET: usize = 200_000;
            while tick_events < TICK_BUDGET {
                batch_buf.clear();
                let got = orch.batch_drain(4096, &mut batch_buf);
                if got == 0 {
                    break;
                }
                tick_events += got;

                let mut i = 0;
                while i < batch_buf.len() {
                    let (ri, ev) = batch_buf[i];
                    let ev_kind = ev.kind();

                    if no_bb && ev_kind == EVENT_BB_ENTRY {
                        i += 1;
                        continue;
                    }

                    if ev_kind == EVENT_REG_SNAPSHOT {
                        let slice_end = (i + 7).min(batch_buf.len());
                        let mut events7: [rtmap::ring::Event; 7] =
                            [rtmap::ring::Event::zero(); 7];
                        let take = slice_end - i;
                        for s in 0..take {
                            events7[s] = batch_buf[i + s].1;
                        }
                        let consumed = reconciler::apply_reg_snapshot(
                            &events7[..take],
                            &mut world,
                            &mut shadow_regs,
                        )
                        .max(1);
                        if let Some(ref mut rec) = recorder {
                            let _ = rec.record_reg_snapshot(&ev, &world.regs());
                        }
                        // tracer assigns 1 seq per REG_SNAPSHOT compound, not per slot
                        if !ev.is_continuation() {
                            let dom = seq_domain(ev_kind);
                            let s32 = ev.seq32();
                            let exp = expected_seq.entry((ev.thread_id, dom)).or_insert(s32);
                            if s32 != *exp {
                                let gap_size = s32.wrapping_sub(*exp);
                                seq_gaps += 1;
                                if seq_gaps <= 10 || seq_gaps.is_power_of_two() {
                                    eprintln!(
                                        "rtmap: SEQ_GAP #{} tid={} expected={} got={} (dropped ~{} events)",
                                        seq_gaps, ev.thread_id, *exp, s32, gap_size
                                    );
                                }
                                if let Some(ref mut ts) = topo {
                                    ts.emit_seq_gap(total, ev.thread_id, *exp, s32);
                                }
                            }
                            *exp = s32.wrapping_add(1);
                        }
                        total += consumed as u64;
                        world.inc_insn_counter();
                        i += consumed;
                        continue;
                    }

                    total += 1;
                    world.inc_insn_counter();

                    // continuation events have no meaningful seq; skip tracking
                    if !ev.is_continuation() {
                        let dom = seq_domain(ev_kind);
                        let s32 = ev.seq32();
                        let exp = expected_seq.entry((ev.thread_id, dom)).or_insert(s32);
                        if s32 != *exp {
                            let gap_size = s32.wrapping_sub(*exp);
                            seq_gaps += 1;
                            if seq_gaps <= 10 || seq_gaps.is_power_of_two() {
                                eprintln!(
                                    "rtmap: SEQ_GAP #{} tid={} expected={} got={} (dropped ~{} events)",
                                    seq_gaps, ev.thread_id, *exp, s32, gap_size
                                );
                            }
                            if let Some(ref mut ts) = topo {
                                ts.emit_seq_gap(total, ev.thread_id, *exp, s32);
                            }
                        }
                        *exp = s32.wrapping_add(1);
                    }

                    let interesting = reconciler::process_event(
                        &ev,
                        ri,
                        &orch,
                        &mut world,
                        &mut addr_index,
                        &mut dwarf_info,
                        &mut stacks,
                        &mut next_frame_id,
                        &mut relocation_delta,
                        &mut returned_frames,
                        &mut shadow_regs,
                        &mut heap_graph,
                        &mut heap_oracle,
                        &mut topo,
                    );
                    if ev_kind == EVENT_PROCESS_FORK {
                        child_tracker.register_fork(ev.addr as u32);
                        if let Some(ref mut ts) = topo {
                            ts.emit_process_fork(total, ev.addr as u32, ev.value as u32);
                        }
                    }
                    if ev_kind == reconciler::EVENT_WRITE && child_tracker.child_count() > 0 {
                        if let Some(region) = child_tracker.is_shared_addr(ev.addr) {
                            if let Some(ref mut ts) = topo {
                                ts.emit_cross_process_write(total, ev.thread_id, ev.addr, ev.size, region);
                            }
                        }
                    }
                    if let Some(ref mut rec) = recorder {
                        let _ = rec.record(&ev);
                    }
                    if interesting && !ev.is_continuation() {
                        journal.push_back(JournalEntry {
                            seq: total,
                            kind: ev_kind,
                            thread_id: ev.thread_id,
                            addr: ev.addr,
                            size: ev.size,
                            value: ev.value,
                        });
                        if journal.len() > 1000 {
                            journal.pop_front();
                        }
                    }
                    if ev_kind == EVENT_CALL {
                        need_finalize = true;
                    }
                    i += 1;
                }

                // drain child process events; full reconciler dispatch
                batch_buf.clear();
                let child_got = child_tracker.batch_drain(4096, &mut batch_buf);
                if child_got > 0 {
                    tick_events += child_got;
                    let mut j = 0;
                    while j < batch_buf.len() {
                        let (cri, cev) = batch_buf[j];
                        let ck = cev.kind();
                        if no_bb && ck == EVENT_BB_ENTRY { j += 1; continue; }

                        if ck == EVENT_REG_SNAPSHOT {
                            let cslice_end = (j + 7).min(batch_buf.len());
                            let mut cev7: [rtmap::ring::Event; 7] =
                                [rtmap::ring::Event::zero(); 7];
                            let ctake = cslice_end - j;
                            for s in 0..ctake {
                                cev7[s] = batch_buf[j + s].1;
                            }
                            let cconsumed = reconciler::apply_reg_snapshot(
                                &cev7[..ctake],
                                &mut world,
                                &mut shadow_regs,
                            ).max(1);
                            if let Some(ref mut rec) = recorder {
                                let _ = rec.record_reg_snapshot(&cev, &world.regs());
                            }
                            total += cconsumed as u64;
                            world.inc_insn_counter();
                            j += cconsumed;
                            continue;
                        }

                        total += 1;
                        world.inc_insn_counter();

                        let cinteresting = reconciler::process_event(
                            &cev,
                            cri,
                            &orch,
                            &mut world,
                            &mut addr_index,
                            &mut dwarf_info,
                            &mut stacks,
                            &mut next_frame_id,
                            &mut relocation_delta,
                            &mut returned_frames,
                            &mut shadow_regs,
                            &mut heap_graph,
                            &mut heap_oracle,
                            &mut topo,
                        );
                        if ck == EVENT_PROCESS_FORK {
                            child_tracker.register_fork(cev.addr as u32);
                            if let Some(ref mut ts) = topo {
                                ts.emit_process_fork(total, cev.addr as u32, cev.value as u32);
                            }
                        }
                        if ck == reconciler::EVENT_WRITE && child_tracker.child_count() > 0 {
                            if let Some(region) = child_tracker.is_shared_addr(cev.addr) {
                                if let Some(ref mut ts) = topo {
                                    ts.emit_cross_process_write(total, cev.thread_id, cev.addr, cev.size, region);
                                }
                            }
                        }
                        if let Some(ref mut rec) = recorder {
                            let _ = rec.record(&cev);
                        }
                        if cinteresting && !cev.is_continuation() {
                            journal.push_back(JournalEntry {
                                seq: total,
                                kind: ck,
                                thread_id: cev.thread_id,
                                addr: cev.addr,
                                size: cev.size,
                                value: cev.value,
                            });
                            if journal.len() > 1000 {
                                journal.pop_front();
                            }
                        }
                        if ck == EVENT_CALL {
                            need_finalize = true;
                        }
                        j += 1;
                    }
                }
            } // while tick_events < TICK_BUDGET

            if need_finalize {
                addr_index.finalize();
            }
            if total & 0xFFF == 0 {
                world.cache_heat_tick();
                world.cl_tracker_tick();
            }
            if total & 0xFFFF == 0 {
                heap_graph.gc_stale(total, 500_000);
            }
            orch.update_backpressure();
            child_tracker.update_backpressure();

            // deferred: relocate library globals once sidecar is populated
            if !lib_globals_done && relocation_delta.is_some() {
                if let (Some(ref mut info), Some(pid)) = (&mut dwarf_info, orch.target_pid()) {
                    if info.lib_globals.is_empty() {
                        lib_globals_done = true;
                    } else {
                        let (ng, nf) = reconciler::populate_lib_globals(info, pid, &mut addr_index, &mut world);
                        if ng > 0 || nf > 0 {
                            eprintln!("rtmap: {} library globals, {} functions relocated", ng, nf);
                            lib_globals_done = true;
                        }
                    }
                }
            }
            // initial warm scan: after 100K events, globals are initialized
            if lib_globals_done && warm_scanner.is_none() && total > 100_000 {
                if let (Some(ref mut info), Some(pid), Some(delta)) =
                    (&mut dwarf_info, orch.target_pid(), relocation_delta)
                {
                    let scanner = warm_scanner.get_or_insert_with(|| {
                        match reconciler::WarmScanner::new(pid, 12) {
                            Ok(s) => s,
                            Err(e) => {
                                eprintln!("rtmap: warm-scan init failed: {}", e);
                                std::process::exit(1);
                            }
                        }
                    });
                    scanner.seed(info, delta, &heap_oracle, &mut topo, &mut world.stm, &world.heap_allocs);
                    let _ = scanner.step(2000, info, &mut world, &heap_oracle, &mut topo);
                    eprintln!(
                        "rtmap: warm-scan seed: {} stamps, {} reads, {} queued",
                        scanner.stats.stamps_applied, scanner.stats.reads, scanner.stats.enqueued
                    );
                    if scanner.stats.queue_cap_hits > 0 {
                        eprintln!(
                            "rtmap: warm-scan WARNING: {} BFS nodes dropped (queue cap {})",
                            scanner.stats.queue_cap_hits, reconciler::WARM_SCAN_QUEUE_CAP
                        );
                    }
                    last_reseed_total = total;
                }
            }

            // re-seed every 200K events; globals may be lazily initialized
            if warm_scanner.is_some()
                && relocation_delta.is_some()
                && total >= last_reseed_total + 200_000
            {
                last_reseed_total = total;
                if let (Some(ref mut info), Some(_pid), Some(delta)) =
                    (&mut dwarf_info, orch.target_pid(), relocation_delta)
                {
                    let scanner = warm_scanner.as_mut().unwrap();
                    let prev_stamps = scanner.stats.stamps_applied;
                    scanner.seed(info, delta, &heap_oracle, &mut topo, &mut world.stm, &world.heap_allocs);
                    let _ = scanner.step(2000, info, &mut world, &heap_oracle, &mut topo);
                    let new_stamps = scanner.stats.stamps_applied - prev_stamps;
                    if new_stamps > 0 {
                        eprintln!(
                            "rtmap: warm-scan reseed @{}: +{} stamps, {} reads, {} dropped",
                            total, new_stamps, scanner.stats.reads, scanner.stats.queue_cap_hits,
                        );
                    }
                }
            }
        }

        let now = time::Instant::now();
        if now.duration_since(last_render) >= refresh {
            let live_snap = world.snapshot();
            tick += 1;
            snap_ring.push(live_snap.clone(), tick, total);

            let display_snap = match app.time_travel_idx {
                Some(idx) => snap_ring
                    .get(idx)
                    .map(|sr| sr.snap.clone())
                    .unwrap_or(live_snap),
                None => live_snap,
            };

            let (fill_used, fill_pct) = orch.total_fill();
            let snap_total = snap_ring.len();
            tui::draw(
                &mut terminal,
                &display_snap,
                &world.cl_tracker,
                &world.stm,
                &journal,
                total,
                orch.ring_count(),
                fill_used,
                fill_pct,
                &mut app,
                snap_total,
                &stacks,
                seq_gaps,
                &shadow_regs,
                &heap_graph,
            );
            last_render = now;
        }

        if !app.paused {
            thread::sleep(time::Duration::from_millis(5));
        } else {
            thread::sleep(time::Duration::from_millis(20));
        }
    }

    if let Some(ref mut ts) = topo {
        ts.emit_summary(
            total,
            world.node_count(),
            world.edge_count(),
            world.stm.len(),
            world.heap_allocs.live_count(),
            world.hazards.len(),
        );
    }
    if let Some(rec) = recorder {
        match rec.finish() {
            Ok(n) => eprintln!("rtmap: recorded {} events", n),
            Err(e) => eprintln!("rtmap: recording finalize error: {}", e),
        }
    }
    if let Some(ts) = topo {
        match ts.finish() {
            Ok(n) => eprintln!("rtmap: topology: {} lines", n),
            Err(e) => eprintln!("rtmap: topology finalize error: {}", e),
        }
    }
    tui::restore_terminal(&mut terminal);
}

#[allow(clippy::too_many_arguments)]
fn run_headless(
    orch: &mut RingOrchestrator,
    dwarf_info: &mut Option<DwarfInfo>,
    server_mode: bool,
    addr_index: &mut AddressIndex,
    world: &mut WorldState,
    stacks: &mut HashMap<u16, ShadowStack>,
    next_frame_id: &mut FrameId,
    total: &mut u64,
    journal: &mut VecDeque<JournalEntry>,
    relocation_delta: &mut Option<u64>,
    returned_frames: &mut VecDeque<FrameId>,
    shadow_regs: &mut HashMap<u16, ShadowRegisterFile>,
    heap_graph: &mut HeapGraph,
    heap_oracle: &mut HeapOracle,
    recorder: &mut Option<EventRecorder>,
    recorder_topo: &mut Option<TopologyStream>,
    no_bb: bool,
) {
    use std::io::Write;
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let mut last_discovery = time::Instant::now();
    let mut batch_buf: Vec<(usize, rtmap::ring::Event)> = Vec::with_capacity(128_000);
    let mut idle_rounds: u32 = 0;
    let mut warm_scanner: Option<reconciler::WarmScanner> = None;
    let mut last_reseed_total: u64 = 0;
    let mut child_tracker = ChildProcessTracker::new();
    // two seq domains per thread (see seq_domain())
    let mut expected_seq: HashMap<(u16, u8), u32> = HashMap::new();
    let mut seq_gaps: u64 = 0;
    let mut lib_globals_done = false;

    loop {
        let now_disc = time::Instant::now();
        if now_disc.duration_since(last_discovery) >= time::Duration::from_millis(200) {
            orch.poll_new_rings();
            if child_tracker.root_pid.is_none() {
                if let Some(pid) = orch.target_pid() {
                    child_tracker.set_root_pid(pid);
                }
            }
            if world.proc_mem.is_none() {
                if let Some(pid) = orch.target_pid() {
                    if let Ok(f) = std::fs::File::open(format!("/proc/{}/mem", pid)) {
                        world.proc_mem = Some(f);
                    }
                }
            }
            child_tracker.discover();
            last_discovery = now_disc;
        }

        let mut need_finalize = false;
        let mut drained = 0usize;
        let mut tick_events = 0usize;
        const HEADLESS_BUDGET: usize = 500_000;
        while tick_events < HEADLESS_BUDGET {
            batch_buf.clear();
            let got = orch.batch_drain(4096, &mut batch_buf);
            if got == 0 {
                break;
            }
            tick_events += got;
            drained += got;

            let mut i = 0;
            while i < batch_buf.len() {
                let (ri, ev) = batch_buf[i];
                let ev_kind = ev.kind();

                if no_bb && ev_kind == EVENT_BB_ENTRY {
                    i += 1;
                    continue;
                }

                if ev_kind == EVENT_REG_SNAPSHOT {
                    let slice_end = (i + 7).min(batch_buf.len());
                    let mut events7: [rtmap::ring::Event; 7] = [rtmap::ring::Event::zero(); 7];
                    let take = slice_end - i;
                    for s in 0..take {
                        events7[s] = batch_buf[i + s].1;
                    }
                    let consumed =
                        reconciler::apply_reg_snapshot(&events7[..take], world, shadow_regs).max(1);
                    if let Some(ref mut rec) = recorder {
                        let _ = rec.record_reg_snapshot(&ev, &world.regs());
                    }
                    // tracer assigns 1 seq per REG_SNAPSHOT compound, not per slot
                    if !ev.is_continuation() {
                        let dom = seq_domain(ev_kind);
                        let s32 = ev.seq32();
                        let exp = expected_seq.entry((ev.thread_id, dom)).or_insert(s32);
                        if s32 != *exp {
                            let gap_size = s32.wrapping_sub(*exp);
                            seq_gaps += 1;
                            if seq_gaps <= 10 || seq_gaps.is_power_of_two() {
                                eprintln!(
                                    "rtmap: SEQ_GAP #{} tid={} expected={} got={} (dropped ~{} events)",
                                    seq_gaps, ev.thread_id, *exp, s32, gap_size
                                );
                            }
                            if let Some(ref mut ts) = recorder_topo {
                                ts.emit_seq_gap(*total, ev.thread_id, *exp, s32);
                            }
                        }
                        *exp = s32.wrapping_add(1);
                    }
                    *total += consumed as u64;
                    world.inc_insn_counter();
                    i += consumed;
                    continue;
                }

                *total += 1;
                world.inc_insn_counter();

                if !ev.is_continuation() {
                    let dom = seq_domain(ev_kind);
                    let s32 = ev.seq32();
                    let exp = expected_seq.entry((ev.thread_id, dom)).or_insert(s32);
                    if s32 != *exp {
                        let gap_size = s32.wrapping_sub(*exp);
                        seq_gaps += 1;
                        if seq_gaps <= 10 || seq_gaps.is_power_of_two() {
                            eprintln!(
                                "rtmap: SEQ_GAP #{} tid={} expected={} got={} (dropped ~{} events)",
                                seq_gaps, ev.thread_id, *exp, s32, gap_size
                            );
                        }
                        if let Some(ref mut ts) = recorder_topo {
                            ts.emit_seq_gap(*total, ev.thread_id, *exp, s32);
                        }
                    }
                    *exp = s32.wrapping_add(1);
                }

                let interesting = reconciler::process_event(
                    &ev,
                    ri,
                    orch,
                    world,
                    addr_index,
                    &mut *dwarf_info,
                    stacks,
                    next_frame_id,
                    relocation_delta,
                    returned_frames,
                    shadow_regs,
                    heap_graph,
                    heap_oracle,
                    recorder_topo,
                );
                if ev_kind == EVENT_PROCESS_FORK {
                    child_tracker.register_fork(ev.addr as u32);
                    if let Some(ref mut ts) = recorder_topo {
                        ts.emit_process_fork(*total, ev.addr as u32, ev.value as u32);
                    }
                }
                if ev_kind == reconciler::EVENT_WRITE && child_tracker.child_count() > 0 {
                    if let Some(region) = child_tracker.is_shared_addr(ev.addr) {
                        if let Some(ref mut ts) = recorder_topo {
                            ts.emit_cross_process_write(*total, ev.thread_id, ev.addr, ev.size, region);
                        }
                    }
                }
                if let Some(ref mut rec) = recorder {
                    let _ = rec.record(&ev);
                }
                if interesting && !ev.is_continuation() {
                    journal.push_back(JournalEntry {
                        seq: *total,
                        kind: ev_kind,
                        thread_id: ev.thread_id,
                        addr: ev.addr,
                        size: ev.size,
                        value: ev.value,
                    });
                    if journal.len() > 1000 {
                        journal.pop_front();
                    }
                }
                if ev_kind == EVENT_CALL {
                    need_finalize = true;
                }
                i += 1;
            }

            // drain child process events; full reconciler dispatch
            batch_buf.clear();
            let child_got = child_tracker.batch_drain(4096, &mut batch_buf);
            if child_got > 0 {
                tick_events += child_got;
                drained += child_got;
                let mut j = 0;
                while j < batch_buf.len() {
                    let (cri, cev) = batch_buf[j];
                    let ck = cev.kind();
                    if no_bb && ck == EVENT_BB_ENTRY { j += 1; continue; }

                    if ck == EVENT_REG_SNAPSHOT {
                        let cslice_end = (j + 7).min(batch_buf.len());
                        let mut cev7: [rtmap::ring::Event; 7] =
                            [rtmap::ring::Event::zero(); 7];
                        let ctake = cslice_end - j;
                        for s in 0..ctake {
                            cev7[s] = batch_buf[j + s].1;
                        }
                        let cconsumed = reconciler::apply_reg_snapshot(
                            &cev7[..ctake],
                            world,
                            shadow_regs,
                        ).max(1);
                        if let Some(ref mut rec) = recorder {
                            let _ = rec.record_reg_snapshot(&cev, &world.regs());
                        }
                        *total += cconsumed as u64;
                        world.inc_insn_counter();
                        j += cconsumed;
                        continue;
                    }

                    *total += 1;
                    world.inc_insn_counter();

                    let cinteresting = reconciler::process_event(
                        &cev,
                        cri,
                        orch,
                        world,
                        addr_index,
                        &mut *dwarf_info,
                        stacks,
                        next_frame_id,
                        relocation_delta,
                        returned_frames,
                        shadow_regs,
                        heap_graph,
                        heap_oracle,
                        recorder_topo,
                    );
                    if ck == EVENT_PROCESS_FORK {
                        child_tracker.register_fork(cev.addr as u32);
                        if let Some(ref mut ts) = recorder_topo {
                            ts.emit_process_fork(*total, cev.addr as u32, cev.value as u32);
                        }
                    }
                    if ck == reconciler::EVENT_WRITE && child_tracker.child_count() > 0 {
                        if let Some(region) = child_tracker.is_shared_addr(cev.addr) {
                            if let Some(ref mut ts) = recorder_topo {
                                ts.emit_cross_process_write(*total, cev.thread_id, cev.addr, cev.size, region);
                            }
                        }
                    }
                    if let Some(ref mut rec) = recorder {
                        let _ = rec.record(&cev);
                    }
                    if cinteresting && !cev.is_continuation() {
                        journal.push_back(JournalEntry {
                            seq: *total,
                            kind: ck,
                            thread_id: cev.thread_id,
                            addr: cev.addr,
                            size: cev.size,
                            value: cev.value,
                        });
                        if journal.len() > 1000 {
                            journal.pop_front();
                        }
                    }
                    if ck == EVENT_CALL {
                        need_finalize = true;
                    }
                    j += 1;
                }
            }
        }

        if need_finalize {
            addr_index.finalize();
        }

        if drained == 0 {
            idle_rounds += 1;

            let tracer_gone = TRACER_EXITED.load(AtomicOrdering::Relaxed);

            // We deliberately do NOT arm on world.stm.len() (boot-time warm-scan
            // stamps globals before any query), which previously caused the idle
            // timer to expire during slow DBI startup while the parent sat idle
            // in select(). tracer death always triggers immediate exit.
            let idle_limit = if server_mode { 200 } else { 50 };
            let armed = if server_mode {
                orch.tripwire_hit() || child_tracker.child_count() > 0
            } else {
                *total > 0
            };
            // Don't auto-exit on idle while any child process is
            // still alive; rely on SIGINT or tracer death to terminate. This
            // prevents premature exit during slow DBI startup when the parent
            // sits in select() producing no instrumented writes.
            let children_alive = server_mode && child_tracker.child_count() > 0;
            if tracer_gone || (!children_alive && armed && idle_rounds >= idle_limit) {
                // final ring discovery sweep: catch rings from short-lived
                // threads that spawned and died between poll intervals.
                orch.poll_new_rings();
                let mut final_buf: Vec<(usize, rtmap::ring::Event)> = Vec::with_capacity(4096);
                loop {
                    final_buf.clear();
                    let got = orch.batch_drain(4096, &mut final_buf);
                    if got == 0 {
                        break;
                    }
                    for &(ri, ref ev) in &final_buf {
                        let ev_kind = ev.kind();
                        if no_bb && ev_kind == EVENT_BB_ENTRY {
                            continue;
                        }
                        *total += 1;
                        world.inc_insn_counter();
                        reconciler::process_event(
                            ev,
                            ri,
                            orch,
                            world,
                            addr_index,
                            &mut *dwarf_info,
                            stacks,
                            next_frame_id,
                            relocation_delta,
                            returned_frames,
                            shadow_regs,
                            heap_graph,
                            heap_oracle,
                            recorder_topo,
                        );
                        if let Some(ref mut rec) = recorder {
                            let _ = rec.record(ev);
                        }
                    }
                }
                if seq_gaps > 0 {
                    eprintln!(
                        "rtmap: WARNING: {} sequence gaps detected — ring overflow or event loss occurred",
                        seq_gaps
                    );
                }
                eprintln!(
                    "rtmap: {} events processed, rendering snapshot\n\
                     rtmap: STM projections={} indirect_reg={} indirect_stamps={} schisms={} pool_reuse={} deferred_replays={} deferred_pending={}",
                    total,
                    world.stm.len(),
                    world.stm.indirect_registrations,
                    world.stm.indirect_stamps,
                    world.stm.schism_count,
                    world.stm.pool_reuse_count,
                    world.stm.deferred_replays,
                    world.stm.deferred_pending(),
                );
                let snap = world.snapshot();
                headless_render(
                    &mut out,
                    &snap,
                    &world.cl_tracker,
                    &world.stm,
                    &world.heap_allocs,
                    &world.hazards,
                    &world.field_heatmap,
                    &world.type_stability,
                    &world.type_epochs,
                    journal,
                    *total,
                    orch,
                    heap_graph,
                    &world.bb_hits,
                );
                let _ = out.flush();
                return;
            }

            // zero events and tracer is already gone -> attempt one final sweep
            if *total == 0 && tracer_gone {
                // the tracer may have produced events before exiting;
                // attempt a final poll + drain before declaring failure
                orch.poll_new_rings();
                let mut rescue_buf: Vec<(usize, rtmap::ring::Event)> = Vec::with_capacity(4096);
                loop {
                    rescue_buf.clear();
                    let got = orch.batch_drain(4096, &mut rescue_buf);
                    if got == 0 { break; }
                    for &(ri, ref ev) in &rescue_buf {
                        let ev_kind = ev.kind();
                        if no_bb && ev_kind == EVENT_BB_ENTRY { continue; }
                        *total += 1;
                        world.inc_insn_counter();
                        reconciler::process_event(
                            ev, ri, orch, world, addr_index,
                            &mut *dwarf_info, stacks, next_frame_id,
                            relocation_delta, returned_frames, shadow_regs,
                            heap_graph, heap_oracle, recorder_topo,
                        );
                        if let Some(ref mut rec) = recorder {
                            let _ = rec.record(ev);
                        }
                    }
                }
                if *total > 0 {
                    // rescued events; fall through to the normal exit path
                    idle_rounds = 50;
                    continue;
                }
                let status = TRACER_EXIT_STATUS.load(AtomicOrdering::Relaxed);
                eprintln!("rtmap: error: tracer exited before any events were received.");
                if libc::WIFEXITED(status) {
                    let code = libc::WEXITSTATUS(status);
                    eprintln!("rtmap: tracer exit code: {}", code);
                } else if libc::WIFSIGNALED(status) {
                    let sig = libc::WTERMSIG(status);
                    eprintln!("rtmap: tracer killed by signal: {}", sig);
                }
                eprintln!("rtmap: possible causes:");
                eprintln!("  - target program exited before tracer could instrument it");
                eprintln!(
                    "  - DynamoRIO injection failed (missing --cap-add=SYS_PTRACE in Docker?)"
                );
                eprintln!("  - target binary is not a dynamically-linked ELF executable");
                eprintln!("  - shared memory ring was not created (tracer init failed)");
                std::process::exit(1);
            }

            // zero events but tracer still running; keep waiting, but warn after 5s
            if *total == 0 && idle_rounds == 500 {
                eprintln!("rtmap: warning: 5s elapsed with no events from tracer");
                eprintln!(
                    "rtmap: still waiting... (tracer pid {} is alive)",
                    TRACER_PID.load(AtomicOrdering::Relaxed)
                );
            }

            thread::sleep(time::Duration::from_millis(10));
        } else {
            idle_rounds = 0;
        }

        orch.update_backpressure();
        child_tracker.update_backpressure();

        if !lib_globals_done && relocation_delta.is_some() {
            if let (Some(ref mut info), Some(pid)) = (&mut *dwarf_info, orch.target_pid()) {
                if info.lib_globals.is_empty() {
                    lib_globals_done = true;
                } else {
                    let (ng, nf) = reconciler::populate_lib_globals(info, pid, addr_index, world);
                    if ng > 0 || nf > 0 {
                        eprintln!("rtmap: {} library globals, {} functions relocated", ng, nf);
                        lib_globals_done = true;
                    }
                }
            }
        }
        // initial warm scan: after 100K events, globals are initialized
        if lib_globals_done && warm_scanner.is_none() && *total > 100_000 {
            if let (Some(ref mut info), Some(pid), Some(delta)) =
                (&mut *dwarf_info, orch.target_pid(), *relocation_delta)
            {
                let scanner = warm_scanner.get_or_insert_with(|| {
                    match reconciler::WarmScanner::new(pid, 12) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("rtmap: warm-scan init failed: {}", e);
                            std::process::exit(1);
                        }
                    }
                });
                scanner.seed(info, delta, heap_oracle, recorder_topo, &mut world.stm, &world.heap_allocs);
                let _ = scanner.step(2000, info, world, heap_oracle, recorder_topo);
                eprintln!(
                    "rtmap: warm-scan seed: {} stamps, {} reads, {} queued",
                    scanner.stats.stamps_applied, scanner.stats.reads, scanner.stats.enqueued
                );
                if scanner.stats.queue_cap_hits > 0 {
                    eprintln!(
                        "rtmap: warm-scan WARNING: {} BFS nodes dropped (queue cap {})",
                        scanner.stats.queue_cap_hits, reconciler::WARM_SCAN_QUEUE_CAP
                    );
                }
                last_reseed_total = *total;
            }
        }

        if *total & 0xFFF == 0 {
            world.cache_heat_tick();
            world.cl_tracker_tick();
        }

        // re-seed every 200K events; globals may be lazily initialized
        if warm_scanner.is_some()
            && relocation_delta.is_some()
            && *total >= last_reseed_total + 200_000
        {
            last_reseed_total = *total;
            if let (Some(ref mut info), Some(_pid), Some(delta)) =
                (&mut *dwarf_info, orch.target_pid(), *relocation_delta)
            {
                let scanner = warm_scanner.as_mut().unwrap();
                let prev_stamps = scanner.stats.stamps_applied;
                scanner.seed(info, delta, heap_oracle, recorder_topo, &mut world.stm, &world.heap_allocs);
                let _ = scanner.step(2000, info, world, heap_oracle, recorder_topo);
                let new_stamps = scanner.stats.stamps_applied - prev_stamps;
                if new_stamps > 0 {
                    eprintln!(
                        "rtmap: warm-scan reseed: +{} stamps, {} reads, {} dropped",
                        new_stamps, scanner.stats.reads, scanner.stats.queue_cap_hits,
                    );
                }
            }
        }

        // safety valve: user sent SIGINT/SIGTERM
        if GOT_SIGNAL.load(AtomicOrdering::Relaxed) {
            eprintln!("rtmap: interrupted, {} events processed", total);
            break;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn headless_render(
    out: &mut impl std::io::Write,
    world: &rtmap::world::WorldInner,
    cl_tracker: &rtmap::world::CacheLineTracker,
    stm: &rtmap::world::ShadowTypeMap,
    heap_allocs: &rtmap::world::HeapAllocTracker,
    hazards: &[rtmap::world::HeapHazard],
    field_heatmap: &rtmap::world::FieldHeatmap,
    type_stability: &rtmap::world::TypeStabilityMonitor,
    type_epochs: &rtmap::world::TypeEpochLog,
    journal: &VecDeque<JournalEntry>,
    total: u64,
    orch: &RingOrchestrator,
    heap_graph: &HeapGraph,
    bb_hits: &HashMap<u32, u64>,
) {
    let (lag, _) = orch.total_fill();
    let lag_str = if lag >= 1_000_000 {
        format!("{}M", lag / 1_000_000)
    } else if lag >= 1_000 {
        format!("{}K", lag / 1_000)
    } else {
        format!("{}", lag)
    };
    let _ = writeln!(
        out,
        "RTMAP │ insn {} │ events {} │ nodes {} │ edges {} │ rings {} │ LAG {} │ allocs {}/{} live {}{}",
        world.insn_counter,
        total,
        world.nodes.len(),
        world.edges.len(),
        orch.ring_count(),
        lag_str,
        heap_allocs.total_allocs,
        heap_allocs.total_frees,
        heap_allocs.live_count(),
        if heap_allocs.orphan_frees > 0 {
            format!(" orphan_free={}", heap_allocs.orphan_frees)
        } else {
            String::new()
        },
    );
    let _ = writeln!(out, "{}", "─".repeat(100));
    let _ = writeln!(out, "MEMORY MAP");

    let mut sorted: Vec<_> = world.nodes.iter().filter(|(_, n)| n.size > 0).collect();
    sorted.sort_by_key(|(_, n)| (n.addr, std::cmp::Reverse(n.last_write_insn)));
    sorted.dedup_by(|a, b| {
        matches!(a.0, NodeId::Local(..))
            && matches!(b.0, NodeId::Local(..))
            && a.1.addr == b.1.addr
            && a.1.name == b.1.name
    });

    let mut by_pri: Vec<_> = world.nodes.iter().collect();
    by_pri.sort_by_key(|(nid, _)| match nid {
        NodeId::Field(..) => 0u8,
        NodeId::Global(_) => 1,
        NodeId::Local(..) => 2,
    });
    let mut addr_names: HashMap<u64, String> = HashMap::with_capacity(by_pri.len());
    for (_, n) in &by_pri {
        addr_names.insert(n.addr, n.name.clone());
    }
    let resolve = |val: u64| -> String {
        if val == 0 {
            return String::new();
        }
        match addr_names.get(&val) {
            Some(name) => format!("  → {}", name),
            None => format!("  → 0x{:x}", val),
        }
    };

    let mut last_cl: u64 = u64::MAX;
    for (nid, node) in &sorted {
        if matches!(nid, NodeId::Field(..)) {
            continue;
        }
        let cl = node.addr / 64;
        if cl != last_cl {
            let fs = cl_tracker.contention_score(node.addr);
            let fs_tag = if fs > 1 {
                format!(" FALSE_SHARE T={}", fs)
            } else {
                String::new()
            };
            let _ = writeln!(out, "  ── cacheline 0x{:x} ──{}", cl * 64, fs_tag);
            last_cl = cl;
        }
        let ptr_info = if node.type_info.is_pointer && node.raw_value != 0 {
            resolve(node.raw_value)
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "  {:>12x}  {:>4}B  {:<20} {:<14}  val={:>18x}{}",
            node.addr, node.size, node.name, node.type_info.name, node.raw_value, ptr_info
        );
        if let NodeId::Global(gi) = nid {
            if !node.type_info.is_pointer {
                for (fi, f) in node.type_info.fields.iter().enumerate() {
                    if f.byte_size == 0 || f.name == "<pointee>" {
                        continue;
                    }
                    let fa = node.addr + f.byte_offset;
                    let fid = NodeId::Field(*gi, fi as u16);
                    let fval = world.nodes.get(&fid).map(|n| n.raw_value).unwrap_or(0);
                    let fptr = if f.type_info.is_pointer && fval != 0 {
                        resolve(fval)
                    } else {
                        String::new()
                    };
                    let _ = writeln!(
                        out,
                        "    {:>12x}  {:>4}B  {:<20} {:<14}  val={:>18x}{}",
                        fa, f.byte_size, f.name, f.type_info.name, fval, fptr
                    );
                }
            }
        }
    }

    if !stm.is_empty() {
        let _ = writeln!(
            out,
            "\nHEAP TYPES (Shadow Type Map: {} projections)",
            stm.len()
        );
        let mut stm_sorted: Vec<_> = stm.iter().collect();
        stm_sorted.sort_by_key(|(addr, _)| *addr);
        for (&base, proj) in &stm_sorted {
            let _ = writeln!(
                out,
                "  {:>12x}  {:>4}B  {:<20} (via {})",
                base, proj.type_info.byte_size, proj.type_info.name, proj.source_name
            );
            for f in &proj.type_info.fields {
                if f.byte_size == 0 {
                    continue;
                }
                let fa = base + f.byte_offset;
                let ptr_tag = if f.type_info.is_pointer {
                    if let Some(tgt) = stm.lookup(fa) {
                        format!("  → {} (0x{:x})", tgt.type_info.name, tgt.base_addr)
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                let _ = writeln!(
                    out,
                    "    {:>12x}  {:>4}B  {:<20} {:<14}{}",
                    fa, f.byte_size, f.name, f.type_info.name, ptr_tag
                );
            }
        }
    }

    if !heap_allocs.size_mismatches.is_empty() {
        let _ = writeln!(
            out,
            "\n⚠ HEAP SIZE MISMATCHES ({} detected)",
            heap_allocs.size_mismatches.len()
        );
        for m in &heap_allocs.size_mismatches {
            let _ = writeln!(
                out,
                "  0x{:x}: type {} needs {}B but alloc only {}B",
                m.addr, m.type_name, m.type_size, m.alloc_size
            );
        }
    }

    {
        let objs = heap_graph.objects();
        let typed = objs.values().filter(|o| o.inferred_type.is_some()).count();
        let _ = writeln!(
            out,
            "\nHEAP GRAPH: {} objects, {} typed, {} rescores, {} contradictions",
            objs.len(),
            typed,
            heap_graph.rescores,
            heap_graph.contradictions
        );
        for obj in objs.values().filter(|o| o.inferred_type.is_some()) {
            let _ = writeln!(
                out,
                "  {:>12x}  {:>4}B  {:<30} conf={:.2}  fields={}  writes={}",
                obj.base_addr,
                obj.inferred_size,
                obj.inferred_type.as_deref().unwrap_or("?"),
                obj.type_confidence,
                obj.fields.len(),
                obj.fields
                    .values()
                    .map(|f| f.write_count as u64)
                    .sum::<u64>(),
            );
        }
    }

    if !hazards.is_empty() {
        use rtmap::world::HazardKind;
        let oob = hazards
            .iter()
            .filter(|h| matches!(h.kind, HazardKind::OutOfBounds))
            .count();
        let hole = hazards.len() - oob;
        let _ = writeln!(out, "\n🛑 HEAP HAZARDS ({} OOB, {} heap-hole)", oob, hole);
        for h in hazards {
            match h.kind {
                HazardKind::OutOfBounds => {
                    let sym = match (&h.type_name, &h.field_name) {
                        (Some(t), Some(f)) => format!(" (intended for {}.{})", t, f),
                        (Some(t), None) => format!(" (within {})", t),
                        _ => String::new(),
                    };
                    let _ = writeln!(
                        out,
                        "  OOB  0x{:x} +{}B exceeds alloc [0x{:x}..+{}] by {}B{}",
                        h.write_addr,
                        h.write_size,
                        h.alloc_base,
                        h.alloc_size,
                        h.overflow_bytes,
                        sym
                    );
                }
                HazardKind::HeapHole => {
                    let sym = h
                        .type_name
                        .as_ref()
                        .map(|t| format!(" (stale {} projection)", t))
                        .unwrap_or_default();
                    let _ = writeln!(
                        out,
                        "  HOLE 0x{:x} +{}B not in any live allocation{}",
                        h.write_addr, h.write_size, sym
                    );
                }
            }
        }
    }

    // type stability: per-type tally of field boundary violations
    if !type_stability.is_empty() {
        use rtmap::world::ViolationKind;
        let _ = writeln!(
            out,
            "\n\u{26a0}\u{fe0f}  TYPE STABILITY ({} violations across {} checked writes)",
            type_stability.total_violations,
            type_stability.total_checked,
        );
        let mut tallies: Vec<_> = type_stability.tally_iter().collect();
        tallies.sort_by(|a, b| {
            (b.1.interstitial + b.1.spanning).cmp(&(a.1.interstitial + a.1.spanning))
        });
        for (tn, t) in tallies.iter().take(20) {
            if t.interstitial + t.spanning == 0 {
                continue;
            }
            let _ = writeln!(
                out,
                "  {:<30} aligned={:<8} synthesized={:<6} interstitial={:<8} spanning={}",
                tn, t.aligned, t.synthesized, t.interstitial, t.spanning
            );
        }
        let _ = writeln!(out, "  Top violations (capped at 128):");
        for v in type_stability.violations.iter().take(20) {
            let kind_str = match v.kind {
                ViolationKind::Interstitial => "INTERSTICE",
                ViolationKind::Spanning => "SPANNING  ",
            };
            let field_str = v.expected_field.as_deref().unwrap_or("<none>");
            let _ = writeln!(
                out,
                "    {} 0x{:x} +{}B  {} +0x{:x}  field={}  pc=0x{:x}",
                kind_str, v.write_addr, v.write_size, v.type_name, v.offset, field_str, v.pc
            );
        }
    } else if type_stability.total_checked > 0 {
        let _ = writeln!(
            out,
            "\n\u{2705} TYPE STABILITY: {} writes checked, 0 violations",
            type_stability.total_checked,
        );
    }

    // type epoch summary
    if !type_epochs.is_empty() {
        let _ = writeln!(
            out,
            "\nTYPE EPOCHS ({} closed, {} in log)",
            type_epochs.total_closed,
            type_epochs.len(),
        );
        let summary = type_epochs.summary();
        let mut sorted: Vec<_> = summary.iter().collect();
        sorted.sort_by(|a, b| b.1.count.cmp(&a.1.count));
        for (tn, s) in sorted.iter().take(20) {
            let avg = if s.count > 0 { s.total_lifetime / s.count } else { 0 };
            let _ = writeln!(
                out,
                "  {:<30} epochs={:<6} avg_life={:<8} free={} realloc={} schism={}",
                tn, s.count, avg,
                s.by_reason[0], s.by_reason[1], s.by_reason[2],
            );
        }
    }

    // field heatmap: top writes + contention report
    if !field_heatmap.is_empty() {
        let _ = writeln!(
            out,
            "\n FIELD WRITE HEATMAP ({} distinct entries)",
            field_heatmap.len()
        );
        let _ = writeln!(
            out,
            "  Top 20 hottest fields (thread, type.field, offset, writes):"
        );
        for (key, count) in field_heatmap.top_entries(20) {
            let _ = writeln!(
                out,
                "    T{:<3} {}.{:<24} +0x{:<4x} {:>10} writes",
                key.thread_id, key.type_name, key.field_name, key.field_offset, count
            );
        }
        let contention = field_heatmap.contention_report(cl_tracker);
        if !contention.is_empty() {
            let _ = writeln!(
                out,
                "\n CROSS-THREAD FIELD CONTENTION ({} fields written by multiple threads):",
                contention.len()
            );
            for ce in contention.iter().take(20) {
                let thread_detail: Vec<String> = ce
                    .threads
                    .iter()
                    .map(|(tid, cnt)| format!("T{}={}", tid, cnt))
                    .collect();
                let _ = writeln!(
                    out,
                    "    {}.{:<24} +0x{:<4x} total={:<10} [{}]",
                    ce.type_name,
                    ce.field_name,
                    ce.field_offset,
                    ce.total_writes,
                    thread_detail.join(", ")
                );
            }
        }
    }

    if field_heatmap.read_len() > 0 {
        let _ = writeln!(
            out,
            "\n FIELD READ HEATMAP ({} distinct entries)",
            field_heatmap.read_len()
        );
        let _ = writeln!(
            out,
            "  Top 20 hottest reads (thread, type.field, offset, reads):"
        );
        for (key, count) in field_heatmap.top_read_entries(20) {
            let _ = writeln!(
                out,
                "    T{:<3} {}.{:<24} +0x{:<4x} {:>10} reads",
                key.thread_id, key.type_name, key.field_name, key.field_offset, count
            );
        }
    }

    if !world.edges.is_empty() {
        let _ = writeln!(out, "\nPOINTER EDGES");
        let mut seen: std::collections::HashSet<(String, u64)> = std::collections::HashSet::new();
        for (src, edge) in &world.edges {
            let src_name = world
                .nodes
                .get(src)
                .map(|n| n.name.clone())
                .unwrap_or_default();
            let key = (src_name.clone(), edge.ptr_value);
            if !seen.insert(key) {
                continue;
            }
            let tgt_name = addr_names
                .get(&edge.ptr_value)
                .map(|s| s.as_str())
                .unwrap_or("?");
            let _ = writeln!(
                out,
                "  {} ──> {} (0x{:x})",
                src_name, tgt_name, edge.ptr_value
            );
        }
    }

    if !bb_hits.is_empty() {
        let total_hits: u64 = bb_hits.values().sum();
        let _ = writeln!(
            out,
            "\nBB COVERAGE: {} unique blocks, {} total hits",
            bb_hits.len(),
            total_hits
        );
        let mut top: Vec<_> = bb_hits.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1));
        let _ = writeln!(out, "  Top 10 hottest basic blocks (rip_offset, hits):");
        for (&rip, &count) in top.iter().take(10) {
            let _ = writeln!(out, "    0x{:<12x} {:>10}", rip, count);
        }
    }

    let tail_n = 12usize;
    let start = if journal.len() > tail_n {
        journal.len() - tail_n
    } else {
        0
    };
    let _ = writeln!(out, "\nEVENTS (last {})", tail_n);
    for e in journal.iter().skip(start) {
        let kind_str = match e.kind {
            0 => "W",
            1 => "R",
            2 => "CALL",
            3 => "RET",
            4 => "OVF",
            5 => "REG",
            6 => "CMIS",
            7 => "MLOAD",
            8 => "TCALL",
            11 => "BB",
            12 => "RLOAD",
            _ => "?",
        };
        let _ = writeln!(
            out,
            "  {:>8} {:<5} T{:<3} {:>12x}  {:>4}  {:>16x}",
            e.seq, kind_str, e.thread_id, e.addr, e.size, e.value
        );
    }
}

fn export_bb_coverage(path: &std::path::Path, bb_hits: &HashMap<u32, u64>) {
    use std::io::Write;
    let file = match std::fs::File::create(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("rtmap: failed to create coverage file: {}", e);
            return;
        }
    };
    let mut out = io::BufWriter::new(file);
    let mut sorted: Vec<_> = bb_hits.iter().collect();
    sorted.sort_by_key(|(rip, _)| *rip);
    let _ = writeln!(out, "rip_offset\thits");
    for (&rip, &count) in &sorted {
        let _ = writeln!(out, "0x{:x}\t{}", rip, count);
    }
    eprintln!(
        "rtmap: coverage exported to {} ({} BBs)",
        path.display(),
        sorted.len()
    );
}

fn run_replay(
    replay_path: &str,
    elf_path: Option<&str>,
    _once: bool,
    topo_path: Option<String>,
    no_bb: bool,
) {
    use std::io::Write;

    let mut dwarf_info: Option<DwarfInfo> = elf_path.and_then(|path| {
        eprintln!("rtmap: parsing DWARF from {}", path);
        match dwarf::parse_elf(path) {
            Ok(info) => {
                eprintln!(
                    "rtmap: {} globals, {} functions",
                    info.globals.len(),
                    info.functions.len()
                );
                Some(info)
            }
            Err(e) => {
                eprintln!("rtmap: DWARF parse failed: {}", e);
                None
            }
        }
    });

    let mut player = match EventPlayer::open(std::path::Path::new(replay_path)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("rtmap: failed to open recording: {}", e);
            return;
        }
    };
    eprintln!(
        "rtmap: replaying {} events from {}",
        player.event_count(),
        replay_path
    );

    let mut addr_index = AddressIndex::new();
    let mut world = WorldState::new();
    let mut stacks: HashMap<u16, ShadowStack> = HashMap::new();
    let mut next_frame_id: FrameId = 1;
    let mut total: u64 = 0;
    let mut journal: VecDeque<JournalEntry> = VecDeque::with_capacity(1024);
    let mut relocation_delta: Option<u64> = None;
    let mut returned_frames: VecDeque<FrameId> = VecDeque::with_capacity(64);
    let mut shadow_regs: HashMap<u16, ShadowRegisterFile> = HashMap::new();
    let mut heap_graph = HeapGraph::new();
    let mut heap_oracle = HeapOracle::new();
    if let Some(ref info) = dwarf_info {
        heap_graph.init_candidates(info);
    }
    // dummy orchestrator for headless_render (LAG will be 0)
    let orch = RingOrchestrator::new();

    let mut topo: Option<TopologyStream> =
        topo_path
            .as_ref()
            .and_then(|p| match TopologyStream::create(std::path::Path::new(p)) {
                Ok(t) => {
                    eprintln!("rtmap: topology stream → {}", p);
                    Some(t)
                }
                Err(e) => {
                    eprintln!("rtmap: failed to create topology stream: {}", e);
                    None
                }
            });

    if let Some(ref info) = dwarf_info {
        reconciler::populate_globals(info, 0, &mut addr_index, &mut world);
    }

    let mut event_buf: Vec<Event> = Vec::with_capacity(4096);
    loop {
        event_buf.clear();
        let got = match player.read_batch(&mut event_buf, 4096) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("rtmap: replay read error: {}", e);
                break;
            }
        };
        if got == 0 {
            break;
        }

        let mut need_finalize = false;
        let mut i = 0;
        while i < event_buf.len() {
            let ev = &event_buf[i];
            let ev_kind = ev.kind();

            if no_bb && ev_kind == EVENT_BB_ENTRY {
                i += 1;
                continue;
            }

            if ev_kind == EVENT_REG_SNAPSHOT {
                let consumed =
                    reconciler::apply_reg_snapshot(&event_buf[i..], &mut world, &mut shadow_regs)
                        .max(1);
                total += consumed as u64;
                world.inc_insn_counter();
                i += consumed;
                continue;
            }

            total += 1;
            world.inc_insn_counter();

            let interesting = reconciler::process_event(
                ev,
                0,
                &orch,
                &mut world,
                &mut addr_index,
                &mut dwarf_info,
                &mut stacks,
                &mut next_frame_id,
                &mut relocation_delta,
                &mut returned_frames,
                &mut shadow_regs,
                &mut heap_graph,
                &mut heap_oracle,
                &mut topo,
            );
            if interesting && !ev.is_continuation() {
                journal.push_back(JournalEntry {
                    seq: total,
                    kind: ev_kind,
                    thread_id: ev.thread_id,
                    addr: ev.addr,
                    size: ev.size,
                    value: ev.value,
                });
                if journal.len() > 1000 {
                    journal.pop_front();
                }
            }
            if ev_kind == EVENT_CALL {
                need_finalize = true;
            }
            i += 1;
        }
        if need_finalize {
            addr_index.finalize();
        }
        if total & 0xFFF == 0 {
            world.cache_heat_tick();
            world.cl_tracker_tick();
        }
        if total & 0xFFFF == 0 {
            heap_graph.gc_stale(total, 500_000);
        }
    }

    if let Some(ref mut ts) = topo {
        ts.emit_summary(
            total,
            world.node_count(),
            world.edge_count(),
            world.stm.len(),
            world.heap_allocs.live_count(),
            world.hazards.len(),
        );
    }
    if let Some(ts) = topo {
        match ts.finish() {
            Ok(n) => eprintln!("rtmap: topology: {} lines", n),
            Err(e) => eprintln!("rtmap: topology finalize error: {}", e),
        }
    }

    eprintln!("rtmap: replay complete, {} events processed", total);
    let snap = world.snapshot();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    headless_render(
        &mut out,
        &snap,
        &world.cl_tracker,
        &world.stm,
        &world.heap_allocs,
        &world.hazards,
        &world.field_heatmap,
        &world.type_stability,
        &world.type_epochs,
        &journal,
        total,
        &orch,
        &heap_graph,
        &world.bb_hits,
    );
    let _ = out.flush();
}

fn cleanup_shm_for_pid(pid: u32) {
    let ctl_name = format!("/rtmap_ctl_{}\0", pid);
    unsafe {
        libc::shm_unlink(ctl_name.as_ptr() as *const libc::c_char);
    }
    for i in 0..256u32 {
        let name = format!("/rtmap_ring_{}_{}\0", pid, i);
        unsafe {
            libc::shm_unlink(name.as_ptr() as *const libc::c_char);
        }
    }
}

fn cleanup_shm() {
    unsafe {
        libc::shm_unlink(c"/rtmap_ctl".as_ptr());
    }
    for i in 0..256u32 {
        let name = format!("/rtmap_ring_{}\0", i);
        unsafe {
            libc::shm_unlink(name.as_ptr() as *const libc::c_char);
        }
    }
}

fn find_drrun(cfg: &rtmap::config::Config) -> Option<std::path::PathBuf> {
    if let Some(ref p) = cfg.drrun_path {
        let path = std::path::PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }
    if let Ok(p) = env::var("RTMAP_DRRUN") {
        let path = std::path::PathBuf::from(&p);
        if path.exists() {
            return Some(path);
        }
    }
    if let Ok(home) = env::var("DYNAMORIO_HOME") {
        let path = std::path::PathBuf::from(&home).join("bin64/drrun");
        if path.exists() {
            return Some(path);
        }
    }
    if let Some(ref home) = cfg.dynamorio_home {
        let path = std::path::PathBuf::from(home).join("bin64/drrun");
        if path.exists() {
            return Some(path);
        }
    }
    if let Ok(output) = std::process::Command::new("which").arg("drrun").output() {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !s.is_empty() {
                return Some(std::path::PathBuf::from(s));
            }
        }
    }
    if let Some(dr_home) = rtmap::config::discover_dynamorio() {
        let path = dr_home.join("bin64/drrun");
        if path.exists() {
            return Some(path);
        }
    }
    None
}

fn find_tracer(cfg: &rtmap::config::Config) -> Option<std::path::PathBuf> {
    if let Some(ref p) = cfg.tracer_path {
        let path = std::path::PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }
    if let Ok(p) = env::var("RTMAP_TRACER") {
        let path = std::path::PathBuf::from(&p);
        if path.exists() {
            return Some(path);
        }
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            for candidate in &[
                dir.join("../../build/librtmap_tracer.so"),
                dir.join("../../../build/librtmap_tracer.so"),
                dir.join("librtmap_tracer.so"),
            ] {
                if let Ok(canon) = candidate.canonicalize() {
                    if canon.exists() {
                        return Some(canon);
                    }
                }
            }
        }
    }
    None
}

static TRACER_PID: AtomicI32 = AtomicI32::new(0);
static GOT_SIGNAL: AtomicBool = AtomicBool::new(false);
static TRACER_EXITED: AtomicBool = AtomicBool::new(false);
static TRACER_EXIT_STATUS: AtomicI32 = AtomicI32::new(0);

extern "C" fn signal_handler(_sig: libc::c_int) {
    GOT_SIGNAL.store(true, AtomicOrdering::SeqCst);
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(
            libc::SIGINT,
            signal_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            signal_handler as *const () as libc::sighandler_t,
        );
    }
}

fn run_consumer(elf_path: Option<&str>, cfg: RunConfig) {
    let dwarf_info: Option<DwarfInfo> = elf_path.and_then(|path| {
        eprintln!("rtmap: parsing DWARF from {}", path);
        match dwarf::parse_elf(path) {
            Ok(info) => {
                eprintln!(
                    "rtmap: {} globals, {} functions",
                    info.globals.len(),
                    info.functions.len()
                );
                Some(info)
            }
            Err(e) => {
                eprintln!("rtmap: DWARF parse failed: {}", e);
                None
            }
        }
    });

    let mut orch = RingOrchestrator::new();
    eprintln!("rtmap: waiting for tracer...");
    let deadline = time::Instant::now() + time::Duration::from_secs(30);
    loop {
        if GOT_SIGNAL.load(AtomicOrdering::Relaxed) {
            eprintln!("rtmap: interrupted while waiting for tracer");
            return;
        }
        if TRACER_EXITED.load(AtomicOrdering::Relaxed) {
            // tracer died before we could drain; retry a few times to
            // let the SHM contents become visible (kernel page flush).
            let tpid = TRACER_PID.load(AtomicOrdering::Relaxed) as u32;
            for _retry in 0..5 {
                if tpid > 0 { orch.try_attach_ctl_for_pid(tpid); } else { orch.try_attach_ctl(); }
                orch.poll_new_rings();
                if orch.ring_count() > 0 {
                    eprintln!(
                        "rtmap: attached (tracer already exited), {} ring(s)",
                        orch.ring_count()
                    );
                    run(orch, dwarf_info, cfg);
                    return;
                }
                thread::sleep(time::Duration::from_millis(50));
            }
            let status = TRACER_EXIT_STATUS.load(AtomicOrdering::Relaxed);
            eprintln!("rtmap: error: tracer process exited before shared memory was created.");
            if libc::WIFEXITED(status) {
                eprintln!("rtmap: tracer exit code: {}", libc::WEXITSTATUS(status));
            } else if libc::WIFSIGNALED(status) {
                eprintln!(
                    "rtmap: tracer killed by signal: {}",
                    libc::WTERMSIG(status)
                );
            }
            eprintln!("rtmap: possible causes:");
            eprintln!("  - DynamoRIO injection failed (missing --cap-add=SYS_PTRACE in Docker?)");
            eprintln!("  - target binary not found or not executable");
            eprintln!("  - tracer .so not compatible with this DynamoRIO version");
            std::process::exit(1);
        }
        if time::Instant::now() > deadline {
            eprintln!("rtmap: timeout waiting for tracer (30s).");
            eprintln!("rtmap: the tracer process is still running but has not created the shared memory ring.");
            eprintln!("rtmap: possible causes:");
            eprintln!("  - DynamoRIO is still loading (very large binary)");
            eprintln!("  - tracer initialization is blocked or hung");
            std::process::exit(1);
        }
        let tpid_normal = TRACER_PID.load(AtomicOrdering::Relaxed) as u32;
        let attached = if tpid_normal > 0 {
            orch.try_attach_ctl_for_pid(tpid_normal)
        } else {
            orch.try_attach_ctl()
        };
        if attached {
            orch.poll_new_rings();
            if orch.ring_count() > 0 {
                eprintln!("rtmap: attached, {} thread ring(s)", orch.ring_count());
                run(orch, dwarf_info, cfg);
                return;
            }
        }
        thread::sleep(time::Duration::from_millis(100));
    }
}

/// resolve a function symbol name to its ELF offset (vaddr - base_vaddr).
/// uses the object crate to read .symtab/.dynsym without full DWARF parse.
fn resolve_elf_symbol_offset(elf_path: &str, symbol_name: &str) -> Option<u64> {
    use object::{Object, ObjectSegment, ObjectSymbol, SymbolKind};
    let data = std::fs::read(elf_path).ok()?;
    let file = object::File::parse(&*data).ok()?;
    let base_vaddr = file.segments()
        .filter(|s| s.size() > 0)
        .map(|s| s.address())
        .min()
        .unwrap_or(0);
    for sym in file.symbols().chain(file.dynamic_symbols()) {
        if sym.name() == Ok(symbol_name) && sym.kind() == SymbolKind::Text {
            let addr = sym.address();
            if addr > 0 {
                return Some(addr - base_vaddr);
            }
        }
    }
    eprintln!("rtmap: warning: tripwire symbol '{}' not found in {}", symbol_name, elf_path);
    None
}

fn launch(target: &str, target_args: &[String], cfg: RunConfig, resolved_cfg: &rtmap::config::Config) {
    let drrun = match find_drrun(resolved_cfg) {
        Some(p) => p,
        None => {
            eprintln!("rtmap: error: could not locate DynamoRIO.");
            eprintln!();
            eprintln!("  To fix this, do ONE of the following:");
            eprintln!();
            eprintln!("    1. Run 'rtmap setup' to auto-discover and persist the path.");
            eprintln!("    2. Set the environment variable:");
            eprintln!("         export DYNAMORIO_HOME=/path/to/DynamoRIO-Linux-*");
            eprintln!("    3. Add to ~/.config/rtmap/config:");
            eprintln!("         paths.dynamorio_home = /path/to/DynamoRIO-Linux-*");
            eprintln!();
            eprintln!("  Searched: RTMAP_DRRUN, DYNAMORIO_HOME, config file, PATH, ~/DynamoRIO-Linux-*, /opt/dynamorio");
            std::process::exit(1);
        }
    };
    let tracer = match find_tracer(resolved_cfg) {
        Some(p) => p,
        None => {
            eprintln!("rtmap: error: could not locate librtmap_tracer.so.");
            eprintln!();
            eprintln!("  To fix this, do ONE of the following:");
            eprintln!();
            eprintln!("    1. Build the tracer:");
            eprintln!("         cd build && cmake .. -DDynamoRIO_DIR=$DYNAMORIO_HOME/cmake && make");
            eprintln!("    2. Run 'rtmap setup' to auto-detect after building.");
            eprintln!("    3. Set the environment variable:");
            eprintln!("         export RTMAP_TRACER=/path/to/librtmap_tracer.so");
            eprintln!();
            eprintln!("  Searched: config file, RTMAP_TRACER, relative to rtmap binary");
            std::process::exit(1);
        }
    };

    eprintln!("rtmap: drrun  = {}", drrun.display());
    eprintln!("rtmap: tracer = {}", tracer.display());
    eprintln!("rtmap: target = {}", target);

    cleanup_shm();

    install_signal_handlers();

    // resolve tripwire symbol to ELF offset before spawning drrun
    let tripwire_offset: Option<u64> = cfg.tripwire_symbol.as_ref().and_then(|sym| {
        resolve_elf_symbol_offset(target, sym)
    });

    // resolve arena/pool sub-allocator symbols to ELF offsets.
    let arena_specs: Vec<String> = cfg.alloc_fns.iter().filter_map(|(sym, arg)| {
        match resolve_elf_symbol_offset(target, sym) {
            Some(off) => {
                eprintln!("rtmap: arena allocator '{}' at ELF offset 0x{:x} (size_arg={})",
                          sym, off, arg);
                Some(format!("{:x}:{}", off, arg))
            }
            None => None,
        }
    }).collect();

    let mut cmd = std::process::Command::new(&drrun);
    cmd.arg("-c").arg(&tracer);
    // argv[1] must always be the tripwire offset (0 = disabled) so that
    // arena specs in argv[2..] keep their positional meaning.
    if let Some(off) = tripwire_offset {
        cmd.arg(format!("{:x}", off));
        eprintln!("rtmap: tripwire '{}' at ELF offset 0x{:x}",
                  cfg.tripwire_symbol.as_deref().unwrap_or("?"), off);
    } else if !arena_specs.is_empty() {
        cmd.arg("0");
    }
    for spec in &arena_specs {
        cmd.arg(spec);
    }
    cmd.arg("--").arg(target);
    for a in target_args {
        cmd.arg(a);
    }
    if !cfg.once {
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
    }

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("rtmap: failed to launch tracer: {}", e);
            cleanup_shm();
            std::process::exit(1);
        }
    };

    let child_pid = child.id() as i32;
    TRACER_PID.store(child_pid, AtomicOrdering::SeqCst);
    eprintln!("rtmap: tracer pid={}", child_pid);


    let _reaper = thread::Builder::new()
        .name("tracer-reaper".into())
        .spawn(move || {
            let mut status: libc::c_int = 0;
            unsafe {
                libc::waitpid(child_pid, &mut status, 0);
            }
            TRACER_EXIT_STATUS.store(status, AtomicOrdering::SeqCst);
            TRACER_EXITED.store(true, AtomicOrdering::SeqCst);
            if libc::WIFEXITED(status) {
                let code = libc::WEXITSTATUS(status);
                if code != 0 {
                    eprintln!("rtmap: tracer exited with code {}", code);
                }
            } else if libc::WIFSIGNALED(status) {
                let sig = libc::WTERMSIG(status);
                eprintln!("rtmap: tracer killed by signal {}", sig);
            }
        })
        .expect("rtmap: failed to spawn reaper thread");

    let target_owned = target.to_string();
    let handle = thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || run_consumer(Some(&target_owned), cfg))
        .expect("rtmap: failed to spawn consumer thread");
    let _ = handle.join();

    if !TRACER_EXITED.load(AtomicOrdering::SeqCst) {
        unsafe {
            libc::kill(child_pid, libc::SIGTERM);
            let mut status: libc::c_int = 0;
            libc::waitpid(child_pid, &mut status, 0);
        }
    }
    cleanup_shm();
    /* pid-scoped cleanup: target pid may differ from drrun pid */
    cleanup_shm_for_pid(child_pid as u32);
    eprintln!("rtmap: done.");
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    eprintln!("rtmap {} — runtime memory topology analyzer", VERSION);
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  rtmap <target> [-- target_args]    Instrument a binary");
    eprintln!("  rtmap <target> --live              Interactive TUI");
    eprintln!();
    eprintln!("COMMANDS:");
    eprintln!("  setup                  One-time setup: locate DynamoRIO, persist config");
    eprintln!("  init <target>          Create .rtmap project profile with auto-detected tripwire");
    eprintln!("  record -o <f> <target> Record event trace for offline replay");
    eprintln!("  replay <file>          Replay a recorded trace");
    eprintln!("  attach                 Attach to an already-running tracer");
    eprintln!();
    eprintln!("COMMON OPTIONS:");
    eprintln!("  --tripwire <sym>       Begin tracing at <sym>; implies server mode (wait for exit)");
    eprintln!("  --live                 Interactive TUI instead of headless snapshot");
    eprintln!("  --topology <file>      Export topology graph as JSONL");
    eprintln!("  --heatmap <file>       Export field write heatmap as TSV");
    eprintln!("  -h, --help             Show this help");
    eprintln!("  -V, --version          Print version");
    eprintln!();
    eprintln!("GETTING STARTED:");
    eprintln!("  rtmap setup                       Auto-detect DynamoRIO and write config");
    eprintln!("  rtmap ./my_server                 Headless snapshot");
    eprintln!("  rtmap ./my_server -- --port 9999  Override target args");
    eprintln!();
    eprintln!("  Run 'rtmap help advanced' for all options and tuning flags.");
}

fn print_help_advanced() {
    eprintln!("rtmap {} — advanced options", VERSION);
    eprintln!();
    eprintln!("INSTRUMENTATION:");
    eprintln!("  --tripwire <sym>       Defer tracing until function <sym> is entered");
    eprintln!("  --alloc-fn <sym>[:<n>] Treat <sym> as an arena/pool allocator; size is arg n");
    eprintln!("                         (default 0). Repeatable. Recovers object boundaries");
    eprintln!("                         for malloc-bypassing allocators");
    eprintln!("  --no-bb                Skip BB_ENTRY events (reduces ring buffer volume)");
    eprintln!("  --min-events <N>       Minimum events before snapshot (default: 1)");
    eprintln!("  --dr-home <path>       Explicit DynamoRIO installation (overrides config/env)");
    eprintln!();
    eprintln!("EXPORTS:");
    eprintln!("  --topology <file>      Export topology graph as JSONL");
    eprintln!("  --heatmap <file>       Export field write heatmap as TSV");
    eprintln!("  --coverage <file>      Export basic-block coverage map as TSV");
    eprintln!("  -o, --output <file>    Output file (for record)");
    eprintln!();
    eprintln!("REPLAY:");
    eprintln!("  --dwarf <elf>          Explicit DWARF source (if separate from target)");
    eprintln!();
    eprintln!("CONFIGURATION:");
    eprintln!("  Global:  ~/.config/rtmap/config   (created by 'rtmap setup')");
    eprintln!("  Project: .rtmap                   (created by 'rtmap init')");
    eprintln!();
    eprintln!("  Resolution order: CLI > env var > .rtmap > global config > auto-detect");
    eprintln!();
    eprintln!("ENVIRONMENT (optional — auto-detected if not set):");
    eprintln!("  DYNAMORIO_HOME         DynamoRIO installation directory");
    eprintln!("  RTMAP_DRRUN           Explicit path to drrun binary");
    eprintln!("  RTMAP_TRACER          Explicit path to librtmap_tracer.so");
    eprintln!();
    eprintln!("ARGUMENT OVERRIDE SEMANTICS:");
    eprintln!("  rtmap [RTMAP_FLAGS] <target> [-- TARGET_ARGS]");
    eprintln!();
    eprintln!("  Args after '--' fully REPLACE any target.*.args from .rtmap.");
    eprintln!("  Without '--', target args come from the project profile (if defined).");
}

fn die(msg: &str) -> ! {
    eprintln!("rtmap: error: {}", msg);
    eprintln!("  Run 'rtmap --help' for usage.");
    std::process::exit(1);
}

fn take_flag_value(args: &mut Vec<String>, flag: &str) -> Option<String> {
    if let Some(pos) = args.iter().position(|a| a == flag) {
        if pos + 1 < args.len() {
            args.remove(pos);
            return Some(args.remove(pos));
        } else {
            eprintln!("rtmap: error: {} requires a value", flag);
            std::process::exit(1);
        }
    }
    None
}

fn take_flag(args: &mut Vec<String>, flag: &str) -> bool {
    if let Some(pos) = args.iter().position(|a| a == flag) {
        args.remove(pos);
        true
    } else {
        false
    }
}

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        print_help();
        std::process::exit(1);
    }

    if take_flag(&mut args, "--help") || take_flag(&mut args, "-h") {
        print_help();
        std::process::exit(0);
    }
    if take_flag(&mut args, "--version") || take_flag(&mut args, "-V") {
        eprintln!("rtmap {}", VERSION);
        std::process::exit(0);
    }

    let first = args.first().map(|s| s.as_str()).unwrap_or("");
    match first {
        "setup" => {
            args.remove(0);
            cmd_setup(&mut args);
        }
        "init" => {
            args.remove(0);
            cmd_init(&mut args);
        }
        "record" => {
            args.remove(0);
            cmd_record(&mut args);
        }
        "replay" => {
            args.remove(0);
            cmd_replay(&mut args);
        }
        "attach" => {
            args.remove(0);
            cmd_attach(&mut args);
        }
        "run" => {
            args.remove(0);
            cmd_run(&mut args);
        }
        "help" => {
            args.remove(0);
            if args.first().map(|s| s.as_str()) == Some("advanced") {
                print_help_advanced();
            } else {
                print_help();
            }
            std::process::exit(0);
        }
        _ => {
            if args.iter().any(|a| a == "--replay") {
                cmd_replay_compat(&mut args);
            } else if take_flag(&mut args, "--consumer-only") {
                cmd_attach(&mut args);
            } else if args.iter().any(|a| a == "--record") {
                cmd_record_compat(&mut args);
            } else {
                cmd_run(&mut args);
            }
        }
    }
}

fn parse_common_flags(args: &mut Vec<String>) -> RunConfig {
    let live = take_flag(args, "--live");
    take_flag(args, "--once");
    let no_bb = take_flag(args, "--no-bb");
    let tripwire_symbol = take_flag_value(args, "--tripwire");
    // --alloc-fn <sym>[:<size_arg>] is repeatable; size_arg defaults to 0.
    let mut alloc_fns: Vec<(String, u32)> = Vec::new();
    while let Some(spec) = take_flag_value(args, "--alloc-fn") {
        let (sym, arg) = match spec.split_once(':') {
            Some((s, a)) => (s.to_string(), a.parse::<u32>().unwrap_or(0)),
            None => (spec, 0),
        };
        if sym.is_empty() {
            eprintln!("rtmap: warning: ignoring empty --alloc-fn spec");
            continue;
        }
        alloc_fns.push((sym, arg));
    }
    RunConfig {
        once: !live,
        server_mode: tripwire_symbol.is_some(),
        record_path: take_flag_value(args, "--record")
            .or_else(|| take_flag_value(args, "-o"))
            .or_else(|| take_flag_value(args, "--output")),
        topo_path: take_flag_value(args, "--topology")
            .or_else(|| take_flag_value(args, "--export-topology")),
        heatmap_path: take_flag_value(args, "--heatmap")
            .or_else(|| take_flag_value(args, "--export-heatmap")),
        coverage_path: take_flag_value(args, "--coverage"),
        no_bb,
        tripwire_symbol,
        alloc_fns,
    }
}

fn cmd_run(args: &mut Vec<String>) {
    let dr_home_flag = take_flag_value(args, "--dr-home");
    let mut cfg = parse_common_flags(args);

    let (mut resolved_cfg, proj_cfg) = rtmap::config::resolve_config();
    if let Some(ref dr) = dr_home_flag {
        resolved_cfg.drrun_path = Some(format!("{}/bin64/drrun", dr));
        resolved_cfg.dynamorio_home = Some(dr.clone());
    }

    let target_idx = args.iter().position(|a| !a.starts_with('-'));
    let target_idx = match target_idx {
        Some(i) => i,
        None => die("no target binary specified"),
    };

    let target = args[target_idx].clone();

    // '--' boundary: full override, no merge
    let has_separator = args[target_idx + 1..].iter().any(|a| a == "--");
    let target_args: Vec<String> = if has_separator {
        let sep_pos = args[target_idx + 1..].iter().position(|a| a == "--").unwrap();
        args[target_idx + 1 + sep_pos + 1..].to_vec()
    } else {
        let profile = rtmap::config::resolve_target_profile(&proj_cfg, &target);
        if let Some(prof) = profile {
            if cfg.tripwire_symbol.is_none() {
                cfg.tripwire_symbol = prof.tripwire.clone();
                if cfg.tripwire_symbol.is_some() {
                    cfg.server_mode = true;
                }
            }
            if cfg.topo_path.is_none() {
                cfg.topo_path = prof.topology.clone();
            }
            if cfg.heatmap_path.is_none() {
                cfg.heatmap_path = prof.heatmap.clone();
            }
            if cfg.coverage_path.is_none() {
                cfg.coverage_path = prof.coverage.clone();
            }
            if !prof.args.is_empty() {
                prof.args.clone()
            } else {
                args[target_idx + 1..].to_vec()
            }
        } else {
            args[target_idx + 1..].to_vec()
        }
    };

    if cfg.topo_path.is_none() && resolved_cfg.default_topology == Some(true) {
        let base = std::path::Path::new(&target)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("rtmap");
        cfg.topo_path = Some(format!("{}.topo.jsonl", base));
    }
    if cfg.heatmap_path.is_none() && resolved_cfg.default_heatmap == Some(true) {
        let base = std::path::Path::new(&target)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("rtmap");
        cfg.heatmap_path = Some(format!("{}.heatmap.tsv", base));
    }

    launch(&target, &target_args, cfg, &resolved_cfg);
}

fn cmd_record(args: &mut Vec<String>) {
    let dr_home_flag = take_flag_value(args, "--dr-home");
    let cfg = parse_common_flags(args);
    if cfg.record_path.is_none() {
        die("record requires -o <file>");
    }

    let (mut resolved_cfg, _proj_cfg) = rtmap::config::resolve_config();
    if let Some(ref dr) = dr_home_flag {
        resolved_cfg.drrun_path = Some(format!("{}/bin64/drrun", dr));
        resolved_cfg.dynamorio_home = Some(dr.clone());
    }

    let target_idx = args.iter().position(|a| !a.starts_with('-'));
    let target_idx = match target_idx {
        Some(i) => i,
        None => die("record requires a target binary"),
    };

    let target = args[target_idx].clone();
    let target_args: Vec<String> = args[target_idx + 1..].to_vec();

    launch(&target, &target_args, cfg, &resolved_cfg);
}

fn cmd_replay(args: &mut Vec<String>) {
    take_flag(args, "--once");
    let no_bb = take_flag(args, "--no-bb");
    let topo_path =
        take_flag_value(args, "--topology").or_else(|| take_flag_value(args, "--export-topology"));
    let dwarf_path = take_flag_value(args, "--dwarf");

    let trace_path = args.iter().position(|a| !a.starts_with('-'));
    let trace_path = match trace_path {
        Some(i) => args.remove(i),
        None => die("replay requires a trace file"),
    };

    let elf_path = dwarf_path.or_else(|| {
        args.iter()
            .position(|a| !a.starts_with('-'))
            .map(|i| args.remove(i))
    });

    let tp_owned = topo_path;
    let handle = thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || run_replay(&trace_path, elf_path.as_deref(), true, tp_owned, no_bb))
        .expect("rtmap: failed to spawn replay thread");
    let _ = handle.join();
}

fn cmd_attach(args: &mut Vec<String>) {
    let cfg = parse_common_flags(args);
    let dwarf_path = take_flag_value(args, "--dwarf");

    let elf_path: Option<String> = dwarf_path.or_else(|| {
        args.iter()
            .position(|a| !a.starts_with('-'))
            .map(|i| args.remove(i))
    });

    let handle = thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || run_consumer(elf_path.as_deref(), cfg))
        .expect("rtmap: failed to spawn consumer thread");
    let _ = handle.join();
}

fn cmd_replay_compat(args: &mut Vec<String>) {
    let replay_path = take_flag_value(args, "--replay").unwrap();
    take_flag(args, "--once");
    let no_bb = take_flag(args, "--no-bb");
    let topo_path =
        take_flag_value(args, "--topology").or_else(|| take_flag_value(args, "--export-topology"));

    let elf_path: Option<String> = args
        .iter()
        .position(|a| !a.starts_with('-'))
        .map(|i| args.remove(i));

    let tp_owned = topo_path;
    let handle = thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || run_replay(&replay_path, elf_path.as_deref(), true, tp_owned, no_bb))
        .expect("rtmap: failed to spawn replay thread");
    let _ = handle.join();
}

fn cmd_record_compat(args: &mut Vec<String>) {
    let record_path = take_flag_value(args, "--record").unwrap();
    cmd_run_with_record(args, record_path);
}

fn cmd_run_with_record(args: &mut Vec<String>, record_path: String) {
    let dr_home_flag = take_flag_value(args, "--dr-home");
    let mut cfg = parse_common_flags(args);
    cfg.record_path = Some(record_path);

    let (mut resolved_cfg, _proj_cfg) = rtmap::config::resolve_config();
    if let Some(ref dr) = dr_home_flag {
        resolved_cfg.drrun_path = Some(format!("{}/bin64/drrun", dr));
        resolved_cfg.dynamorio_home = Some(dr.clone());
    }

    let target_idx = args.iter().position(|a| !a.starts_with('-'));
    let target_idx = match target_idx {
        Some(i) => i,
        None => die("no target binary specified"),
    };

    let target = args[target_idx].clone();
    let target_args: Vec<String> = args[target_idx + 1..].to_vec();

    launch(&target, &target_args, cfg, &resolved_cfg);
}

fn cmd_setup(_args: &mut Vec<String>) {
    eprintln!("rtmap {} — setup", VERSION);
    eprintln!();

    // step 1: find DynamoRIO
    let dr_home = if let Ok(home) = env::var("DYNAMORIO_HOME") {
        let p = std::path::PathBuf::from(&home);
        if p.join("bin64/drrun").exists() {
            eprintln!("[1/3] DynamoRIO");
            eprintln!("  Found (env): {}", p.display());
            Some(p)
        } else {
            eprintln!("[1/3] DynamoRIO");
            eprintln!("  DYNAMORIO_HOME is set but bin64/drrun not found at: {}", p.display());
            None
        }
    } else if let Some(discovered) = rtmap::config::discover_dynamorio() {
        eprintln!("[1/3] DynamoRIO");
        eprintln!("  Auto-discovered: {}", discovered.display());
        Some(discovered)
    } else {
        eprintln!("[1/3] DynamoRIO");
        eprintln!("  NOT FOUND.");
        eprintln!();
        eprintln!("  To install DynamoRIO:");
        eprintln!("    wget https://github.com/DynamoRIO/dynamorio/releases/download/release_11.0.0/DynamoRIO-Linux-11.0.19548.tar.gz");
        eprintln!("    tar xzf DynamoRIO-Linux-*.tar.gz -C ~/");
        eprintln!();
        eprintln!("  Then re-run: rtmap setup");
        None
    };

    // step 2: find tracer
    let temp_cfg = rtmap::config::Config {
        dynamorio_home: dr_home.as_ref().map(|p| p.to_string_lossy().to_string()),
        ..Default::default()
    };
    let tracer = find_tracer(&temp_cfg);
    match &tracer {
        Some(p) => {
            eprintln!("[2/3] Tracer");
            eprintln!("  Found: {}", p.display());
        }
        None => {
            eprintln!("[2/3] Tracer");
            eprintln!("  NOT FOUND.");
            eprintln!();
            if let Some(ref dr) = dr_home {
                eprintln!("  To build the tracer:");
                eprintln!("    mkdir -p build && cd build");
                eprintln!("    cmake .. -DDynamoRIO_DIR={}/cmake", dr.display());
                eprintln!("    make");
                eprintln!();
                eprintln!("  Then re-run: rtmap setup");
            } else {
                eprintln!("  Install DynamoRIO first (step 1), then build the tracer.");
            }
        }
    }

    // step 3: write config
    let cfg_dir = rtmap::config::global_config_dir();
    let cfg_path = cfg_dir.join("config");
    let dr_str = dr_home.as_ref().map(|p| p.to_string_lossy().to_string());
    let tracer_str = tracer.as_ref().map(|p| p.to_string_lossy().to_string());
    let content = rtmap::config::generate_global_config(
        dr_str.as_deref(),
        tracer_str.as_deref(),
    );

    eprintln!("[3/3] Writing config");
    if let Err(e) = std::fs::create_dir_all(&cfg_dir) {
        eprintln!("  Failed to create {}: {}", cfg_dir.display(), e);
        std::process::exit(1);
    }
    if let Err(e) = std::fs::write(&cfg_path, &content) {
        eprintln!("  Failed to write {}: {}", cfg_path.display(), e);
        std::process::exit(1);
    }
    eprintln!("  Wrote: {}", cfg_path.display());
    eprintln!();

    if dr_home.is_some() && tracer.is_some() {
        eprintln!("Done. You can now run:");
        eprintln!("  rtmap ./your_binary");
    } else {
        eprintln!("Setup incomplete — resolve the issues above and re-run 'rtmap setup'.");
        std::process::exit(1);
    }
}

fn cmd_init(args: &mut Vec<String>) {
    let target = match args.first() {
        Some(t) => t.clone(),
        None => {
            eprintln!("rtmap: error: 'init' requires a target binary path.");
            eprintln!();
            eprintln!("  Usage: rtmap init ./my_server");
            eprintln!();
            eprintln!("  This creates a .rtmap project file with a target profile,");
            eprintln!("  including an auto-detected tripwire symbol if possible.");
            std::process::exit(1);
        }
    };

    let target_path = std::path::Path::new(&target);
    if !target_path.exists() {
        eprintln!("rtmap: error: target '{}' does not exist.", target);
        eprintln!("  Provide a path to the binary you want to instrument.");
        std::process::exit(1);
    }

    let target_name = target_path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(&target);

    eprintln!("rtmap init — creating .rtmap profile for '{}'", target_name);
    eprintln!();

    // tripwire auto detection via symbol name 
    let tripwire = detect_tripwire_symbol(&target);

    match &tripwire {
        Some(sym) => eprintln!("  Tripwire auto-detected: {}", sym),
        None => eprintln!("  No tripwire auto-detected (you can set one manually in .rtmap)"),
    }

    let rtmap_path = std::path::Path::new(".rtmap");
    if rtmap_path.exists() {
        eprintln!();
        eprintln!("  .rtmap already exists. Appending profile for '{}'.", target_name);
        let existing = std::fs::read_to_string(rtmap_path).unwrap_or_default();
        let profile_key = format!("target.{}.tripwire", target_name);
        if existing.contains(&profile_key) {
            eprintln!("  Profile for '{}' already present — skipping.", target_name);
            return;
        }
        let mut append = String::new();
        append.push_str(&format!("\n# Profile for: {}\n", target_name));
        if let Some(ref tw) = tripwire {
            append.push_str(&format!("target.{}.tripwire = {}\n", target_name, tw));
        }
        append.push_str(&format!("# target.{}.args = \n", target_name));
        if let Err(e) = std::fs::OpenOptions::new()
            .append(true)
            .open(rtmap_path)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(append.as_bytes())
            })
        {
            eprintln!("  Failed to append to .rtmap: {}", e);
            std::process::exit(1);
        }
    } else {
        let content = rtmap::config::generate_project_config(target_name, tripwire.as_deref());
        if let Err(e) = std::fs::write(rtmap_path, &content) {
            eprintln!("  Failed to write .rtmap: {}", e);
            std::process::exit(1);
        }
    }
    eprintln!("  Wrote: .rtmap");
    eprintln!();
    eprintln!("You can now run:");
    eprintln!("  rtmap {}", target_name);
}

// score ELF text symbols by event-loop likelihood: pattern weight + brevity bonus + size penalty.
fn detect_tripwire_symbol(elf_path: &str) -> Option<String> {
    use object::{Object, ObjectSymbol, SymbolKind};
    let data = std::fs::read(elf_path).ok()?;
    let file = object::File::parse(&*data).ok()?;

    let mut text_syms: Vec<(String, u64, u64)> = Vec::new();
    for sym in file.symbols().chain(file.dynamic_symbols()) {
        if sym.kind() == SymbolKind::Text && sym.size() > 0 {
            if let Ok(name) = sym.name() {
                if !name.is_empty() && !name.starts_with('_') && !name.starts_with('.') {
                    text_syms.push((name.to_string(), sym.address(), sym.size()));
                }
            }
        }
    }

    let loop_patterns: &[(&str, u32)] = &[
        ("Main", 15), ("main_loop", 20), ("event_loop", 20),
        ("Loop", 10), ("Cycle", 12), ("Run", 8), ("run_server", 18),
        ("Process", 6), ("process_events", 18), ("dispatch", 10), ("serve", 8),
    ];

    let mut candidates: Vec<(&str, u32)> = Vec::new();
    for (name, _addr, size) in &text_syms {
        if name == "main" || name == "_start" {
            continue;
        }
        if name.contains("init") || name.contains("Init") || name.contains("Setup")
            || name.contains("Config") || name.contains("config")
        {
            continue;
        }
        if name.starts_with("RM_") || name.starts_with("__") {
            continue;
        }

        let mut score: u32 = 0;
        for &(pat, weight) in loop_patterns {
            if name.contains(pat) {
                score += weight;
                if name.ends_with(pat) {
                    score += 10;
                }
            }
        }
        // brevity correlates with entry-point status
        if name.len() <= 12 && score > 0 {
            score += 8;
        } else if name.len() <= 20 && score > 0 {
            score += 3;
        }
        if *size > 10000 {
            score = score.saturating_sub(5);
        }
        if *size > 50 && *size < 2000 {
            score += 3;
        }
        if score > 0 {
            candidates.push((name, score));
        }
    }

    candidates.sort_by(|a, b| b.1.cmp(&a.1));
    candidates.first().map(|(name, _)| name.to_string())
}

