// SPDX-License-Identifier: Apache-2.0

// Core event reconciler: process_event + populate_globals, extracted for library consumers.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

use arrayvec::ArrayVec;

use crate::dwarf::{self, DwarfInfo, TypeInfo};
use crate::heap_graph::{HeapGraph, HeapOracle};
use crate::index::{AddressIndex, FrameId, NodeId};
use crate::ring::{Event, RingOrchestrator};
use crate::shadow_regs::ShadowRegisterFile;
use crate::topology::TopologyStream;
use crate::world::{EpochClose, HazardKind, ShadowStack, StampResult, WorldState, REG_COUNT};

pub const EVENT_WRITE: u8 = 0;
pub const EVENT_READ: u8 = 1;
pub const EVENT_CALL: u8 = 2;
pub const EVENT_RETURN: u8 = 3;
pub const EVENT_REG_SNAPSHOT: u8 = 5;
pub const EVENT_CACHE_MISS: u8 = 6;
pub const EVENT_MODULE_LOAD: u8 = 7;
pub const EVENT_ALLOC: u8 = 9;
pub const EVENT_FREE: u8 = 10;
pub const EVENT_BB_ENTRY: u8 = 11;
pub const EVENT_RELOAD: u8 = 12;
pub const EVENT_PROCESS_FORK: u8 = 13;
pub const EVENT_SHARED_MAP: u8 = 14;

/// REG_SNAPSHOT is 7 contiguous ring slots (header + 6 continuations carrying
/// regs[0..18] packed 3/slot). returns slots consumed: 7 on success, 1 on
/// short/corrupt tail so callers advance past the header.
pub fn apply_reg_snapshot(
    events: &[Event],
    world: &mut WorldState,
    shadow_regs: &mut HashMap<u16, ShadowRegisterFile>,
) -> usize {
    if events.is_empty() || events[0].kind() != EVENT_REG_SNAPSHOT {
        return 0;
    }
    if events.len() < 7 {
        return 1;
    }
    let cont = &events[1..7];
    if !cont.iter().all(|c| c.kind() == EVENT_REG_SNAPSHOT) {
        return 1;
    }
    let header = &events[0];
    let mut regs = [0u64; REG_COUNT];
    for s in 0..6usize {
        regs[s * 3] = cont[s].addr;
        regs[s * 3 + 1] = cont[s].size as u64;
        regs[s * 3 + 2] = cont[s].value;
    }
    world.update_regs(regs, header.addr);
    let srf = shadow_regs.entry(header.thread_id).or_default();
    srf.apply_snapshot(&regs, header.seq as u64, header.addr);
    7
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn process_event(
    ev: &Event,
    ring_idx: usize,
    orch: &RingOrchestrator,
    world: &mut WorldState,
    addr_index: &mut AddressIndex,
    dwarf_info: &mut Option<DwarfInfo>,
    stacks: &mut HashMap<u16, ShadowStack>,
    next_frame_id: &mut FrameId,
    relocation_delta: &mut Option<u64>,
    returned_frames: &mut VecDeque<FrameId>,
    shadow_regs: &mut HashMap<u16, ShadowRegisterFile>,
    heap_graph: &mut HeapGraph,
    heap_oracle: &mut HeapOracle,
    topo: &mut Option<TopologyStream>,
) -> bool {
    world.total_event_count += 1;
    let ev_kind = ev.kind();
    match ev_kind {
        EVENT_WRITE => {
            let truncated = ev.is_truncated();
            let continuation = ev.is_continuation();
            // compound header: value is real low 8B, no poison needed.
            // continuation: value is real 8B chunk at chunk addr.
            // truncated (REP/LOCK fallback): zero-poison to block phantom ptrs.
            let val = if truncated { 0u64 } else { ev.value };
            let cl_writers = world.record_cl_write(ev.addr, ev.thread_id);
            if !continuation {
                if let Some(ref info) = dwarf_info {
                    if addr_index.in_universe(ev.addr) {
                        let elf_pc = match *relocation_delta {
                            Some(d) => ev.addr.wrapping_sub(d),
                            None => ev.addr,
                        };
                        let func = info.func_containing(elf_pc);
                        let srf = shadow_regs.entry(ev.thread_id).or_default();
                        srf.observe_write(ev.addr, val, elf_pc, ev.seq32() as u64, func);
                    }
                }
            }
            if !truncated && !continuation && cl_writers.count_ones() > 1 {
                for (&tid, srf) in shadow_regs.iter_mut() {
                    if tid != ev.thread_id {
                        srf.check_coherence(ev.addr, val, ev.size, ev.seq32() as u64);
                    }
                }
            }
            if heap_oracle.is_heap(ev.addr) {
                heap_graph.process_write(
                    ev.addr,
                    ev.size,
                    val,
                    ev.seq32() as u64,
                    heap_oracle,
                );
                // single covering() call: heatmap + stability + link emission
                // clone only the fields needed; avoid full TypeInfo deep-copy
                let covering_snap = world.stm.covering(ev.addr).map(|c| {
                    (c.base_addr, c.type_info.clone(), c.source_name.clone(), c.stamp_seq)
                });
                if let Some((base, ref ti, ref source, stamp_seq)) = covering_snap {
                    let offset = ev.addr - base;
                    if let Some(field) =
                        ti.fields.iter().find(|f| {
                            offset >= f.byte_offset && offset < f.byte_offset + f.byte_size
                        })
                    {
                        world.field_heatmap.record(
                            ev.thread_id,
                            &ti.name,
                            &field.name,
                            field.byte_offset,
                        );
                    } else {
                        world
                            .field_heatmap
                            .record(ev.thread_id, &ti.name, "<unresolved>", offset);
                    }
                    let proj = crate::world::TypeProjection {
                        base_addr: base,
                        type_info: ti.clone(),
                        source_name: source.clone(),
                        stamp_seq,
                    };
                    let pc = ev.rip_lo as u64;
                    if world.type_stability.check_write(ev.addr, ev.size, &proj, pc) {
                        if let Some(ref mut ts) = topo {
                            let v = world.type_stability.violations.last().unwrap();
                            let kind_str = match v.kind {
                                crate::world::ViolationKind::Interstitial => "INTERSTICE",
                                crate::world::ViolationKind::Spanning => "SPANNING",
                            };
                            ts.emit_type_violation(
                                ev.seq32() as u64,
                                kind_str,
                                v.write_addr,
                                v.write_size,
                                v.base_addr,
                                v.offset,
                                &v.type_name,
                                v.expected_field.as_deref(),
                                v.pc,
                            );
                        }
                    }
                    // topology link emission: reuse same covering result
                    if ev.size == 8 && val != 0 {
                        if let Some(ref mut ts) = topo {
                            if let Some(field) = ti.fields.iter().find(|f| {
                                f.byte_offset == offset && f.type_info.is_pointer
                            }) {
                                let pointee = field
                                    .type_info
                                    .name
                                    .strip_prefix('*')
                                    .unwrap_or(&field.type_info.name);
                                ts.emit_link(
                                    ev.seq32() as u64,
                                    &ti.name,
                                    ev.addr,
                                    val,
                                    pointee,
                                    &field.name,
                                );
                            }
                        }
                    }
                }
                if let Some(ref mut info) = dwarf_info {
                    let stamped = world.stm.propagate_field_write(
                        ev.addr,
                        val,
                        ev.size,
                        ev.seq32() as u64,
                        &info.type_registry,
                        &world.heap_allocs,
                    );
                    // defer unresolved 8-byte pointer writes for retroactive replay.
                    // value-space filter: only buffer if the written value is a
                    // plausible aligned heap pointer. drops raw integers, counters,
                    // string data, stack/TLS/code refs. does NOT gate on
                    // HeapAllocTracker (alloc event may not have arrived yet).
                    if !stamped && ev.size == 8 && val != 0
                        && val % 8 == 0
                        && heap_oracle.is_heap(val)
                    {
                        world.stm.defer_write(ev.addr, val, ev.seq32() as u64);
                    }
                    if stamped {
                        // ensure_type: upgrade shallow / materialize absent / chase transitive ptrs
                        if let Some(proj) = world.stm.lookup(val) {
                            let tname = proj.type_info.name.clone();
                            let src = proj.source_name.clone();
                            let was_shallow = proj.type_info.shallow;
                            info.ensure_type(&tname);
                            if was_shallow {
                                if let Some(deep) = info.type_registry.get(&tname) {
                                    if !deep.shallow {
                                        world.stm.stamp_type(val, deep, &src, ev.seq32() as u64);
                                    }
                                }
                            }
                        }
                        world.stm.retrospective_scan(
                            val,
                            heap_graph,
                            &world.heap_allocs,
                            &info.type_registry,
                            ev.seq32() as u64,
                            world.proc_mem.as_ref(),
                        );
                        if let Some(ref mut ts) = topo {
                            if let Some(proj) = world.stm.lookup(val) {
                                ts.emit_stamp(
                                    ev.seq32() as u64,
                                    val,
                                    &proj.type_info.name,
                                    proj.type_info.byte_size,
                                    &proj.source_name,
                                    proj.type_info.fields.len(),
                                );
                            }
                        }
                    }
                }
                if world.hazards.len() < 64 {
                    if let Some(mut h) = world
                        .heap_allocs
                        .check_write_bounds(ev.addr, ev.size, &world.stm)
                    {
                        // suppress HeapHole within 256 events of any
                        // ALLOC to avoid false positives from cross-thread ring
                        // reordering (WRITE arrives before its ALLOC on a different ring).
                        // OOB is never suppressed; it references a known allocation boundary.
                        const HEAP_HOLE_GRACE: u64 = 256;
                        if matches!(h.kind, HazardKind::HeapHole)
                            && world.total_event_count.saturating_sub(world.last_alloc_event_count)
                                < HEAP_HOLE_GRACE
                        {
                            // within grace window; discard probable false positive
                        } else {
                            let dominated = world
                                .hazards
                                .iter()
                                .any(|prev| prev.write_addr == h.write_addr);
                            if !dominated {
                                h.pc = ev.rip_lo as u64;
                                h.reg_snapshot = shadow_regs.get(&ev.thread_id).map(|srf| srf.values());
                                if let Some(ref mut ts) = topo {
                                    let kind_str = match h.kind {
                                        HazardKind::OutOfBounds => "OOB",
                                        HazardKind::HeapHole => "HOLE",
                                    };
                                    ts.emit_hazard(
                                        ev.seq32() as u64,
                                        kind_str,
                                        h.write_addr,
                                        h.write_size,
                                        h.alloc_base,
                                        h.alloc_size,
                                        h.overflow_bytes,
                                        h.type_name.as_deref(),
                                        h.field_name.as_deref(),
                                    );
                                }
                                world.hazards.push(h);
                            }
                        }
                    }
                }
            }
            if let Some(h) = addr_index.lookup(ev.addr) {
                let nid = h.node_id;
                let h_name = h.name.to_string();
                let h_type_name = h.type_info.name.clone();
                let is_ptr = h.type_info.is_pointer;
                // defer TypeInfo clone: only needed when inserting a new node
                if !world.node_exists(nid) {
                    let h_type = h.type_info.clone();
                    world.ensure_node(nid, &h_name, &h_type, ev.addr, ev.size as u64);
                }
                world.update_value(nid, val, world.insn_counter());
                if is_ptr && ev.size == 8 {
                    let target = if ev.value == 0 {
                        None
                    } else {
                        addr_index.lookup(ev.value).map(|t| t.node_id)
                    };
                    world.update_edge(nid, target, ev.value);
                    if ev.value != 0 {
                        let is_heap = heap_oracle.is_heap(ev.value);
                        if is_heap {
                            if let Some(ref mut info) = dwarf_info {
                                let pointee_name =
                                    h_type_name.strip_prefix('*').unwrap_or("").to_string();
                                info.ensure_type(&pointee_name);
                                if let Some(pointee_ti) =
                                    info.type_registry.get(&pointee_name).cloned()
                                {
                                    let mut patched = pointee_ti;
                                    info.patch_shallow_fields(&mut patched);
                                    world.heap_allocs.check_size(ev.value, &patched);
                                    let stamp_res = world.stm.stamp_type(
                                        ev.value,
                                        &patched,
                                        &h_name,
                                        ev.seq32() as u64,
                                    );
                                    match &stamp_res {
                                        StampResult::Schism { old_type, old_source, old_stamp_seq }
                                        | StampResult::PoolReuse { old_type, old_source, old_stamp_seq } => {
                                            let is_reuse = matches!(stamp_res, StampResult::PoolReuse { .. });
                                            if let Some(alloc_size) = world.heap_allocs.alloc_size(ev.value) {
                                                let fake_proj = crate::world::TypeProjection {
                                                    base_addr: ev.value,
                                                    type_info: TypeInfo { name: old_type.clone(), byte_size: alloc_size, fields: vec![], is_pointer: false, is_volatile: false, is_atomic: false, shallow: false },
                                                    source_name: old_source.clone(),
                                                    stamp_seq: *old_stamp_seq,
                                                };
                                                world.type_epochs.close_epoch(ev.value, alloc_size, &fake_proj, ev.seq32() as u64, EpochClose::Schism);
                                            }
                                            if !is_reuse {
                                                thread_local! {
                                                    static ONLINE_SCHISM_COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
                                                }
                                                ONLINE_SCHISM_COUNT.with(|c| {
                                                    let n = c.get() + 1;
                                                    c.set(n);
                                                    if n <= 20 {
                                                        eprintln!(
                                                            "rtmap: TYPE_SCHISM at 0x{:x}: {} (via {}) overwrites {} (via {})",
                                                            ev.value, patched.name, h_name, old_type, old_source
                                                        );
                                                    } else if n == 21 {
                                                        eprintln!("rtmap: suppressing further online TYPE_SCHISM messages");
                                                    }
                                                });
                                            }
                                            if let Some(ref mut ts) = topo {
                                                ts.emit_type_schism(
                                                    ev.seq32() as u64,
                                                    ev.value,
                                                    old_type,
                                                    &patched.name,
                                                    old_source,
                                                    &h_name,
                                                );
                                                let close_reason = if is_reuse { "pool_reuse" } else { "schism" };
                                                ts.emit_type_epoch_close(ev.seq32() as u64, ev.value, old_type, old_source, *old_stamp_seq, ev.seq32() as u64, close_reason);
                                            }
                                        }
                                        _ => {}
                                    }
                                    if matches!(stamp_res, StampResult::Stamped | StampResult::Schism { .. } | StampResult::PoolReuse { .. }) {
                                        orch.bloom_insert(ev.value);
                                        world.stm.replay_deferred(
                                            ev.value, patched.byte_size,
                                            &info.type_registry, &world.heap_allocs,
                                        );
                                        world.stm.retrospective_scan(
                                            ev.value,
                                            heap_graph,
                                            &world.heap_allocs,
                                            &info.type_registry,
                                            ev.seq32() as u64,
                                            world.proc_mem.as_ref(),
                                        );
                                        if let Some(ref mut ts) = topo {
                                            ts.emit_stamp(
                                                ev.seq32() as u64,
                                                ev.value,
                                                &patched.name,
                                                patched.byte_size,
                                                &h_name,
                                                patched.fields.len(),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(ref mut ts) = topo {
                            let pointee_name =
                                h_type_name.strip_prefix('*').unwrap_or(&h_type_name);
                            ts.emit_link(
                                ev.seq32() as u64,
                                &h_name,
                                ev.addr,
                                ev.value,
                                pointee_name,
                                &h_name,
                            );
                        }
                    }
                }
                return true;
            }
            false
        }
        EVENT_CALL => {
            {
                let srf = shadow_regs.entry(ev.thread_id).or_default();
                srf.on_call(ev.addr, ev.value, ev.seq32() as u64);
            }
            heap_oracle.update_stack(ev.thread_id, ev.value);
            if let Some(ref info) = dwarf_info {
                let elf_pc = match *relocation_delta {
                    Some(d) => ev.addr.wrapping_sub(d),
                    None => ev.addr,
                };
                if let Some(func) = info.functions.get(&elf_pc) {
                    let fid = *next_frame_id;
                    *next_frame_id += 1;
                    let tid = ev.thread_id;
                    stacks
                        .entry(tid)
                        .or_insert_with(ShadowStack::new)
                        .push_call(fid, ev.addr, func.name.clone());
                    for (li, l) in func.locals.iter().enumerate() {
                        let piece = l
                            .location
                            .lookup(elf_pc)
                            .or_else(|| l.location.entries.first().map(|(_, p)| p));
                        let addr = match piece {
                            Some(dwarf::LocationPiece::FrameBaseOffset(_))
                            | Some(dwarf::LocationPiece::RegisterOffset(_, _))
                            | None => (ev.value as i64 + l.frame_offset) as u64,
                            Some(p) => {
                                let regs = world.regs();
                                dwarf::resolve_location(p, &regs, ev.value, func.frame_base_is_cfa)
                                    .unwrap_or((ev.value as i64 + l.frame_offset) as u64)
                            }
                        };
                        let nid = NodeId::Local(fid, li as u16);
                        world.ensure_node(nid, &l.name, &l.type_info, addr, l.size);
                    }
                    let locals: Vec<_> = func
                        .locals
                        .iter()
                        .map(|l| (l.frame_offset, l.size, l.name.clone(), l.type_info.clone()))
                        .collect();
                    if !locals.is_empty() {
                        addr_index.insert_frame_locals(fid, ev.value, &locals);
                    }
                }
            }
            true
        }
        EVENT_RETURN => {
            {
                let srf = shadow_regs.entry(ev.thread_id).or_default();
                if let Some(ref info) = dwarf_info {
                    let callee_pc = srf.callee_pc();
                    if let Some(saved) = callee_pc.and_then(|pc| info.cfi.saved_regs_at(pc)) {
                        srf.on_return_cfi(ev.seq32() as u64, ev.addr, saved);
                    } else {
                        srf.on_return(ev.seq32() as u64, ev.addr);
                    }
                } else {
                    srf.on_return(ev.seq32() as u64, ev.addr);
                }
            }
            let tid = ev.thread_id;
            if let Some(stack) = stacks.get_mut(&tid) {
                if let Some(frame) = stack.pop_return() {
                    addr_index.remove_frame(frame.frame_id);
                    returned_frames.push_back(frame.frame_id);
                    while returned_frames.len() > 32 {
                        if let Some(old_fid) = returned_frames.pop_front() {
                            world.remove_frame_nodes(old_fid);
                        }
                    }
                }
            }
            true
        }
        EVENT_REG_SNAPSHOT => {
            // handled by apply_reg_snapshot() on the drained batch; see note there.
            let _ = (orch, ring_idx);
            true
        }
        EVENT_CACHE_MISS => {
            if let Some(h) = addr_index.lookup(ev.addr) {
                world.record_cache_miss(h.node_id);
            }
            true
        }
        EVENT_RELOAD => {
            let reg_idx = ((ev.kind_flags >> 8) & 0xFF) as usize;
            let srf = shadow_regs.entry(ev.thread_id).or_default();
            srf.on_reload(
                reg_idx,
                ev.value,
                ev.addr,
                ev.size,
                ev.seq32() as u64,
                ev.addr,
            );
            true
        }
        EVENT_ALLOC => {
            world.last_alloc_event_count = world.total_event_count;
            let ptr = ev.addr;
            // ev.value carries full 64-bit size; ev.size is uint32_t (truncates >4GB)
            let size = if ev.value != 0 { ev.value } else { ev.size as u64 };
            let is_duplicate = match world.heap_allocs.on_alloc(ptr, size) {
                Some(old_size) if old_size == size => true,  // nested wrapper (zmalloc->malloc)
                Some(old_size) => {
                    // realloc at same address with different size; close prior epoch
                    if let Some(proj) = world.stm.lookup(ptr).cloned() {
                        let seq = ev.seq32() as u64;
                        world.type_epochs.close_epoch(ptr, old_size, &proj, seq, EpochClose::Realloc);
                        if let Some(ref mut ts) = topo {
                            ts.emit_type_epoch_close(seq, ptr, &proj.type_info.name, &proj.source_name, proj.stamp_seq, seq, "realloc");
                        }
                    }
                    world.stm.purge_range(ptr, old_size);
                    heap_graph.on_free(ptr, old_size);
                    false
                }
                None => false,
            };
            if !is_duplicate {
                if let Some(ref mut ts) = topo {
                    ts.emit_alloc(ev.seq32() as u64, ev.thread_id, ptr, size);
                }
            }
            // alloc-site type oracle: stamp at birth.
            // build caller PC stack: rip_lo (malloc's caller, e.g. zmalloc) +
            // shadow stack frames (application callers above allocator wrappers).
            if let (Some(ref mut info), Some(delta)) = (dwarf_info, *relocation_delta) {
                let delta_lo = delta & 0xFFFF_FFFF;
                let mut caller_pcs = ArrayVec::<u64, 8>::new();
                if ev.rip_lo != 0 {
                    caller_pcs.push((ev.rip_lo as u64).wrapping_sub(delta_lo));
                }
                if let Some(stack) = stacks.get(&ev.thread_id) {
                    for frame in stack.frames.iter().rev().take(6) {
                        if caller_pcs.is_full() { break; }
                        let elf_pc = frame.callee_pc.wrapping_sub(delta);
                        if !caller_pcs.contains(&elf_pc) {
                            caller_pcs.push(elf_pc);
                        }
                    }
                }
                // enrich with inlined subroutine PCs: if any caller_pc falls
                // within an inlined function, add its low_pc so the oracle can
                // match alloc-site signatures that originate from inlined callers.
                // under -O3 aggressive inlining, the shadow stack has no CALL for
                // inlined functions; this closes the oracle's blind spot.
                {
                    let base_len = caller_pcs.len();
                    for i in 0..base_len {
                        if caller_pcs.is_full() { break; }
                        let pc = caller_pcs[i];
                        // scan up to 3 preceding BTreeMap entries for overlapping inlines
                        for (fpc, func) in info.functions.range(..=pc).rev().take(3) {
                            if pc < func.high_pc && func.name.starts_with("[inlined]") {
                                if !caller_pcs.contains(fpc) && !caller_pcs.is_full() {
                                    caller_pcs.push(*fpc);
                                }
                            }
                        }
                    }
                }
                if let Some(ti) = info.alloc_oracle.resolve(size, &caller_pcs).cloned() {
                    let source_pc = caller_pcs.first().copied().unwrap_or(0);
                    let source = format!("alloc@{:#x}", source_pc);
                    info.ensure_type(&ti.name);
                    let mut stamp_ti = info.type_registry.get(&ti.name).cloned().unwrap_or(ti);
                    info.patch_shallow_fields(&mut stamp_ti);
                    let stamp_res = world.stm.stamp_type(ptr, &stamp_ti, &source, ev.seq32() as u64);
                    if matches!(stamp_res, StampResult::Stamped | StampResult::Schism { .. } | StampResult::PoolReuse { .. }) {
                        orch.bloom_insert(ptr);
                        // bloom-insert field offsets: protects initialization writes
                        // from tiered backpressure shedding (BP=2)
                        for field in &stamp_ti.fields {
                            orch.bloom_insert(ptr + field.byte_offset);
                        }
                        world.stm.replay_deferred(
                            ptr, stamp_ti.byte_size,
                            &info.type_registry, &world.heap_allocs,
                        );
                        world.stm.retrospective_scan(
                            ptr, heap_graph, &world.heap_allocs,
                            &info.type_registry, ev.seq32() as u64,
                            world.proc_mem.as_ref(),
                        );
                        if let Some(ref mut ts) = topo {
                            ts.emit_stamp(
                                ev.seq32() as u64, ptr, &stamp_ti.name,
                                stamp_ti.byte_size, &source, stamp_ti.fields.len(),
                            );
                        }
                    }
                }
            }
            true
        }
        EVENT_FREE => {
            let ptr = ev.addr;
            let freed_size = world.heap_allocs.on_free(ptr);
            if let Some(old_size) = freed_size {
                // close type epoch before purge destroys the projection
                if let Some(proj) = world.stm.lookup(ptr).cloned() {
                    let seq = ev.seq32() as u64;
                    world.type_epochs.close_epoch(ptr, old_size, &proj, seq, EpochClose::Free);
                    if let Some(ref mut ts) = topo {
                        ts.emit_type_epoch_close(seq, ptr, &proj.type_info.name, &proj.source_name, proj.stamp_seq, seq, "free");
                    }
                }
                world.stm.purge_range(ptr, old_size);
                world.stm.purge_indirect(ptr, old_size);
                world.stm.purge_deferred(ptr, old_size);
                heap_graph.on_free(ptr, old_size);
                if let Some(ref mut ts) = topo {
                    ts.emit_free(ev.seq32() as u64, ev.thread_id, ptr, old_size);
                }
            } else if let Some(proj) = world.stm.lookup(ptr).cloned() {
                // orphan free: alloc happened during PHASE_BOOT (untracked).
                // purge the warm-scan stamp to prevent schism on address reuse.
                let purge_size = proj.type_info.byte_size;
                let seq = ev.seq32() as u64;
                world.type_epochs.close_epoch(ptr, purge_size, &proj, seq, EpochClose::Free);
                if let Some(ref mut ts) = topo {
                    ts.emit_type_epoch_close(seq, ptr, &proj.type_info.name, &proj.source_name, proj.stamp_seq, seq, "free");
                }
                world.stm.purge_range(ptr, purge_size);
                world.stm.purge_indirect(ptr, purge_size);
                world.stm.purge_deferred(ptr, purge_size);
                heap_graph.on_free(ptr, purge_size);
            }
            true
        }
        EVENT_READ => {
            world.inc_insn_counter();
            if heap_oracle.is_heap(ev.addr) && ev.value != 0 {
                if let Some(covering) = world.stm.covering(ev.addr) {
                    let offset = ev.addr - covering.base_addr;
                    let tn = &covering.type_info.name;
                    if let Some(field) =
                        covering.type_info.fields.iter().find(|f| {
                            offset >= f.byte_offset && offset < f.byte_offset + f.byte_size
                        })
                    {
                        world.field_heatmap.record_read(
                            ev.thread_id,
                            tn,
                            &field.name,
                            field.byte_offset,
                        );
                    }
                }
            }
            true
        }
        EVENT_BB_ENTRY => {
            world.record_bb_entry(ev.rip_lo);
            true
        }
        EVENT_MODULE_LOAD => {
            heap_oracle.add_module(ev.addr, ev.value);
            if relocation_delta.is_none() {
                if let Some(ref info) = dwarf_info {
                    let runtime_base = ev.addr;
                    let delta = runtime_base.wrapping_sub(info.elf_base_vaddr);
                    eprintln!(
                        "rtmap: relocation delta=0x{:x} (runtime=0x{:x} elf=0x{:x})",
                        delta, runtime_base, info.elf_base_vaddr
                    );
                    *relocation_delta = Some(delta);
                    *addr_index = AddressIndex::new();
                    populate_globals(info, delta, addr_index, world);
                }
            }
            true
        }
        EVENT_PROCESS_FORK => {
            let child_pid = ev.addr as u32;
            let parent_pid = ev.value as u32;
            eprintln!(
                "rtmap: PROCESS_FORK child_pid={} parent_pid={}",
                child_pid, parent_pid
            );
            true
        }
        EVENT_SHARED_MAP => {
            // in-band shared mapping notification from syscall hooks.
            // size==0xFFFFFFFF sentinel = munmap; otherwise mmap.
            let map_addr = ev.addr;
            let length = ev.value;
            let is_unmap = ev.size == 0xFFFFFFFF;
            if is_unmap {
                eprintln!(
                    "rtmap: SHARED_UNMAP addr=0x{:x} len=0x{:x}",
                    map_addr, length
                );
            } else {
                let fd = ev.size as i32;
                eprintln!(
                    "rtmap: SHARED_MAP addr=0x{:x} len=0x{:x} fd={}",
                    map_addr, length, fd
                );
            }
            // engine's SharedIntervalMap updated by caller (main.rs)
            // via world.shared_map_events; we just log here.
            true
        }
        _ => false,
    }
}

pub fn populate_globals(
    info: &DwarfInfo,
    delta: u64,
    addr_index: &mut AddressIndex,
    world: &mut WorldState,
) {
    for (i, g) in info.globals.iter().enumerate() {
        let base = g.addr.wrapping_add(delta);
        let gi = i as u32;
        addr_index.insert_global(base, g.size, g.name.clone(), g.type_info.clone(), gi);
        world.remove_node(NodeId::Global(gi));
        world.ensure_node(NodeId::Global(gi), &g.name, &g.type_info, base, g.size);
        // globals with struct fields are statically typed; seed STM directly
        if !g.type_info.fields.is_empty() && g.type_info.byte_size > 0 {
            world.stm.stamp_type(base, &g.type_info, &g.name, 0);
        }
        if g.type_info.is_pointer {
            continue;
        }
        let mut fi_counter: u16 = 0;
        register_fields_recursive(
            &g.name,
            base,
            &g.type_info,
            gi,
            &mut fi_counter,
            addr_index,
            world,
            0,
        );
    }
    addr_index.finalize();
}

/// read the tracer's sidecar module table from /dev/shm/rtmap_modules_<pid>.
/// retries briefly since the tracer may still be writing it.
/// returns vec of (runtime_base, full_path). cleans up the sidecar after reading.
fn read_module_table(pid: u32) -> Vec<(u64, String)> {
    let path = format!("/dev/shm/rtmap_modules_{}", pid);
    let content = match std::fs::read_to_string(&path) {
        Ok(c) if !c.is_empty() => c,
        _ => return Vec::new(),
    };
    content.lines().filter_map(|line| {
        let mut parts = line.splitn(2, ' ');
        let base = u64::from_str_radix(parts.next()?, 16).ok()?;
        let path = parts.next()?.to_string();
        if path.is_empty() { None } else { Some((base, path)) }
    }).collect()
}

pub fn cleanup_module_table(pid: u32) {
    let path = format!("/dev/shm/rtmap_modules_{}", pid);
    let _ = std::fs::remove_file(&path);
}

/// relocate library globals + functions into addr_index and DwarfInfo.functions
/// using the tracer's sidecar module table (immune to DR's private loader).
/// returns (0,0) silently if sidecar is missing or incomplete; caller retries.
pub fn populate_lib_globals(
    info: &mut DwarfInfo,
    pid: u32,
    addr_index: &mut AddressIndex,
    world: &mut WorldState,
) -> (usize, usize) {
    let modtab = read_module_table(pid);
    if modtab.is_empty() {
        return (0, 0);
    }

    // pre-check: all libraries must be resolvable before we commit any changes
    let mut deltas: Vec<u64> = Vec::with_capacity(info.lib_globals.len());
    for lg in &info.lib_globals {
        let lib_basename = lg.lib_path.rsplit('/').next().unwrap_or(&lg.lib_path);
        let found = modtab.iter().find_map(|(base, path)| {
            if path == &lg.lib_path
                || path.rsplit('/').next() == Some(lib_basename)
            {
                Some(*base)
            } else {
                None
            }
        });
        match found {
            Some(load_addr) => deltas.push(load_addr.wrapping_sub(lg.elf_base_vaddr)),
            None => return (0, 0), // sidecar incomplete, retry later
        }
    }

    let base_gi = info.globals.len() as u32;
    let mut total_g = 0u32;
    let mut total_f = 0usize;

    let libs = std::mem::take(&mut info.lib_globals);

    for (i, lg) in libs.iter().enumerate() {
        let delta = deltas[i];
        let lib_basename = lg.lib_path.rsplit('/').next().unwrap_or(&lg.lib_path);

        for g in &lg.globals {
            let addr = g.addr.wrapping_add(delta);
            let gi = base_gi + total_g;
            total_g += 1;
            addr_index.insert_global(addr, g.size, g.name.clone(), g.type_info.clone(), gi);
            world.ensure_node(NodeId::Global(gi), &g.name, &g.type_info, addr, g.size);
            if !g.type_info.fields.is_empty() && g.type_info.byte_size > 0 {
                world.stm.stamp_type(addr, &g.type_info, &g.name, 0);
            }
            if g.type_info.is_pointer {
                continue;
            }
            let mut fi_counter: u16 = 0;
            register_fields_recursive(
                &g.name, addr, &g.type_info, gi,
                &mut fi_counter, addr_index, world, 0,
            );
        }

        // relocate function PCs and merge into info.functions
        for (elf_pc, func) in &lg.functions {
            let runtime_pc = elf_pc.wrapping_add(delta);
            let mut relocated = func.clone();
            relocated.low_pc = runtime_pc;
            relocated.high_pc = func.high_pc.wrapping_add(delta);
            info.functions.insert(runtime_pc, relocated);
            total_f += 1;
        }

        eprintln!(
            "rtmap: lib dwarf: {} — {} globals, {} functions at delta=0x{:x}",
            lib_basename, lg.globals.len(), lg.functions.len(), delta
        );
    }

    // restore (now empty, but keeps the field valid)
    info.lib_globals = libs;

    if total_g > 0 {
        addr_index.finalize();
    }
    (total_g as usize, total_f)
}

#[allow(clippy::too_many_arguments)]
fn register_fields_recursive(
    parent_name: &str,
    parent_base: u64,
    parent_type: &crate::dwarf::TypeInfo,
    gi: u32,
    fi_counter: &mut u16,
    addr_index: &mut AddressIndex,
    world: &mut WorldState,
    depth: u32,
) {
    if depth > 6 {
        return;
    }
    for f in &parent_type.fields {
        if f.byte_size == 0 || f.name == "<pointee>" {
            continue;
        }
        let faddr = parent_base + f.byte_offset;
        let fi = *fi_counter;
        if fi == u16::MAX {
            return;
        }
        *fi_counter = fi + 1;
        let fid = NodeId::Field(gi, fi);
        let qualified = format!("{}.{}", parent_name, f.name);
        addr_index.insert_field(
            faddr,
            f.byte_size,
            qualified.clone(),
            f.type_info.clone(),
            gi,
            fi,
        );
        world.remove_node(fid);
        world.ensure_node(fid, &qualified, &f.type_info, faddr, f.byte_size);
        if !f.type_info.is_pointer && !f.type_info.fields.is_empty() && f.byte_size > 8 {
            register_fields_recursive(
                &qualified,
                faddr,
                &f.type_info,
                gi,
                fi_counter,
                addr_index,
                world,
                depth + 1,
            );
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct WarmScanStats {
    pub reads: u64,
    pub stamps_applied: u64,
    pub max_depth_reached: u32,
    pub read_errors: u64,
    pub queue_visits: u64,
    pub enqueued: u64,
    pub null_ptrs: u64,
    pub missing_pointee_ti: u64,
    pub not_heap: u64,
    pub globals_scanned: u64,
    pub container_of_stamps: u64,
    pub schisms: u64,
    pub queue_cap_hits: u64,
}

// hard BFS limit; prevents runaway on dense overlapping globals
pub const WARM_SCAN_QUEUE_CAP: usize = 50_000;

pub struct WarmScanner {
    mem: File,
    queue: VecDeque<(u64, TypeInfo, String, u32)>,
    visited: HashSet<u64>,
    pub stats: WarmScanStats,
    pub passes: u32,
    max_depth: u32,
    pub seeded: bool,
}

impl WarmScanner {
    pub fn new(pid: u32, max_depth: u32) -> io::Result<Self> {
        let mem = File::open(format!("/proc/{}/mem", pid))?;
        Ok(Self {
            mem,
            queue: VecDeque::new(),
            visited: HashSet::new(),
            stats: WarmScanStats::default(),
            passes: 0,
            max_depth,
            seeded: false,
        })
    }

    #[cfg(test)]
    pub fn from_file(mem: File, max_depth: u32) -> Self {
        Self {
            mem,
            queue: VecDeque::new(),
            visited: HashSet::new(),
            stats: WarmScanStats::default(),
            passes: 0,
            max_depth,
            seeded: false,
        }
    }

    pub fn is_idle(&self) -> bool {
        self.seeded && self.queue.is_empty()
    }

    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    // seed queue from globals; call before first step or to re-scan.
    pub fn seed(
        &mut self,
        info: &mut DwarfInfo,
        delta: u64,
        heap_oracle: &HeapOracle,
        topo: &mut Option<TopologyStream>,
        stm: &mut crate::world::ShadowTypeMap,
        alloc_tracker: &crate::world::HeapAllocTracker,
    ) {
        // ensure_type on each global's type so depth-truncated structs
        // (e.g. redisServer with 600+ fields) are fully materialized
        // before scan_ptr_fields iterates their fields.
        let global_names: Vec<String> = info.globals.iter().map(|g| g.type_info.name.clone()).collect();
        for tn in &global_names {
            info.ensure_type(tn);
        }
        // rebuild global type_info from the now-deep registry
        // two-pass to avoid borrow conflict: collect patches, then apply
        let patches: Vec<(usize, TypeInfo)> = info.globals.iter().enumerate()
            .filter_map(|(i, g)| {
                info.type_registry.get(&g.type_info.name)
                    .filter(|fresh| fresh.fields.len() > g.type_info.fields.len())
                    .map(|fresh| (i, fresh.clone()))
            }).collect();
        for (i, ti) in patches {
            info.globals[i].type_info = ti;
        }
        for idx in 0..info.globals.len() {
            let mut ti = info.globals[idx].type_info.clone();
            info.patch_shallow_fields(&mut ti);
            info.globals[idx].type_info = ti;
        }
        
        for g in &info.globals {
            let base = g.addr.wrapping_add(delta);
            self.stats.globals_scanned += 1;
            scan_ptr_fields(
                &self.mem,
                base,
                &g.type_info,
                &g.name,
                1,
                &mut self.queue,
                &mut self.stats,
                heap_oracle,
                &info.type_registry,
                &info.container_of_map,
                topo,
                u64::MAX,
                stm,
                alloc_tracker,
                &self.visited,
            );
        }
        self.seeded = true;
        self.passes += 1;
    }

    // process up to `budget` reads from the queue. returns stamps applied this step.
    pub fn step(
        &mut self,
        budget: u64,
        info: &mut DwarfInfo,
        world: &mut WorldState,
        heap_oracle: &HeapOracle,
        topo: &mut Option<TopologyStream>,
    ) -> u64 {
        let start_reads = self.stats.reads;
        let mut stamps_this_step = 0u64;

        while let Some((target_addr, mut pointee_ti, source_name, depth)) = self.queue.pop_front() {
            // ensure full type graph is materialized before field iteration
            if pointee_ti.shallow || pointee_ti.fields.is_empty() {
                info.ensure_type(&pointee_ti.name);
                if let Some(fresh) = info.type_registry.get(&pointee_ti.name) {
                    if fresh.fields.len() > pointee_ti.fields.len() {
                        pointee_ti = fresh.clone();
                    }
                }
                info.patch_shallow_fields(&mut pointee_ti);
            }
            if self.stats.reads - start_reads >= budget {
                self.queue
                    .push_front((target_addr, pointee_ti, source_name, depth));
                break;
            }
            if depth > self.max_depth {
                continue;
            }
            if !self.visited.insert(target_addr) {
                continue;
            }
            self.stats.queue_visits += 1;
            self.stats.max_depth_reached = self.stats.max_depth_reached.max(depth);

            if heap_oracle.is_heap(target_addr) {
                world.heap_allocs.check_size(target_addr, &pointee_ti);
            } else {
                self.stats.not_heap += 1;
            }
            let stamp_res = world
                .stm
                .stamp_type(target_addr, &pointee_ti, &source_name, 0);
            match &stamp_res {
                StampResult::Schism { ref old_type, ref old_source, old_stamp_seq } => {
                    self.stats.schisms += 1;
                    if self.stats.schisms <= 10 {
                        eprintln!(
                            "rtmap: TYPE_SCHISM (warm-scan) at 0x{:x}: {} (via {}) overwrites {} (via {})",
                            target_addr, pointee_ti.name, source_name, old_type, old_source
                        );
                    } else if self.stats.schisms == 11 {
                        eprintln!("rtmap: suppressing further TYPE_SCHISM messages (dense global layout)");
                    }
                    if let Some(alloc_size) = world.heap_allocs.alloc_size(target_addr) {
                        let fake_proj = crate::world::TypeProjection {
                            base_addr: target_addr,
                            type_info: TypeInfo { name: old_type.clone(), byte_size: alloc_size, fields: vec![], is_pointer: false, is_volatile: false, is_atomic: false, shallow: false },
                            source_name: old_source.clone(),
                            stamp_seq: *old_stamp_seq,
                        };
                        world.type_epochs.close_epoch(target_addr, alloc_size, &fake_proj, 0, EpochClose::Schism);
                    }
                    if let Some(ref mut ts) = topo {
                        ts.emit_type_schism(0, target_addr, old_type, &pointee_ti.name, old_source, &source_name);
                        ts.emit_type_epoch_close(0, target_addr, old_type, old_source, *old_stamp_seq, 0, "schism");
                    }
                }
                StampResult::PoolReuse { ref old_type, ref old_source, old_stamp_seq } => {
                    if let Some(ref mut ts) = topo {
                        ts.emit_type_epoch_close(0, target_addr, old_type, old_source, *old_stamp_seq, 0, "pool_reuse");
                    }
                }
                _ => {}
            }
            if matches!(stamp_res, StampResult::Stamped | StampResult::Schism { .. } | StampResult::PoolReuse { .. }) {
                self.stats.stamps_applied += 1;
                stamps_this_step += 1;
                world.stm.replay_deferred(
                    target_addr, pointee_ti.byte_size,
                    &info.type_registry, &world.heap_allocs,
                );
                if let Some(ref mut ts) = topo {
                    ts.emit_cold_stamp(
                        target_addr,
                        &pointee_ti.name,
                        pointee_ti.byte_size,
                        &source_name,
                        pointee_ti.fields.len(),
                        depth,
                    );
                }
            }
            // retroscan with mem fallback: catches pointer fields in nested
            // structs that scan_ptr_fields might miss due to depth limits
            if pointee_ti.fields.iter().any(|f| f.type_info.is_pointer && f.byte_size == 8) {
                // dummy heap_graph; warm-scan relies on mem reads, not HeapGraph
                let empty_hg = crate::heap_graph::HeapGraph::new();
                world.stm.retrospective_scan(
                    target_addr,
                    &empty_hg,
                    &world.heap_allocs,
                    &info.type_registry,
                    0,
                    Some(&self.mem),
                );
            }
            scan_ptr_fields(
                &self.mem,
                target_addr,
                &pointee_ti,
                &source_name,
                depth + 1,
                &mut self.queue,
                &mut self.stats,
                heap_oracle,
                &info.type_registry,
                &info.container_of_map,
                topo,
                u64::MAX,
                &mut world.stm,
                &world.heap_allocs,
                &self.visited,
            );
        }
        stamps_this_step
    }
}

// one-shot BFS (retained for replay and backward compat)
#[allow(clippy::too_many_arguments)]
pub fn warm_scan(
    info: &DwarfInfo,
    pid: u32,
    delta: u64,
    world: &mut WorldState,
    heap_oracle: &HeapOracle,
    topo: &mut Option<TopologyStream>,
    max_reads: u64,
    max_depth: u32,
) -> io::Result<WarmScanStats> {
    let mem_path = format!("/proc/{}/mem", pid);
    let mem = File::open(&mem_path)?;
    let mut stats = WarmScanStats::default();
    let mut visited: HashSet<u64> = HashSet::new();
    let mut queue: VecDeque<(u64, TypeInfo, String, u32)> = VecDeque::new();

    for g in &info.globals {
        if stats.reads >= max_reads {
            break;
        }
        let base = g.addr.wrapping_add(delta);
        stats.globals_scanned += 1;
        scan_ptr_fields(
            &mem,
            base,
            &g.type_info,
            &g.name,
            1,
            &mut queue,
            &mut stats,
            heap_oracle,
            &info.type_registry,
            &info.container_of_map,
            topo,
            max_reads,
            &mut world.stm,
            &world.heap_allocs,
            &visited,
        );
    }

    while let Some((target_addr, pointee_ti, source_name, depth)) = queue.pop_front() {
        if stats.reads >= max_reads {
            break;
        }
        if depth > max_depth {
            continue;
        }
        if !visited.insert(target_addr) {
            continue;
        }
        stats.queue_visits += 1;
        stats.max_depth_reached = stats.max_depth_reached.max(depth);

        let on_heap = heap_oracle.is_heap(target_addr);
        if on_heap {
            world.heap_allocs.check_size(target_addr, &pointee_ti);
        } else {
            stats.not_heap += 1;
        }
        let stamp_res = world
            .stm
            .stamp_type(target_addr, &pointee_ti, &source_name, 0);
        match &stamp_res {
            StampResult::Schism { ref old_type, ref old_source, old_stamp_seq } => {
                eprintln!(
                    "rtmap: TYPE_SCHISM (legacy warm-scan) at 0x{:x}: {} (via {}) overwrites {} (via {})",
                    target_addr, pointee_ti.name, source_name, old_type, old_source
                );
                if let Some(alloc_size) = world.heap_allocs.alloc_size(target_addr) {
                    let fake_proj = crate::world::TypeProjection {
                        base_addr: target_addr,
                        type_info: TypeInfo { name: old_type.clone(), byte_size: alloc_size, fields: vec![], is_pointer: false, is_volatile: false, is_atomic: false, shallow: false },
                        source_name: old_source.clone(),
                        stamp_seq: *old_stamp_seq,
                    };
                    world.type_epochs.close_epoch(target_addr, alloc_size, &fake_proj, 0, EpochClose::Schism);
                }
                if let Some(ref mut ts) = topo {
                    ts.emit_type_schism(0, target_addr, old_type, &pointee_ti.name, old_source, &source_name);
                    ts.emit_type_epoch_close(0, target_addr, old_type, old_source, *old_stamp_seq, 0, "schism");
                }
            }
            StampResult::PoolReuse { ref old_type, ref old_source, old_stamp_seq } => {
                if let Some(ref mut ts) = topo {
                    ts.emit_type_epoch_close(0, target_addr, old_type, old_source, *old_stamp_seq, 0, "pool_reuse");
                }
            }
            _ => {}
        }
        if matches!(stamp_res, StampResult::Stamped | StampResult::Schism { .. } | StampResult::PoolReuse { .. }) {
            stats.stamps_applied += 1;
            world.stm.replay_deferred(
                target_addr, pointee_ti.byte_size,
                &info.type_registry, &world.heap_allocs,
            );
            if let Some(ref mut ts) = topo {
                ts.emit_cold_stamp(
                    target_addr,
                    &pointee_ti.name,
                    pointee_ti.byte_size,
                    &source_name,
                    pointee_ti.fields.len(),
                    depth,
                );
            }
        }
        scan_ptr_fields(
            &mem,
            target_addr,
            &pointee_ti,
            &source_name,
            depth + 1,
            &mut queue,
            &mut stats,
            heap_oracle,
            &info.type_registry,
            &info.container_of_map,
            topo,
            max_reads,
            &mut world.stm,
            &world.heap_allocs,
            &visited,
        );
    }

    Ok(stats)
}

#[allow(clippy::only_used_in_recursion, clippy::too_many_arguments)]
fn scan_ptr_fields(
    mem: &File,
    base: u64,
    ti: &TypeInfo,
    source: &str,
    depth: u32,
    queue: &mut VecDeque<(u64, TypeInfo, String, u32)>,
    stats: &mut WarmScanStats,
    heap_oracle: &HeapOracle,
    type_registry: &HashMap<String, TypeInfo>,
    container_of_map: &HashMap<String, Vec<dwarf::ContainerOfEntry>>,
    topo: &mut Option<TopologyStream>,
    max_reads: u64,
    stm: &mut crate::world::ShadowTypeMap,
    alloc_tracker: &crate::world::HeapAllocTracker,
    visited: &HashSet<u64>,
) {
    for f in &ti.fields {
        if stats.reads >= max_reads {
            return;
        }
        if f.name == "<pointee>" {
            continue;
        }
        let faddr = base.wrapping_add(f.byte_offset);
        if f.type_info.is_pointer && f.byte_size == 8 {
            let mut buf = [0u8; 8];
            match mem.read_at(&mut buf, faddr) {
                Ok(8) => {
                    stats.reads += 1;
                    let ptr = u64::from_le_bytes(buf);
                    if ptr == 0 {
                        stats.null_ptrs += 1;
                        continue;
                    }
                    let pointee_name = f.type_info.name.strip_prefix('*').unwrap_or("");
                    let qualified = format!("{}.{}", source, f.name);
                    let pointee_ti_opt = type_registry.get(pointee_name).cloned().or_else(|| {
                        f.type_info
                            .fields
                            .iter()
                            .find(|sf| sf.name == "<pointee>")
                            .map(|sf| sf.type_info.clone())
                    });
                    match pointee_ti_opt {
                        Some(pointee_ti) if pointee_ti.byte_size > 0 => {
                            if let Some(ref mut ts) = topo {
                                ts.emit_cold_link(source, faddr, ptr, pointee_name, &f.name);
                            }
                            // container_of: if this pointee type is embedded inside
                            // a larger struct at a non-zero offset, also enqueue the
                            // container base (ptr - offset) with the container type.
                            if let Some(containers) = container_of_map.get(pointee_name) {
                                for entry in containers {
                                    if queue.len() >= WARM_SCAN_QUEUE_CAP {
                                        stats.queue_cap_hits += 1;
                                        break;
                                    }
                                    let container_base = ptr.wrapping_sub(entry.field_offset);
                                    if container_base != 0
                                        && !visited.contains(&container_base)
                                        && heap_oracle.is_plausible_ptr(container_base)
                                    {
                                        if let Some(container_ti) = type_registry.get(&entry.container_type) {
                                            let cof_source = format!("{}->container_of({}.{})",
                                                qualified, entry.container_type, entry.field_name);
                                            queue.push_back((container_base, container_ti.clone(), cof_source, depth));
                                            stats.container_of_stamps += 1;
                                            stats.enqueued += 1;
                                        }
                                    }
                                }
                            }
                            if !visited.contains(&ptr) && queue.len() < WARM_SCAN_QUEUE_CAP {
                                queue.push_back((ptr, pointee_ti, qualified, depth));
                                stats.enqueued += 1;
                            } else if queue.len() >= WARM_SCAN_QUEUE_CAP {
                                stats.queue_cap_hits += 1;
                            }
                        }
                        _ if pointee_name.starts_with('*') => {
                            // **T: ptr is base of an allocation holding *T slots.
                            // register indirect so online propagation stamps writes into it.
                            // also read through the array to enqueue reachable T elements.
                            let inner_name = pointee_name.strip_prefix('*').unwrap_or("");
                            if let Some(inner_ti) = type_registry.get(inner_name) {
                                // heap_oracle VMA check: alloc_tracker may miss due to event loss
                                if heap_oracle.is_heap(ptr) {
                                    stm.register_indirect(ptr, inner_ti.clone());
                                    stm.indirect_registrations += 1;
                                }
                                // read through: the allocation at ptr holds *T pointers.
                                // prefer alloc_tracker size; fall back to 16 slots for VMA-only hits
                                let slot_limit = alloc_tracker.alloc_size(ptr)
                                    .map(|sz| (sz / 8).min(128) as usize)
                                    .unwrap_or_else(|| if heap_oracle.is_heap(ptr) { 16 } else { 0 });
                                for slot_idx in 0..slot_limit {
                                    if stats.reads >= max_reads {
                                        break;
                                    }
                                    let slot_addr = ptr + (slot_idx as u64) * 8;
                                    let mut sbuf = [0u8; 8];
                                    match mem.read_at(&mut sbuf, slot_addr) {
                                        Ok(8) => {
                                            stats.reads += 1;
                                            let elem = u64::from_le_bytes(sbuf);
                                            if elem != 0 && heap_oracle.is_plausible_ptr(elem) {
                                                if !visited.contains(&elem) && queue.len() < WARM_SCAN_QUEUE_CAP {
                                                    let elem_source = format!("{}[{}]", qualified, slot_idx);
                                                    queue.push_back((elem, inner_ti.clone(), elem_source, depth + 1));
                                                    stats.enqueued += 1;
                                                } else if queue.len() >= WARM_SCAN_QUEUE_CAP {
                                                    stats.queue_cap_hits += 1;
                                                }
                                            }
                                        }
                                        _ => { stats.read_errors += 1; break; }
                                    }
                                }
                            }
                        }
                        _ => {
                            stats.missing_pointee_ti += 1;
                        }
                    }
                }
                Ok(_) | Err(_) => stats.read_errors += 1,
            }
        } else if !f.type_info.is_pointer && !f.type_info.fields.is_empty() && depth <= 6 {
            scan_ptr_fields(
                mem,
                faddr,
                &f.type_info,
                &format!("{}.{}", source, f.name),
                depth + 1,
                queue,
                stats,
                heap_oracle,
                type_registry,
                container_of_map,
                topo,
                max_reads,
                stm,
                alloc_tracker,
                visited,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap_graph::{HeapGraph, HeapOracle};
    use crate::index::AddressIndex;
    use crate::ring::{Event, RingOrchestrator};
    use crate::shadow_regs::ShadowRegisterFile;
    use crate::world::{ShadowStack, WorldState};
    use std::collections::{HashMap, VecDeque};

    fn make_bb_entry_event(rip_lo: u32) -> Event {
        Event {
            addr: 0x4000_0000 + rip_lo as u64,
            size: 0,
            thread_id: 0,
            seq: 1,
            value: 0,
            kind_flags: EVENT_BB_ENTRY as u32,
            rip_lo,
        }
    }

    fn make_unknown_event() -> Event {
        Event {
            addr: 0,
            size: 0,
            thread_id: 0,
            seq: 0,
            value: 0,
            kind_flags: 0xFF,
            rip_lo: 0,
        }
    }

    #[test]
    fn test_process_event_bb_entry() {
        let orch = RingOrchestrator::new();
        let mut world = WorldState::new();
        let mut addr_index = AddressIndex::new();
        let mut dwarf_info: Option<DwarfInfo> = None;
        let mut stacks: HashMap<u16, ShadowStack> = HashMap::new();
        let mut next_frame_id: u64 = 0;
        let mut relocation_delta: Option<u64> = None;
        let mut returned_frames: VecDeque<u64> = VecDeque::new();
        let mut shadow_regs: HashMap<u16, ShadowRegisterFile> = HashMap::new();
        let mut heap_graph = HeapGraph::new();
        let mut heap_oracle = HeapOracle::new();
        let mut topo: Option<TopologyStream> = None;

        let ev = make_bb_entry_event(0xABCD);
        let accepted = process_event(
            &ev,
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
        assert!(
            accepted,
            "BB_ENTRY must return true, not fall through to _ => false"
        );
        assert_eq!(world.insn_counter(), 1);
        assert_eq!(world.bb_hits[&0xABCD], 1);

        // second hit to same BB
        let ev2 = make_bb_entry_event(0xABCD);
        let accepted2 = process_event(
            &ev2,
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
        assert!(accepted2);
        assert_eq!(world.insn_counter(), 2);
        assert_eq!(world.bb_hits[&0xABCD], 2);

        // different BB
        let ev3 = make_bb_entry_event(0x1234);
        process_event(
            &ev3,
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
        assert_eq!(world.bb_hits.len(), 2);
        assert_eq!(world.bb_hits[&0x1234], 1);
    }

    #[test]
    fn test_process_event_read() {
        let orch = RingOrchestrator::new();
        let mut world = WorldState::new();
        let mut addr_index = AddressIndex::new();
        let mut dwarf_info: Option<DwarfInfo> = None;
        let mut stacks: HashMap<u16, ShadowStack> = HashMap::new();
        let mut next_frame_id: u64 = 0;
        let mut relocation_delta: Option<u64> = None;
        let mut returned_frames: VecDeque<u64> = VecDeque::new();
        let mut shadow_regs: HashMap<u16, ShadowRegisterFile> = HashMap::new();
        let mut heap_graph = HeapGraph::new();
        let mut heap_oracle = HeapOracle::new();
        let mut topo: Option<TopologyStream> = None;

        let ev = Event {
            addr: 0x5555_0000_1000,
            size: 8,
            thread_id: 0,
            seq: 1,
            value: 0xDEAD_BEEF,
            kind_flags: EVENT_READ as u32,
            rip_lo: 0,
        };
        let accepted = process_event(
            &ev,
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
        assert!(accepted, "EVENT_READ must be accepted");
        assert_eq!(world.insn_counter(), 1, "read must increment insn_counter");
    }

    #[test]
    fn test_abi_event_kind_parity() {
        // these must match rtmap_bridge.h RTMAP_EVENT_* defines exactly.
        // any drift here is a silent data corruption bug.
        assert_eq!(EVENT_WRITE, 0, "EVENT_WRITE != RTMAP_EVENT_WRITE");
        assert_eq!(EVENT_READ, 1, "EVENT_READ != RTMAP_EVENT_READ");
        assert_eq!(EVENT_CALL, 2, "EVENT_CALL != RTMAP_EVENT_CALL");
        assert_eq!(EVENT_RETURN, 3, "EVENT_RETURN != RTMAP_EVENT_RETURN");
        assert_eq!(
            EVENT_REG_SNAPSHOT, 5,
            "EVENT_REG_SNAPSHOT != RTMAP_EVENT_REG_SNAPSHOT"
        );
        assert_eq!(
            EVENT_CACHE_MISS, 6,
            "EVENT_CACHE_MISS != RTMAP_EVENT_CACHE_MISS"
        );
        assert_eq!(
            EVENT_MODULE_LOAD, 7,
            "EVENT_MODULE_LOAD != RTMAP_EVENT_MODULE_LOAD"
        );
        assert_eq!(EVENT_ALLOC, 9, "EVENT_ALLOC != RTMAP_EVENT_ALLOC");
        assert_eq!(EVENT_FREE, 10, "EVENT_FREE != RTMAP_EVENT_FREE");
        assert_eq!(
            EVENT_BB_ENTRY, 11,
            "EVENT_BB_ENTRY != RTMAP_EVENT_BB_ENTRY"
        );
        assert_eq!(EVENT_RELOAD, 12, "EVENT_RELOAD != RTMAP_EVENT_RELOAD");
        assert_eq!(
            EVENT_PROCESS_FORK, 13,
            "EVENT_PROCESS_FORK != RTMAP_EVENT_PROCESS_FORK"
        );
    }

    #[test]
    fn test_abi_event_struct_size() {
        // Event must be 32 bytes to match rtmap_event_v3_t
        assert_eq!(
            std::mem::size_of::<Event>(),
            32,
            "Event struct size drift — ABI mismatch with rtmap_event_v3_t"
        );
    }

    #[test]
    fn test_process_event_unknown_kind_rejected() {
        let orch = RingOrchestrator::new();
        let mut world = WorldState::new();
        let mut addr_index = AddressIndex::new();
        let mut dwarf_info: Option<DwarfInfo> = None;
        let mut stacks: HashMap<u16, ShadowStack> = HashMap::new();
        let mut next_frame_id: u64 = 0;
        let mut relocation_delta: Option<u64> = None;
        let mut returned_frames: VecDeque<u64> = VecDeque::new();
        let mut shadow_regs: HashMap<u16, ShadowRegisterFile> = HashMap::new();
        let mut heap_graph = HeapGraph::new();
        let mut heap_oracle = HeapOracle::new();
        let mut topo: Option<TopologyStream> = None;

        let ev = make_unknown_event();
        let accepted = process_event(
            &ev,
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
        assert!(!accepted, "unknown kind must return false");
        assert_eq!(world.insn_counter(), 0);
        assert!(world.bb_hits.is_empty());
    }

    // a->b->c pointer chain in a synthetic pread-able file
    fn make_synthetic_mem() -> (std::fs::File, dwarf::DwarfInfo) {
        use std::collections::BTreeMap;
        use std::os::unix::fs::FileExt;
        let path = &format!("/tmp/rtmap_test_synth_mem_{:?}", std::thread::current().id());
        let f = std::fs::File::create(path).unwrap();
        let mut buf = vec![0u8; 0x4000];
        buf[0x1000..0x1008].copy_from_slice(&0x2000u64.to_le_bytes());
        buf[0x2000..0x2008].copy_from_slice(&0x3000u64.to_le_bytes());
        buf[0x3000..0x3004].copy_from_slice(&42u32.to_le_bytes());
        f.write_all_at(&buf, 0).unwrap();

        let mk = |name: &str, sz: u64, ptr: bool, fields: Vec<dwarf::FieldInfo>| dwarf::TypeInfo {
            name: name.into(),
            byte_size: sz,
            is_pointer: ptr,
            is_volatile: false,
            is_atomic: false,
            shallow: false,
            fields,
        };
        let loc = dwarf::LocationTable { entries: vec![] };
        let ti_c = mk(
            "struct_c",
            4,
            false,
            vec![dwarf::FieldInfo {
                name: "val".into(),
                byte_offset: 0,
                byte_size: 4,
                type_info: mk("int", 4, false, vec![]),
                alignment: 0,
            }],
        );
        let ti_b = mk(
            "struct_b",
            8,
            false,
            vec![dwarf::FieldInfo {
                name: "ptr_to_c".into(),
                byte_offset: 0,
                byte_size: 8,
                type_info: mk(
                    "*struct_c",
                    8,
                    true,
                    vec![dwarf::FieldInfo {
                        name: "<pointee>".into(),
                        byte_offset: 0,
                        byte_size: 4,
                        type_info: ti_c.clone(),
                        alignment: 0,
                    }],
                ),
                alignment: 0,
            }],
        );
        let ti_a = mk(
            "struct_a",
            8,
            false,
            vec![dwarf::FieldInfo {
                name: "ptr_to_b".into(),
                byte_offset: 0,
                byte_size: 8,
                type_info: mk(
                    "*struct_b",
                    8,
                    true,
                    vec![dwarf::FieldInfo {
                        name: "<pointee>".into(),
                        byte_offset: 0,
                        byte_size: 8,
                        type_info: ti_b.clone(),
                        alignment: 0,
                    }],
                ),
                alignment: 0,
            }],
        );

        let mut type_registry: HashMap<String, dwarf::TypeInfo> = HashMap::new();
        type_registry.insert("struct_a".into(), ti_a.clone());
        type_registry.insert("struct_b".into(), ti_b);
        type_registry.insert("struct_c".into(), ti_c);

        let info = dwarf::DwarfInfo {
            globals: vec![dwarf::GlobalVar {
                name: "global_a".into(),
                addr: 0x1000,
                size: 8,
                type_info: ti_a,
                location: loc,
            }],
            functions: BTreeMap::new(),
            elf_base_vaddr: 0,
            type_registry,
            container_of_map: HashMap::new(),
            cfi: dwarf::CfiTable::default(),
            elf_path: String::new(),
            name_accel: None,
            lib_globals: Vec::new(),
            alloc_oracle: dwarf::AllocSiteOracle::empty(),
            types_materialized: 0,
        };
        let f = std::fs::File::open(path).unwrap();
        (f, info)
    }

    #[test]
    fn test_warm_scanner_full_traversal() {
        let (mem, mut info) = make_synthetic_mem();
        let mut scanner = WarmScanner::from_file(mem, 8);
        let mut world = WorldState::new();
        let oracle = HeapOracle::new();
        let mut topo: Option<TopologyStream> = None;

        assert!(!scanner.seeded);
        scanner.seed(&mut info, 0, &oracle, &mut topo, &mut world.stm, &world.heap_allocs);
        assert!(scanner.seeded);
        assert!(!scanner.is_idle());

        let stamps = scanner.step(1000, &mut info, &mut world, &oracle, &mut topo);
        assert!(stamps > 0);
        assert!(scanner.is_idle());
        assert_eq!(scanner.passes, 1);
        assert!(scanner.stats.reads > 0);
    }

    #[test]
    fn test_warm_scanner_budget_exhaustion_and_resume() {
        let (mem, mut info) = make_synthetic_mem();
        let mut scanner = WarmScanner::from_file(mem, 8);
        let mut world = WorldState::new();
        let oracle = HeapOracle::new();
        let mut topo: Option<TopologyStream> = None;

        scanner.seed(&mut info, 0, &oracle, &mut topo, &mut world.stm, &world.heap_allocs);
        let mut total_stamps = 0u64;
        let mut steps = 0u32;
        while !scanner.is_idle() {
            total_stamps += scanner.step(1, &mut info, &mut world, &oracle, &mut topo);
            steps += 1;
            assert!(steps < 100, "runaway BFS");
        }

        // parity: step-by-step == one-shot
        let (mem2, mut info2) = make_synthetic_mem();
        let mut sc2 = WarmScanner::from_file(mem2, 8);
        let mut w2 = WorldState::new();
        sc2.seed(&mut info2, 0, &oracle, &mut topo, &mut w2.stm, &w2.heap_allocs);
        let oneshot = sc2.step(1000, &mut info2, &mut w2, &oracle, &mut topo);

        assert_eq!(
            total_stamps, oneshot,
            "step-by-step stamps != one-shot stamps"
        );
        assert_eq!(
            scanner.stats.reads, sc2.stats.reads,
            "step-by-step reads != one-shot reads"
        );
    }

    #[test]
    fn test_warm_scanner_reseed() {
        let (mem, mut info) = make_synthetic_mem();
        let mut scanner = WarmScanner::from_file(mem, 8);
        let mut world = WorldState::new();
        let oracle = HeapOracle::new();
        let mut topo: Option<TopologyStream> = None;

        scanner.seed(&mut info, 0, &oracle, &mut topo, &mut world.stm, &world.heap_allocs);
        scanner.step(1000, &mut info, &mut world, &oracle, &mut topo);
        assert!(scanner.is_idle());
        assert_eq!(scanner.passes, 1);
        let r1 = scanner.stats.reads;

        scanner.seed(&mut info, 0, &oracle, &mut topo, &mut world.stm, &world.heap_allocs);
        assert_eq!(scanner.passes, 2);
        scanner.step(1000, &mut info, &mut world, &oracle, &mut topo);
        assert!(scanner.is_idle());
        assert!(scanner.stats.reads >= r1);
    }
}
