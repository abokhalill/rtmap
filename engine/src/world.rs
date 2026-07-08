// SPDX-License-Identifier: Apache-2.0
// world state: variables, pointer edges, register file, cache miss tracking.
// arc-wrapped inner for cow snapshotting - mutation clones only when shared.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;

/// Key for per-thread, per-field write heatmap.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FieldHeatKey {
    pub thread_id: u16,
    pub type_name: String,
    pub field_name: String,
    pub field_offset: u64,
}

// compact key: zero-alloc hot path. strings resolved via intern table on export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CompactHeatKey {
    thread_id: u16,
    type_id: u32,
    field_id: u32,
    field_offset: u64,
}

/// Per-field write heatmap: tracks how many times each thread writes to each
/// typed field on STM-projected heap addresses. Used to produce symbolic
/// pressure maps for cacheline contention analysis.
#[derive(Debug, Clone)]
pub struct FieldHeatmap {
    counts: HashMap<CompactHeatKey, u64>,
    read_counts: HashMap<CompactHeatKey, u64>,
    // intern tables: string -> id and id -> string
    str_to_id: HashMap<String, u32>,
    id_to_str: Vec<String>,
    pub contention_hits: u64,
}

impl Default for FieldHeatmap {
    fn default() -> Self {
        Self {
            counts: HashMap::with_capacity(512),
            read_counts: HashMap::with_capacity(256),
            str_to_id: HashMap::with_capacity(128),
            id_to_str: Vec::with_capacity(128),
            contention_hits: 0,
        }
    }
}

impl FieldHeatmap {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn intern(&mut self, s: &str) -> u32 {
        if let Some(&id) = self.str_to_id.get(s) {
            return id;
        }
        let id = self.id_to_str.len() as u32;
        self.id_to_str.push(s.to_string());
        self.str_to_id.insert(s.to_string(), id);
        id
    }

    #[inline]
    pub fn record(&mut self, thread_id: u16, type_name: &str, field_name: &str, field_offset: u64) {
        let type_id = self.intern(type_name);
        let field_id = self.intern(field_name);
        let key = CompactHeatKey { thread_id, type_id, field_id, field_offset };
        *self.counts.entry(key).or_insert(0) += 1;
    }

    #[inline]
    pub fn record_read(
        &mut self,
        thread_id: u16,
        type_name: &str,
        field_name: &str,
        field_offset: u64,
    ) {
        let type_id = self.intern(type_name);
        let field_id = self.intern(field_name);
        let key = CompactHeatKey { thread_id, type_id, field_id, field_offset };
        *self.read_counts.entry(key).or_insert(0) += 1;
    }

    pub fn len(&self) -> usize {
        self.counts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    pub fn read_len(&self) -> usize {
        self.read_counts.len()
    }

    // resolve compact key to string key (cold path only)
    fn resolve(&self, k: &CompactHeatKey) -> FieldHeatKey {
        FieldHeatKey {
            thread_id: k.thread_id,
            type_name: self.id_to_str.get(k.type_id as usize).cloned().unwrap_or_default(),
            field_name: self.id_to_str.get(k.field_id as usize).cloned().unwrap_or_default(),
            field_offset: k.field_offset,
        }
    }

    // TSV export for divergence analysis: type\tfield\toffset\tthread\twrites
    pub fn export_tsv(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::io::BufWriter::new(std::fs::File::create(path)?);
        writeln!(f, "type\tfield\toffset\tthread\twrites")?;
        let mut entries: Vec<_> = self.counts.iter()
            .map(|(k, &c)| (self.resolve(k), c))
            .collect();
        entries.sort_by(|a, b| {
            a.0.type_name
                .cmp(&b.0.type_name)
                .then(a.0.field_offset.cmp(&b.0.field_offset))
                .then(a.0.thread_id.cmp(&b.0.thread_id))
        });
        for (k, c) in &entries {
            writeln!(
                f,
                "{}\t{}\t{}\t{}\t{}",
                k.type_name, k.field_name, k.field_offset, k.thread_id, c
            )?;
        }
        f.flush()
    }

    /// Return all entries sorted by write count descending.
    pub fn top_entries(&self, limit: usize) -> Vec<(FieldHeatKey, u64)> {
        let mut v: Vec<_> = self.counts.iter()
            .map(|(k, &c)| (self.resolve(k), c))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(limit);
        v
    }

    pub fn top_read_entries(&self, limit: usize) -> Vec<(FieldHeatKey, u64)> {
        let mut v: Vec<_> = self.read_counts.iter()
            .map(|(k, &c)| (self.resolve(k), c))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(limit);
        v
    }

    /// For a given cacheline address, find all fields written by different threads.
    /// Returns groups: type_name.field_name -> set of (thread_id, write_count).
    pub fn contention_report(&self, cl_tracker: &CacheLineTracker) -> Vec<ContentionEntry> {
        // group by (type_name, field_name, field_offset)
        let mut by_field: HashMap<(String, String, u64), Vec<(u16, u64)>> = HashMap::new();
        for (key, &count) in &self.counts {
            let r = self.resolve(key);
            by_field
                .entry((r.type_name, r.field_name, r.field_offset))
                .or_default()
                .push((key.thread_id, count));
        }
        let mut result = Vec::new();
        for ((type_name, field_name, field_offset), threads) in &by_field {
            if threads.len() < 2 {
                continue;
            }
            let total: u64 = threads.iter().map(|(_, c)| c).sum();
            let mut ts = threads.clone();
            ts.sort_by(|a, b| b.1.cmp(&a.1));
            result.push(ContentionEntry {
                type_name: type_name.clone(),
                field_name: field_name.clone(),
                field_offset: *field_offset,
                threads: ts,
                total_writes: total,
            });
        }
        let _ = cl_tracker;
        result.sort_by(|a, b| b.total_writes.cmp(&a.total_writes));
        result
    }
}

#[derive(Debug, Clone)]
pub struct ContentionEntry {
    pub type_name: String,
    pub field_name: String,
    pub field_offset: u64,
    pub threads: Vec<(u16, u64)>,
    pub total_writes: u64,
}

use crate::dwarf::TypeInfo;
use crate::index::NodeId;

pub const REG_NAMES: &[&str] = &[
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15", "rip", "rflags",
];
pub const REG_COUNT: usize = 18;

#[derive(Debug, Clone)]
pub struct LiveRegisterFile {
    pub values: [u64; REG_COUNT],
    pub prev: [u64; REG_COUNT],
    pub insn: u64,
}

impl LiveRegisterFile {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            values: [0; REG_COUNT],
            prev: [0; REG_COUNT],
            insn: 0,
        }
    }
    pub fn update(&mut self, regs: [u64; REG_COUNT], insn: u64) {
        self.prev = self.values;
        self.values = regs;
        self.insn = insn;
    }
}

const CL_SHIFT: u32 = 6;
const CL_SLOTS: usize = 16384;
const CL_MASK: usize = CL_SLOTS - 1;

#[derive(Debug, Clone, Copy, Default)]
pub struct ClSlot {
    pub cl_addr: u64,
    pub write_count: u16,
    pub writers: u16,
    // per-writer counts for observation-bias correction.
    // indexed by thread_id & 15. allows distinguishing real
    // contention from asymmetric backpressure artifacts.
    pub per_writer: [u16; 16],
}

#[derive(Debug, Clone)]
pub struct CacheLineTracker {
    pub slots: Box<[ClSlot; CL_SLOTS]>,
}

impl Default for CacheLineTracker {
    fn default() -> Self {
        Self {
            slots: Box::new([ClSlot::default(); CL_SLOTS]),
        }
    }
}

impl CacheLineTracker {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline(always)]
    pub fn record_write(&mut self, addr: u64, thread_id: u16) -> u16 {
        let cl = addr >> CL_SHIFT;
        let idx = (cl as usize) & CL_MASK;
        let ti = (thread_id & 15) as usize;
        let s = unsafe { self.slots.get_unchecked_mut(idx) };
        if s.cl_addr != cl {
            *s = ClSlot {
                cl_addr: cl,
                write_count: 1,
                writers: 1u16 << ti,
                ..ClSlot::default()
            };
            s.per_writer[ti] = 1;
            return s.writers;
        }
        s.write_count = s.write_count.saturating_add(1);
        s.writers |= 1u16 << ti;
        s.per_writer[ti] = s.per_writer[ti].saturating_add(1);
        s.writers
    }

    // raw thread count, no bias correction
    pub fn contention_score(&self, addr: u64) -> u32 {
        let cl = addr >> CL_SHIFT;
        let idx = (cl as usize) & CL_MASK;
        let s = &self.slots[idx];
        if s.cl_addr == cl {
            s.writers.count_ones()
        } else {
            0
        }
    }

    // bias-corrected: only count threads whose write fraction exceeds
    // `min_frac` of the total writes to this cache line. filters out
    // threads that wrote once due to backpressure asymmetry or noise.
    // min_frac=0.01 means a thread must account for >=1% of writes.
    pub fn contention_score_weighted(&self, addr: u64, min_frac: f32) -> u32 {
        let cl = addr >> CL_SHIFT;
        let idx = (cl as usize) & CL_MASK;
        let s = &self.slots[idx];
        if s.cl_addr != cl || s.write_count == 0 {
            return 0;
        }
        let total = s.write_count as f32;
        let threshold = (total * min_frac).max(1.0);
        let mut count = 0u32;
        let mut mask = s.writers;
        while mask != 0 {
            let bit = mask.trailing_zeros() as usize;
            if s.per_writer[bit] as f32 >= threshold {
                count += 1;
            }
            mask &= mask - 1;
        }
        count
    }

    // per writer breakdown for a cache line. returns (thread_idx, writes) pairs.
    pub fn writer_breakdown(&self, addr: u64) -> Vec<(u8, u16)> {
        let cl = addr >> CL_SHIFT;
        let idx = (cl as usize) & CL_MASK;
        let s = &self.slots[idx];
        if s.cl_addr != cl {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut mask = s.writers;
        while mask != 0 {
            let bit = mask.trailing_zeros() as u8;
            out.push((bit, s.per_writer[bit as usize]));
            mask &= mask - 1;
        }
        out
    }

    pub fn tick(&mut self) {
        for s in self.slots.iter_mut() {
            s.write_count >>= 1;
            if s.write_count == 0 {
                s.writers = 0;
                s.cl_addr = 0;
                s.per_writer = [0; 16];
            } else {
                // decay per-writer counts in lockstep
                for pw in s.per_writer.iter_mut() {
                    *pw >>= 1;
                }
                // recompute writer mask from surviving counts
                let mut new_mask = 0u16;
                for (i, &pw) in s.per_writer.iter().enumerate() {
                    if pw > 0 {
                        new_mask |= 1u16 << i;
                    }
                }
                s.writers = new_mask;
            }
        }
    }
}

const DECAY_FACTOR: f32 = 0.95;

#[derive(Debug, Clone)]
pub struct CacheMissEntry {
    pub count: u32,
    pub heat: f32,
}

#[derive(Debug, Clone)]
pub struct CacheHeatmap {
    pub per_node: HashMap<NodeId, CacheMissEntry>,
}

impl CacheHeatmap {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            per_node: HashMap::new(),
        }
    }
    pub fn record_miss(&mut self, nid: NodeId) {
        let e = self.per_node.entry(nid).or_insert(CacheMissEntry {
            count: 0,
            heat: 0.0,
        });
        e.count += 1;
        e.heat = (e.heat + 1.0).min(1.0);
    }
    pub fn tick(&mut self) {
        self.per_node.retain(|_, e| {
            e.heat *= DECAY_FACTOR;
            e.heat > 0.01
        });
    }
}

#[derive(Debug, Clone)]
pub struct Node {
    pub name: String,
    pub type_info: TypeInfo,
    pub addr: u64,
    pub size: u64,
    pub raw_value: u64,
    pub last_write_insn: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerEdge {
    pub source: NodeId,
    pub target: NodeId,
    pub ptr_value: u64,
    pub is_dangling: bool,
}

#[derive(Debug, Clone)]
pub struct WorldInner {
    pub nodes: BTreeMap<NodeId, Node>,
    pub edges: BTreeMap<NodeId, PointerEdge>,
    pub insn_counter: u64,
    pub reg_file: LiveRegisterFile,
    pub cache_heat: CacheHeatmap,
}

impl WorldInner {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
            insn_counter: 0,
            reg_file: LiveRegisterFile::new(),
            cache_heat: CacheHeatmap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TypeProjection {
    pub base_addr: u64,
    pub type_info: TypeInfo,
    pub source_name: String,
    pub stamp_seq: u64,
}

/// Result of a stamp_type call. Carries schism info for the caller to act on
pub enum StampResult {
    /// new stamp applied, no prior projection
    Stamped,
    /// stamp applied, prior projection had the same type (re-stamp, not a schism)
    Restamped,
    /// stamp applied, prior projection had a DIFFERENT type; type schism
    Schism {
        old_type: String,
        old_source: String,
        old_stamp_seq: u64,
    },
    /// oscillating types at the same address; pool/arena reuse, not confusion
    PoolReuse {
        old_type: String,
        old_source: String,
        old_stamp_seq: u64,
    },
    /// stamp rejected (null addr or zero-size type)
    Rejected,
}

// deferred pointer write: buffered when propagate_field_write finds no
// covering STM projection. replayed when stamp_type lands a new stamp
// on a region that covers the write address.
const DEFERRED_CAP: usize = 4096;

#[derive(Clone)]
struct DeferredWrite {
    write_addr: u64,
    write_value: u64,
    seq: u64,
}

pub struct ShadowTypeMap {
    map: BTreeMap<u64, TypeProjection>,
    // indirect element map: alloc base -> element TypeInfo.
    // populated when a **T field write stores a pointer to an allocation;
    // that allocation is known to hold *T values (e.g. dict.ht_table -> dictEntry*[]).
    indirect: HashMap<u64, TypeInfo>,
    deferred: VecDeque<DeferredWrite>,
    // per-address schism count; ≥2 → pool/arena reuse
    addr_schisms: HashMap<u64, u16>,
    pub schism_count: u64,
    pub pool_reuse_count: u64,
    pub indirect_stamps: u64,
    pub indirect_registrations: u64,
    pub deferred_replays: u64,
}

impl Default for ShadowTypeMap {
    fn default() -> Self {
        Self {
            map: BTreeMap::new(),
            indirect: HashMap::with_capacity(64),
            deferred: VecDeque::with_capacity(256),
            addr_schisms: HashMap::new(),
            schism_count: 0,
            pool_reuse_count: 0,
            indirect_stamps: 0,
            indirect_registrations: 0,
            deferred_replays: 0,
        }
    }
}

impl ShadowTypeMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stamp_type(
        &mut self,
        target_addr: u64,
        pointee_type: &TypeInfo,
        source_name: &str,
        seq: u64,
    ) -> StampResult {
        if target_addr == 0 || pointee_type.byte_size == 0 {
            return StampResult::Rejected;
        }
        if let Some(existing) = self.map.get(&target_addr) {
            if existing.type_info.name == pointee_type.name {
                return StampResult::Restamped;
            }
            // never overwrite a stamp with a higher seq.
            // cold warm-scan stamps (seq=0) never overwrite online stamps (seq>0).
            // stale indirect/deferred replays (lower seq) never overwrite newer stamps.
            if existing.stamp_seq > seq {
                return StampResult::Rejected;
            }
            let addr_hits = self.addr_schisms.entry(target_addr).or_insert(0);
            *addr_hits = addr_hits.saturating_add(1);
            let is_reuse = *addr_hits >= 2;
            if is_reuse {
                self.pool_reuse_count += 1;
            } else {
                self.schism_count += 1;
            }
            let old_type = existing.type_info.name.clone();
            let old_source = existing.source_name.clone();
            let old_stamp_seq = existing.stamp_seq;
            let result = if is_reuse {
                StampResult::PoolReuse { old_type, old_source, old_stamp_seq }
            } else {
                StampResult::Schism { old_type, old_source, old_stamp_seq }
            };
            let proj = TypeProjection {
                base_addr: target_addr,
                type_info: pointee_type.clone(),
                source_name: source_name.to_string(),
                stamp_seq: seq,
            };
            self.map.insert(target_addr, proj);
            result
        } else {
            let proj = TypeProjection {
                base_addr: target_addr,
                type_info: pointee_type.clone(),
                source_name: source_name.to_string(),
                stamp_seq: seq,
            };
            self.map.insert(target_addr, proj);
            StampResult::Stamped
        }
    }

    /// replay deferred pointer writes against all current STM projections.
    /// convergence loop: each successful propagation may stamp a new region
    /// whose own deferred writes must also be replayed (e.g. A->B->C chains).
    /// capped at 8 passes to bound pathological graphs.
    const REPLAY_MAX_PASSES: usize = 8;

    pub fn replay_deferred(
        &mut self,
        _base: u64,
        _size: u64,
        type_registry: &HashMap<String, TypeInfo>,
        alloc_tracker: &HeapAllocTracker,
    ) -> usize {
        let mut total_replayed = 0usize;
        for _ in 0..Self::REPLAY_MAX_PASSES {
            // drain all entries that now have a covering projection
            let mut hits: Vec<DeferredWrite> = Vec::new();
            self.deferred.retain(|d| {
                let covered = self.map
                    .range(..=d.write_addr)
                    .next_back()
                    .filter(|(_, p)| d.write_addr < p.base_addr + p.type_info.byte_size)
                    .is_some();
                if covered {
                    hits.push(d.clone());
                    false
                } else {
                    true
                }
            });
            if hits.is_empty() {
                break;
            }
            let mut pass_replayed = 0usize;
            for d in &hits {
                if self.propagate_field_write(
                    d.write_addr, d.write_value, 8, d.seq,
                    type_registry, alloc_tracker,
                ) {
                    pass_replayed += 1;
                }
            }
            total_replayed += pass_replayed;
            // no new stamps produced this pass -> no point continuing
            if pass_replayed == 0 {
                break;
            }
        }
        self.deferred_replays += total_replayed as u64;
        total_replayed
    }

    /// buffer an 8-byte pointer write that had no covering STM projection.
    /// bounded ring; oldest entries evicted silently.
    pub fn defer_write(&mut self, write_addr: u64, write_value: u64, seq: u64) {
        if self.deferred.len() >= DEFERRED_CAP {
            self.deferred.pop_front();
        }
        self.deferred.push_back(DeferredWrite { write_addr, write_value, seq });
    }

    /// purge deferred writes for freed range
    pub fn purge_deferred(&mut self, addr: u64, size: u64) {
        let hi = addr.saturating_add(size);
        self.deferred.retain(|d| d.write_addr < addr || d.write_addr >= hi);
    }

    /// resolve *T->T on pointer field writes within stamped regions.
    /// also handles **T->register indirect element type on target alloc.
    /// freshness guard: skip if covering projection predates alloc epoch.
    pub fn propagate_field_write(
        &mut self,
        write_addr: u64,
        write_value: u64,
        write_size: u32,
        seq: u64,
        type_registry: &HashMap<String, TypeInfo>,
        alloc_tracker: &HeapAllocTracker,
    ) -> bool {
        if write_size != 8 || write_value == 0 {
            return false;
        }

        // path 1: write into a region with known indirect element type (e.g. bucket array)
        // the written pointer value is *T; stamp it as T.
        if let Some(element_ti) = self.indirect_lookup(write_addr, alloc_tracker) {
            let res = self.stamp_type(write_value, &element_ti, "<indirect>", seq);
            if matches!(res, StampResult::Stamped | StampResult::Schism { .. } | StampResult::PoolReuse { .. }) {
                self.indirect_stamps += 1;
                return true;
            }
            return false;
        }

        // path 2: write within a stamped struct's field 
        let covering = self
            .map
            .range(..=write_addr)
            .next_back()
            .filter(|(_, p)| write_addr < p.base_addr + p.type_info.byte_size)
            .map(|(_, p)| (p.base_addr, p.stamp_seq, p.type_info.clone()));

        let (base, stamp_seq, ti) = match covering {
            Some(x) => x,
            None => return false,
        };

        if let Some(alloc_seq) = alloc_tracker.alloc_seq(base) {
            if stamp_seq < alloc_seq {
                return false;
            }
        }

        let offset = write_addr - base;
        // union-aware: when multiple fields share the same offset (union layout),
        // prefer the field whose byte_size matches write_size. falls back to
        // largest field at offset (pointer > primitive for propagation).
        let field_match = {
            let candidates: Vec<_> = ti.fields.iter()
                .filter(|f| f.byte_offset == offset && f.name != "<pointee>")
                .collect();
            if candidates.len() <= 1 {
                candidates.into_iter().next()
            } else {
                // exact size match first; then largest (pointers are 8B)
                candidates.iter().copied()
                    .find(|f| f.byte_size == write_size as u64)
                    .or_else(|| candidates.into_iter().max_by_key(|f| f.byte_size))
            }
        };
        if let Some(field) = field_match {
            if field.type_info.is_pointer {
                let pointee_name = field.type_info.name.strip_prefix('*').unwrap_or("");
                if let Some(pointee_ti) = type_registry.get(pointee_name) {
                    // guard: don't create schisms from propagation; with event
                    // loss the write_value may be stale/corrupt. only stamp
                    // unstamped addresses or re-stamps of the same type.
                    if let Some(existing) = self.map.get(&write_value) {
                        if existing.type_info.name != pointee_ti.name {
                            return false;
                        }
                    }
                    let res = self.stamp_type(write_value, pointee_ti, &field.name, seq);
                    if matches!(res, StampResult::Stamped | StampResult::Restamped) {
                        return matches!(res, StampResult::Stamped);
                    }
                } else if pointee_name.starts_with('*') {
                    // **T field: the written value is a pointer to an array of *T.
                    // register the target allocation as holding T elements.
                    let inner_name = pointee_name.strip_prefix('*').unwrap_or("");
                    if let Some(inner_ti) = type_registry.get(inner_name) {
                        self.indirect.insert(write_value, inner_ti.clone());
                        self.indirect_registrations += 1;
                    }
                }
            }
        }
        false
    }

    /// check if addr falls within an allocation whose base is registered in indirect map.
    /// returns the element TypeInfo if so.
    fn indirect_lookup(&self, addr: u64, alloc_tracker: &HeapAllocTracker) -> Option<TypeInfo> {
        // find containing alloc, check if its base is in indirect map
        let (base, size) = alloc_tracker.containing_alloc(addr)?;
        if addr >= base + size {
            return None;
        }
        self.indirect.get(&base).cloned()
    }

    /// register an indirect element type for an allocation base.
    /// called externally when alloc-site or other mechanisms know the element type.
    pub fn register_indirect(&mut self, alloc_base: u64, element_ti: TypeInfo) {
        self.indirect.insert(alloc_base, element_ti);
    }

    /// purge indirect entries for freed range
    pub fn purge_indirect(&mut self, addr: u64, size: u64) {
        let hi = addr.saturating_add(size);
        self.indirect.retain(|&base, _| base < addr || base >= hi);
    }

    pub fn lookup(&self, addr: u64) -> Option<&TypeProjection> {
        self.map.get(&addr)
    }

    pub fn covering(&self, addr: u64) -> Option<&TypeProjection> {
        // O(log N) primary; one backward step if immediate match fails bounds
        // (defends against nested/overlapping sub-projections masking a parent)
        let mut iter = self.map.range(..=addr).rev();
        if let Some((_, p)) = iter.next() {
            if addr < p.base_addr + p.type_info.byte_size {
                return Some(p);
            }
        }
        // fallback: next-lower entry may be a larger parent that spans addr
        if let Some((_, p)) = iter.next() {
            if addr < p.base_addr + p.type_info.byte_size {
                return Some(p);
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn deferred_pending(&self) -> usize {
        self.deferred.len()
    }

    pub fn indirect_len(&self) -> usize {
        self.indirect.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&u64, &TypeProjection)> {
        self.map.iter()
    }

    pub fn purge_range(&mut self, addr: u64, size: u64) -> usize {
        let hi = addr.saturating_add(size);
        let before = self.map.len();
        self.map
            .retain(|_, p| p.base_addr < addr || p.base_addr >= hi);
        before - self.map.len()
    }

    /// bounded BFS from a freshly stamped address. reads pointer values from
    /// HeapGraph first; falls back to /proc/pid/mem when HeapGraph has no data
    /// (typical for fields written before the stamp, i.e. the temporal gap).
    pub fn retrospective_scan(
        &mut self,
        seed_addr: u64,
        heap_graph: &crate::heap_graph::HeapGraph,
        allocs: &HeapAllocTracker,
        type_registry: &HashMap<String, TypeInfo>,
        seq: u64,
        mem: Option<&std::fs::File>,
    ) -> usize {
        use std::os::unix::fs::FileExt;
        // adaptive fuel: scale with root type's pointer field count.
        // deep types (redisServer: ~60 ptrs) get fuel=240; simple structs get floor=64.
        let fuel = match self.map.get(&seed_addr) {
            Some(p) => {
                let ptr_fields = p.type_info.fields.iter()
                    .filter(|f| f.type_info.is_pointer && f.byte_size == 8)
                    .count();
                (ptr_fields * 4).max(64).min(256)
            }
            None => 64,
        };
        let mut queue: VecDeque<u64> = VecDeque::with_capacity(16);
        let mut visited: HashSet<u64> = HashSet::with_capacity(fuel);
        queue.push_back(seed_addr);
        visited.insert(seed_addr);
        let mut stamped = 0usize;

        while let Some(base) = queue.pop_front() {
            if stamped >= fuel {
                break;
            }

            let proj = match self.map.get(&base) {
                Some(p) => p.type_info.clone(),
                None => continue,
            };
            // try HeapGraph for cached field values
            let hg_obj = heap_graph.find_object_base(base).and_then(|hg_base| {
                heap_graph.objects().get(&hg_base).map(|o| (hg_base, o))
            });

            let mut candidates: Vec<(&str, u64, &TypeInfo)> = Vec::new();
            for f in &proj.fields {
                if !f.type_info.is_pointer || f.byte_size != 8 {
                    continue;
                }
                // read field value: HeapGraph first, then /proc/pid/mem fallback
                let field_addr = base.wrapping_add(f.byte_offset);
                let field_val = if let Some((hg_base, obj)) = &hg_obj {
                    let delta = base.wrapping_sub(*hg_base);
                    let hg_offset = delta + f.byte_offset;
                    obj.fields.get(&hg_offset)
                        .map(|fi| fi.last_value)
                        .filter(|&v| v != 0)
                } else {
                    None
                };
                // mem fallback: field not in HeapGraph (pre-stamp write)
                let field_val = match field_val {
                    Some(v) => v,
                    None => {
                        match mem {
                            Some(m) => {
                                let mut buf = [0u8; 8];
                                match m.read_at(&mut buf, field_addr) {
                                    Ok(8) => {
                                        let v = u64::from_le_bytes(buf);
                                        if v == 0 { continue; }
                                        v
                                    }
                                    _ => continue,
                                }
                            }
                            None => continue,
                        }
                    }
                };
                let pointee_name = f.type_info.name.strip_prefix('*').unwrap_or("");
                // when mem is Some, pointer values are live reads; trust aligned non-zero
                // values even if alloc_tracker missed the alloc event (ring overflow)
                let known_alloc = allocs.alloc_size(field_val).is_some();
                let live_plausible = mem.is_some() && field_val > 0x1000 && field_val & 0x7 == 0;
                match type_registry.get(pointee_name) {
                    Some(ti) => {
                        if self.map.contains_key(&field_val) || (!known_alloc && !live_plausible) {
                            continue;
                        }
                        candidates.push((&f.name, field_val, ti));
                    }
                    None if pointee_name.starts_with('*') => {
                        // **T: register target alloc as holding T elements
                        let inner = pointee_name.strip_prefix('*').unwrap_or("");
                        if let Some(inner_ti) = type_registry.get(inner) {
                            if (known_alloc || live_plausible) && !self.indirect.contains_key(&field_val) {
                                self.indirect.insert(field_val, inner_ti.clone());
                                self.indirect_registrations += 1;
                            }
                        }
                    }
                    _ => {}
                };
            }
            candidates.sort_by_key(|(name, _, _)| *name);
            for (name, field_val, pointee_ti) in &candidates {
                if !visited.insert(*field_val) {
                    continue;
                }
                self.stamp_type(*field_val, pointee_ti, name, seq);
                stamped += 1;
                queue.push_back(*field_val);
            }
        }
        stamped
    }
}

// Type epoch log: captures the full lifecycle of typed heap regions.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochClose {
    Free,
    Realloc,
    Schism,
}

#[derive(Debug, Clone)]
pub struct TypeEpoch {
    pub addr: u64,
    pub size: u64,
    pub type_name: String,
    pub source: String,
    pub open_seq: u64,
    pub close_seq: u64,
    pub close_reason: EpochClose,
}

pub struct TypeEpochLog {
    buf: Vec<TypeEpoch>,
    cap: usize,
    head: usize, // next write position
    len: usize,
    pub total_closed: u64,
}

impl TypeEpochLog {
    pub fn new(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap.min(1024)),
            cap,
            head: 0,
            len: 0,
            total_closed: 0,
        }
    }

    #[inline]
    pub fn close_epoch(
        &mut self,
        addr: u64,
        size: u64,
        proj: &TypeProjection,
        close_seq: u64,
        reason: EpochClose,
    ) {
        let epoch = TypeEpoch {
            addr,
            size,
            type_name: proj.type_info.name.clone(),
            source: proj.source_name.clone(),
            open_seq: proj.stamp_seq,
            close_seq,
            close_reason: reason,
        };
        if self.buf.len() < self.cap {
            self.buf.push(epoch);
        } else {
            self.buf[self.head] = epoch;
        }
        self.head = (self.head + 1) % self.cap;
        self.len = (self.len + 1).min(self.cap);
        self.total_closed += 1;
    }

    pub fn query(&self, addr: u64, seq: u64) -> Option<&TypeEpoch> {
        self.iter().find(|e| e.addr == addr && seq >= e.open_seq && seq < e.close_seq)
    }

    pub fn history(&self, addr: u64) -> Vec<&TypeEpoch> {
        self.iter().filter(|e| e.addr == addr).collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = &TypeEpoch> {
        // ring buffer iteration: oldest to newest
        let (a, b) = if self.buf.len() < self.cap {
            (self.buf.as_slice(), &[] as &[TypeEpoch])
        } else {
            let (tail, head) = self.buf.split_at(self.head);
            (head, tail)
        };
        a.iter().chain(b.iter())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn summary(&self) -> BTreeMap<String, EpochStats> {
        let mut out: BTreeMap<String, EpochStats> = BTreeMap::new();
        for e in self.iter() {
            let s = out.entry(e.type_name.clone()).or_insert(EpochStats {
                count: 0,
                total_lifetime: 0,
                by_reason: [0; 3],
            });
            s.count += 1;
            s.total_lifetime += e.close_seq.saturating_sub(e.open_seq);
            s.by_reason[e.close_reason as usize] += 1;
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct EpochStats {
    pub count: u64,
    pub total_lifetime: u64,
    pub by_reason: [u64; 3], // [Free, Realloc, Schism]
}

#[derive(Debug, Clone)]
pub enum HazardKind {
    OutOfBounds,
    HeapHole,
}

#[derive(Debug, Clone)]
pub struct HeapHazard {
    pub kind: HazardKind,
    pub write_addr: u64,
    pub write_size: u32,
    pub alloc_base: u64,
    pub alloc_size: u64,
    pub overflow_bytes: u64,
    pub type_name: Option<String>,
    pub field_name: Option<String>,
    pub pc: u64,
    pub reg_snapshot: Option<[u64; REG_COUNT]>,
}

// type stability monitor: detects writes to STM-stamped regions that violate
// the projected type's field boundaries. two violation classes:
// - interstitial: write offset matches no field (lands in padding or beyond)
// - spanning: write straddles a field boundary or undershoots field size
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationKind {
    Interstitial, // offset hits no field
    Spanning,     // offset within a field but size mismatches
}

#[derive(Debug, Clone)]
pub struct TypeViolation {
    pub kind: ViolationKind,
    pub write_addr: u64,
    pub write_size: u32,
    pub base_addr: u64,
    pub offset: u64,
    pub type_name: String,
    pub expected_field: Option<String>, // populated for Spanning
    pub expected_size: Option<u64>,     // populated for Spanning
    pub pc: u64,
}

pub struct TypeStabilityMonitor {
    // per-type tally: avoids allocating per-event. keyed by type name index
    // in a dense vec to keep the hot path branch-free after the covering() call.
    tally: HashMap<String, TypeStabilityTally>,
    pub violations: Vec<TypeViolation>, // capped, for headless report
    pub total_checked: u64,
    pub total_violations: u64,
}

pub struct TypeStabilityTally {
    pub interstitial: u64,
    pub spanning: u64,
    pub aligned: u64,
    pub synthesized: u64,
}

impl TypeStabilityMonitor {
    pub fn new() -> Self {
        Self {
            tally: HashMap::with_capacity(64),
            violations: Vec::new(),
            total_checked: 0,
            total_violations: 0,
        }
    }

    // hot path: classify a write against a type projection's field layout.
    // fields must be sorted by byte_offset (DWARF guarantees this for structs).
    // returns true if the write is a violation.
    #[inline]
    pub fn check_write(
        &mut self,
        write_addr: u64,
        write_size: u32,
        proj: &TypeProjection,
        pc: u64,
    ) -> bool {
        self.total_checked += 1;
        let offset = write_addr - proj.base_addr;
        let fields = &proj.type_info.fields;

        // empty field list: type is opaque (e.g. primitive typedef). no violation.
        if fields.is_empty() {
            return false;
        }

        // find the field that contains this offset
        let field = fields.iter().find(|f| {
            offset >= f.byte_offset && offset < f.byte_offset + f.byte_size
        });

        let tally = self.tally.entry(proj.type_info.name.clone())
            .or_insert(TypeStabilityTally { interstitial: 0, spanning: 0, aligned: 0, synthesized: 0 });

        match field {
            Some(f) => {
                let field_end = f.byte_offset + f.byte_size;
                let write_end = offset + write_size as u64;
                if write_end > field_end {
                    // wide store: compiler may coalesce adjacent field writes
                    // (e.g. 16B XMM store across two 8B fields). check if
                    // write_end lands exactly on a field boundary.
                    // coalesced: write lands within an adjacent field's boundary
                    let coalesced = fields.iter().any(|nf| {
                        nf.byte_offset >= field_end
                            && nf.byte_offset + nf.byte_size >= write_end
                            && write_end <= nf.byte_offset + nf.byte_size
                    });
                    // tail spill: write extends past the last field into struct
                    // tail padding or alignment space. tolerance scaled by SIMD width:
                    // SSE=8B, AVX2=24B, AVX-512=56B. covers coalesced zero-init
                    // and vectorized memset that overwrite tail padding.
                    let max_tail: u64 = if write_size >= 64 { 56 }
                        else if write_size >= 32 { 24 }
                        else if write_size >= 16 { 8 }
                        else { 0 };
                    let tail_spill = !coalesced
                        && write_end <= proj.type_info.byte_size + max_tail
                        && write_end > proj.type_info.byte_size;
                    if !coalesced && !tail_spill {
                        tally.spanning += 1;
                        self.total_violations += 1;
                        self.record_violation(TypeViolation {
                            kind: ViolationKind::Spanning,
                            write_addr,
                            write_size,
                            base_addr: proj.base_addr,
                            offset,
                            type_name: proj.type_info.name.clone(),
                            expected_field: Some(f.name.clone()),
                            expected_size: Some(f.byte_size),
                            pc,
                        });
                        return true;
                    }
                }
                tally.aligned += 1;
                false
            }
            None => {
                // No field covers this offset. if the write is within the
                // type's declared byte_size, it hits a DWARF shadow zone:
                // feature-gated or macro-disabled fields that occupy real
                // struct space but lack DW_TAG_member entries. synthesize
                // an anonymous field and classify as aligned.
                let write_end = offset + write_size as u64;
                if write_end <= proj.type_info.byte_size {
                    tally.synthesized += 1;
                    tally.aligned += 1;
                    false
                } else {
                    tally.interstitial += 1;
                    self.total_violations += 1;
                    self.record_violation(TypeViolation {
                        kind: ViolationKind::Interstitial,
                        write_addr,
                        write_size,
                        base_addr: proj.base_addr,
                        offset,
                        type_name: proj.type_info.name.clone(),
                        expected_field: None,
                        expected_size: None,
                        pc,
                    });
                    true
                }
            }
        }
    }

    fn record_violation(&mut self, v: TypeViolation) {
        // cap stored violations to avoid unbounded growth; tally is always accurate
        if self.violations.len() < 128 {
            self.violations.push(v);
        }
    }

    pub fn tally_iter(&self) -> impl Iterator<Item = (&str, &TypeStabilityTally)> {
        self.tally.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn is_empty(&self) -> bool {
        self.total_violations == 0
    }
}

#[derive(Default)]
pub struct HeapAllocTracker {
    allocs: BTreeMap<u64, (u64, u64)>, // addr -> (size, alloc_seq)
    pub total_allocs: u64,
    pub total_frees: u64,
    pub orphan_frees: u64,
    pub size_mismatches: Vec<SizeMismatch>,
}

#[derive(Debug, Clone)]
pub struct SizeMismatch {
    pub addr: u64,
    pub alloc_size: u64,
    pub type_size: u64,
    pub type_name: String,
}

impl HeapAllocTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// returns Some(old_size) if the address was already tracked (allocator reuse)
    pub fn on_alloc(&mut self, addr: u64, size: u64) -> Option<u64> {
        let seq = self.total_allocs;
        let old = self.allocs.insert(addr, (size, seq));
        self.total_allocs += 1;
        old.map(|(sz, _)| sz)
    }

    pub fn on_free(&mut self, addr: u64) -> Option<u64> {
        self.total_frees += 1;
        let r = self.allocs.remove(&addr);
        if r.is_none() {
            self.orphan_frees += 1;
        }
        r.map(|(sz, _)| sz)
    }

    pub fn alloc_size(&self, addr: u64) -> Option<u64> {
        self.allocs.get(&addr).map(|&(sz, _)| sz)
    }

    /// returns the alloc_seq for the allocation at addr, if tracked
    pub fn alloc_seq(&self, addr: u64) -> Option<u64> {
        self.allocs.get(&addr).map(|&(_, seq)| seq)
    }

    pub fn allocs_iter(&self) -> impl Iterator<Item = (&u64, &u64)> + '_ {
        self.allocs.iter().map(|(k, (sz, _))| (k, sz))
    }

    pub fn live_count(&self) -> usize {
        self.allocs.len()
    }

    /// O(log N) lookup: find the allocation whose range covers `addr`
    pub fn containing_alloc(&self, addr: u64) -> Option<(u64, u64)> {
        use std::ops::Bound;
        self.allocs
            .range((Bound::Unbounded, Bound::Included(&addr)))
            .next_back()
            .filter(|(&base, &(sz, _))| addr < base.saturating_add(sz))
            .map(|(&base, &(sz, _))| (base, sz))
    }

    /// check if a write at [addr, addr+write_size) stays within a live allocation.
    /// returns Some(hazard) if OOB or heap-hole detected.
    pub fn check_write_bounds(
        &self,
        addr: u64,
        write_size: u32,
        stm: &ShadowTypeMap,
    ) -> Option<HeapHazard> {
        // addr is tracer-supplied; wrap would yield a false in-bounds verdict.
        let end = addr.checked_add(write_size as u64)?;
        if let Some((base, alloc_sz)) = self.containing_alloc(addr) {
            let alloc_end = base.saturating_add(alloc_sz);
            if end > alloc_end {
                let overflow = end - alloc_end;
                let sym = stm.covering(addr).map(|p| {
                    let off = addr - p.base_addr;
                    let field = p
                        .type_info
                        .fields
                        .iter()
                        .find(|f| f.byte_offset == off)
                        .map(|f| f.name.clone());
                    (p.type_info.name.clone(), field)
                });
                return Some(HeapHazard {
                    kind: HazardKind::OutOfBounds,
                    write_addr: addr,
                    write_size,
                    alloc_base: base,
                    alloc_size: alloc_sz,
                    overflow_bytes: overflow,
                    type_name: sym.as_ref().map(|(t, _)| t.clone()),
                    field_name: sym.and_then(|(_, f)| f),
                    pc: 0,
                    reg_snapshot: None,
                });
            }
            return None;
        }
        // only flag heap-hole if addr falls within the span of known allocations
        let lo = self.allocs.keys().next().copied().unwrap_or(u64::MAX);
        let hi = self
            .allocs
            .iter()
            .next_back()
            .map(|(&b, &(s, _))| b + s)
            .unwrap_or(0);
        if addr >= lo && addr < hi {
            return Some(HeapHazard {
                kind: HazardKind::HeapHole,
                write_addr: addr,
                write_size,
                alloc_base: 0,
                alloc_size: 0,
                overflow_bytes: 0,
                type_name: stm.covering(addr).map(|p| p.type_info.name.clone()),
                field_name: None,
                pc: 0,
                reg_snapshot: None,
            });
        }
        None
    }

    pub fn check_size(&mut self, addr: u64, type_info: &TypeInfo) -> bool {
        if let Some(&(alloc_sz, _)) = self.allocs.get(&addr) {
            if type_info.byte_size > alloc_sz {
                self.size_mismatches.push(SizeMismatch {
                    addr,
                    alloc_size: alloc_sz,
                    type_size: type_info.byte_size,
                    type_name: type_info.name.clone(),
                });
                return false;
            }
        }
        true
    }
}

pub struct WorldState {
    inner: Arc<WorldInner>,
    pub cl_tracker: CacheLineTracker,
    pub stm: ShadowTypeMap,
    pub heap_allocs: HeapAllocTracker,
    pub hazards: Vec<HeapHazard>,
    pub field_heatmap: FieldHeatmap,
    pub bb_hits: HashMap<u32, u64>,
    pub type_stability: TypeStabilityMonitor,
    pub type_epochs: TypeEpochLog,
    // /proc/pid/mem handle for retrospective_scan mem fallback
    pub proc_mem: Option<std::fs::File>,
    // monotonic event counter at last ALLOC; HeapHole hazards are
    // suppressed for HEAP_HOLE_GRACE events after any alloc to avoid
    // false positives from cross-thread ALLOC/WRITE ring reordering.
    pub last_alloc_event_count: u64,
    pub total_event_count: u64,
    /// kind-table drift detector; nonzero means tracer emits kinds the
    /// reconciler does not decode
    pub unknown_event_kinds: u64,
}

impl WorldState {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(WorldInner::new()),
            cl_tracker: CacheLineTracker::new(),
            stm: ShadowTypeMap::new(),
            heap_allocs: HeapAllocTracker::new(),
            hazards: Vec::new(),
            field_heatmap: FieldHeatmap::new(),
            bb_hits: HashMap::new(),
            type_stability: TypeStabilityMonitor::new(),
            type_epochs: TypeEpochLog::new(65536),
            proc_mem: None,
            last_alloc_event_count: 0,
            total_event_count: 0,
            unknown_event_kinds: 0,
        }
    }

    pub fn snapshot(&self) -> Arc<WorldInner> {
        Arc::clone(&self.inner)
    }

    #[inline]
    fn cow(&mut self) -> &mut WorldInner {
        Arc::make_mut(&mut self.inner)
    }

    pub fn insn_counter(&self) -> u64 {
        self.inner.insn_counter
    }
    pub fn inc_insn_counter(&mut self) {
        self.cow().insn_counter += 1;
    }

    pub fn record_bb_entry(&mut self, rip_lo: u32) {
        *self.bb_hits.entry(rip_lo).or_insert(0) += 1;
        self.inc_insn_counter();
    }

    #[inline]
    pub fn node_exists(&self, id: NodeId) -> bool {
        self.inner.nodes.contains_key(&id)
    }

    pub fn ensure_node(
        &mut self,
        id: NodeId,
        name: &str,
        type_info: &TypeInfo,
        addr: u64,
        size: u64,
    ) -> bool {
        let inner = self.cow();
        if inner.nodes.contains_key(&id) {
            return false;
        }
        inner.nodes.insert(
            id,
            Node {
                name: name.to_string(),
                type_info: type_info.clone(),
                addr,
                size,
                raw_value: 0,
                last_write_insn: 0,
            },
        );
        true
    }

    pub fn remove_node(&mut self, id: NodeId) {
        let inner = self.cow();
        inner.nodes.remove(&id);
        inner.edges.remove(&id);
    }

    #[inline]
    pub fn update_value(&mut self, id: NodeId, value: u64, insn: u64) {
        if let Some(node) = self.cow().nodes.get_mut(&id) {
            node.raw_value = value;
            node.last_write_insn = insn;
        }
    }

    pub fn remove_frame_nodes(&mut self, frame_id: crate::index::FrameId) {
        let inner = self.cow();
        let dead: Vec<NodeId> = inner
            .nodes
            .keys()
            .filter(|k| matches!(k, NodeId::Local(fid, _) if *fid == frame_id))
            .copied()
            .collect();
        for id in &dead {
            inner.nodes.remove(id);
            inner.edges.remove(id);
        }
        inner.edges.retain(|_, e| !dead.contains(&e.target));
    }

    // null ptr: remove edge. nonzero unresolved: dangling sentinel.
    pub fn update_edge(&mut self, source: NodeId, target: Option<NodeId>, ptr_value: u64) {
        let inner = self.cow();
        match target {
            Some(tgt) => {
                inner.edges.insert(
                    source,
                    PointerEdge {
                        source,
                        target: tgt,
                        ptr_value,
                        is_dangling: false,
                    },
                );
            }
            None if ptr_value == 0 => {
                inner.edges.remove(&source);
            }
            None => {
                inner.edges.insert(
                    source,
                    PointerEdge {
                        source,
                        target: NodeId::Global(u32::MAX),
                        ptr_value,
                        is_dangling: true,
                    },
                );
            }
        }
    }

    pub fn regs(&self) -> [u64; REG_COUNT] {
        self.inner.reg_file.values
    }

    pub fn update_regs(&mut self, regs: [u64; REG_COUNT], insn: u64) {
        self.cow().reg_file.update(regs, insn);
    }

    pub fn record_cache_miss(&mut self, nid: NodeId) {
        self.cow().cache_heat.record_miss(nid);
    }

    pub fn cache_heat_tick(&mut self) {
        self.cow().cache_heat.tick();
    }

    #[inline(always)]
    pub fn record_cl_write(&mut self, addr: u64, thread_id: u16) -> u16 {
        self.cl_tracker.record_write(addr, thread_id)
    }

    pub fn cl_tracker_tick(&mut self) {
        self.cl_tracker.tick();
    }

    pub fn node_count(&self) -> usize {
        self.inner.nodes.len()
    }
    pub fn edge_count(&self) -> usize {
        self.inner.edges.len()
    }
}

// per-thread shadow stack. validates CALL/RETURN pairing.
#[derive(Debug, Clone)]
pub struct ShadowFrame {
    pub frame_id: crate::index::FrameId,
    pub callee_pc: u64,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct ShadowStack {
    pub frames: Vec<ShadowFrame>,
    pub mismatches: u64,
    pub non_local_jumps: u64,
    pub max_depth: usize,
}

impl ShadowStack {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            frames: Vec::with_capacity(64),
            mismatches: 0,
            non_local_jumps: 0,
            max_depth: 0,
        }
    }

    pub fn push_call(&mut self, frame_id: crate::index::FrameId, callee_pc: u64, name: String) {
        self.frames.push(ShadowFrame {
            frame_id,
            callee_pc,
            name,
        });
        if self.frames.len() > self.max_depth {
            self.max_depth = self.frames.len();
        }
    }

    // returns frame if matched, None + increments mismatch if stack empty
    pub fn pop_return(&mut self) -> Option<ShadowFrame> {
        match self.frames.pop() {
            Some(f) => Some(f),
            None => {
                self.mismatches += 1;
                None
            }
        }
    }

    // longjmp-aware return: if `return_pc` doesn't match the top frame's
    // callee, scan the stack for a frame whose caller pushed this PC.
    // if found, unwind to that point (non-local jump). if not found,
    // fall back to normal pop and count as true mismatch.
    // returns (popped_frame, frames_unwound). frames_unwound > 1 means
    // non-local jump detected.
    pub fn pop_return_checked(&mut self, return_pc: u64) -> (Option<ShadowFrame>, usize) {
        if self.frames.is_empty() {
            self.mismatches += 1;
            return (None, 0);
        }
        // fast path: normal return matches top of stack
        let top = self.frames.last().unwrap();
        if top.callee_pc == return_pc {
            return (self.frames.pop(), 1);
        }
        // scan for non-local jump target deeper in the stack.
        // search from top-1 downward for a frame whose callee_pc matches.
        let mut found_idx = None;
        for i in (0..self.frames.len().saturating_sub(1)).rev() {
            if self.frames[i].callee_pc == return_pc {
                found_idx = Some(i);
                break;
            }
        }
        match found_idx {
            Some(idx) => {
                // non-local jump: unwind frames from top down to idx
                let unwound = self.frames.len() - idx;
                self.frames.truncate(idx);
                self.non_local_jumps += 1;
                // return the target frame (already removed by truncate,
                // but we need a ShadowFrame to return)
                (None, unwound)
            }
            None => {
                // true mismatch: return_pc not on stack at all
                self.mismatches += 1;
                (self.frames.pop(), 1)
            }
        }
    }

    pub fn depth(&self) -> usize {
        self.frames.len()
    }
}

// circular snapshot buffer with triple-index for time-travel
pub struct SnapshotRing {
    buf: Vec<SnapEntry>,
    cap: usize,
    write_pos: usize,
    len: usize,
}

struct SnapEntry {
    snap: Arc<WorldInner>,
    insn: u64,
    tick: u64,
    event_seq: u64,
}

pub struct SnapRef<'a> {
    pub snap: &'a Arc<WorldInner>,
    pub insn: u64,
    pub tick: u64,
    pub event_seq: u64,
}

impl SnapshotRing {
    pub fn new(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
            cap,
            write_pos: 0,
            len: 0,
        }
    }

    pub fn push(&mut self, snap: Arc<WorldInner>, tick: u64, event_seq: u64) {
        let insn = snap.insn_counter;
        let entry = SnapEntry {
            snap,
            insn,
            tick,
            event_seq,
        };
        if self.buf.len() < self.cap {
            self.buf.push(entry);
        } else {
            self.buf[self.write_pos] = entry;
        }
        self.write_pos = (self.write_pos + 1) % self.cap;
        self.len = (self.len + 1).min(self.cap);
    }

    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    // index 0 = oldest, len-1 = newest
    fn slot(&self, idx: usize) -> Option<&SnapEntry> {
        if idx >= self.len {
            return None;
        }
        let start = if self.len < self.cap {
            0
        } else {
            self.write_pos
        };
        let real = (start + idx) % self.cap;
        Some(&self.buf[real])
    }

    pub fn get(&self, idx: usize) -> Option<SnapRef<'_>> {
        self.slot(idx).map(|e| SnapRef {
            snap: &e.snap,
            insn: e.insn,
            tick: e.tick,
            event_seq: e.event_seq,
        })
    }

    pub fn latest(&self) -> Option<SnapRef<'_>> {
        if self.len == 0 {
            return None;
        }
        self.get(self.len - 1)
    }

    // binary search by insn counter, returns nearest <= target
    pub fn find_by_insn(&self, target_insn: u64) -> Option<usize> {
        if self.len == 0 {
            return None;
        }
        let mut lo = 0usize;
        let mut hi = self.len;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.slot(mid).unwrap().insn <= target_insn {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo > 0 {
            Some(lo - 1)
        } else {
            None
        }
    }

    pub fn find_by_tick(&self, target_tick: u64) -> Option<usize> {
        if self.len == 0 {
            return None;
        }
        let mut lo = 0usize;
        let mut hi = self.len;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.slot(mid).unwrap().tick <= target_tick {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo > 0 {
            Some(lo - 1)
        } else {
            None
        }
    }

    pub fn find_by_seq(&self, target_seq: u64) -> Option<usize> {
        if self.len == 0 {
            return None;
        }
        let mut lo = 0usize;
        let mut hi = self.len;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.slot(mid).unwrap().event_seq <= target_seq {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo > 0 {
            Some(lo - 1)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotDelta {
    pub older_seq: u64,
    pub newer_seq: u64,
    pub node_delta: i64,
    pub edge_delta: i64,
    pub nodes_added: Vec<String>,
    pub nodes_removed: Vec<String>,
    pub edges_added: u64,
    pub edges_removed: u64,
    pub value_changes: Vec<(String, u64, u64)>,
}

impl SnapshotRing {
    pub fn delta(&self, older_idx: usize, newer_idx: usize) -> Option<SnapshotDelta> {
        let a = self.slot(older_idx)?;
        let b = self.slot(newer_idx)?;
        let sa = &a.snap;
        let sb = &b.snap;

        let a_keys: std::collections::BTreeSet<&NodeId> = sa.nodes.keys().collect();
        let b_keys: std::collections::BTreeSet<&NodeId> = sb.nodes.keys().collect();

        let nodes_added: Vec<String> = b_keys
            .difference(&a_keys)
            .filter_map(|nid| sb.nodes.get(nid).map(|n| n.name.clone()))
            .collect();
        let nodes_removed: Vec<String> = a_keys
            .difference(&b_keys)
            .filter_map(|nid| sa.nodes.get(nid).map(|n| n.name.clone()))
            .collect();

        let a_edge_keys: std::collections::BTreeSet<&NodeId> = sa.edges.keys().collect();
        let b_edge_keys: std::collections::BTreeSet<&NodeId> = sb.edges.keys().collect();

        let mut value_changes = Vec::new();
        for nid in a_keys.intersection(&b_keys) {
            if let (Some(na), Some(nb)) = (sa.nodes.get(nid), sb.nodes.get(nid)) {
                if na.raw_value != nb.raw_value {
                    value_changes.push((na.name.clone(), na.raw_value, nb.raw_value));
                }
            }
        }

        Some(SnapshotDelta {
            older_seq: a.event_seq,
            newer_seq: b.event_seq,
            node_delta: sb.nodes.len() as i64 - sa.nodes.len() as i64,
            edge_delta: sb.edges.len() as i64 - sa.edges.len() as i64,
            nodes_added,
            nodes_removed,
            edges_added: b_edge_keys.difference(&a_edge_keys).count() as u64,
            edges_removed: a_edge_keys.difference(&b_edge_keys).count() as u64,
            value_changes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dwarf::TypeInfo;

    fn ti(name: &str, sz: u64, ptr: bool) -> TypeInfo {
        TypeInfo {
            name: name.into(),
            byte_size: sz,
            is_pointer: ptr,
            is_volatile: false,
            is_atomic: false,
            shallow: false,
            fields: Vec::new(),
        }
    }

    #[test]
    fn test_cow_snapshot() {
        let mut ws = WorldState::new();
        ws.ensure_node(NodeId::Global(0), "x", &ti("int", 4, false), 0x1000, 4);
        ws.update_value(NodeId::Global(0), 42, 1);
        let snap = ws.snapshot();
        assert_eq!(snap.nodes[&NodeId::Global(0)].raw_value, 42);
        ws.update_value(NodeId::Global(0), 99, 2);
        assert_eq!(ws.snapshot().nodes[&NodeId::Global(0)].raw_value, 99);
        assert_eq!(snap.nodes[&NodeId::Global(0)].raw_value, 42);
    }

    #[test]
    fn test_pointer_edge() {
        let mut ws = WorldState::new();
        ws.ensure_node(NodeId::Global(0), "p", &ti("*int", 8, true), 0x1000, 8);
        ws.ensure_node(NodeId::Global(1), "x", &ti("int", 4, false), 0x2000, 4);
        ws.update_edge(NodeId::Global(0), Some(NodeId::Global(1)), 0x2000);
        assert_eq!(ws.edge_count(), 1);
        assert!(!ws.snapshot().edges[&NodeId::Global(0)].is_dangling);
        ws.update_edge(NodeId::Global(0), None, 0);
        assert_eq!(ws.edge_count(), 0);
        ws.update_edge(NodeId::Global(0), None, 0xdeadbeef);
        assert!(ws.snapshot().edges[&NodeId::Global(0)].is_dangling);
    }

    #[test]
    fn test_frame_cleanup() {
        let mut ws = WorldState::new();
        ws.ensure_node(NodeId::Global(0), "g", &ti("int", 4, false), 0x1000, 4);
        ws.ensure_node(NodeId::Local(1, 0), "a", &ti("int", 4, false), 0x7000, 4);
        ws.ensure_node(NodeId::Local(1, 1), "p", &ti("*int", 8, true), 0x7008, 8);
        ws.update_edge(NodeId::Local(1, 1), Some(NodeId::Global(0)), 0x1000);
        assert_eq!(ws.node_count(), 3);
        ws.remove_frame_nodes(1);
        assert_eq!(ws.node_count(), 1);
        assert_eq!(ws.edge_count(), 0);
    }

    #[test]
    fn test_snapshot_ring() {
        let mut ws = WorldState::new();
        ws.ensure_node(NodeId::Global(0), "x", &ti("int", 4, false), 0x1000, 4);

        let mut ring = SnapshotRing::new(4);
        for i in 0..6u64 {
            ws.update_value(NodeId::Global(0), i * 10, i);
            ws.inc_insn_counter();
            ring.push(ws.snapshot(), i, i);
        }

        assert_eq!(ring.len(), 4);
        assert_eq!(ring.get(0).unwrap().event_seq, 2);
        assert_eq!(ring.get(3).unwrap().event_seq, 5);
        assert_eq!(ring.latest().unwrap().event_seq, 5);

        let idx = ring.find_by_insn(4).unwrap();
        let sr = ring.get(idx).unwrap();
        assert!(sr.insn <= 4);

        assert!(ring.find_by_insn(0).is_none());
    }

    #[test]
    fn test_snapshot_delta_identity() {
        let mut ws = WorldState::new();
        ws.ensure_node(NodeId::Global(0), "x", &ti("int", 4, false), 0x1000, 4);
        ws.update_value(NodeId::Global(0), 42, 1);

        let mut ring = SnapshotRing::new(4);
        let snap = ws.snapshot();
        ring.push(snap.clone(), 0, 100);
        ring.push(snap, 1, 101);

        let d = ring.delta(0, 1).unwrap();
        assert_eq!(d.node_delta, 0);
        assert_eq!(d.edge_delta, 0);
        assert!(d.nodes_added.is_empty());
        assert!(d.nodes_removed.is_empty());
        assert!(d.value_changes.is_empty());
        assert_eq!(d.edges_added, 0);
        assert_eq!(d.edges_removed, 0);
    }

    #[test]
    fn test_snapshot_delta_known_mutation() {
        let mut ws = WorldState::new();
        ws.ensure_node(NodeId::Global(0), "x", &ti("int", 4, false), 0x1000, 4);
        ws.update_value(NodeId::Global(0), 10, 1);

        let mut ring = SnapshotRing::new(4);
        ring.push(ws.snapshot(), 0, 100);

        ws.ensure_node(NodeId::Global(1), "y", &ti("int", 4, false), 0x2000, 4);
        ws.update_value(NodeId::Global(0), 99, 2);
        ws.ensure_node(NodeId::Global(2), "p", &ti("*int", 8, true), 0x3000, 8);
        ws.update_edge(NodeId::Global(2), Some(NodeId::Global(0)), 0x1000);
        ring.push(ws.snapshot(), 1, 200);

        let d = ring.delta(0, 1).unwrap();
        assert_eq!(d.node_delta, 2); // y + p added
        assert_eq!(d.edge_delta, 1);
        assert_eq!(d.nodes_added.len(), 2);
        assert!(d.nodes_added.contains(&"y".to_string()));
        assert!(d.nodes_added.contains(&"p".to_string()));
        assert!(d.nodes_removed.is_empty());
        assert_eq!(d.edges_added, 1);
        assert_eq!(d.value_changes.len(), 1);
        assert_eq!(d.value_changes[0], ("x".to_string(), 10, 99));
        assert_eq!(d.older_seq, 100);
        assert_eq!(d.newer_seq, 200);
    }

    #[test]
    fn test_snapshot_delta_wraparound() {
        let mut ws = WorldState::new();
        ws.ensure_node(NodeId::Global(0), "a", &ti("int", 4, false), 0x1000, 4);

        let mut ring = SnapshotRing::new(3);
        // push 5 snapshots into a ring of cap 3 -> slots 0,1 overwritten
        for i in 0..5u64 {
            ws.update_value(NodeId::Global(0), i * 10, i);
            ws.inc_insn_counter();
            ring.push(ws.snapshot(), i, i * 100);
        }
        assert_eq!(ring.len(), 3);
        // oldest is seq=200 (i=2), newest is seq=400 (i=4)
        assert_eq!(ring.get(0).unwrap().event_seq, 200);
        assert_eq!(ring.get(2).unwrap().event_seq, 400);

        let d = ring.delta(0, 2).unwrap();
        assert_eq!(d.older_seq, 200);
        assert_eq!(d.newer_seq, 400);
        // value at i=2 was 20, at i=4 was 40
        assert_eq!(d.value_changes.len(), 1);
        assert_eq!(d.value_changes[0], ("a".to_string(), 20, 40));
    }

    #[test]
    fn test_snapshot_delta_node_removal() {
        let mut ws = WorldState::new();
        ws.ensure_node(NodeId::Global(0), "x", &ti("int", 4, false), 0x1000, 4);
        ws.ensure_node(
            NodeId::Local(1, 0),
            "local_a",
            &ti("int", 4, false),
            0x7000,
            4,
        );

        let mut ring = SnapshotRing::new(4);
        ring.push(ws.snapshot(), 0, 100);

        ws.remove_frame_nodes(1);
        ring.push(ws.snapshot(), 1, 200);

        let d = ring.delta(0, 1).unwrap();
        assert_eq!(d.node_delta, -1);
        assert!(d.nodes_removed.contains(&"local_a".to_string()));
        assert!(d.nodes_added.is_empty());
    }

    #[test]
    fn test_snapshot_delta_out_of_bounds() {
        let ring = SnapshotRing::new(4);
        assert!(ring.delta(0, 1).is_none());
    }

    #[test]
    fn test_bb_entry_hits() {
        let mut ws = WorldState::new();
        assert_eq!(ws.insn_counter(), 0);
        assert!(ws.bb_hits.is_empty());

        ws.record_bb_entry(0x1234);
        ws.record_bb_entry(0x1234);
        ws.record_bb_entry(0x5678);

        assert_eq!(ws.insn_counter(), 3);
        assert_eq!(ws.bb_hits.len(), 2);
        assert_eq!(ws.bb_hits[&0x1234], 2);
        assert_eq!(ws.bb_hits[&0x5678], 1);
    }

    #[test]
    fn test_cl_tracker_per_writer_counts() {
        let mut cl = CacheLineTracker::new();
        let addr = 0x1000u64;
        // thread 0 writes 100 times, thread 1 writes once
        for _ in 0..100 {
            cl.record_write(addr, 0);
        }
        cl.record_write(addr, 1);

        // raw score: 2 threads
        assert_eq!(cl.contention_score(addr), 2);

        // weighted at 5%: thread 1 has 1/101 ≈ 0.99% < 5%, filtered out
        assert_eq!(cl.contention_score_weighted(addr, 0.05), 1);

        // weighted at 0.5%: thread 1 has ~0.99% >= 0.5%, both count
        assert_eq!(cl.contention_score_weighted(addr, 0.005), 2);
    }

    #[test]
    fn test_cl_tracker_symmetric_writers() {
        let mut cl = CacheLineTracker::new();
        let addr = 0x2000u64;
        // two threads write equally
        for _ in 0..50 {
            cl.record_write(addr, 0);
            cl.record_write(addr, 1);
        }
        assert_eq!(cl.contention_score(addr), 2);
        // both exceed any reasonable threshold
        assert_eq!(cl.contention_score_weighted(addr, 0.10), 2);
    }

    #[test]
    fn test_cl_tracker_writer_breakdown() {
        let mut cl = CacheLineTracker::new();
        let addr = 0x3000u64;
        for _ in 0..10 { cl.record_write(addr, 2); }
        for _ in 0..20 { cl.record_write(addr, 5); }

        let breakdown = cl.writer_breakdown(addr);
        assert_eq!(breakdown.len(), 2);
        // check both threads present with correct counts
        let t2 = breakdown.iter().find(|(t, _)| *t == 2).unwrap();
        let t5 = breakdown.iter().find(|(t, _)| *t == 5).unwrap();
        assert_eq!(t2.1, 10);
        assert_eq!(t5.1, 20);
    }

    #[test]
    fn test_cl_tracker_tick_decays_per_writer() {
        let mut cl = CacheLineTracker::new();
        let addr = 0x4000u64;
        for _ in 0..100 { cl.record_write(addr, 0); }
        cl.record_write(addr, 1);

        assert_eq!(cl.contention_score(addr), 2);

        // after one tick, write_count halves. thread 1's single write
        // decays to 0, removing it from the writer mask.
        cl.tick();
        assert_eq!(cl.contention_score(addr), 1);

        let breakdown = cl.writer_breakdown(addr);
        assert_eq!(breakdown.len(), 1);
        assert_eq!(breakdown[0].0, 0);
    }

    #[test]
    fn test_cl_tracker_empty_line() {
        let cl = CacheLineTracker::new();
        assert_eq!(cl.contention_score(0x5000), 0);
        assert_eq!(cl.contention_score_weighted(0x5000, 0.01), 0);
        assert!(cl.writer_breakdown(0x5000).is_empty());
    }

    #[test]
    fn test_cl_tracker_collision_evicts() {
        let mut cl = CacheLineTracker::new();
        let addr_a = 0x6000u64;
        cl.record_write(addr_a, 0);
        assert_eq!(cl.contention_score(addr_a), 1);

        // different cache line that maps to the same slot
        let addr_b = addr_a + ((CL_SLOTS as u64) << CL_SHIFT);
        cl.record_write(addr_b, 1);
        // addr_a evicted
        assert_eq!(cl.contention_score(addr_a), 0);
        assert_eq!(cl.contention_score(addr_b), 1);
    }

    // --- longjmp-aware shadow stack tests ---

    #[test]
    fn test_shadow_stack_normal_return() {
        let mut ss = ShadowStack::new();
        ss.push_call(1, 0xA000, "foo".into());
        ss.push_call(2, 0xB000, "bar".into());

        let (frame, unwound) = ss.pop_return_checked(0xB000);
        assert!(frame.is_some());
        assert_eq!(unwound, 1);
        assert_eq!(frame.unwrap().name, "bar");
        assert_eq!(ss.depth(), 1);
        assert_eq!(ss.mismatches, 0);
        assert_eq!(ss.non_local_jumps, 0);
    }

    #[test]
    fn test_shadow_stack_longjmp_unwind() {
        let mut ss = ShadowStack::new();
        // simulate: main -> f1 -> f2 -> f3, then longjmp back to f1
        ss.push_call(1, 0xA000, "main".into());
        ss.push_call(2, 0xB000, "f1".into());
        ss.push_call(3, 0xC000, "f2".into());
        ss.push_call(4, 0xD000, "f3".into());
        assert_eq!(ss.depth(), 4);

        // longjmp returns to f1's callee_pc, unwinding f2+f3+f4
        let (frame, unwound) = ss.pop_return_checked(0xB000);
        assert!(frame.is_none()); // container_of unwind, no single frame
        assert_eq!(unwound, 3); // f2, f3, f4 unwound
        assert_eq!(ss.depth(), 1); // only main remains
        assert_eq!(ss.non_local_jumps, 1);
        assert_eq!(ss.mismatches, 0);
    }

    #[test]
    fn test_shadow_stack_true_mismatch() {
        let mut ss = ShadowStack::new();
        ss.push_call(1, 0xA000, "foo".into());
        ss.push_call(2, 0xB000, "bar".into());

        // return to an address not on the stack at all
        let (frame, unwound) = ss.pop_return_checked(0xDEAD);
        assert!(frame.is_some()); // pops top frame as fallback
        assert_eq!(unwound, 1);
        assert_eq!(ss.mismatches, 1);
        assert_eq!(ss.non_local_jumps, 0);
    }

    #[test]
    fn test_shadow_stack_empty_mismatch() {
        let mut ss = ShadowStack::new();
        let (frame, unwound) = ss.pop_return_checked(0x1234);
        assert!(frame.is_none());
        assert_eq!(unwound, 0);
        assert_eq!(ss.mismatches, 1);
    }

    #[test]
    fn test_shadow_stack_longjmp_to_bottom() {
        let mut ss = ShadowStack::new();
        ss.push_call(1, 0xA000, "main".into());
        ss.push_call(2, 0xB000, "deep1".into());
        ss.push_call(3, 0xC000, "deep2".into());

        // longjmp all the way back to main's callee_pc
        let (_, unwound) = ss.pop_return_checked(0xA000);
        assert_eq!(unwound, 3);
        assert_eq!(ss.depth(), 0);
        assert_eq!(ss.non_local_jumps, 1);
        assert_eq!(ss.mismatches, 0);
    }

    // -- type epoch log tests --

    fn make_proj(addr: u64, name: &str, source: &str, seq: u64) -> TypeProjection {
        TypeProjection {
            base_addr: addr,
            type_info: ti(name, 24, false),
            source_name: source.into(),
            stamp_seq: seq,
        }
    }

    #[test]
    fn test_epoch_free_lifecycle() {
        let mut log = TypeEpochLog::new(64);
        let proj = make_proj(0x1000, "dictEntry", "alloc@0x42", 100);
        log.close_epoch(0x1000, 24, &proj, 500, EpochClose::Free);

        assert_eq!(log.len(), 1);
        assert_eq!(log.total_closed, 1);

        let e = log.iter().next().unwrap();
        assert_eq!(e.addr, 0x1000);
        assert_eq!(e.type_name, "dictEntry");
        assert_eq!(e.open_seq, 100);
        assert_eq!(e.close_seq, 500);
        assert_eq!(e.close_reason, EpochClose::Free);
    }

    #[test]
    fn test_epoch_realloc_lifecycle() {
        let mut log = TypeEpochLog::new(64);
        let proj = make_proj(0x2000, "sds", "alloc@0x10", 50);
        log.close_epoch(0x2000, 32, &proj, 200, EpochClose::Realloc);

        let e = log.iter().next().unwrap();
        assert_eq!(e.close_reason, EpochClose::Realloc);
        assert_eq!(e.size, 32);
    }

    #[test]
    fn test_epoch_schism_lifecycle() {
        let mut log = TypeEpochLog::new(64);
        let proj = make_proj(0x3000, "listNode", "server.db", 10);
        log.close_epoch(0x3000, 24, &proj, 80, EpochClose::Schism);

        let e = log.iter().next().unwrap();
        assert_eq!(e.close_reason, EpochClose::Schism);
        assert_eq!(e.type_name, "listNode");
    }

    #[test]
    fn test_epoch_query() {
        let mut log = TypeEpochLog::new(64);
        let p1 = make_proj(0x1000, "A", "s1", 100);
        log.close_epoch(0x1000, 24, &p1, 200, EpochClose::Free);
        let p2 = make_proj(0x1000, "B", "s2", 300);
        log.close_epoch(0x1000, 24, &p2, 500, EpochClose::Free);

        // seq 150 falls in first epoch [100, 200)
        let r = log.query(0x1000, 150).unwrap();
        assert_eq!(r.type_name, "A");

        // seq 400 falls in second epoch [300, 500)
        let r = log.query(0x1000, 400).unwrap();
        assert_eq!(r.type_name, "B");

        // seq 250 falls between epochs; no match
        assert!(log.query(0x1000, 250).is_none());

        // wrong address; no match
        assert!(log.query(0x2000, 150).is_none());
    }

    #[test]
    fn test_epoch_history() {
        let mut log = TypeEpochLog::new(64);
        let p1 = make_proj(0x1000, "A", "s1", 10);
        log.close_epoch(0x1000, 24, &p1, 20, EpochClose::Free);
        let p2 = make_proj(0x1000, "B", "s2", 30);
        log.close_epoch(0x1000, 24, &p2, 40, EpochClose::Free);
        let p3 = make_proj(0x2000, "C", "s3", 50);
        log.close_epoch(0x2000, 24, &p3, 60, EpochClose::Free);

        let h = log.history(0x1000);
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].type_name, "A");
        assert_eq!(h[1].type_name, "B");
    }

    #[test]
    fn test_epoch_ring_overflow() {
        let cap = 4;
        let mut log = TypeEpochLog::new(cap);
        for i in 0..6u64 {
            let p = make_proj(0x1000 + i * 0x100, &format!("T{}", i), "src", i * 10);
            log.close_epoch(0x1000 + i * 0x100, 24, &p, i * 10 + 5, EpochClose::Free);
        }

        // ring holds last 4
        assert_eq!(log.len(), 4);
        assert_eq!(log.total_closed, 6);

        let names: Vec<&str> = log.iter().map(|e| e.type_name.as_str()).collect();
        assert_eq!(names, vec!["T2", "T3", "T4", "T5"]);
    }

    #[test]
    fn test_epoch_summary() {
        let mut log = TypeEpochLog::new(64);
        for i in 0..3u64 {
            let p = make_proj(0x1000 * (i + 1), "dictEntry", "alloc", i * 100);
            log.close_epoch(0x1000 * (i + 1), 24, &p, i * 100 + 50, EpochClose::Free);
        }
        let p = make_proj(0x5000, "dictEntry", "alloc", 400);
        log.close_epoch(0x5000, 24, &p, 500, EpochClose::Realloc);

        let s = log.summary();
        let stats = s.get("dictEntry").unwrap();
        assert_eq!(stats.count, 4);
        assert_eq!(stats.by_reason[EpochClose::Free as usize], 3);
        assert_eq!(stats.by_reason[EpochClose::Realloc as usize], 1);
        assert_eq!(stats.total_lifetime, 50 * 3 + 100); // 3×50 + 1×100
    }
}
