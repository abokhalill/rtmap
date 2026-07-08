// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{_mm_prefetch, _MM_HINT_T0};

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::{mem, ptr};

pub const CACHE_LINE: usize = 64;
pub const RTMAP_MAGIC: u64 = 0x52544D4150425200;
pub const RTMAP_CTL_MAGIC: u64 = 0x5254435430303032;
pub const RTMAP_PROTO_VERSION: u32 = 3;
pub const MAX_THREADS: usize = 256;
pub const RING_NAME_LEN: usize = 48;

fn fnv_feed(h: &mut u32, v: u32) {
    for i in 0..4 {
        *h ^= (v >> (i * 8)) & 0xFF;
        *h = h.wrapping_mul(0x01000193);
    }
}

macro_rules! field_offset {
    ($T:ty, $field:ident) => {{
        let uninit = mem::MaybeUninit::<$T>::uninit();
        let base = uninit.as_ptr() as usize;
        let field = unsafe { &(*uninit.as_ptr()).$field as *const _ as usize };
        (field - base) as u32
    }};
}

pub fn rtmap_abi_hash() -> u32 {
    let mut h = 0x811c9dc5u32;
    fnv_feed(&mut h, mem::size_of::<Event>() as u32);
    fnv_feed(&mut h, field_offset!(Event, addr));
    fnv_feed(&mut h, field_offset!(Event, value));
    fnv_feed(&mut h, field_offset!(Event, kind_flags));
    fnv_feed(&mut h, field_offset!(Event, rip_lo));
    fnv_feed(&mut h, mem::size_of::<RingHeader>() as u32);
    fnv_feed(&mut h, field_offset!(RingHeader, head));
    fnv_feed(&mut h, field_offset!(RingHeader, tail));
    fnv_feed(&mut h, field_offset!(RingHeader, status));
    fnv_feed(&mut h, 128); // sizeof(rtmap_scratch_pad_t)
    fnv_feed(&mut h, 28);   // nesting_level
    fnv_feed(&mut h, 32);   // stat_reentrant_drops
    fnv_feed(&mut h, 40);   // stat_truncated_writes
    h
}

#[derive(Clone, Copy)]
#[repr(C, align(32))]
pub struct Event {
    pub addr: u64,
    pub size: u32,
    pub thread_id: u16,
    pub seq: u16,
    pub value: u64,
    pub kind_flags: u32,
    pub rip_lo: u32,
}
const _: () = assert!(mem::size_of::<Event>() == 32);

impl Event {
    #[inline(always)]
    pub fn kind(&self) -> u8 {
        (self.kind_flags & 0xFF) as u8
    }

    #[inline(always)]
    pub fn flags(&self) -> u8 {
        ((self.kind_flags >> 8) & 0xFF) as u8
    }

    #[inline(always)]
    pub fn is_truncated(&self) -> bool {
        self.flags() & 0x80 != 0
    }

    #[inline(always)]
    pub fn is_compound(&self) -> bool {
        self.flags() & 0x40 != 0
    }

    #[inline(always)]
    pub fn is_continuation(&self) -> bool {
        self.flags() & 0x20 != 0
    }

    /// total ring slots consumed by this event (1 for normal, N for compound)
    #[inline(always)]
    pub fn compound_slots(&self) -> usize {
        if !self.is_compound() { return 1; }
        let total = ((self.size as usize) + 7) / 8;
        total.min(COMPOUND_MAX_SLOTS)
    }

    #[inline(always)]
    pub fn seq32(&self) -> u32 {
        let hi = self.kind_flags >> 16;
        (hi << 16) | (self.seq as u32)
    }

    pub fn zero() -> Self {
        Self {
            addr: 0,
            size: 0,
            thread_id: 0,
            seq: 0,
            value: 0,
            kind_flags: 0,
            rip_lo: 0,
        }
    }
}

pub const MV_STATUS_ACTIVE: u32 = 0;
pub const MV_STATUS_TERMINAL: u32 = 1;
// RTMAP_BP_TIER_* parity 
pub const BP_TIER_SHED_READS: u32 = 1;
pub const BP_TIER_SHED_WRITES: u32 = 2;
pub const COMPOUND_MAX_SLOTS: usize = 8;
pub const EVENT_PROCESS_FORK: u8 = 13;

#[repr(C)]
pub struct RingHeader {
    pub magic: u64,
    pub capacity: u32,
    pub entry_size: u32,
    pub flags: u64,
    pub backpressure: AtomicU32,
    pub proto_version: u32,
    pub status: AtomicU32,
    _pad0: [u8; CACHE_LINE - 36],
    pub head: AtomicU64,
    _pad1: [u8; CACHE_LINE - mem::size_of::<AtomicU64>()],
    pub tail: AtomicU64,
    _pad2: [u8; CACHE_LINE - mem::size_of::<AtomicU64>()],
}
const _: () = assert!(mem::size_of::<RingHeader>() == 3 * CACHE_LINE);

impl RingHeader {
    /// # Safety
    /// Caller must ensure `self` points to a valid mapped ring with data region
    /// immediately following the header.
    pub unsafe fn data(&self) -> *const Event {
        (self as *const Self as *const u8).add(mem::size_of::<Self>()) as *const Event
    }
}

#[repr(C)]
struct ThreadEntry {
    state: AtomicU32,
    thread_id: u16,
    _reserved: u16,
    shm_name: [u8; RING_NAME_LEN],
}

const THREAD_STATE_EMPTY: u32 = 0;
const THREAD_STATE_ACTIVE: u32 = 1;
const THREAD_STATE_DEAD: u32 = 2;
const THREAD_STATE_INITIALIZING: u32 = 3;

const BLOOM_U64S: usize = 512;
const BLOOM_BITS: u32 = (BLOOM_U64S as u32) * 64;

#[repr(C)]
struct CtlHeader {
    magic: u64,
    proto_version: u32,
    thread_count: AtomicU32,
    max_threads: u32,
    build_hash: u32,
    target_pid: u32,
    parent_pid: u32,
    tripwire_hit: AtomicU32,
    _ctl_reserved: u32,
    priority_bloom: [u64; BLOOM_U64S],
    threads: [ThreadEntry; MAX_THREADS],
}

fn bloom_h1(addr: u64) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for i in 0..8 {
        h ^= ((addr >> (i * 8)) & 0xFF) as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h % BLOOM_BITS
}
fn bloom_h2(addr: u64) -> u32 {
    let mut h: u32 = 0x01000193;
    for i in 0..8 {
        h ^= ((addr >> (i * 8)) & 0xFF) as u32;
        h = h.wrapping_mul(0x811c9dc5);
    }
    h % BLOOM_BITS
}

pub struct MappedShm {
    ptr: *mut u8,
    len: usize,
}
unsafe impl Send for MappedShm {}
unsafe impl Sync for MappedShm {}

impl MappedShm {
    fn open(name: &[u8]) -> Option<Self> {
        unsafe {
            let fd = libc::shm_open(name.as_ptr() as *const libc::c_char, libc::O_RDWR, 0o600);
            if fd < 0 {
                return None;
            }
            let mut st: libc::stat = mem::zeroed();
            if libc::fstat(fd, &mut st) != 0 {
                libc::close(fd);
                return None;
            }
            let len = st.st_size as usize;
            if len == 0 {
                libc::close(fd);
                return None;
            }
            let p = libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            libc::close(fd);
            if p == libc::MAP_FAILED {
                return None;
            }
            Some(Self {
                ptr: p as *mut u8,
                len,
            })
        }
    }
}
impl Drop for MappedShm {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}

pub struct ThreadRing {
    shm: MappedShm,
    pub thread_id: u16,
    pub alive: bool,
    /// events destroyed by producer lap (inline paths have no full check)
    pub lapped_events: u64,
    lap_episodes: u64,
}

impl ThreadRing {
    fn from_shm(shm: MappedShm, thread_id: u16) -> Option<Self> {
        // header fields drive pointer arithmetic; reject corrupt/truncated
        // shm here, not as a segfault in the drain loop
        if shm.len < mem::size_of::<RingHeader>() {
            eprintln!(
                "rtmap: ring tid={} REJECTED: shm {} B < header {} B",
                thread_id,
                shm.len,
                mem::size_of::<RingHeader>()
            );
            return None;
        }
        let hdr = unsafe { &*(shm.ptr as *const RingHeader) };
        if hdr.magic != RTMAP_MAGIC {
            return None;
        }
        if hdr.proto_version != RTMAP_PROTO_VERSION {
            eprintln!(
                "rtmap: ring proto mismatch: expected {}, got {}",
                RTMAP_PROTO_VERSION, hdr.proto_version
            );
            return None;
        }
        if hdr.capacity == 0 || !hdr.capacity.is_power_of_two() {
            eprintln!(
                "rtmap: ring tid={} REJECTED: capacity {} not a power of two",
                thread_id, hdr.capacity
            );
            return None;
        }
        if hdr.entry_size as usize != mem::size_of::<Event>() {
            eprintln!(
                "rtmap: ring tid={} REJECTED: entry_size {} != {}",
                thread_id,
                hdr.entry_size,
                mem::size_of::<Event>()
            );
            return None;
        }
        let need = mem::size_of::<RingHeader>() + hdr.capacity as usize * mem::size_of::<Event>();
        if shm.len < need {
            eprintln!(
                "rtmap: ring tid={} REJECTED: shm {} B < required {} B (capacity {})",
                thread_id, shm.len, need, hdr.capacity
            );
            return None;
        }
        Some(Self {
            shm,
            thread_id,
            alive: true,
            lapped_events: 0,
            lap_episodes: 0,
        })
    }

    fn record_lap(&mut self, lost: u64) {
        self.lapped_events += lost;
        self.lap_episodes += 1;
        if self.lap_episodes <= 4 || self.lap_episodes.is_power_of_two() {
            eprintln!(
                "rtmap: RING_LAP #{} tid={} — producer overwrote ~{} unconsumed events (total {})",
                self.lap_episodes, self.thread_id, lost, self.lapped_events
            );
        }
    }

    pub fn header(&self) -> &RingHeader {
        unsafe { &*(self.shm.ptr as *const RingHeader) }
    }

    pub fn is_terminal(&self) -> bool {
        self.header().status.load(Ordering::Acquire) == MV_STATUS_TERMINAL
    }

    #[inline]
    pub fn consume_batch(&mut self, out: &mut [Event]) -> usize {
        // atomic compound runs: REG_SNAPSHOT (7 slots) and COMPOUND writes
        // (variable slots) must never be split across batch boundaries.
        const EVENT_REG_SNAPSHOT: u8 = 5;
        // unbounded lifetime via raw deref: record_lap needs &mut self below
        let hdr: &RingHeader = unsafe { &*(self.shm.ptr as *const RingHeader) };
        let ring_cap = hdr.capacity as u64;
        let mask = ring_cap - 1;
        let data = unsafe { hdr.data() };
        let mut t = hdr.tail.load(Ordering::Relaxed);
        let h = hdr.head.load(Ordering::Acquire);
        // producer lap: inline paths have no full check; slots in
        // [t, h-cap) are already overwritten. skip loudly, resync.
        if h.saturating_sub(t) > ring_cap {
            let resync = h - ring_cap;
            self.record_lap(resync - t);
            t = resync;
        }
        let avail = h.saturating_sub(t) as usize;
        let cap = avail.min(out.len());
        if cap == 0 {
            return 0;
        }
        let mut n = 0usize;
        let mut run_tail: u8 = 0;
        while n < cap {
            #[cfg(target_arch = "x86_64")]
            if n + 8 < cap {
                unsafe {
                    _mm_prefetch(
                        data.add(((t + (n + 8) as u64) & mask) as usize) as *const i8,
                        _MM_HINT_T0,
                    );
                }
            }
            let ev: Event =
                unsafe { ptr::read_volatile(data.add(((t + n as u64) & mask) as usize)) };
            if run_tail == 0 {
                if ev.kind() == EVENT_REG_SNAPSHOT {
                    if n + 7 > cap { break; }
                    run_tail = 6;
                } else if ev.is_compound() {
                    let slots = ev.compound_slots();
                    if n + slots > cap { break; }
                    run_tail = (slots - 1) as u8;
                }
            } else {
                run_tail = run_tail.saturating_sub(1);
            }
            out[n] = ev;
            n += 1;
        }
        // torn-read check: producer lapped into [t, t+n) during the copy —
        // copied slots may be torn/reordered. discard whole batch, resync.
        let h2 = hdr.head.load(Ordering::Acquire);
        if h2.saturating_sub(t) > ring_cap {
            let resync = h2 - ring_cap;
            self.record_lap(resync - t);
            hdr.tail.store(resync, Ordering::Release);
            return 0;
        }
        hdr.tail.store(t + n as u64, Ordering::Release);
        n
    }
}

const BATCH_SIZE: usize = 4096;

#[derive(Default)]
pub struct RingOrchestrator {
    ctl: Option<MappedShm>,
    pub rings: Vec<ThreadRing>,
    known_count: u32,
    rr_idx: usize,
    scratch: Vec<Event>,
}

impl RingOrchestrator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_offline() -> Self {
        Self::default()
    }

    fn attach_ctl_shm(&mut self, shm: MappedShm) -> bool {
        let hdr = unsafe { &*(shm.ptr as *const CtlHeader) };
        if hdr.magic != RTMAP_CTL_MAGIC {
            return false;
        }
        if hdr.proto_version != RTMAP_PROTO_VERSION {
            eprintln!(
                "rtmap: ctl proto mismatch: expected {}, got {}",
                RTMAP_PROTO_VERSION, hdr.proto_version
            );
            return false;
        }
        let expected_hash = rtmap_abi_hash();
        if hdr.build_hash != expected_hash {
            eprintln!(
                "rtmap: ABI MISMATCH: tracer hash=0x{:08x}, engine hash=0x{:08x}",
                hdr.build_hash, expected_hash
            );
            eprintln!("rtmap: rebuild both tracer and engine from the same rtmap_bridge.h");
            return false;
        }
        eprintln!(
            "rtmap: ctl attached (proto={}, abi_hash=0x{:08x}, target_pid={}, parent_pid={})",
            hdr.proto_version, hdr.build_hash, hdr.target_pid, hdr.parent_pid
        );
        self.ctl = Some(shm);
        true
    }

    pub fn try_attach_ctl(&mut self) -> bool {
        if self.ctl.is_some() {
            return true;
        }
        if let Some(shm) = MappedShm::open(b"/rtmap_ctl\0") {
            return self.attach_ctl_shm(shm);
        }
        false
    }

    /// prefer the pid-scoped ctl (/rtmap_ctl_<pid>) which receives live
    /// thread registrations, falling back to the legacy name
    pub fn try_attach_ctl_for_pid(&mut self, pid: u32) -> bool {
        if self.ctl.is_some() {
            return true;
        }
        let pid_name = format!("/rtmap_ctl_{}\0", pid);
        if let Some(shm) = MappedShm::open(pid_name.as_bytes()) {
            return self.attach_ctl_shm(shm);
        }
        if let Some(shm) = MappedShm::open(b"/rtmap_ctl\0") {
            return self.attach_ctl_shm(shm);
        }
        false
    }

    /// attach to a specific process's ctl ring by pid
    pub fn try_attach_ctl_pid(&mut self, pid: u32) -> bool {
        if self.ctl.is_some() {
            return true;
        }
        let name = format!("/rtmap_ctl_{}\0", pid);
        if let Some(shm) = MappedShm::open(name.as_bytes()) {
            return self.attach_ctl_shm(shm);
        }
        false
    }

    pub fn target_pid(&self) -> Option<u32> {
        let shm = self.ctl.as_ref()?;
        let hdr = unsafe { &*(shm.ptr as *const CtlHeader) };
        if hdr.target_pid == 0 {
            None
        } else {
            Some(hdr.target_pid)
        }
    }

    pub fn tripwire_hit(&self) -> bool {
        let shm = match self.ctl.as_ref() {
            Some(s) => s,
            None => return false,
        };
        let hdr = unsafe { &*(shm.ptr as *const CtlHeader) };
        hdr.tripwire_hit.load(Ordering::Relaxed) != 0
    }

    pub fn parent_pid(&self) -> Option<u32> {
        let shm = self.ctl.as_ref()?;
        let hdr = unsafe { &*(shm.ptr as *const CtlHeader) };
        if hdr.parent_pid == 0 {
            None
        } else {
            Some(hdr.parent_pid)
        }
    }

    pub fn poll_new_rings(&mut self) {
        let ctl_ptr = match &self.ctl {
            Some(s) => s.ptr,
            None => return,
        };
        let hdr = unsafe { &*(ctl_ptr as *const CtlHeader) };
        let count = hdr.thread_count.load(Ordering::Acquire);

        while self.known_count < count {
            let idx = self.known_count as usize;

            let entry = &hdr.threads[idx];
            let state = entry.state.load(Ordering::Acquire);
            if state == THREAD_STATE_INITIALIZING {
                break;
            }
            self.known_count += 1;
            if state == THREAD_STATE_EMPTY {
                continue;
            }

            let name_bytes = &entry.shm_name;
            let name_len = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(RING_NAME_LEN);
            if name_len == 0 {
                continue;
            }

            let mut shm_name = Vec::with_capacity(name_len + 1);
            shm_name.extend_from_slice(&name_bytes[..name_len]);
            shm_name.push(0);

            if let Some(shm) = MappedShm::open(&shm_name) {
                if let Some(ring) = ThreadRing::from_shm(shm, entry.thread_id) {
                    eprintln!(
                        "rtmap: discovered ring for thread {} ({})",
                        entry.thread_id,
                        std::str::from_utf8(&name_bytes[..name_len]).unwrap_or("?")
                    );
                    self.rings.push(ring);
                }
            }

            if state == THREAD_STATE_DEAD {
                if let Some(r) = self
                    .rings
                    .iter_mut()
                    .find(|r| r.thread_id == entry.thread_id)
                {
                    r.alive = false;
                }
            }
        }

        for entry_idx in 0..count as usize {
            let entry = &hdr.threads[entry_idx];
            let state = entry.state.load(Ordering::Acquire);
            if state == THREAD_STATE_DEAD {
                if let Some(r) = self
                    .rings
                    .iter_mut()
                    .find(|r| r.thread_id == entry.thread_id && r.alive)
                {
                    r.alive = false;
                }
            } else if state == THREAD_STATE_ACTIVE {
                let tid = entry.thread_id;
                let already_known = self.rings.iter().any(|r| r.thread_id == tid && r.alive);
                if !already_known {
                    let name_bytes = &entry.shm_name;
                    let name_len = name_bytes
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(RING_NAME_LEN);
                    if name_len > 0 {
                        let mut shm_name = Vec::with_capacity(name_len + 1);
                        shm_name.extend_from_slice(&name_bytes[..name_len]);
                        shm_name.push(0);
                        if let Some(shm) = MappedShm::open(&shm_name) {
                            if let Some(ring) = ThreadRing::from_shm(shm, tid) {
                                eprintln!(
                                    "rtmap: discovered reclaimed ring for thread {} ({})",
                                    tid,
                                    std::str::from_utf8(&name_bytes[..name_len]).unwrap_or("?")
                                );
                                self.rings.push(ring);
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn total_fill(&self) -> (u64, u32) {
        let mut total_used = 0u64;
        let mut total_cap = 0u64;
        for ring in &self.rings {
            let hdr = ring.header();
            let h = hdr.head.load(Ordering::Relaxed);
            let t = hdr.tail.load(Ordering::Relaxed);
            total_used += h.saturating_sub(t);
            total_cap += hdr.capacity as u64;
        }
        let pct = if total_cap > 0 {
            ((total_used * 100) / total_cap) as u32
        } else {
            0
        };
        (total_used, pct)
    }

    pub fn ring_count(&self) -> usize {
        self.rings.len()
    }
    pub fn active_count(&self) -> usize {
        self.rings.iter().filter(|r| r.alive).count()
    }
    pub fn total_lapped(&self) -> u64 {
        self.rings.iter().map(|r| r.lapped_events).sum()
    }

    pub fn bloom_insert(&self, addr: u64) {
        let shm = match &self.ctl {
            Some(s) => s,
            None => return,
        };
        let hdr = unsafe { &mut *(shm.ptr as *mut CtlHeader) };
        let b1 = bloom_h1(addr) as usize;
        let b2 = bloom_h2(addr) as usize;
        hdr.priority_bloom[b1 / 64] |= 1u64 << (b1 % 64);
        hdr.priority_bloom[b2 / 64] |= 1u64 << (b2 % 64);
    }

    /// tiered backpressure; tier values must match RTMAP_BP_TIER_* in
    /// rtmap_bridge.h. thresholds: 6/8 -> shed reads+bb, 7/8 -> shed inline
    /// writes, <3/8 -> clear.
    pub fn update_backpressure(&self) {
        const BP_SHED_READS: u64 = 6;
        const BP_SHED_WRITES: u64 = 7;
        const BP_LOW: u64 = 3;
        for ring in &self.rings {
            let hdr = ring.header();
            let h = hdr.head.load(Ordering::Relaxed);
            let t = hdr.tail.load(Ordering::Relaxed);
            let fill_eighths = (h.saturating_sub(t) << 3) / hdr.capacity as u64;
            let bp = hdr.backpressure.load(Ordering::Relaxed);
            let new_bp = if fill_eighths >= BP_SHED_WRITES {
                BP_TIER_SHED_WRITES
            } else if fill_eighths >= BP_SHED_READS {
                BP_TIER_SHED_READS
            } else if fill_eighths < BP_LOW {
                0
            } else {
                bp
            };
            if new_bp != bp {
                hdr.backpressure.store(new_bp, Ordering::Release);
            }
        }
    }

    pub fn batch_drain(&mut self, per_ring: usize, buf: &mut Vec<(usize, Event)>) -> usize {
        let n = self.rings.len();
        if n == 0 {
            return 0;
        }
        let limit = per_ring.min(BATCH_SIZE);
        if self.scratch.len() < limit {
            self.scratch.resize(limit, Event::zero());
        }
        let mut total = 0;
        for offset in 0..n {
            let i = (self.rr_idx + offset) % n;
            let got = self.rings[i].consume_batch(&mut self.scratch[..limit]);
            for j in 0..got {
                buf.push((i, self.scratch[j]));
            }
            total += got;

            /* last-gasp: if ring is terminal and fully drained, retire it */
            if self.rings[i].alive && self.rings[i].is_terminal() {
                let hdr = self.rings[i].header();
                let h = hdr.head.load(Ordering::Acquire);
                let t = hdr.tail.load(Ordering::Relaxed);
                if h == t {
                    eprintln!("rtmap: ring {} terminal, retired", self.rings[i].thread_id);
                    self.rings[i].alive = false;
                }
            }
        }
        self.rr_idx = (self.rr_idx + 1) % n.max(1);
        total
    }
}

/// Used to discover forked children whose in-band PROCESS_FORK event
/// is trapped inside their own (not yet attached) ring. 
/// Returns None if the ctl is absent or invalid.
pub fn peek_ctl_identity(pid: u32) -> Option<(u32, u32)> {
    let name = format!("/rtmap_ctl_{}\0", pid);
    let shm = MappedShm::open(name.as_bytes())?;
    let hdr = unsafe { &*(shm.ptr as *const CtlHeader) };
    if hdr.magic != RTMAP_CTL_MAGIC
        || hdr.proto_version != RTMAP_PROTO_VERSION
        || hdr.build_hash != rtmap_abi_hash()
    {
        return None;
    }
    Some((hdr.target_pid, hdr.parent_pid))
}

/// Enumerate POSIX shm objects (/dev/shm) and return every pid that has a
/// live `rtmap_ctl_<pid>` segment. Cheap directory scan; validation is
/// deferred to `peek_ctl_identity`.
pub fn enumerate_ctl_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/dev/shm") {
        for ent in rd.flatten() {
            if let Ok(name) = ent.file_name().into_string() {
                if let Some(rest) = name.strip_prefix("rtmap_ctl_") {
                    if let Ok(pid) = rest.parse::<u32>() {
                        pids.push(pid);
                    }
                }
            }
        }
    }
    pids
}
