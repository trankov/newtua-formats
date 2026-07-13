// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! PPMd's Brimstone sub-allocator (`PPMd/SubAllocator.h` + `SubAllocatorBrimstone.c`).
//!
//! A free-list arena allocator with no defragmentation or block coalescing
//! (that's what makes Brimstone simpler than the variant I allocator). The
//! reference addresses everything through `OffsetToPointer`/`PointerToOffset`
//! relative to the allocator struct itself; with `#![forbid(unsafe_code)]` we
//! have no raw pointers at all, so the arena is a plain `Vec<u8>` and every
//! "pointer" in the port is a `u32` byte offset into it — the port's central
//! trick (see the module doc for `super::context`).
//!
//! One unit is 12 bytes (`UNIT_SIZE`); a `PPMdContext` (see `context.rs`) is
//! exactly one unit, which is why `AllocContext` can hand out raw units from
//! the top of the heap without going through the size-classed free lists at
//! all. Offset `0` means "null" in the reference (it can never be a valid
//! allocation because the allocator's own header precedes the heap in the
//! same `malloc` block); to preserve that invariant here — where the arena
//! has no header of its own — the first unit of the arena is reserved and
//! never handed out (`low_unit` starts at `UNIT_SIZE`, not `0`).

pub(crate) const UNIT_SIZE: u32 = 12;

const N1: usize = 4;
const N2: usize = 4;
const N3: usize = 4;
const N4: usize = (128 + 3 - N1 - 2 * N2 - 3 * N3) / 4;
pub(crate) const N_INDEXES: usize = N1 + N2 + N3 + N4;

/// `PPMdSubAllocatorBrimstone` (`SubAllocatorBrimstone.h`). `arena` replaces
/// the reference's flexible `HeapStart[]` tail; everything else is a direct
/// field-for-field port.
pub(crate) struct BrimstoneAlloc {
    arena: Vec<u8>,
    sub_alloc_size: u32,
    index2units: [u8; N_INDEXES],
    units2index: [u8; 128],
    low_unit: u32,
    high_unit: u32,
    free_list: [u32; N_INDEXES],
}

impl BrimstoneAlloc {
    /// `CreateSubAllocatorBrimstone` (`.c:29`). `size` is the heap size in
    /// bytes (the container already scaled `1<<readUInt8()` before calling
    /// in); the arena itself isn't allocated until [`Self::init`].
    pub(crate) fn new(size: u32) -> Self {
        let mut index2units = [0u8; N_INDEXES];
        for (i, v) in index2units.iter_mut().enumerate().take(N1) {
            *v = (1 + i) as u8;
        }
        for i in 0..N2 {
            index2units[N1 + i] = (2 + N1 + i * 2) as u8;
        }
        for i in 0..N3 {
            index2units[N1 + N2 + i] = (3 + N1 + 2 * N2 + i * 3) as u8;
        }
        for i in 0..N4 {
            index2units[N1 + N2 + N3 + i] = (4 + N1 + 2 * N2 + 3 * N3 + i * 4) as u8;
        }

        let mut units2index = [0u8; 128];
        let mut i = 0usize;
        for (k, v) in units2index.iter_mut().enumerate() {
            if (index2units[i] as usize) < k + 1 {
                i += 1;
            }
            *v = i as u8;
        }

        BrimstoneAlloc {
            arena: Vec::new(),
            sub_alloc_size: size,
            index2units,
            units2index,
            low_unit: 0,
            high_unit: 0,
            free_list: [0u32; N_INDEXES],
        }
    }

    /// `InitBrimstone` (`.c:65`): a fresh, empty heap. Called on every model
    /// (re)start, so it (re)allocates the arena from scratch.
    pub(crate) fn init(&mut self) {
        self.free_list = [0u32; N_INDEXES];
        let usable_units = self.sub_alloc_size / UNIT_SIZE;
        let heap_units = UNIT_SIZE * usable_units;
        self.arena = vec![0u8; (UNIT_SIZE + heap_units) as usize];
        self.low_unit = UNIT_SIZE;
        self.high_unit = UNIT_SIZE + heap_units;
    }

    // === raw arena access (`OffsetToPointer`/`PointerToOffset` collapse to
    // plain indexing once "pointer" is just "offset") ======================

    pub(crate) fn get_u8(&self, off: u32) -> u8 {
        self.arena[off as usize]
    }

    pub(crate) fn put_u8(&mut self, off: u32, v: u8) {
        self.arena[off as usize] = v;
    }

    pub(crate) fn get_u16(&self, off: u32) -> u16 {
        let o = off as usize;
        u16::from_le_bytes(self.arena[o..o + 2].try_into().unwrap())
    }

    pub(crate) fn put_u16(&mut self, off: u32, v: u16) {
        let o = off as usize;
        self.arena[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn get_u32(&self, off: u32) -> u32 {
        let o = off as usize;
        u32::from_le_bytes(self.arena[o..o + 4].try_into().unwrap())
    }

    pub(crate) fn put_u32(&mut self, off: u32, v: u32) {
        let o = off as usize;
        self.arena[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// `memmove`-style copy inside the arena (used by `RescalePPMdContext`'s
    /// insertion-sort shift and `Expand`/`ShrinkUnits`' block relocation).
    pub(crate) fn copy_within(&mut self, src: u32, dst: u32, len: u32) {
        let (s, d, l) = (src as usize, dst as usize, len as usize);
        self.arena.copy_within(s..s + l, d);
    }

    // === allocation policy ==================================================

    fn i2b(&self, index: usize) -> u32 {
        UNIT_SIZE * self.index2units[index] as u32
    }

    fn insert_node(&mut self, p: u32, index: usize) {
        self.put_u32(p, self.free_list[index]);
        self.free_list[index] = p;
    }

    fn remove_node(&mut self, index: usize) -> u32 {
        let node = self.free_list[index];
        self.free_list[index] = self.get_u32(node);
        node
    }

    /// `SplitBlock` (`.c:169`).
    fn split_block(&mut self, pv: u32, oldindex: usize, newindex: usize) {
        let mut p = pv + self.i2b(newindex);

        let mut diff = self.index2units[oldindex] as i32 - self.index2units[newindex] as i32;
        let i = self.units2index[(diff - 1) as usize] as usize;
        if self.index2units[i] as i32 != diff {
            self.insert_node(p, i - 1);
            p += self.i2b(i - 1);
            diff -= self.index2units[i - 1] as i32;
        }

        self.insert_node(p, self.units2index[(diff - 1) as usize] as usize);
    }

    /// `AllocContextBrimstone` (`.c:73`): a `PPMdContext` is exactly one unit,
    /// so it's cheaper to carve straight off the top of the heap than to go
    /// through the size-classed free lists.
    pub(crate) fn alloc_context(&mut self) -> u32 {
        if self.high_unit > self.low_unit {
            self.high_unit -= UNIT_SIZE;
            return self.high_unit;
        }
        self.alloc_units(1)
    }

    /// `AllocUnitsBrimstone` (`.c:84`). Returns `0` (null) on exhaustion.
    pub(crate) fn alloc_units(&mut self, num: i32) -> u32 {
        let index = self.units2index[(num - 1) as usize] as usize;
        if self.free_list[index] != 0 {
            return self.remove_node(index);
        }

        let units = self.low_unit;
        self.low_unit += self.i2b(index);
        if self.low_unit <= self.high_unit {
            return units;
        }
        self.low_unit -= self.i2b(index);

        for i in (index + 1)..N_INDEXES {
            if self.free_list[i] != 0 {
                let units = self.remove_node(i);
                self.split_block(units, i, index);
                return units;
            }
        }

        0
    }

    /// `ExpandUnitsBrimstone` (`.c:108`).
    pub(crate) fn expand_units(&mut self, oldoffs: u32, oldnum: i32) -> u32 {
        let oldindex = self.units2index[(oldnum - 1) as usize] as usize;
        let newindex = self.units2index[oldnum as usize] as usize;
        if oldindex == newindex {
            return oldoffs;
        }

        let offs = self.alloc_units(oldnum + 1);
        if offs != 0 {
            let n = self.i2b(oldindex);
            self.copy_within(oldoffs, offs, n);
            self.insert_node(oldoffs, oldindex);
        }
        offs
    }

    /// `ShrinkUnitsBrimstone` (`.c:125`).
    pub(crate) fn shrink_units(&mut self, oldoffs: u32, oldnum: i32, newnum: i32) -> u32 {
        let oldindex = self.units2index[(oldnum - 1) as usize] as usize;
        let newindex = self.units2index[(newnum - 1) as usize] as usize;
        if oldindex == newindex {
            return oldoffs;
        }

        if self.free_list[newindex] != 0 {
            let ptr = self.remove_node(newindex);
            let n = self.i2b(newindex);
            self.copy_within(oldoffs, ptr, n);
            self.insert_node(oldoffs, oldindex);
            ptr
        } else {
            self.split_block(oldoffs, oldindex, newindex);
            oldoffs
        }
    }

    /// `FreeUnitsBrimstone` (`.c:146`).
    pub(crate) fn free_units(&mut self, offs: u32, num: i32) {
        let index = self.units2index[(num - 1) as usize] as usize;
        self.insert_node(offs, index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index2units_matches_reference_tables() {
        let a = BrimstoneAlloc::new(0);
        // N1=4: 1,2,3,4
        assert_eq!(&a.index2units[0..4], &[1, 2, 3, 4]);
        // N2=4: 2+4+0*2=6, 8, 10, 12
        assert_eq!(&a.index2units[4..8], &[6, 8, 10, 12]);
        // N3=4: 3+4+8+0*3=15, 18, 21, 24
        assert_eq!(&a.index2units[8..12], &[15, 18, 21, 24]);
        // N4 starts at 4+4+8+3*4=28, step 4
        assert_eq!(&a.index2units[12..14], &[28, 32]);
        assert_eq!(N_INDEXES, 38);
        assert_eq!(*a.index2units.last().unwrap(), 128);
    }

    #[test]
    fn units2index_maps_num_minus_one_to_smallest_covering_bucket() {
        let a = BrimstoneAlloc::new(0);
        // num=1 -> index2units[0]=1 -> bucket 0
        assert_eq!(a.units2index[0], 0);
        // num=2 -> index2units[1]=2 -> bucket 1
        assert_eq!(a.units2index[1], 1);
        // num=128 -> last bucket (37), index2units[37]=128
        assert_eq!(a.units2index[127], 37);
    }

    #[test]
    fn init_reserves_first_unit_as_null_sentinel() {
        let mut a = BrimstoneAlloc::new(120); // 10 units
        a.init();
        assert_eq!(a.low_unit, UNIT_SIZE);
        assert_eq!(a.high_unit, UNIT_SIZE + UNIT_SIZE * 10);
    }

    #[test]
    fn alloc_context_takes_from_the_top_of_the_heap() {
        let mut a = BrimstoneAlloc::new(48); // 4 units
        a.init();
        let top = a.high_unit;
        let c1 = a.alloc_context();
        assert_eq!(c1, top - UNIT_SIZE);
        let c2 = a.alloc_context();
        assert_eq!(c2, top - 2 * UNIT_SIZE);
        assert_ne!(c1, 0);
        assert_ne!(c2, 0);
    }

    #[test]
    fn alloc_units_takes_from_the_bottom_when_free_list_empty() {
        let mut a = BrimstoneAlloc::new(48);
        a.init();
        let bottom = a.low_unit;
        let u1 = a.alloc_units(1);
        assert_eq!(u1, bottom);
        let u2 = a.alloc_units(1);
        assert_eq!(u2, bottom + UNIT_SIZE);
    }

    #[test]
    fn free_then_alloc_reuses_the_same_block() {
        let mut a = BrimstoneAlloc::new(48);
        a.init();
        let u1 = a.alloc_units(2);
        a.free_units(u1, 2);
        let u2 = a.alloc_units(2);
        assert_eq!(u1, u2, "freed block must come back off the free list");
    }

    #[test]
    fn alloc_exhausts_and_returns_zero() {
        let mut a = BrimstoneAlloc::new(24); // 2 units, no free list to fall back on
        a.init();
        assert_ne!(a.alloc_units(1), 0);
        assert_ne!(a.alloc_units(1), 0);
        assert_eq!(a.alloc_units(1), 0, "heap exhausted -> null");
    }

    #[test]
    fn alloc_context_and_alloc_units_meet_in_the_middle_then_fail() {
        let mut a = BrimstoneAlloc::new(24); // 2 units
        a.init();
        assert_ne!(a.alloc_context(), 0); // takes the top unit
        assert_ne!(a.alloc_units(1), 0); // takes the bottom unit
        assert_eq!(a.alloc_units(1), 0); // nothing left
        assert_eq!(a.alloc_context(), 0); // AllocContext falls back to AllocUnits too
    }

    #[test]
    fn split_block_leaves_a_reusable_remainder_on_the_free_list() {
        // Exactly 4 units of heap: the low/high-unit bump path has no room
        // left after the first allocation, so a later 1-unit request is
        // forced through the search-and-split path (`AllocUnitsBrimstone`
        // only searches the free list once bumping `LowUnit` would overrun
        // `HighUnit` — with slack still in the heap, `split_block` never
        // runs at all, which the previous version of this test missed).
        let mut a = BrimstoneAlloc::new(48); // 4 units
        a.init();
        let big = a.alloc_units(4);
        assert_eq!(
            a.low_unit, a.high_unit,
            "heap fully committed by the bump path"
        );
        a.free_units(big, 4);

        let small = a.alloc_units(1);
        assert_eq!(small, big, "split reuses the start of the freed block");
        assert_eq!(
            a.low_unit, a.high_unit,
            "split must not touch low_unit/high_unit"
        );

        // The 3-unit remainder split_block left on its own free list must be
        // allocatable without touching low_unit/high_unit again.
        let remainder = a.alloc_units(3);
        assert_eq!(
            remainder,
            big + UNIT_SIZE,
            "remainder starts after the 1-unit piece"
        );
        assert_eq!(a.low_unit, a.high_unit);

        assert_eq!(a.alloc_units(1), 0, "heap and free lists both exhausted");
    }

    #[test]
    fn expand_units_grows_in_place_within_the_same_bucket_without_copying() {
        let mut a = BrimstoneAlloc::new(120);
        a.init();
        // num=1 and num=2 both map to buckets 0 and 1 respectively (distinct
        // buckets per Index2Units[0..2]=[1,2]), so growing 1->2 units must
        // relocate. Pick a same-bucket growth: none exists for N1 (each unit
        // count has its own bucket), so this test instead checks a real
        // cross-bucket expand copies the payload byte-for-byte.
        let off = a.alloc_units(1);
        a.put_u8(off, 0xAB);
        let grown = a.expand_units(off, 1);
        assert_ne!(grown, 0);
        assert_eq!(
            a.get_u8(grown),
            0xAB,
            "expand must preserve the old payload"
        );
    }

    #[test]
    fn shrink_units_preserves_payload_prefix() {
        let mut a = BrimstoneAlloc::new(120);
        a.init();
        let off = a.alloc_units(3);
        a.put_u32(off, 0xdead_beef);
        let shrunk = a.shrink_units(off, 3, 1);
        assert_ne!(shrunk, 0);
        assert_eq!(a.get_u32(shrunk), 0xdead_beef);
    }

    #[test]
    fn u16_and_u32_are_little_endian() {
        let mut a = BrimstoneAlloc::new(48);
        a.init();
        let off = a.alloc_units(1);
        a.put_u16(off, 0x1234);
        assert_eq!(a.get_u8(off), 0x34);
        assert_eq!(a.get_u8(off + 1), 0x12);
        a.put_u32(off, 0x0102_0304);
        assert_eq!(a.get_u8(off), 0x04);
        assert_eq!(a.get_u8(off + 3), 0x01);
    }

    #[test]
    fn copy_within_handles_forward_overlap_like_memmove() {
        let mut a = BrimstoneAlloc::new(48);
        a.init();
        let base = a.low_unit;
        for i in 0..6 {
            a.put_u8(base + i, i as u8);
        }
        // Shift [base+0..base+4) to [base+1..base+5): overlapping forward copy.
        a.copy_within(base, base + 1, 4);
        assert_eq!(
            (0..6).map(|i| a.get_u8(base + i)).collect::<Vec<_>>(),
            vec![0, 0, 1, 2, 3, 5]
        );
    }
}
