const std = @import("std");
const math = std.math;
const mem = std.mem;
const sort = std.sort;
const testing = std.testing;

const assert = std.debug.assert;

const Range = @import("Range.zig");
const log = std.log.scoped(.address_allocator);

const AddressAllocator = @This();

/// The **sorted** list of `Range`s that are blocked.
ranges: std.ArrayListUnmanaged(Range) = .empty,
child_allocator: mem.Allocator,

// TODO: we should likely create an init function that blocks the entire negative address space
pub fn init(child_allocator: mem.Allocator) !AddressAllocator {
    var aa: AddressAllocator = .{ .child_allocator = child_allocator };

    const ranges = try child_allocator.alloc(Range, std.heap.pageSize() / @sizeOf(Range));
    aa.ranges = .initBuffer(ranges);

    aa.block(.fromSlice(Range, ranges)) catch unreachable;

    return aa;
}

pub fn deinit(self: *AddressAllocator) void {
    self.ranges.deinit(self.child_allocator);
}

pub fn allocator(self: *AddressAllocator) mem.Allocator {
    return .{
        .ptr = self,
        .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        },
    };
}

fn alloc(ctx: *anyopaque, n: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
    const self: *AddressAllocator = @ptrCast(@alignCast(ctx));

    const ptr = self.child_allocator.rawAlloc(n, alignment, ra) orelse return null;
    self.block(.fromPtr(ptr, n)) catch @panic("OOM");
    return ptr;
}

fn resize(
    ctx: *anyopaque,
    buf: []u8,
    alignment: std.mem.Alignment,
    new_len: usize,
    ret_addr: usize,
) bool {
    const self: *AddressAllocator = @ptrCast(@alignCast(ctx));

    const success = self.child_allocator.rawResize(buf, alignment, new_len, ret_addr);
    if (success) {
        self.block(.fromPtr(buf.ptr, new_len)) catch @panic("OOM");
    }
    return success;
}

fn remap(
    context: *anyopaque,
    memory: []u8,
    alignment: std.mem.Alignment,
    new_len: usize,
    return_address: usize,
) ?[*]u8 {
    const self: *AddressAllocator = @ptrCast(@alignCast(context));

    const ptr = self.child_allocator.rawRemap(memory, alignment, new_len, return_address) orelse
        return null;

    if (ptr != memory.ptr) { // new memory location
        self.unblock(.fromSlice(u8, memory)) catch @panic("OOM");
    }
    self.block(.fromPtr(ptr, new_len)) catch @panic("OOM");
    return ptr;
}

fn free(
    ctx: *anyopaque,
    buf: []u8,
    alignment: std.mem.Alignment,
    ret_addr: usize,
) void {
    const self: *AddressAllocator = @ptrCast(@alignCast(ctx));

    self.unblock(.fromSlice(u8, buf)) catch @panic("OOM");
    return self.child_allocator.rawFree(buf, alignment, ret_addr);
}

/// Block a range to not be used by the `allocate` function. This function will always succeed, if
/// there is enough memory available.
pub fn block(self: *AddressAllocator, range: Range) !void {
    if (range.size() == 0) return;

    // Find the correct sorted position to insert the new range.
    const insert_idx = sort.lowerBound(
        Range,
        self.ranges.items,
        range,
        Range.compareTouching,
    );
    log.debug(
        "block: range: {f}, insert_idx: {}",
        .{ range, insert_idx },
    );
    // If we don't overlap any existing one, we just insert.
    if (insert_idx == self.ranges.items.len or
        self.ranges.items[insert_idx].compareTouching(range) == .gt)
    {
        return self.ranges.insert(self.child_allocator, insert_idx, range);
    }
    errdefer comptime unreachable;
    assert(self.ranges.items.len > 0);

    // Now `insert_idx` points to the first entry, that touches `range`.
    const first = &self.ranges.items[insert_idx];
    assert(first.touches(range));
    if (insert_idx > 0 and self.ranges.items.len > 0) {
        assert(!self.ranges.items[insert_idx - 1].touches(range));
    }
    log.debug("block: `range` touches at least one existing range.", .{});

    first.start = @min(first.start, range.start);
    first.end = @max(first.end, range.end);

    // Merge any following overlapping ranges into this one.
    // NOTE: We "iterate" through the slice by removing unneeded items and moving all following ones
    // back by one. That's why we always look at `insert_idx + 1`.
    while (insert_idx + 1 < self.ranges.items.len and
        self.ranges.items[insert_idx + 1].touches(range))
    {
        const neighbor = self.ranges.items[insert_idx + 1];
        assert(range.end >= neighbor.start);
        assert(range.start <= neighbor.start);
        first.end = @max(first.end, neighbor.end);
        _ = self.ranges.orderedRemove(insert_idx + 1);
    }
}

pub fn unblock(
    self: *AddressAllocator,
    range: Range,
) !void {

    // Find the correct sorted position to remove the range.
    var remove_idx = sort.lowerBound(
        Range,
        self.ranges.items,
        range,
        Range.compareOverlapping,
    );
    log.debug(
        "unblock: range: {f}, remove_idx: {}",
        .{ range, remove_idx },
    );
    // If we don't overlap any existing one, we just return.
    if (remove_idx == self.ranges.items.len or
        self.ranges.items[remove_idx].compareOverlapping(range) == .gt)
    {
        log.debug("unblock: Range to unblock overlaps nothing", .{});
        for (self.ranges.items) |r| {
            assert(!r.overlaps(range));
        }
        return;
    }
    assert(self.ranges.items.len > 0);

    // Now `remove_idx` points to the first entry, that touches `range`.
    const first = &self.ranges.items[remove_idx];
    assert(first.touches(range));
    if (remove_idx > 0 and self.ranges.items.len > 0) {
        assert(!self.ranges.items[remove_idx - 1].overlaps(range));
    }
    log.debug("unblock: `range` touches at least one existing range.", .{});

    // We have multiple cases for the first touching range:
    //
    //          [ range to unblock ]
    // 0   [           first            ]   -> split
    //
    //          [ range to unblock ]
    // 1              [     first       ]
    // 1        [         first         ]   -> change start
    //
    //          [ range to unblock ]
    // 2        [ first ]
    // 2             [ first ]
    // 2                   [ first ]        -> remove
    //
    //          [ range to unblock ]
    // 3   [     first       ]
    // 3   [         first         ]        -> change end
    //
    // If it's cases 0 or 1 the operation is finished because we can't overlap another one. For cases 2
    // and 3 we will have to remove the following ranges until we arrive at one of the following cases:
    // 1.
    //          [ range to unblock ]
    //                         [ last ]
    // 2.
    //          [ range to unblock ]
    //                               [ last ]
    //
    if (first.start < range.start and first.end > range.end) {
        const old_end = first.end;
        first.end = range.start;
        try self.ranges.insert(self.child_allocator, remove_idx + 1, .{
            .start = range.end,
            .end = old_end,
        });
        return;
    } else if (first.start >= range.start and first.start < range.end and first.end > range.end) {
        first.start = range.end;
        return;
    } else if (first.start >= range.start and first.end <= range.end) {
        _ = self.ranges.orderedRemove(remove_idx);
    } else if (first.start < range.start and first.end > range.start and first.end <= range.end) {
        first.end = range.start;
        remove_idx += 1;
    } else {
        unreachable;
    }

    // NOTE: We "iterate" through the slice by removing unneeded items and moving all following ones
    // back by one. That's why we always look at `insert_idx + 1`.
    while (remove_idx < self.ranges.items.len) {
        const next_range = &self.ranges.items[remove_idx];
        if (next_range.start >= range.end) break;

        if (next_range.end <= range.end) {
            _ = self.ranges.orderedRemove(remove_idx);
        } else {
            next_range.start = range.end;
            break;
        }
    }
}

test "fuzz against bitset" {
    const iterations = 64 * 1024;
    const size = 1024;

    var aa = AddressAllocator{ .child_allocator = testing.allocator };
    defer aa.deinit();

    var bitset_ref = try std.bit_set.DynamicBitSetUnmanaged.initEmpty(testing.allocator, size);
    defer bitset_ref.deinit(testing.allocator);

    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const random = prng.random();

    var expected_ranges = try std.ArrayListUnmanaged(Range).initCapacity(testing.allocator, size / 2);
    defer expected_ranges.deinit(testing.allocator);

    var bitset_temp = try std.bit_set.DynamicBitSetUnmanaged.initEmpty(testing.allocator, size);
    defer bitset_temp.deinit(testing.allocator);

    for (0..iterations) |_| {
        const is_block = random.boolean();
        const start = random.intRangeLessThan(usize, 0, size);
        const len = random.intRangeAtMost(usize, 1, size - start);
        const end = start + len;

        const range = Range{ .start = @intCast(start), .end = @intCast(end) };

        if (is_block) {
            try aa.block(range);
            bitset_ref.setRangeValue(.{ .start = start, .end = end }, true);
        } else {
            try aa.unblock(range);
            bitset_ref.setRangeValue(.{ .start = start, .end = end }, false);
        }

        bitset_temp.unsetAll();
        for (aa.ranges.items) |r| {
            bitset_temp.setRangeValue(.{ .start = @intCast(r.start), .end = @intCast(r.end) }, true);
        }
        try testing.expect(bitset_ref.eql(bitset_temp));
    }
}

/// An internal iterator that cleanly yields unblocked memory holes.
const HoleIterator = struct {
    ranges: []const Range,
    valid_range: Range,
    size: i64,
    candidate_start: i64,
    idx: usize,

    fn init(aa: *const AddressAllocator, valid_range: Range, size: u64) HoleIterator {
        const start_idx = sort.lowerBound(
            Range,
            aa.ranges.items,
            valid_range,
            Range.compareOverlapping,
        );
        return .{
            .ranges = aa.ranges.items,
            .valid_range = valid_range,
            .size = @intCast(size),
            .candidate_start = valid_range.start,
            .idx = start_idx,
        };
    }

    fn next(self: *HoleIterator) ?Range {
        while (self.idx < self.ranges.len) {
            const reserved = self.ranges[self.idx];
            if (self.candidate_start >= self.valid_range.end) return null;

            if (self.candidate_start < reserved.start) {
                const hole_end = @min(reserved.start, self.valid_range.end);
                const hole_start = self.candidate_start;
                self.candidate_start = reserved.end;

                if (hole_end >= hole_start + self.size) {
                    return Range{ .start = hole_start, .end = hole_end };
                }
            } else {
                self.candidate_start = @max(self.candidate_start, reserved.end);
            }
            self.idx += 1;
        }

        if (self.candidate_start < self.valid_range.end) {
            const hole_start = self.candidate_start;
            const hole_end = self.valid_range.end;
            self.candidate_start = self.valid_range.end; // Mark done to prevent infinite loops
            if (hole_end >= hole_start + self.size) {
                return Range{ .start = hole_start, .end = hole_end };
            }
        }

        return null;
    }

    test {
        var aa = AddressAllocator{ .child_allocator = testing.allocator };
        defer aa.deinit();

        try aa.block(.{ .start = 100, .end = 200 });
        try aa.block(.{ .start = 300, .end = 400 });

        var it = HoleIterator.init(&aa, .{ .start = 0, .end = 500 }, 10);

        try testing.expectEqual(Range{ .start = 0, .end = 100 }, it.next().?);
        try testing.expectEqual(Range{ .start = 200, .end = 300 }, it.next().?);
        try testing.expectEqual(Range{ .start = 400, .end = 500 }, it.next().?);
        try testing.expectEqual(null, it.next());
    }
};

const Constraint = struct {
    min_rel: i32,
    max_rel: i32,
    mask: u32,
    pattern: u32,
};

/// Solves a single 32-bit relative jump constraint in O(1) time.
///
/// Returns the smallest `rel32` such that
/// - `min_rel <= rel32 <= max_rel` and
/// - `(rel32 & mask) == pattern`
///
/// Context:
/// During "Instruction Punning", we overwrite an instruction with a 5-byte jump (`E9 xx xx xx xx`).
/// If the original instruction is smaller than 5 bytes, our jump offset (`xx xx xx xx`) will spill
/// into the next instruction. To prevent crashing, the spilled bytes must form the successor
/// instruction. This restricts certain bits/bytes of our `rel32` offset to fixed values.
///
/// The algorithm uses a bit-twiddling hack to isolate the "free" (unmasked) bits, increment them as
/// a single continuous integer, and map them back around the fixed "pattern" bits, completely
/// avoiding loops over the search space.
///
/// Visualization of the bit-twiddling constraint logic:
/// -------------------------------------------------------------------------
/// Mask:    1111 1111 0000 0000 1111 1111 0000 0000 (1 = Locked bits)
/// Pattern: 0000 0000 0000 0000 1110 1001 0000 0000 (The forced values)
/// Free:    0000 0000 1111 1111 0000 0000 1111 1111 (~Mask)
///
/// Current Candidate: [ Fixed A ] [ Free 1 ] [ Fixed B ] [ Free 0 ]
///
/// If `Current Candidate < min_rel`, we add 1 to the "Free" bits.
/// The hack `(((candidate & free) | mask) + 1) & free` allows the arithmetic carry to jump over the
/// fixed bits without corrupting them:
///
/// Next Valid Val:    [ Fixed A ][ Free 1 + carry ] [ Fixed B ] [ Free 0 + 1 ]
/// -------------------------------------------------------------------------
fn solveRelativeConstraint(c: Constraint) ?i32 {
    log.debug(
        "solveRelative: min: {x}, max: {x}, mask: {x}, pattern: {x}",
        .{ c.min_rel, c.max_rel, c.mask, c.pattern },
    );
    assert((c.pattern & ~c.mask) == 0);
    if (c.min_rel > c.max_rel) return null;

    // Force the pattern onto the current minimum value
    var candidate: u32 = (@as(u32, @bitCast(c.min_rel)) & ~c.mask) | c.pattern;
    log.debug("  candidate (init): {x}", .{candidate});

    // If forcing the pattern made the value smaller than min_rel, we must increment the "free" bits
    // to find the next valid higher number.
    if (@as(i32, @bitCast(candidate)) < c.min_rel) {
        if (~c.mask == 0) {
            log.debug("  failed: fully constrained", .{});
            return null;
        }

        const incremented_free = (((candidate & ~c.mask) | c.mask) +% 1) & ~c.mask;
        assert(incremented_free & c.mask == 0); // All constrained bits are 0
        candidate = incremented_free | c.pattern;
        log.debug("  candidate (incr): {x}", .{candidate});
    }

    const result: i32 = @bitCast(candidate);
    if (result >= c.min_rel and result <= c.max_rel) {
        log.debug("  success: {x}", .{result});
        return result;
    }
    log.debug("  failed: result {x} out of bounds", .{result});
    return null;
}

test "solveRelativeConstraint basic" {
    try testing.expectEqual(100, solveRelativeConstraint(.{
        .min_rel = 100,
        .max_rel = 200,
        .mask = 0,
        .pattern = 0,
    }));
}

test "solveRelativeConstraint aligned" {
    try testing.expectEqual(0x10E8, solveRelativeConstraint(.{
        .min_rel = 0x1000,
        .max_rel = 0x2000,
        .mask = 0xFF,
        .pattern = 0xE8,
    }));
    try testing.expectEqual(0x10E8, solveRelativeConstraint(.{
        .min_rel = 0x10E8,
        .max_rel = 0x2000,
        .mask = 0xFF,
        .pattern = 0xE8,
    }));
    try testing.expectEqual(0x11E8, solveRelativeConstraint(.{
        .min_rel = 0x10E9,
        .max_rel = 0x2000,
        .mask = 0xFF,
        .pattern = 0xE8,
    }));
}

test "solveRelativeConstraint negative" {
    try testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xFFFFF0E8))), solveRelativeConstraint(.{
        .min_rel = -0x1000,
        .max_rel = 0,
        .mask = 0xFF,
        .pattern = 0xE8,
    }));
}

test "solveRelativeConstraint impossible" {
    try testing.expectEqual(null, solveRelativeConstraint(.{
        .min_rel = 0x1000,
        .max_rel = 0x10E7,
        .mask = 0xFF,
        .pattern = 0xE8,
    }));
    try testing.expectEqual(null, solveRelativeConstraint(.{
        .min_rel = 0x10000000,
        .max_rel = 0x11000000,
        .mask = 0xFFFFFFFF,
        .pattern = 0x12345678,
    }));
}

test "solveRelativeConstraint overflow" {
    try testing.expectEqual(0x12345678, solveRelativeConstraint(.{
        .min_rel = 0x10000000,
        .max_rel = 0x20000000,
        .mask = 0xFFFFFFFF,
        .pattern = 0x12345678,
    }));

    try testing.expectEqual(null, solveRelativeConstraint(.{
        .min_rel = 2147483640,
        .max_rel = 2147483647,
        .mask = 0xFF,
        .pattern = 0x00,
    }));
}

pub const Request = struct {
    source: u64,
    size: u64,
    valid_range: Range,
    mask: u32 = 0,
    pattern: u32 = 0,
};

/// Finds the first free range of `size` bytes within `valid_range` that also satisfies the relative
/// 32-bit jump constraints `mask` and `pattern` from `jump_source`.
/// Runs in `O(|H| + log(#R))` for
/// - `H` being the set of holes in the valid range and
/// - `#R` being the number of ranges in the AddressAllocator.
pub fn findAllocation(
    self: *AddressAllocator,
    r: Request,
) ?Range {
    if (r.valid_range.size() < r.size) return null;
    if (r.size == 0) return null;

    var it = HoleIterator.init(self, r.valid_range, r.size);
    while (it.next()) |hole| {
        log.debug("findAllocation: Hole: {f}", .{hole});
        const bounds = getRelativeBounds(hole, @intCast(r.size), r.source) orelse continue;
        const rel32 = solveRelativeConstraint(.{
            .min_rel = bounds.min,
            .max_rel = bounds.max,
            .mask = r.mask,
            .pattern = r.pattern,
        }) orelse continue;

        const start = @as(i64, @intCast(r.source)) + rel32;
        const end = start + @as(i64, @intCast(r.size));

        assert(end - start == r.size);
        assert(start >= r.valid_range.start);
        assert(end <= r.valid_range.end);
        return .{ .start = start, .end = end };
    }

    return null;
}

fn getRelativeBounds(hole: Range, size: i64, source: u64) ?struct { min: i32, max: i32 } {
    if (hole.end - hole.start < size) return null;

    const offset_to_min = hole.start - @as(i64, @intCast(source));
    const offset_to_max = (hole.end - size) - @as(i64, @intCast(source));

    const min_rel = @max(offset_to_min, math.minInt(i32));
    const max_rel = @min(offset_to_max, math.maxInt(i32));
    if (min_rel > max_rel) return null;

    return .{
        .min = @intCast(min_rel),
        .max = @intCast(max_rel),
    };
}

test "findConstrainedAllocation" {
    var aa = AddressAllocator{ .child_allocator = testing.allocator };
    defer aa.deinit();

    try aa.block(.{ .start = 0x1000, .end = 0x2000 });
    try aa.block(.{ .start = 0x3000, .end = 0x4000 });

    try testing.expectEqual(
        Range{ .start = 0x00AA, .end = 0x00BA },
        aa.findAllocation(.{
            .size = 0x10,
            .valid_range = .{ .start = 0x0000, .end = 0x4000 },
            .source = 0,
            .mask = 0xFF,
            .pattern = 0xAA,
        }),
    );

    try testing.expectEqual(
        Range{ .start = 0x20AA, .end = 0x20BA },
        aa.findAllocation(.{
            .size = 0x10,
            .valid_range = .{ .start = 0x1000, .end = 0x4000 },
            .source = 0,
            .mask = 0xFF,
            .pattern = 0xAA,
        }),
    );

    try testing.expectEqual(
        null,
        aa.findAllocation(.{
            .size = 0x10,
            .valid_range = .{ .start = 0x2000, .end = 0x8000 },
            .source = 0,
            .mask = 0xFFFF,
            .pattern = 0xAAAA,
        }),
    );

    try testing.expectEqual(
        Range{ .start = 0x40AA, .end = 0x50AA },
        aa.findAllocation(.{
            .size = 0x1000,
            .valid_range = .{ .start = 0x2000, .end = 0x8000 },
            .source = 0,
            .mask = 0xFF,
            .pattern = 0xAA,
        }),
    );
}

pub const CoupledResult = struct {
    rel1: i32,
    rel2: i32,
};

/// Attempts to find a joint bit-pattern that satisfies two overlapping jump constraints.
///
/// Context:
/// In tactics like Successor Eviction, we overwrite two adjacent instructions with 5-byte jumps (J1
/// and J2). If the distance between them is less than 5 bytes, their physical bytes overlap in
/// memory.
///
/// `k` represents the physical distance (in bytes) between the start of J1 and J2 (1 <= k <= 4).
/// Because x86_64 uses Little-Endian representation, the Most Significant Bytes (MSB) of J1's
/// relative offset (`rel1`) physically overlap with the Least Significant Bytes (LSB) of J2's
/// relative offset (`rel2`).
///
/// Furthermore, J2's opcode (`0xE9`) falls squarely inside the bytes of `rel1`.
///
/// Memory Layout & Endianness Overlap (Example where K = 2):
/// -----------------------------------------------------------------------------------
/// Memory Offset:   +0       +1       +2       +3       +4       +5       +6
/// J1 Bytes:       [0xE9]   [ X0 ]   [ X1 ]   [ X2 ]   [ X3 ]
/// J2 Bytes:                         [0xE9]   [ Y0 ]   [ Y1 ]   [ Y2 ]   [ Y3 ]
///
/// Consequences for `rel1` (X) and `rel2` (Y):
/// 1. Opcode Constraint:  `X1` MUST exactly equal `0xE9`.
/// 2. Shared Bytes (S):   `X2` MUST exactly equal `Y0`.
///                        `X3` MUST exactly equal `Y1`.
/// -----------------------------------------------------------------------------------
///
/// Algorithm ("The Squeeze"):
/// Iterating possibly billions of combinations of X and Y is too slow. Instead, we use the
/// constraints of the memory layout:
///
/// `rel1` is constrained to a physical memory hole `[min1, max1]`. Because memory holes are usually
/// small (e.g., 4KB), the Most Significant Bytes of `rel1` (which are exactly our Shared Bytes 'S')
/// are heavily restricted.
///
/// There are usually only a few possible values for S:
/// 1. We extract the possible values for S from `min1..max1`.
/// 2. We apply S as a strict constraint on the lower bytes of `rel2`.
/// 3. We delegate the remaining independent bits (X0, Y2 and Y3) to the `solveRelativeConstraint`.
///
/// Parameters:
/// `k`: The physical byte offset of J2 relative to J1 (1 <= k <= 4).
/// `min1`, `max1`: The valid rel32 hardware bounds for J1.
/// `min2`, `max2`: The valid rel32 hardware bounds for J2.
/// `mask1`, `pattern1`: The original byte constraints on J1.
/// `mask2`, `pattern2`: The original byte constraints on J2.
pub fn solveCoupledConstraint(
    k: u8,
    c1: Constraint,
    c2: Constraint,
) ?CoupledResult {
    log.debug("solveCoupled: k={}", .{k});
    log.debug("  C1: min={x} max={x} mask={x} pat={x}", .{ c1.min_rel, c1.max_rel, c1.mask, c1.pattern });
    log.debug("  C2: min={x} max={x} mask={x} pat={x}", .{ c2.min_rel, c2.max_rel, c2.mask, c2.pattern });
    assert(k >= 1);
    assert(k <= 4);

    // The opcode for J2 (0xE9) physically falls inside rel32 of J1 at byte index `k - 1` of rel1.
    const e9_shift = @as(u5, @intCast(k - 1)) * 8;
    const e9_mask = @as(u32, 0xFF) << e9_shift;

    if ((c1.mask & e9_mask) != 0 and (c1.pattern & e9_mask) != (@as(u32, 0xE9) << e9_shift)) {
        log.debug("  failed: opcode 0xE9 conflict in C1", .{});
        return null; // Caller's pattern conflicts with the mandatory J2 opcode
    }
    const c_mask1 = c1.mask | e9_mask;
    const c_pattern1 = (c1.pattern & ~e9_mask) | (@as(u32, 0xE9) << e9_shift);

    if (k == 4) {
        // J1 is completely resolved just with the 0xE9 constraint applied above.
        log.debug("  Fast path K=4", .{});
        const rel1 = solveRelativeConstraint(.{
            .min_rel = c1.min_rel,
            .max_rel = c1.max_rel,
            .mask = c_mask1,
            .pattern = c_pattern1,
        }) orelse return null;
        const rel2 = solveRelativeConstraint(.{
            .min_rel = c2.min_rel,
            .max_rel = c2.max_rel,
            .mask = c2.mask,
            .pattern = c2.pattern,
        }) orelse return null;
        return .{ .rel1 = rel1, .rel2 = rel2 };
    }

    // Determine the bitwise shift and mask for the Shared Bytes (S)
    const s_shift = @as(u5, @intCast(k)) * 8;
    const num_shared = @as(u5, @intCast(4 - k));
    const s_mask = (@as(u32, 1) << (num_shared * 8)) - 1;

    log.debug("  Shared Bytes: shift={}, mask={x}", .{ s_shift, s_mask });

    var current_min = c1.min_rel;
    while (current_min <= c1.max_rel) {
        const u_rel: u32 = @bitCast(current_min);
        const S = u_rel >> s_shift; // Extract shared bytes from top of rel1

        // Calculate the maximum u32 value that shares this S
        const max_u_rel_for_S = (S << s_shift) | ((@as(u32, 1) << s_shift) - 1);
        const max_i_rel_for_S: i32 = @bitCast(max_u_rel_for_S);
        const local_max1 = @min(c1.max_rel, max_i_rel_for_S);

        // Does this S conflict with J2's requirements?
        if ((c2.mask & s_mask) != 0) {
            if ((c2.pattern & c2.mask & s_mask) != (S & c2.mask & s_mask)) {
                // Advance to the next block of S.
                log.debug("  Conflict at S={x} (min={x})", .{ S, current_min });
                if (max_i_rel_for_S == std.math.maxInt(i32)) break;
                const next_min = max_i_rel_for_S + 1;
                if (next_min > c1.max_rel) break;
                current_min = next_min;
                continue;
            }
        }

        log.debug("  Trying S={x} range [{x}, {x}]", .{ S, current_min, local_max1 });

        // Apply S as a strict constraint on the lowest bytes of J2
        const c_mask2 = c2.mask | s_mask;
        const c_pattern2 = (c2.pattern & ~s_mask) | S;

        // O(1) solver execution for this specific S value
        const opt_rel1 = solveRelativeConstraint(.{
            .min_rel = current_min,
            .max_rel = local_max1,
            .mask = c_mask1,
            .pattern = c_pattern1,
        });
        const opt_rel2 = solveRelativeConstraint(.{
            .min_rel = c2.min_rel,
            .max_rel = c2.max_rel,
            .mask = c_mask2,
            .pattern = c_pattern2,
        });
        if (opt_rel1 != null and opt_rel2 != null) {
            log.debug("  Success: rel1={x} rel2={x}", .{ opt_rel1.?, opt_rel2.? });
            return .{ .rel1 = opt_rel1.?, .rel2 = opt_rel2.? };
        }

        if (max_i_rel_for_S == std.math.maxInt(i32)) break;
        const next_min = max_i_rel_for_S + 1;
        if (next_min > c1.max_rel) break;
        current_min = next_min;
    }

    log.debug("  failed: no coupled solution found", .{});
    return null;
}

test "solveCoupledConstraint K=4 (Independent)" {
    // If K=4, J1 and J2 don't share rel32 bytes, but byte 3 of rel1 MUST be 0xE9 (the J2 opcode).
    // Let's force rel1 to be in[0x12000000, 0x120000FF].
    // Since highest byte (byte 3) must be 0xE9, no value starting with 0x12 will work.
    try testing.expectEqual(null, solveCoupledConstraint(
        4,
        .{
            .min_rel = 0x12000000,
            .max_rel = 0x120000FF,
            .mask = 0,
            .pattern = 0,
        },
        .{
            .min_rel = 0,
            .max_rel = 100,
            .mask = 0,
            .pattern = 0,
        },
    ));

    const res = solveCoupledConstraint(
        4,
        .{
            .min_rel = @bitCast(@as(u32, 0xE8000000)),
            .max_rel = @bitCast(@as(u32, 0xEA000000)),
            .mask = 0,
            .pattern = 0,
        },
        .{
            .min_rel = 0x1234,
            .max_rel = 0x1234,
            .mask = 0,
            .pattern = 0,
        },
    );
    try testing.expect(res != null);
    try testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xE9000000))), res.?.rel1);
    try testing.expectEqual(0x1234, res.?.rel2);
}

test "solveCoupledConstraint K=2 (2 byte overlap)" {
    // K=2 means the top 2 bytes of rel1 are the bottom 2 bytes of rel2.
    // J2 opcode (0xE9) sits at byte 1 of rel1.
    const res = solveCoupledConstraint(
        2,
        .{
            .min_rel = 0x12340000,
            .max_rel = 0x1234FFFF,
            .mask = 0,
            .pattern = 0,
        },
        .{
            .min_rel = 0x00000000,
            .max_rel = 0x0000FFFF,
            .mask = 0,
            .pattern = 0,
        },
    );
    try testing.expect(res != null);
    try testing.expectEqual(0x1234E900, res.?.rel1);
    try testing.expectEqual(0x00001234, res.?.rel2);
}

test "solveCoupledConstraint K=2 conflict" {
    // Same as above, but J2 explicitly forbids lower bytes from being 0x1234.
    const res = solveCoupledConstraint(
        2,
        .{
            .min_rel = 0x12340000,
            .max_rel = 0x1234FFFF,
            .mask = 0,
            .pattern = 0,
        },
        .{
            .min_rel = 0x00000000,
            .max_rel = 0x0000FFFF,
            .mask = 0x0000FFFF,
            .pattern = 0x00005678,
        },
    );
    try testing.expectEqual(null, res);
}

test "solveCoupledConstraint K=2 spans multiple S values" {
    // We give J1 a wide range:[0x00000000, 0x00060000]. S can be 0 to 6.
    // We force J2 to require lower bytes = 0x0004. This forces the solver to skip S=0 and similar
    // and find S=4.
    const res = solveCoupledConstraint(
        2,
        .{
            .min_rel = 0,
            .max_rel = 0x00060000,
            .mask = 0,
            .pattern = 0,
        },
        .{
            .min_rel = 0,
            .max_rel = 0x0000FFFF,
            .mask = 0x0000FFFF,
            .pattern = 0x00000004,
        },
    );
    try testing.expect(res != null);
    try testing.expectEqual(0x0004E900, res.?.rel1);
    try testing.expectEqual(0x00000004, res.?.rel2);
}

/// Finds two allocations that simultaneously satisfy their individual offset constraints and the
/// physical overlap constraints of their origin instructions.
/// `r1` (for J1) and `r2` (for J2) separated by `k` bytes.
///
/// Runs in O(|H1| * |H2| + log(#R)) for
/// - `H1` and `H2` being the set of holes in the valid ranges in `r1` and `r2`
/// - `#R` being the number of ranges in the AddressAllocator.
pub fn findCoupledAllocation(
    self: *AddressAllocator,
    k: u8,
    r1: Request,
    r2: Request,
) ?[2]Range {
    if (r1.valid_range.size() < r1.size or r1.size == 0) return null;
    if (r2.valid_range.size() < r2.size or r2.size == 0) return null;
    assert(r2.source > r1.source);
    assert(r2.source - r1.source == k);

    var it1 = HoleIterator.init(self, r1.valid_range, r1.size);
    while (it1.next()) |hole1| {
        log.debug("findCoupledAllocation: Hole1: {f}", .{hole1});
        const b1 = getRelativeBounds(hole1, @intCast(r1.size), r1.source) orelse continue;

        var it2 = HoleIterator.init(self, r2.valid_range, r2.size);
        while (it2.next()) |hole2| {
            log.debug("  Hole2: {f}", .{hole2});
            const b2 = getRelativeBounds(hole2, @intCast(r2.size), r2.source) orelse continue;

            const c1 = Constraint{
                .min_rel = b1.min,
                .max_rel = b1.max,
                .mask = r1.mask,
                .pattern = r1.pattern,
            };
            const c2 = Constraint{
                .min_rel = b2.min,
                .max_rel = b2.max,
                .mask = r2.mask,
                .pattern = r2.pattern,
            };

            if (solveCoupledConstraint(k, c1, c2)) |result| {
                const start1 = @as(i64, @intCast(r1.source)) + result.rel1;
                const end1 = start1 + @as(i64, @intCast(r1.size));

                const start2 = @as(i64, @intCast(r2.source)) + result.rel2;
                const end2 = start2 + @as(i64, @intCast(r2.size));

                assert(end1 - start1 == r1.size);
                assert(end2 - start2 == r2.size);

                // If we used the same hole, we must ensure the actual allocations don't overlap.
                const range1 = Range{ .start = start1, .end = end1 };
                const range2 = Range{ .start = start2, .end = end2 };
                // TODO: Support allocating both trampolines in the exact same memory hole.
                // This requires dynamically partitioning the hole so the trampolines don't overlap
                // each other. For now, simply skip this case.
                if (range1.overlaps(range2)) continue;

                return [2]Range{
                    .{ .start = start1, .end = end1 },
                    .{ .start = start2, .end = end2 },
                };
            }
        }
    }

    return null;
}

/// A generic helper to mechanically verify that a coupled allocation satisfies all bitwise and
/// physical overlap constraints.
fn verifyCoupled(k: u8, r1: Request, r2: Request, j1_range: Range, j2_range: Range) !void {
    const rel1: i32 = @intCast(j1_range.start - @as(i64, @intCast(r1.source)));
    const rel2: i32 = @intCast(j2_range.start - @as(i64, @intCast(r2.source)));
    const u_rel1: u32 = @bitCast(rel1);
    const u_rel2: u32 = @bitCast(rel2);

    // Opcode Constraint
    const e9_shift = @as(u5, @intCast(k - 1)) * 8;
    try testing.expectEqual(@as(u32, 0xE9), (u_rel1 >> e9_shift) & 0xFF);

    // Shared Bytes Constraint
    if (k < 4) {
        const shared_shift = @as(u5, @intCast(k)) * 8;
        const shared_mask = (@as(u32, 1) << (@as(u5, @intCast(4 - k)) * 8)) - 1;
        const shared1 = (u_rel1 >> shared_shift) & shared_mask;
        const shared2 = u_rel2 & shared_mask;
        try testing.expectEqual(shared1, shared2);
    }

    // Original User Constraints
    try testing.expectEqual(r1.pattern, u_rel1 & r1.mask);
    try testing.expectEqual(r2.pattern, u_rel2 & r2.mask);
}

test "findCoupledAllocation" {
    var aa = AddressAllocator{ .child_allocator = testing.allocator };
    defer aa.deinit();

    // Block memory so we have distinct holes.
    // We need a hole that allows `rel1` to have `0xE9` in its second byte.
    // This means `rel1` needs to be around `0xE900`.
    try aa.block(.{ .start = 0x2000, .end = 0xE000 });
    try aa.block(.{ .start = 0xF000, .end = 0x10000 });

    const r1 = Request{ .source = 0, .size = 10, .valid_range = .{ .start = 0, .end = 0x20000 } };
    const r2 = Request{ .source = 2, .size = 10, .valid_range = .{ .start = 0, .end = 0x20000 } };
    const res = aa.findCoupledAllocation(2, r1, r2);
    try testing.expect(res != null);

    const j1_range = res.?[0];
    const j2_range = res.?[1];
    try testing.expect(j1_range.start >= 0xE000 and j1_range.end <= 0xF000);
    try testing.expect(j2_range.start >= 0x0000 and j2_range.end <= 0x2000);

    try verifyCoupled(2, r1, r2, j1_range, j2_range);
}

test "findCoupledAllocation K=1 (3 shared bytes)" {
    var aa = AddressAllocator{ .child_allocator = testing.allocator };
    defer aa.deinit();

    try aa.block(.{ .start = 0x2000, .end = 0x01000000 });

    const r1 = Request{ .source = 0, .size = 10, .valid_range = .{ .start = 0, .end = 0x10000000 } };
    const r2 = Request{ .source = 1, .size = 10, .valid_range = .{ .start = 0, .end = 0x10000000 } };
    const res = aa.findCoupledAllocation(1, r1, r2);
    try testing.expect(res != null);

    // For K=1, rel1's lowest byte MUST be 0xE9.
    // In Hole 1, the smallest valid rel1 is 0x000000E9.
    // This makes the shared bytes (top 3 bytes) 0x000000.
    try testing.expectEqual(0xE9, res.?[0].start);
    try testing.expectEqual(0x01, res.?[1].start);

    try verifyCoupled(1, r1, r2, res.?[0], res.?[1]);
}

test "findCoupledAllocation K=3 (1 shared byte)" {
    var aa = AddressAllocator{ .child_allocator = testing.allocator };
    defer aa.deinit();

    // K=3 means rel1 byte 2 MUST be 0xE9. rel1 looks like 0xXXE9XXXX.
    // Smallest positive is ~0x00E90000. We need a hole there.
    try aa.block(.{ .start = 0x2000, .end = 0x00E90000 });

    const r1 = Request{ .source = 0, .size = 10, .valid_range = .{ .start = 0, .end = 0x10000000 } };
    const r2 = Request{ .source = 3, .size = 10, .valid_range = .{ .start = 0, .end = 0x10000000 } };
    const res = aa.findCoupledAllocation(3, r1, r2);
    try testing.expect(res != null);
    try verifyCoupled(3, r1, r2, res.?[0], res.?[1]);
}

test "findCoupledAllocation K=4 (Independent)" {
    var aa = AddressAllocator{ .child_allocator = testing.allocator };
    defer aa.deinit();

    try aa.block(.{ .start = 0x2000, .end = 0x01000000 });

    const r1 = Request{
        .source = 0x50000000,
        .size = 10,
        .valid_range = .{ .start = 0, .end = 0x60000000 },
    };
    const r2 = Request{
        .source = 0x50000004,
        .size = 10,
        .valid_range = .{ .start = 0, .end = 0x60000000 },
    };

    const res = aa.findCoupledAllocation(4, r1, r2);
    try testing.expect(res != null);
    try verifyCoupled(4, r1, r2, res.?[0], res.?[1]);
}

test "findCoupledAllocation Negative Jumps (Both Backwards)" {
    var aa = AddressAllocator{ .child_allocator = testing.allocator };
    defer aa.deinit();

    // We block everything except two specific holes far behind the jump source.
    try aa.block(.{ .start = 0, .end = 0x10000000 });
    try aa.block(.{ .start = 0x10010000, .end = 0x20000000 });
    try aa.block(.{ .start = 0x20010000, .end = 0x60000000 });

    const r1 = Request{
        .source = 0x50000000,
        .size = 10,
        .valid_range = .{ .start = 0, .end = 0x60000000 },
    };
    const r2 = Request{
        .source = 0x50000002,
        .size = 10,
        .valid_range = .{ .start = 0, .end = 0x60000000 },
    };

    // The math solver natively handles the two's complement wraparound.
    const res = aa.findCoupledAllocation(2, r1, r2);
    try testing.expect(res != null);
    try verifyCoupled(2, r1, r2, res.?[0], res.?[1]);
}

test "findCoupledAllocation with Mask/Pattern Constraints" {
    var aa = AddressAllocator{ .child_allocator = testing.allocator };
    defer aa.deinit();

    try aa.block(.{ .start = 0, .end = 0x10000 });
    try aa.block(.{ .start = 0x20000, .end = 0x44440000 });
    try aa.block(.{ .start = 0x44450000, .end = 0x80000000 });

    // K=2. We force the shared bytes to be exactly 0x4444.
    const r1 = Request{ .source = 0, .size = 10, .valid_range = .{ .start = 0, .end = 0x80000000 } };
    const r2 = Request{
        .source = 2,
        .size = 10,
        .valid_range = .{ .start = 0, .end = 0x80000000 },
        .mask = 0x0000FFFF,
        .pattern = 0x00004444,
    };

    const res = aa.findCoupledAllocation(2, r1, r2);
    try testing.expect(res != null);
    try verifyCoupled(2, r1, r2, res.?[0], res.?[1]);

    // Explicitly verify the constraint was propagated to J1
    const rel1: i32 = @intCast(res.?[0].start);
    const u_rel1: u32 = @bitCast(rel1);
    try testing.expectEqual(@as(u32, 0x4444), (u_rel1 >> 16) & 0xFFFF);
}

test "findCoupledAllocation Fails on Math Impossibility" {
    var aa = AddressAllocator{ .child_allocator = testing.allocator };
    defer aa.deinit();

    const r1 = Request{
        .source = 0,
        .size = 10,
        .valid_range = .{ .start = 0, .end = 0x80000000 },
        .mask = 0xFFFF0000,
        .pattern = 0x11110000,
    };
    const r2 = Request{
        .source = 2,
        .size = 10,
        .valid_range = .{ .start = 0, .end = 0x80000000 },
        .mask = 0x0000FFFF,
        .pattern = 0x00002222,
    };

    const res = aa.findCoupledAllocation(2, r1, r2);
    try testing.expectEqual(null, res);
}
