const std = @import("std");
const mem = std.mem;
const sort = std.sort;
const testing = std.testing;

const assert = std.debug.assert;

const Range = @import("Range.zig");
const log = std.log.scoped(.address_allocator);

const AddressAllocator = @This();

/// The **sorted** list of `Range`s that are blocked.
ranges: std.ArrayListUnmanaged(Range) = .empty,

pub const empty = AddressAllocator{};

pub fn deinit(address_allocator: *AddressAllocator, gpa: mem.Allocator) void {
    address_allocator.ranges.deinit(gpa);
}

/// Block a range to not be used by the `allocate` function. This function will always succeed, if
/// there is enough memory available.
pub fn block(
    address_allocator: *AddressAllocator,
    gpa: mem.Allocator,
    range: Range,
    alignment: u64,
) !void {
    assert(address_allocator.isSorted());
    defer assert(address_allocator.isSorted());

    const aligned_range = if (alignment != 0) range.alignTo(alignment) else range;
    assert(aligned_range.contains(range));
    if (aligned_range.size() == 0) return;

    // Find the correct sorted position to insert the new range.
    const insert_idx = sort.lowerBound(
        Range,
        address_allocator.ranges.items,
        aligned_range,
        Range.compare,
    );
    log.debug(
        "block: range: {f}, alignment: {}, aligned_range: {f}, insert_idx: {}",
        .{ range, alignment, aligned_range, insert_idx },
    );
    // If the new range is the greatest one OR if the entry at `insert_idx` is greater than the
    // new range, we can just insert.
    if (insert_idx == address_allocator.ranges.items.len or
        address_allocator.ranges.items[insert_idx].compare(aligned_range) == .gt)
    {
        log.debug("block: New range inserted", .{});
        return address_allocator.ranges.insert(gpa, insert_idx, aligned_range);
    }
    errdefer comptime unreachable;
    assert(address_allocator.ranges.items.len > 0);

    // Now `insert_idx` points to the first entry, that touches `aligned_range`.
    assert(address_allocator.ranges.items[insert_idx].touches(aligned_range));
    if (insert_idx > 1 and address_allocator.ranges.items.len > 1) {
        assert(!address_allocator.ranges.items[insert_idx - 1].touches(aligned_range));
    }
    log.debug("block: `aligned_range` touches at least one existing range.", .{});

    // NOTE: We merge entries that touch eachother to speedup future traversals.
    // There are a few cases how to handle the merging:
    // 1. `aligned_range` is contained by the existing range. Then we have to do nothing and can
    //    return early.
    // 2. `aligned_range` contains the existing range. Then we have to overwrite `start` and `end`.
    // 3. The existing range is before `aligned_range`. Set `existing.end` to `aligned_range.end`.
    // 4. The existing range is after `aligned_range`. Set `existing.start` to `aligned.start`.
    // After we have done this to the first range that touches, we will loop over the other ones
    // that touch and just have to apply rule 4 repeatedly.
    const first = &address_allocator.ranges.items[insert_idx];
    if (first.contains(aligned_range)) {
        log.debug("block: Existing range at index {} contains new range. No-op", .{insert_idx});
        return;
    } else if (aligned_range.contains(first.*)) {
        log.debug(
            "block: New range contains existing range at index {}: {f} -> {f}",
            .{ insert_idx, first, aligned_range },
        );
        first.* = aligned_range;
    } else if (aligned_range.start <= first.end and aligned_range.end >= first.end) {
        assert(aligned_range.start > first.start);
        log.debug(
            "block: Adjusting range end at index {}: {} -> {}",
            .{ insert_idx, first.end, aligned_range.end },
        );
        first.*.end = aligned_range.end;
    } else if (aligned_range.end >= first.start and aligned_range.start <= first.start) {
        assert(aligned_range.end < first.end);
        log.debug(
            "block: Adjusting range start at index {}: {} -> {}",
            .{ insert_idx, first.start, aligned_range.start },
        );
        first.*.start = aligned_range.start;
    } else {
        unreachable;
    }

    // TODO: comment why we do this
    if (insert_idx >= address_allocator.ranges.items.len - 1) return;

    var neighbor = &address_allocator.ranges.items[insert_idx + 1];
    var i: u64 = 0;
    while (neighbor.touches(aligned_range)) {
        assert(aligned_range.end >= neighbor.start);
        assert(aligned_range.start <= neighbor.start);

        if (neighbor.end > first.end) {
            log.debug(
                "block: Merging neighbor range at index {}: {} -> {}.",
                .{ insert_idx + 1, first.end, neighbor.end },
            );
            first.end = neighbor.end;
        }
        const removed = address_allocator.ranges.orderedRemove(insert_idx + 1);
        log.debug("block: Removed merged range: {f}", .{removed});
        i += 1;
    }
    log.debug("block: Removed {} ranges.", .{i});
}

/// Allocate and block a `Range` of size `size` which will lie inside the given `valid_range`. If no
/// allocation of the given size is possible, return `null`.
pub fn allocate(
    address_allocator: *AddressAllocator,
    gpa: mem.Allocator,
    size: u64,
    valid_range: Range,
) !?Range {
    log.debug("allocate: Allocating size {} in range {f}", .{ size, valid_range });
    if (valid_range.size() < size) return null;
    if (size == 0) return null;
    const size_i: i64 = @intCast(size);

    // OPTIM: Use binary search to find the start of the valid range inside the reserved ranges.

    // `candidate_start` tracks the beginning of the current free region being examined.
    var candidate_start = valid_range.start;
    for (address_allocator.ranges.items) |reserved| {
        if (candidate_start >= valid_range.end) {
            log.debug("allocate: Searched past the valid range.", .{});
            break;
        }

        // The potential allocation gap is before the current reserved block.
        if (candidate_start < reserved.start) {
            // Determine the actual available portion of the gap within our search `range`.
            const gap_end = @min(reserved.start, valid_range.end);
            if (gap_end >= candidate_start + size_i) {
                const new_range = Range{
                    .start = candidate_start,
                    .end = candidate_start + size_i,
                };
                try address_allocator.block(gpa, new_range, 0);
                assert(valid_range.contains(new_range));
                log.debug("allocate: Found free gap: {f}", .{new_range});
                return new_range;
            }
        }

        // The gap was not large enough. Move the candidate start past the current reserved block
        // for the next iteration.
        candidate_start = @max(candidate_start, reserved.end);
    }

    // Check the remaining space at the end of the search range.
    if (valid_range.end >= candidate_start + size_i) {
        const new_range = Range{
            .start = candidate_start,
            .end = candidate_start + size_i,
        };
        try address_allocator.block(gpa, new_range, 0);
        assert(valid_range.contains(new_range));
        log.debug("allocate: Found free gap at end: {f}", .{new_range});
        return new_range;
    }

    log.debug("allocate: No suitable gap found.", .{});
    return null;
}

fn isSorted(address_allocator: *const AddressAllocator) bool {
    return sort.isSorted(Range, address_allocator.ranges.items, {}, isSortedInner);
}
fn isSortedInner(_: void, lhs: Range, rhs: Range) bool {
    return switch (lhs.compare(rhs)) {
        .lt => true,
        .gt => false,
        .eq => unreachable,
    };
}

test "block basic" {
    var aa = AddressAllocator{};
    defer aa.deinit(testing.allocator);

    try aa.block(testing.allocator, .{ .start = 0, .end = 100 }, 0);
    try testing.expectEqual(Range{ .start = 0, .end = 100 }, aa.ranges.items[0]);

    try aa.block(testing.allocator, .{ .start = 200, .end = 300 }, 0);
    try testing.expectEqual(Range{ .start = 0, .end = 100 }, aa.ranges.items[0]);
    try testing.expectEqual(Range{ .start = 200, .end = 300 }, aa.ranges.items[1]);
    try testing.expectEqual(2, aa.ranges.items.len);
}

test "block in hole" {
    var aa = AddressAllocator{};
    defer aa.deinit(testing.allocator);

    try aa.block(testing.allocator, .{ .start = 0, .end = 100 }, 0);
    try testing.expectEqual(Range{ .start = 0, .end = 100 }, aa.ranges.items[0]);

    try aa.block(testing.allocator, .{ .start = 400, .end = 500 }, 0);
    try testing.expectEqual(2, aa.ranges.items.len);
    try testing.expectEqual(Range{ .start = 0, .end = 100 }, aa.ranges.items[0]);
    try testing.expectEqual(Range{ .start = 400, .end = 500 }, aa.ranges.items[1]);

    try aa.block(testing.allocator, .{ .start = 200, .end = 300 }, 0);
    try testing.expectEqual(3, aa.ranges.items.len);
    try testing.expectEqual(Range{ .start = 0, .end = 100 }, aa.ranges.items[0]);
    try testing.expectEqual(Range{ .start = 200, .end = 300 }, aa.ranges.items[1]);
    try testing.expectEqual(Range{ .start = 400, .end = 500 }, aa.ranges.items[2]);
}

test "block touch with previous" {
    var aa = AddressAllocator{};
    defer aa.deinit(testing.allocator);

    try aa.block(testing.allocator, .{ .start = 0, .end = 100 }, 0);
    try aa.block(testing.allocator, .{ .start = 100, .end = 200 }, 0);
    try testing.expectEqual(Range{ .start = 0, .end = 200 }, aa.ranges.items[0]);
    try testing.expectEqual(1, aa.ranges.items.len);

    try aa.block(testing.allocator, .{ .start = 100, .end = 300 }, 0);
    try testing.expectEqual(Range{ .start = 0, .end = 300 }, aa.ranges.items[0]);
    try testing.expectEqual(1, aa.ranges.items.len);

    try aa.block(testing.allocator, .{ .start = 300, .end = 400 }, 0);
    try testing.expectEqual(Range{ .start = 0, .end = 400 }, aa.ranges.items[0]);
    try testing.expectEqual(1, aa.ranges.items.len);
}

test "block touch with following" {
    var aa = AddressAllocator{};
    defer aa.deinit(testing.allocator);

    try aa.block(testing.allocator, .{ .start = 200, .end = 300 }, 0);
    try aa.block(testing.allocator, .{ .start = 100, .end = 200 }, 0);
    try testing.expectEqual(Range{ .start = 100, .end = 300 }, aa.ranges.items[0]);
    try testing.expectEqual(1, aa.ranges.items.len);

    try aa.block(testing.allocator, .{ .start = 0, .end = 200 }, 0);
    try testing.expectEqual(Range{ .start = 0, .end = 300 }, aa.ranges.items[0]);
    try testing.expectEqual(1, aa.ranges.items.len);

    try aa.block(testing.allocator, .{ .start = -100, .end = 0 }, 0);
    try testing.expectEqual(Range{ .start = -100, .end = 300 }, aa.ranges.items[0]);
    try testing.expectEqual(1, aa.ranges.items.len);
}

test "block overlap with previous and following" {
    var aa = AddressAllocator{};
    defer aa.deinit(testing.allocator);

    try aa.block(testing.allocator, .{ .start = 0, .end = 100 }, 0);
    try aa.block(testing.allocator, .{ .start = 200, .end = 300 }, 0);
    try testing.expectEqual(Range{ .start = 0, .end = 100 }, aa.ranges.items[0]);
    try testing.expectEqual(Range{ .start = 200, .end = 300 }, aa.ranges.items[1]);
    try testing.expectEqual(2, aa.ranges.items.len);

    try aa.block(testing.allocator, .{ .start = 50, .end = 250 }, 0);
    try testing.expectEqual(Range{ .start = 0, .end = 300 }, aa.ranges.items[0]);
    try testing.expectEqual(1, aa.ranges.items.len);
}

test "block contained by existing" {
    var aa = AddressAllocator{};
    defer aa.deinit(testing.allocator);

    try aa.block(testing.allocator, .{ .start = 100, .end = 300 }, 0);
    try aa.block(testing.allocator, .{ .start = 200, .end = 250 }, 0);
    try testing.expectEqual(Range{ .start = 100, .end = 300 }, aa.ranges.items[0]);
    try testing.expectEqual(1, aa.ranges.items.len);
}

test "block contains existing" {
    var aa = AddressAllocator{};
    defer aa.deinit(testing.allocator);

    try aa.block(testing.allocator, .{ .start = 50, .end = 100 }, 0);
    try aa.block(testing.allocator, .{ .start = 0, .end = 200 }, 0);
    try testing.expectEqual(Range{ .start = 0, .end = 200 }, aa.ranges.items[0]);
    try testing.expectEqual(1, aa.ranges.items.len);
}

test "block overlaps multiple" {
    var aa = AddressAllocator{};
    defer aa.deinit(testing.allocator);

    try aa.block(testing.allocator, .{ .start = 0, .end = 100 }, 0);
    try aa.block(testing.allocator, .{ .start = 150, .end = 200 }, 0);
    try aa.block(testing.allocator, .{ .start = 250, .end = 300 }, 0);
    try aa.block(testing.allocator, .{ .start = 350, .end = 400 }, 0);
    try aa.block(testing.allocator, .{ .start = 450, .end = 500 }, 0);
    try testing.expectEqual(5, aa.ranges.items.len);

    try aa.block(testing.allocator, .{ .start = 50, .end = 475 }, 0);
    try testing.expectEqual(Range{ .start = 0, .end = 500 }, aa.ranges.items[0]);
    try testing.expectEqual(1, aa.ranges.items.len);
}

test "allocate in empty allocator" {
    var aa = AddressAllocator{};
    defer aa.deinit(testing.allocator);

    const search_range = Range{ .start = 0, .end = 1000 };
    const allocated = try aa.allocate(testing.allocator, 100, search_range);
    try testing.expectEqual(1, aa.ranges.items.len);
    try testing.expectEqual(Range{ .start = 0, .end = 100 }, aa.ranges.items[0]);
    try testing.expectEqual(Range{ .start = 0, .end = 100 }, allocated);
}

test "allocate with no space" {
    var aa = AddressAllocator{};
    defer aa.deinit(testing.allocator);

    const range = Range{ .start = 0, .end = 1000 };
    try aa.block(testing.allocator, range, 0);
    const allocated = try aa.allocate(testing.allocator, 100, range);
    try testing.expect(allocated == null);
}

test "allocate in a gap" {
    var aa = AddressAllocator{};
    defer aa.deinit(testing.allocator);

    try aa.block(testing.allocator, .{ .start = 0, .end = 100 }, 0);
    try aa.block(testing.allocator, .{ .start = 200, .end = 300 }, 0);

    const search_range = Range{ .start = 0, .end = 1000 };
    const allocated = try aa.allocate(testing.allocator, 50, search_range);
    try testing.expectEqual(Range{ .start = 100, .end = 150 }, allocated);
    try testing.expectEqual(2, aa.ranges.items.len);
    try testing.expectEqual(Range{ .start = 0, .end = 150 }, aa.ranges.items[0]);
    try testing.expectEqual(Range{ .start = 200, .end = 300 }, aa.ranges.items[1]);
}

test "allocate at the end" {
    var aa = AddressAllocator{};
    defer aa.deinit(testing.allocator);

    try aa.block(testing.allocator, .{ .start = 0, .end = 100 }, 0);

    const search_range = Range{ .start = 0, .end = 1000 };
    const allocated = try aa.allocate(testing.allocator, 200, search_range);
    try testing.expectEqual(Range{ .start = 100, .end = 300 }, allocated);
    try testing.expectEqual(1, aa.ranges.items.len);
    try testing.expectEqual(Range{ .start = 0, .end = 300 }, aa.ranges.items[0]);
}

test "allocate within specific search range" {
    var aa = AddressAllocator{};
    defer aa.deinit(testing.allocator);

    try aa.block(testing.allocator, .{ .start = 0, .end = 100 }, 0);
    try aa.block(testing.allocator, .{ .start = 400, .end = 500 }, 0);

    // Search range starts after first block and has a gap
    const search_range = Range{ .start = 200, .end = 400 };
    const allocated = try aa.allocate(testing.allocator, 100, search_range);
    try testing.expectEqual(Range{ .start = 200, .end = 300 }, allocated);
    try testing.expectEqual(3, aa.ranges.items.len);
    try testing.expectEqual(Range{ .start = 0, .end = 100 }, aa.ranges.items[0]);
    try testing.expectEqual(Range{ .start = 400, .end = 500 }, aa.ranges.items[2]);
    try testing.expectEqual(Range{ .start = 200, .end = 300 }, aa.ranges.items[1]);
}

test "allocate exact gap size" {
    var aa = AddressAllocator{};
    defer aa.deinit(testing.allocator);

    try aa.block(testing.allocator, .{ .start = 0, .end = 100 }, 0);
    try aa.block(testing.allocator, .{ .start = 200, .end = 300 }, 0);

    const search_range = Range{ .start = 0, .end = 1000 };
    const allocated = try aa.allocate(testing.allocator, 100, search_range);
    try testing.expectEqual(Range{ .start = 100, .end = 200 }, allocated);
    try testing.expectEqual(1, aa.ranges.items.len);
    try testing.expectEqual(Range{ .start = 0, .end = 300 }, aa.ranges.items[0]);
}

test "allocate fails when too large" {
    var aa = AddressAllocator{};
    defer aa.deinit(testing.allocator);

    try aa.block(testing.allocator, .{ .start = 0, .end = 100 }, 0);
    try aa.block(testing.allocator, .{ .start = 200, .end = 300 }, 0);

    const search_range = Range{ .start = 0, .end = 400 };
    const allocated = try aa.allocate(testing.allocator, 101, search_range);
    try std.testing.expect(allocated == null);
}

test "allocate with zero size" {
    var aa = AddressAllocator{};
    defer aa.deinit(testing.allocator);

    const search_range = Range{ .start = 0, .end = 1000 };
    const allocated = try aa.allocate(testing.allocator, 0, search_range);
    try std.testing.expect(allocated == null);
}

test "allocate with size bigger than range" {
    var aa = AddressAllocator{};
    defer aa.deinit(testing.allocator);

    const search_range = Range{ .start = 0, .end = 100 };
    const allocated = try aa.allocate(testing.allocator, 1000, search_range);
    try std.testing.expect(allocated == null);
}
