//! Iterates through all possible valid address ranges for a `jmp rel32` instruction based on a
//! 4-byte pattern of "free" and "used" bytes.
//!
//! This is the core utility for implementing E9Patch-style instruction punning (B2) and padded
//! jumps (T1).
const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const log = std.log.scoped(.patch_location_iterator);

const Range = @import("Range.zig");

/// Represents a single byte in the 4-byte `rel32` offset pattern.
pub const PatchByte = union(enum) {
    /// This byte can be any value (0x00-0xFF).
    free: void,
    /// This byte is constrained to a specific value.
    used: u8,

    pub fn format(self: @This(), writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .free => try writer.print("free", .{}),
            .used => |val| try writer.print("used({x})", .{val}),
        }
    }
};

const patch_size = 4;
const PatchInt = std.meta.Int(.signed, patch_size * 8);
const PatchLocationIterator = @This();
/// The base address (e.g., RIP of the *next* instruction) that the 32-bit relative offset is
/// calculated from.
offset: i64,
/// The 4-byte little-endian pattern of `used` and `free` bytes that constrain the `rel32` offset.
patch_bytes: [patch_size]PatchByte,
/// Internal state: the byte-level representation of the *start* of the current `rel32` offset being
/// iterated.
start: [patch_size]u8,
/// Internal state: the byte-level representation of the *end* of the current `rel32` offset being
/// iterated.
end: [patch_size]u8,
/// Internal state: flag to handle the first call to `next()` uniquely.
first: bool,
/// Internal state: optimization cache for the number of contiguous `.free` bytes at the *end* of
/// `patch_bytes`.
trailing_free_count: u8,

/// Initializes the iterator.
/// - `patch_bytes`: The 4-byte pattern of the `rel32` offset, in little-endian order.
/// - `offset`: The address of the *next* instruction (i.e., `RIP` after the 5-byte `jmp`).
///   All returned ranges will be relative to this offset.
pub fn init(patch_bytes: [patch_size]PatchByte, offset: u64) PatchLocationIterator {
    log.debug("hi", .{});
    assert(patch_bytes.len == patch_size);

    // Find the number of contiguous free bytes at the end of the pattern.
    var trailing_free: u8 = 0;
    for (0..patch_bytes.len) |i| {
        if (patch_bytes[i] == .free) {
            trailing_free += 1;
        } else {
            break;
        }
    }

    var start = std.mem.zeroes([patch_size]u8);
    var end = std.mem.zeroes([patch_size]u8);
    for (patch_bytes, 0..) |byte, i| {
        switch (byte) {
            .free => {
                start[i] = 0;
                end[i] = if (i < trailing_free) 0xff else 0;
            },
            .used => |val| {
                start[i] = val;
                end[i] = val;
            },
        }
    }

    const out = PatchLocationIterator{
        .offset = @intCast(offset),
        .patch_bytes = patch_bytes,
        .trailing_free_count = trailing_free,
        .start = start,
        .end = end,
        .first = true,
    };
    log.debug("init: {f}", .{out});
    return out;
}

/// Returns the next valid `Range` of target addresses, or `null` if the iteration is complete.
pub fn next(self: *PatchLocationIterator) ?Range {
    defer self.first = false;

    // If the first byte is predetermined and the offset would always be negative we don't need to
    // iterate.
    const last_byte = self.patch_bytes[patch_size - 1];
    if (last_byte == .used and last_byte.used & 0x80 != 0) {
        log.info(
            "next: Search aborted, pattern has predetermined negative offset (last_byte=0x{x})",
            .{last_byte.used},
        );
        return null;
    }

    // If all bytes are free we can just return the maximum range.
    if (self.trailing_free_count == patch_size) {
        if (self.first) {
            const range = Range{ .start = self.offset, .end = self.offset + std.math.maxInt(i32) };
            log.debug("next: All bytes free, returning full positive range: {}", .{range});
            return range;
        } else {
            log.info("next: All bytes free, iteration finished.", .{});
            return null;
        }
    }

    if (self.first) {
        const range = Range{
            .start = std.mem.readInt(PatchInt, self.start[0..], .little) + self.offset,
            .end = std.mem.readInt(PatchInt, self.end[0..], .little) + self.offset,
        };
        log.debug("next: First call, returning initial range: {}", .{range});
        return range;
    }

    var overflow: u1 = 1;
    for (self.patch_bytes, 0..) |byte, i| {
        if (i < self.trailing_free_count or byte == .used) {
            continue;
        }
        assert(byte == .free);
        assert(self.start[i] == self.end[i]);
        defer assert(self.start[i] == self.end[i]);

        if (overflow == 1) {
            const max: u8 = if (i < patch_size - 1) std.math.maxInt(u8) else std.math.maxInt(i8);
            if (self.start[i] == max) {
                self.start[i] = 0;
                self.end[i] = 0;
            } else {
                self.start[i] += 1;
                self.end[i] += 1;
                overflow = 0;
            }
        }
    }
    if (overflow == 1) {
        log.info("next: Iteration finished, no more ranges.", .{});
        return null;
    }

    const start = std.mem.readInt(PatchInt, self.start[0..], .little);
    const end = std.mem.readInt(PatchInt, self.end[0..], .little);
    assert(end >= start);
    const range = Range{
        .start = start + self.offset,
        .end = end + self.offset,
    };
    log.debug("next: new range: {}", .{range});
    return range;
}

pub fn format(self: PatchLocationIterator, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writer.print(".{{ ", .{});
    try writer.print(".offset = {x}, ", .{self.offset});
    try writer.print(
        ".patch_bytes = .{{ {f}, {f}, {f}, {f} }}, ",
        .{ self.patch_bytes[0], self.patch_bytes[1], self.patch_bytes[2], self.patch_bytes[3] },
    );
    try writer.print(
        ".start: 0x{x}, .end: 0x{x}, first: {}, trailing_free_count: {}",
        .{ self.start, self.end, self.first, self.trailing_free_count },
    );
}

test "free bytes" {
    const pattern = [_]PatchByte{
        .{ .free = {} },
        .{ .free = {} },
        .{ .free = {} },
        .{ .free = {} },
    };
    var it = PatchLocationIterator.init(pattern, 0);

    try testing.expectEqual(
        Range{ .start = 0x00000000, .end = 0x7fffffff },
        it.next().?,
    );
    try testing.expectEqual(null, it.next());
}

test "predetermined negative" {
    const pattern = [_]PatchByte{
        .{ .free = {} },
        .{ .free = {} },
        .{ .free = {} },
        .{ .used = 0xe9 },
    };
    var it = PatchLocationIterator.init(pattern, 0);
    try testing.expectEqual(null, it.next());
    it = PatchLocationIterator.init(pattern, 0x12345678);
    try testing.expectEqual(null, it.next());
}

test "trailing free bytes" {
    const pattern = [_]PatchByte{
        .{ .free = {} },
        .{ .free = {} },
        .{ .free = {} },
        .{ .used = 0x79 },
    };
    var it = PatchLocationIterator.init(pattern, 0);

    try testing.expectEqual(
        Range{ .start = 0x79000000, .end = 0x79ffffff },
        it.next().?,
    );
    try testing.expectEqual(null, it.next());
}

test "inner and trailing free bytes" {
    const pattern = [_]PatchByte{
        .{ .free = {} },
        .{ .used = 0xe8 },
        .{ .free = {} },
        .{ .used = 0x79 },
    };
    var it = PatchLocationIterator.init(pattern, 0);

    try testing.expectEqual(
        Range{ .start = 0x7900e800, .end = 0x7900e8ff },
        it.next().?,
    );
    try testing.expectEqual(
        Range{ .start = 0x7901e800, .end = 0x7901e8ff },
        it.next().?,
    );

    // Skip to the last range
    var r_last: ?Range = null;
    var count: u32 = 2; // We already consumed two
    while (it.next()) |r| {
        r_last = r;
        count += 1;
    }
    try testing.expectEqual(
        Range{ .start = 0x79ffe800, .end = 0x79ffe8ff },
        r_last,
    );
    try testing.expectEqual(256, count);
}

test "no free bytes" {
    const pattern = [_]PatchByte{
        .{ .used = 0xe9 },
        .{ .used = 0x00 },
        .{ .used = 0x00 },
        .{ .used = 0x78 },
    };
    var it = PatchLocationIterator.init(pattern, 0);

    try testing.expectEqual(
        Range{ .start = 0x780000e9, .end = 0x780000e9 },
        it.next().?,
    );
    try testing.expectEqual(null, it.next());
}

test "inner and leading free bytes" {
    const pattern = [_]PatchByte{
        .{ .used = 0xe9 },
        .{ .free = {} },
        .{ .used = 0xe8 },
        .{ .free = {} },
    };
    var it = PatchLocationIterator.init(pattern, 0);

    try testing.expectEqual(
        Range{ .start = 0x00e800e9, .end = 0x00e800e9 },
        it.next().?,
    );
    try testing.expectEqual(
        Range{ .start = 0x00e801e9, .end = 0x00e801e9 },
        it.next().?,
    );

    // Skip to the last range
    var r_last: ?Range = null;
    var count: u32 = 2; // We already consumed two
    while (it.next()) |r| {
        r_last = r;
        count += 1;
    }
    try testing.expectEqual(
        Range{ .start = 0x7fe8ffe9, .end = 0x7fe8ffe9 },
        r_last,
    );
    try testing.expectEqual(256 * 128, count);
}

test "only inner" {
    const pattern = [_]PatchByte{
        .{ .used = 0xe9 },
        .{ .free = {} },
        .{ .free = {} },
        .{ .used = 0x78 },
    };
    var it = PatchLocationIterator.init(pattern, 0);

    try testing.expectEqual(
        Range{ .start = 0x780000e9, .end = 0x780000e9 },
        it.next().?,
    );
    try testing.expectEqual(
        Range{ .start = 0x780001e9, .end = 0x780001e9 },
        it.next().?,
    );

    // Skip to the last range
    var r_last: ?Range = null;
    var count: u32 = 2; // We already consumed two
    while (it.next()) |r| {
        r_last = r;
        count += 1;
    }
    try testing.expectEqual(
        Range{ .start = 0x78ffffe9, .end = 0x78ffffe9 },
        r_last,
    );
    try testing.expectEqual(256 * 256, count);
}

test "trailing free bytes offset" {
    const pattern = [_]PatchByte{
        .{ .free = {} },
        .{ .free = {} },
        .{ .free = {} },
        .{ .used = 0x79 },
    };
    const offset = 0x12345678;
    var it = PatchLocationIterator.init(pattern, offset);

    try testing.expectEqual(
        Range{ .start = offset + 0x79000000, .end = offset + 0x79ffffff },
        it.next().?,
    );
    try testing.expectEqual(null, it.next());
}

test "trailing and leading offset" {
    const pattern = [_]PatchByte{
        .{ .free = {} },
        .{ .used = 0xe9 },
        .{ .used = 0xe8 },
        .{ .free = {} },
    };
    const offset = 0x12345678;
    var it = PatchLocationIterator.init(pattern, offset);

    try testing.expectEqual(
        Range{ .start = offset + 0x00e8e900, .end = offset + 0x00e8e9ff },
        it.next().?,
    );
    try testing.expectEqual(
        Range{ .start = offset + 0x01e8e900, .end = offset + 0x01e8e9ff },
        it.next().?,
    );

    // Skip to the last range
    var r_last: ?Range = null;
    var count: u32 = 2; // We already consumed two
    while (it.next()) |r| {
        r_last = r;
        count += 1;
    }
    try testing.expectEqual(
        Range{ .start = offset + 0x7fe8e900, .end = offset + 0x7fe8e9ff },
        r_last,
    );
    try testing.expectEqual(128, count);
}

test "trailing free bytes large offset" {
    const pattern = [_]PatchByte{
        .{ .free = {} },
        .{ .free = {} },
        .{ .free = {} },
        .{ .used = 0x79 },
    };
    const offset = 0x12345678;
    var it = PatchLocationIterator.init(pattern, offset);

    try testing.expectEqual(
        Range{ .start = offset + 0x79000000, .end = offset + 0x79ffffff },
        it.next().?,
    );
    try testing.expectEqual(null, it.next());
}

test "trailing and leading large offset" {
    const pattern = [_]PatchByte{
        .{ .free = {} },
        .{ .used = 0xe9 },
        .{ .used = 0xe8 },
        .{ .free = {} },
    };
    const offset = 0x12345678;
    var it = PatchLocationIterator.init(pattern, offset);

    try testing.expectEqual(
        Range{ .start = offset + 0x00e8e900, .end = offset + 0x00e8e9ff },
        it.next().?,
    );
    try testing.expectEqual(
        Range{ .start = offset + 0x01e8e900, .end = offset + 0x01e8e9ff },
        it.next().?,
    );

    // Skip to the last range
    var r_last: ?Range = null;
    var count: u32 = 2; // We already consumed two
    while (it.next()) |r| {
        r_last = r;
        count += 1;
    }
    try testing.expectEqual(
        Range{ .start = offset + 0x7fe8e900, .end = offset + 0x7fe8e9ff },
        r_last,
    );
    try testing.expectEqual(128, count);
}
