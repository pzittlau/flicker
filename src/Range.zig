//! Represents some kind of signed range with an inclusive lower bound and an exclusive upper bound.
//! An empty Range can be represented by `start == end`.

const std = @import("std");

const assert = std.debug.assert;

const Range = @This();
/// Inclusive lower bound of the range.
start: i64,
/// Exclusive upper bound of the range.
end: i64,

pub fn size(range: Range) u64 {
    assert(range.end >= range.start);
    // return @intCast(@as(i128, range.end) - range.start); // prevent overflow
    return @intCast(range.end - range.start);
}

pub fn alignTo(range: Range, alignment: u64) Range {
    assert(range.end >= range.start);
    assert(std.math.isPowerOfTwo(alignment));
    assert(alignment <= std.math.maxInt(i64));
    const lower = std.mem.alignBackward(i64, range.start, @intCast(alignment));
    const upper = std.mem.alignForward(i64, range.end, @intCast(alignment));
    assert(upper >= lower);
    return .{ .start = lower, .end = upper };
}

pub fn overlaps(range: Range, other: Range) bool {
    assert(range.end >= range.start);
    assert(other.end >= other.start);
    return range.start < other.end and other.start < range.end;
}

pub fn equals(range: Range, other: Range) bool {
    assert(range.end >= range.start);
    assert(other.end >= other.start);
    return range.start == other.start and range.end == other.end;
}

pub fn contains(range: Range, other: Range) bool {
    assert(range.end >= range.start);
    assert(other.end >= other.start);
    return range.start <= other.start and range.end >= other.end;
}

pub fn touches(range: Range, other: Range) bool {
    assert(range.end >= range.start);
    assert(other.end >= other.start);
    return range.start <= other.end and other.start <= range.end;
}

/// Ranges are considered equal if they touch.
pub fn compare(lhs: Range, rhs: Range) std.math.Order {
    assert(lhs.end >= lhs.start);
    assert(rhs.end >= rhs.start);
    return if (lhs.start > rhs.end) .gt else if (lhs.end < rhs.start) .lt else .eq;
}

pub fn getStart(range: Range, T: type) T {
    return @intCast(range.start);
}

pub fn getEnd(range: Range, T: type) T {
    return @intCast(range.end);
}

pub fn format(
    self: @This(),
    writer: *std.Io.Writer,
) std.Io.Writer.Error!void {
    try writer.print(".{{ .start = 0x{x}, .end = 0x{x} }}", .{ self.start, self.end });
}

test "AddressRange size" {
    const range = Range{ .start = 100, .end = 250 };
    try std.testing.expectEqual(@as(u64, 150), range.size());
}

test "AddressRange alignTo unaligned" {
    const range = Range{ .start = 101, .end = 199 };
    const aligned = range.alignTo(16);
    try std.testing.expectEqual(@as(i64, 96), aligned.start);
    try std.testing.expectEqual(@as(i64, 208), aligned.end);
}

test "AddressRange alignTo already aligned" {
    const range = Range{ .start = 64, .end = 128 };
    const aligned = range.alignTo(64);
    try std.testing.expectEqual(@as(i64, 64), aligned.start);
    try std.testing.expectEqual(@as(i64, 128), aligned.end);
}

test "AddressRange no overlap before" {
    const base = Range{ .start = 100, .end = 200 };
    const other = Range{ .start = 0, .end = 100 };
    try std.testing.expect(!base.overlaps(other));
}

test "AddressRange no overlap after" {
    const base = Range{ .start = 100, .end = 200 };
    const other = Range{ .start = 200, .end = 300 };
    try std.testing.expect(!base.overlaps(other));
}

test "AddressRange overlap at start" {
    const base = Range{ .start = 100, .end = 200 };
    const other = Range{ .start = 50, .end = 150 };
    try std.testing.expect(base.overlaps(other));
}

test "AddressRange overlap at end" {
    const base = Range{ .start = 100, .end = 200 };
    const other = Range{ .start = 150, .end = 250 };
    try std.testing.expect(base.overlaps(other));
}

test "AddressRange overlap contained" {
    const base = Range{ .start = 100, .end = 200 };
    const other = Range{ .start = 120, .end = 180 };
    try std.testing.expect(base.overlaps(other));
}

test "AddressRange overlap containing" {
    const base = Range{ .start = 100, .end = 200 };
    const other = Range{ .start = 50, .end = 250 };
    try std.testing.expect(base.overlaps(other));
}

test "AddressRange overlap identical" {
    const base = Range{ .start = 100, .end = 200 };
    const other = Range{ .start = 100, .end = 200 };
    try std.testing.expect(base.overlaps(other));
}

test "AddressRange touches before" {
    const base = Range{ .start = 100, .end = 200 };
    const other = Range{ .start = 0, .end = 100 };
    try std.testing.expect(base.touches(other));
}

test "AddressRange touches after" {
    const base = Range{ .start = 100, .end = 200 };
    const other = Range{ .start = 200, .end = 300 };
    try std.testing.expect(base.touches(other));
}

test "AddressRange touches at start" {
    const base = Range{ .start = 100, .end = 200 };
    const other = Range{ .start = 50, .end = 150 };
    try std.testing.expect(base.touches(other));
}

test "AddressRange touches at end" {
    const base = Range{ .start = 100, .end = 200 };
    const other = Range{ .start = 150, .end = 250 };
    try std.testing.expect(base.touches(other));
}

test "AddressRange touches contained" {
    const base = Range{ .start = 100, .end = 200 };
    const other = Range{ .start = 120, .end = 180 };
    try std.testing.expect(base.touches(other));
}

test "AddressRange touches containing" {
    const base = Range{ .start = 100, .end = 200 };
    const other = Range{ .start = 50, .end = 250 };
    try std.testing.expect(base.touches(other));
}

test "AddressRange touches identical" {
    const base = Range{ .start = 100, .end = 200 };
    const other = Range{ .start = 100, .end = 200 };
    try std.testing.expect(base.touches(other));
}
