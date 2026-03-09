const std = @import("std");
const mem = std.mem;

const Statistics = @This();

/// Direct jumps
jump: u64,
/// Punning - index represents number of prefixes used
punning: [4]u64,
/// Successor Eviction
successor_eviction: u64,
/// Neighbor Eviction
neighbor_eviction: u64,
/// Failed to patch
failed: u64,

pub const empty = mem.zeroes(Statistics);

pub fn punningSum(stats: *const Statistics) u64 {
    return stats.punning[0] + stats.punning[1] + stats.punning[2] + stats.punning[3];
}

pub fn successful(stats: *const Statistics) u64 {
    return stats.jump + stats.punningSum() + stats.successor_eviction + stats.neighbor_eviction;
}

pub fn total(stats: *const Statistics) u64 {
    return stats.successful() + stats.failed;
}

pub fn percentage(stats: *const Statistics) f64 {
    if (stats.total() == 0) return 1;
    const s: f64 = @floatFromInt(stats.successful());
    const t: f64 = @floatFromInt(stats.total());
    return s / t;
}

pub fn add(self: *Statistics, other: *const Statistics) void {
    self.jump += other.jump;
    for (0..self.punning.len) |i| {
        self.punning[i] += other.punning[i];
    }
    self.successor_eviction += other.successor_eviction;
    self.neighbor_eviction += other.neighbor_eviction;
    self.failed += other.failed;
}
