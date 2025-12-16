const std = @import("std");

pub fn main() !void {
    _ = try std.posix.clock_gettime(std.posix.CLOCK.MONOTONIC);

    const msg = "Time gotten\n";
    _ = try std.posix.write(1, msg);
}
