const std = @import("std");

pub fn main() !void {
    var stdout_buffer: [64]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // It is done this way to remove the trailing space with a naive implementation.
    var args = std.process.args();
    if (args.next()) |arg| {
        try stdout.print("{s}", .{arg});
    }
    while (args.next()) |arg| {
        try stdout.print(" {s}", .{arg});
    }
    try stdout.flush();
}
