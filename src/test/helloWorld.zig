const std = @import("std");

pub fn main() !void {
    var stdout_buffer: [64]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    try stdout.print("Hello World!\n", .{});
    try stdout.flush();
}
