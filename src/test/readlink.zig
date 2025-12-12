const std = @import("std");

pub fn main() !void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    // We use /proc/self/exe to test if the loader interception works.
    // const path = try std.posix.readlink("/proc/self/exe", &buf);
    const size = std.posix.system.readlink("/proc/self/exe", &buf, buf.len);
    var stdout_buffer: [64]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    try stdout.print("{s}", .{buf[0..@intCast(size)]});
    try stdout.flush();
}
