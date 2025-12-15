const std = @import("std");
const linux = std.os.linux;

pub fn main() !void {
    const ret = linux.syscall0(.fork);
    const pid: i32 = @intCast(ret);

    if (pid == 0) {
        // --- Child ---
        const msg = "Child: I'm alive!\n";
        _ = linux.syscall3(.write, 1, @intFromPtr(msg.ptr), msg.len);
        linux.exit(0);
    } else if (pid > 0) {
        // --- Parent ---
        var status: u32 = 0;
        _ = linux.syscall4(.wait4, @intCast(pid), @intFromPtr(&status), 0, 0);
        const msg = "Parent: Child died.\n";
        _ = linux.syscall3(.write, 1, @intFromPtr(msg.ptr), msg.len);
    } else {
        const msg = "Fork failed!\n";
        _ = linux.syscall3(.write, 1, @intFromPtr(msg.ptr), msg.len);
    }
}
