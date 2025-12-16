const std = @import("std");
const linux = std.os.linux;

var handled = false;

fn handler(sig: i32, _: *const linux.siginfo_t, _: ?*anyopaque) callconv(.c) void {
    if (sig == linux.SIG.USR1) {
        handled = true;
        const msg = "In signal handler\n";
        _ = linux.syscall3(.write, 1, @intFromPtr(msg.ptr), msg.len);
    }
}

pub fn main() !void {
    const act = linux.Sigaction{
        .handler = .{ .sigaction = handler },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = linux.SA.SIGINFO | linux.SA.RESTART,
    };

    if (linux.sigaction(linux.SIG.USR1, &act, null) != 0) {
        return error.SigactionFailed;
    }

    _ = linux.kill(linux.getpid(), linux.SIG.USR1);

    if (handled) {
        const msg = "Signal handled successfully\n";
        _ = linux.syscall3(.write, 1, @intFromPtr(msg.ptr), msg.len);
    } else {
        const msg = "Signal NOT handled\n";
        _ = linux.syscall3(.write, 1, @intFromPtr(msg.ptr), msg.len);
        std.process.exit(1);
    }
}
