const std = @import("std");
const linux = std.os.linux;
const clone = linux.CLONE;

pub fn main() !void {
    // SIGCHLD: Send signal to parent on exit (required for waitpid)
    const flags = clone.FILES | clone.FS | linux.SIG.CHLD;

    const msg = "Child: Hello\n";
    const msg_len = msg.len;

    // We use inline assembly to perform the clone syscall and handle the child path completely to
    // avoid the compiler generating code that relies on the parent's stack frame in the child
    // process (where the stack is empty).
    const ret = asm volatile (
        \\ syscall
        \\ test %%rax, %%rax
        \\ jnz 1f
        \\
        \\ # Child Path
        \\ # Write to stdout
        \\ mov $1, %%rdi        # fd = 1 (stdout)
        \\ mov %[msg], %%rsi    # buffer
        \\ mov %[len], %%rdx    # length
        \\ mov $1, %%rax        # SYS_write
        \\ syscall
        \\
        \\ # Exit
        \\ mov $0, %%rdi        # code = 0
        \\ mov $60, %%rax       # SYS_exit
        \\ syscall
        \\
        \\ 1:
        \\ # Parent Path continues
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(linux.syscalls.X64.clone)),
          [arg1] "{rdi}" (flags),
          [arg2] "{rsi}" (0),
          [arg3] "{rdx}" (0),
          [arg4] "{r10}" (0),
          [arg5] "{r8}" (0),
          [msg] "r" (msg.ptr),
          [len] "r" (msg_len),
        : .{ .rcx = true, .r11 = true, .memory = true });

    // Parent Process
    const child_pid: i32 = @intCast(ret);
    if (child_pid < 0) {
        _ = linux.syscall3(.write, 1, @intFromPtr("Parent: Clone failed\n"), 21);
        return;
    }

    var status: u32 = 0;
    // wait4 for the child to exit
    _ = linux.syscall4(.wait4, @as(usize, @intCast(child_pid)), @intFromPtr(&status), 0, 0);

    _ = linux.syscall3(.write, 1, @intFromPtr("Parent: Goodbye\n"), 16);
}
