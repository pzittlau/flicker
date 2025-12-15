const std = @import("std");
const linux = std.os.linux;
const Patcher = @import("Patcher.zig");
const assert = std.debug.assert;

/// Represents the stack layout pushed by `syscall_entry` before calling the handler.
pub const UserRegs = extern struct {
    padding: u64, // Result of `sub $8, %rsp` for alignment
    rflags: u64,
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    /// This one isn't pushed on the stack by `syscall_entry`. It's pushed by the `call r11` to get
    /// to the `syscall_entry`
    return_address: u64,
};

/// The main entry point for intercepted syscalls.
///
/// This function is called from `syscall_entry` with a pointer to the saved registers.
/// It effectively emulates the syscall instruction while allowing for interception.
export fn syscall_handler(regs: *UserRegs) callconv(.c) void {
    // TODO: Handle signals (masking) to prevent re-entrancy issues if we touch global state.

    const sys: linux.SYS = @enumFromInt(regs.rax);

    switch (sys) {
        .readlink => {
            // readlink(const char *path, char *buf, size_t bufsiz)
            const path_ptr = @as([*:0]const u8, @ptrFromInt(regs.rdi));
            // TODO: handle relative paths with cwd
            if (isProcSelfExe(path_ptr)) {
                handleReadlink(regs.rsi, regs.rdx, regs);
                return;
            }
        },
        .readlinkat => {
            // readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
            // We only intercept if pathname is absolute "/proc/self/exe".
            // TODO: handle relative paths with dirfd pointing to /proc/self
            // TODO: handle relative paths with dirfd == AT_FDCWD (like readlink)
            // TODO: handle empty pathname
            const path_ptr = @as([*:0]const u8, @ptrFromInt(regs.rsi));
            if (isProcSelfExe(path_ptr)) {
                handleReadlink(regs.rdx, regs.r10, regs);
                return;
            }
        },
        .clone, .clone3 => {
            handleClone(regs);
            std.debug.print("back in `syscall_handler`\n", .{});
            return;
        },
        .fork, .vfork => {
            // fork/vfork duplicate the stack (or share it until exec), so the return path via
            // syscall_entry works fine.
        },
        .rt_sigreturn => {
            @panic("sigreturn is not supported yet");
        },
        .execve, .execveat => |s| {
            // TODO: option to persist across new processes
            std.debug.print("syscall {} called\n", .{s});
        },
        .prctl, .arch_prctl, .set_tid_address => |s| {
            // TODO: what do we need to handle from these?
            // process name
            // fs base(gs?)
            // thread id pointers
            std.debug.print("syscall {} called\n", .{s});
        },
        .mmap, .mprotect => {
            // TODO: JIT support
            // TODO: cleanup
        },
        .munmap, .mremap => {
            // TODO: cleanup
        },

        else => {},
    }

    // Write result back to the saved RAX so it is restored to the application.
    regs.rax = executeSyscall(regs);
}

inline fn executeSyscall(regs: *UserRegs) u64 {
    return linux.syscall6(
        @enumFromInt(regs.rax),
        regs.rdi,
        regs.rsi,
        regs.rdx,
        regs.r10,
        regs.r8,
        regs.r9,
    );
}

/// Assembly trampoline that saves state and calls the Zig handler.
pub fn syscall_entry() callconv(.naked) void {
    asm volatile (
        \\     # Save all GPRs that must be preserved or are arguments
        \\     push %r15
        \\     push %r14
        \\     push %r13
        \\     push %r12
        \\     push %r11
        \\     push %r10
        \\     push %r9
        \\     push %r8
        \\     push %rbp
        \\     push %rdi
        \\     push %rsi
        \\     push %rdx
        \\     push %rcx
        \\     push %rbx
        \\     push %rax
        \\     pushfq # Save Flags
        \\
        \\     # Align stack
        \\     # Current pushes: 16 * 8 = 128 bytes.
        \\     # Red zone sub: 128 bytes.
        \\     # Trampoline call pushed ret addr: 8 bytes.
        \\     # Total misalign: 8 bytes. We need 16-byte alignment for 'call'.
        \\     sub $8, %rsp
        \\
        \\     # Pass pointer to regs (current rsp) as 1st argument (rdi) and call handler.
        \\     mov %rsp, %rdi
        \\     call syscall_handler
        \\
        \\     # Restore State
        \\     add $8, %rsp
        \\     popfq
        \\     pop %rax
        \\     pop %rbx
        \\     pop %rcx
        \\     pop %rdx
        \\     pop %rsi
        \\     pop %rdi
        \\     pop %rbp
        \\     pop %r8
        \\     pop %r9
        \\     pop %r10
        \\     pop %r11
        \\     pop %r12
        \\     pop %r13
        \\     pop %r14
        \\     pop %r15
        \\
        \\     ret
        :
        // TODO: can we somehow use %[handler] in the assembly instead?
        // Right now this is just here such that lto does not discard the `syscall_handler` function
        : [handler] "i" (syscall_handler),
    );
}

fn isProcSelfExe(path: [*:0]const u8) bool {
    const needle = "/proc/self/exe";
    var i: usize = 0;
    while (i < needle.len) : (i += 1) {
        if (path[i] != needle[i]) return false;
    }
    return path[i] == 0;
}

fn handleReadlink(buf_addr: u64, buf_size: u64, regs: *UserRegs) void {
    const target = Patcher.target_exec_path;
    const len = @min(target.len, buf_size);
    const dest = @as([*]u8, @ptrFromInt(buf_addr));
    @memcpy(dest[0..len], target[0..len]);

    // readlink does not null-terminate if the buffer is full, it just returns length.
    regs.rax = len;
}

const CloneArgs = extern struct {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
};

fn handleClone(regs: *UserRegs) void {
    const sys: linux.syscalls.X64 = @enumFromInt(regs.rax);
    std.debug.print("got: {}, Parent PID: \t{}\n", .{ sys, linux.getpid() });
    var child_stack: u64 = 0;

    // Determine stack
    if (sys == .clone) {
        // clone(flags, stack, ...)
        child_stack = regs.rsi;
    } else {
        // clone3(struct clone_args *args, size_t size)
        const args = @as(*const CloneArgs, @ptrFromInt(regs.rdi));
        if (args.stack != 0) {
            child_stack = args.stack + args.stack_size;
        }
    }

    // If no new stack, just execute (like fork)
    if (child_stack == 0) {
        regs.rax = executeSyscall(regs);
        if (regs.rax == 0) {
            postCloneChild(regs);
        } else {
            assert(regs.rax > 0); // TODO:: error handling
            postCloneParent(regs);
        }
        return;
    }

    // Prepare child stack by copying UserRegs and return_address onto it.
    // TODO: test alignment
    child_stack &= ~@as(u64, 0xf - 1); // align to 16 bytes
    const child_regs_addr = child_stack - @sizeOf(UserRegs);
    const child_regs = @as(*UserRegs, @ptrFromInt(child_regs_addr));
    child_regs.* = regs.*;
    child_regs.rax = 0;

    // Prepare arguments for syscall
    var new_rsi = regs.rsi;
    var new_rdi = regs.rdi;
    var clone3_args_copy: CloneArgs = undefined;

    if (sys == .clone) {
        new_rsi = child_regs_addr;
    } else {
        const args = @as(*const CloneArgs, @ptrFromInt(regs.rdi));
        clone3_args_copy = args.*;
        clone3_args_copy.stack = child_regs_addr;
        clone3_args_copy.stack_size = 0; // TODO:
        new_rdi = @intFromPtr(&clone3_args_copy);
    }

    const msg = "Child: This is a debug message from within handleClone\n";

    // Execute clone/clone3 via inline assembly
    // We handle the child path entirely in assembly to avoid stack frame issues.
    const ret = asm volatile (
        \\ syscall
        \\ test %rax, %rax
        \\ jnz 1f
        \\
        \\ # --- CHILD PATH ---
        \\ # We are now on the new stack and %rsp points to child_regs_addr
        \\  
        \\ # Let's do a debug print
        \\ # Write to stdout
        \\ mov $2, %%rdi        # fd = 2 (stderr)
        \\ mov %[msg], %%rsi    # buffer
        \\ mov %[len], %%rdx    # length
        \\ mov $1, %%rax        # SYS_write
        \\ syscall
        \\
        \\ # Run Child Hook
        \\ # Argument 1 (rdi): Pointer to UserRegs (which is current rsp)
        \\ mov %rsp, %rdi
        \\ call postCloneChild
        \\
        \\ # Restore Context
        \\ add $8, %rsp      # Skip padding
        \\ popfq
        \\ pop %rax
        \\ pop %rbx
        \\ pop %rcx
        \\ pop %rdx
        \\ pop %rsi
        \\ pop %rdi
        \\ pop %rbp
        \\ pop %r8
        \\ pop %r9
        \\ pop %r10
        \\ pop %r11
        \\ pop %r12
        \\ pop %r13
        \\ pop %r14
        \\ pop %r15
        \\
        \\ # Jump back to the trampoline
        \\ ret
        \\
        \\ 1:
        \\ # --- PARENT PATH ---
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (regs.rax),
          [arg1] "{rdi}" (new_rdi),
          [arg2] "{rsi}" (new_rsi),
          [arg3] "{rdx}" (regs.rdx),
          [arg4] "{r10}" (regs.r10),
          [arg5] "{r8}" (regs.r8),
          [arg6] "{r9}" (regs.r9),
          [child_hook] "i" (postCloneChild),
          [msg] "r" (msg.ptr),
          [len] "r" (msg.len),
        : .{ .rcx = true, .r11 = true, .memory = true });

    // Parent continues here
    regs.rax = ret;
    postCloneParent(regs);
}

export fn postCloneChild(regs: *UserRegs) callconv(.c) void {
    _ = regs;
    std.debug.print("Child: post clone\n", .{});
}

fn postCloneParent(regs: *UserRegs) void {
    std.debug.print("Parent: post clone; Child PID: \t{}\n", .{regs.rax});
}
