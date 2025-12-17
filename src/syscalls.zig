const std = @import("std");
const linux = std.os.linux;
const Patcher = @import("Patcher.zig");
const assert = std.debug.assert;

/// Represents the stack layout pushed by `syscallEntry` before calling the handler.
pub const SavedContext = extern struct {
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
    /// Pushed automatically by the `call r11` instruction when entering `syscallEntry`.
    /// Crucially we copy this onto the child stack (if needed) because then we can just return at
    /// the end of the child handler inside `handleClone`.
    return_address: u64,
};

/// The main entry point for intercepted syscalls.
///
/// This function is called from `syscallEntry` with a pointer to the saved context.
/// It dispatches specific syscalls to handlers or executes them directly.
export fn syscall_handler(ctx: *SavedContext) callconv(.c) void {
    // TODO: Handle signals (masking) to prevent re-entrancy issues if we touch global state.

    const sys: linux.SYS = @enumFromInt(ctx.rax);

    switch (sys) {
        .readlink => {
            // readlink(const char *path, char *buf, size_t bufsiz)
            const path_ptr = @as([*:0]const u8, @ptrFromInt(ctx.rdi));
            // TODO: handle relative paths with cwd
            if (isProcSelfExe(path_ptr)) {
                handleReadlink(ctx.rsi, ctx.rdx, ctx);
                return;
            }
        },
        .readlinkat => {
            // readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
            // We only intercept if pathname is absolute "/proc/self/exe".
            // TODO: handle relative paths with dirfd pointing to /proc/self
            // TODO: handle relative paths with dirfd == AT_FDCWD (like readlink)
            // TODO: handle empty pathname
            const path_ptr = @as([*:0]const u8, @ptrFromInt(ctx.rsi));
            if (isProcSelfExe(path_ptr)) {
                handleReadlink(ctx.rdx, ctx.r10, ctx);
                return;
            }
        },
        .clone, .clone3 => {
            handleClone(ctx);
            return;
        },
        .rt_sigreturn => {
            // The kernel expects the stack pointer to point to the `ucontext` structure. But in our
            // case `syscallEntry` pushed the `SavedContext` onto the stack.
            // So we just need to reset the stack pointer to what it was before `syscallEntry` was
            // called. The `SavedContext` includes the return address pushed by the trampoline, so
            // the original stack pointer is exactly at the end of `SavedContext`.
            const rsp_orig = @intFromPtr(ctx) + @sizeOf(SavedContext);

            asm volatile (
                \\ mov %[rsp], %%rsp
                \\ syscall
                :
                : [rsp] "r" (rsp_orig),
                  [number] "{rax}" (ctx.rax),
                : .{ .memory = true });
            unreachable;
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
    ctx.rax = executeSyscall(ctx);
}

inline fn executeSyscall(ctx: *SavedContext) u64 {
    return linux.syscall6(
        @enumFromInt(ctx.rax),
        ctx.rdi,
        ctx.rsi,
        ctx.rdx,
        ctx.r10,
        ctx.r8,
        ctx.r9,
    );
}

/// Assembly trampoline that saves state and calls the Zig handler.
/// This is the target of the `call r11` instruction in the syscall flicken.
pub fn syscallEntry() callconv(.naked) void {
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
        \\     # Pass pointer to ctx (current rsp) as 1st argument (rdi) and call handler.
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

fn handleReadlink(buf_addr: u64, buf_size: u64, ctx: *SavedContext) void {
    const target = Patcher.target_exec_path;
    const len = @min(target.len, buf_size);
    const dest = @as([*]u8, @ptrFromInt(buf_addr));
    @memcpy(dest[0..len], target[0..len]);

    // readlink does not null-terminate if the buffer is full, it just returns length.
    ctx.rax = len;
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

/// Handles `clone` and `clone3` syscalls, which are used for thread and process creation.
///
/// **The Stack Switching Problem:**
/// When a thread is created, the caller provides a pointer to a new, empty stack (`child_stack`).
/// 1. The parent enters the kernel via `syscallEntry` (the trampoline).
/// 2. `syscallEntry` saves all registers and the return address onto the **parent's stack**.
/// 3. The kernel creates the child thread and switches its stack pointer (`RSP`) to `child_stack`.
/// 4. The child wakes up. If we simply let it return to `syscallEntry`, it would try to `pop`
///    registers from its `child_stack`. But that stack is empty! It would pop garbage and crash.
///
/// **The Solution:**
/// We manually replicate the parent's saved state onto the child's new stack *before* the syscall.
///
/// For that the following steps occur:
/// 1. We decode the arguments to determine if this is `clone` or `clone3` and locate the target
///    `child_stack`.
/// 2. If `child_stack` is 0 (e.g., `fork`), no stack switching occurs. The function simply executes
///    the syscall and handles the return value normally.
/// 3. Else we need to stack switch:
///    a. We calculate where `SavedContext` (registers + return addr) would sit on the top of the
///       *new* `child_stack`. We then `memcpy` the current `ctx` (from the parent's stack) to this
///       new location.
///    b. We set `rax = 0` in the *copied* context, so the child sees itself as the child.
///    c. We modify the syscall argument (the stack pointer passed to the kernel) to point to the
///       *start* of our copied context on the new stack, rather than the raw top. This ensures that
///       when the child wakes up, its `RSP` points exactly at the saved registers we just copied.
///    d. We execute the raw syscall inline.
///       - **Parent:** Returns from the syscall, updates `ctx.rax` with the Child PID, and returns
///         to the trampoline normally.
///       - **Child:** Wakes up on the new stack. It executes `postCloneChild`, restores all
///         registers from the *new* stack (popping the values we copied in step 3a), and finally
///         executes `ret`. This `ret` pops the `return_address` we copied, jumping directly back
///         to the user code, effectively bypassing the `syscallEntry` epilogue.
fn handleClone(ctx: *SavedContext) void {
    const sys: linux.syscalls.X64 = @enumFromInt(ctx.rax);
    var child_stack: u64 = 0;

    // Determine stack
    if (sys == .clone) {
        // clone(flags, stack, ...)
        child_stack = ctx.rsi;
    } else {
        // clone3(struct clone_args *args, size_t size)
        const args = @as(*const CloneArgs, @ptrFromInt(ctx.rdi));
        if (args.stack != 0) {
            child_stack = args.stack + args.stack_size;
        }
    }

    // If no new stack, just execute (like fork)
    if (child_stack == 0) {
        ctx.rax = executeSyscall(ctx);
        if (ctx.rax == 0) {
            postCloneChild(ctx);
        } else {
            assert(ctx.rax > 0); // TODO:: error handling
            postCloneParent(ctx);
        }
        return;
    }

    // Prepare child stack by copying SavedContext.
    // TODO: test alignment
    child_stack &= ~@as(u64, 0xf - 1); // align to 16 bytes
    const child_ctx_addr = child_stack - @sizeOf(SavedContext);
    const child_ctx = @as(*SavedContext, @ptrFromInt(child_ctx_addr));
    child_ctx.* = ctx.*;
    child_ctx.rax = 0;

    // Prepare arguments for syscall
    var new_rsi = ctx.rsi;
    var new_rdi = ctx.rdi;
    var clone3_args_copy: CloneArgs = undefined;

    if (sys == .clone) {
        new_rsi = child_ctx_addr;
    } else {
        const args = @as(*const CloneArgs, @ptrFromInt(ctx.rdi));
        clone3_args_copy = args.*;
        clone3_args_copy.stack = child_ctx_addr;
        clone3_args_copy.stack_size = 0; // TODO:
        new_rdi = @intFromPtr(&clone3_args_copy);
    }

    // Execute clone/clone3 via inline assembly
    // We handle the child path entirely in assembly to avoid stack frame issues.
    const ret = asm volatile (
        \\ syscall
        \\ test %rax, %rax
        \\ jnz 1f
        \\
        \\ # --- CHILD PATH ---
        \\ # We are now on the new stack and %rsp points to child_ctx_addr
        \\  
        \\ # Run Child Hook
        \\ # Argument 1 (rdi): Pointer to SavedContext (which is current rsp)
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
        \\ # %rsp now points to `return_address` so we can just return.
        \\ ret
        \\
        \\ 1:
        \\ # --- PARENT PATH ---
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (ctx.rax),
          [arg1] "{rdi}" (new_rdi),
          [arg2] "{rsi}" (new_rsi),
          [arg3] "{rdx}" (ctx.rdx),
          [arg4] "{r10}" (ctx.r10),
          [arg5] "{r8}" (ctx.r8),
          [arg6] "{r9}" (ctx.r9),
          [child_hook] "i" (postCloneChild),
        : .{ .rcx = true, .r11 = true, .memory = true });

    // Parent continues here
    ctx.rax = ret;
    postCloneParent(ctx);
}

export fn postCloneChild(ctx: *SavedContext) callconv(.c) void {
    _ = ctx;
}

fn postCloneParent(ctx: *SavedContext) void {
    _ = ctx;
}
