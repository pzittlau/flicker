const std = @import("std");
const linux = std.os.linux;

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
};

/// The main entry point for intercepted syscalls.
///
/// This function is called from `syscall_entry` with a pointer to the saved registers.
/// It effectively emulates the syscall instruction while allowing for interception.
export fn syscall_handler(regs: *UserRegs) void {
    // TODO: Handle signals (masking) to prevent re-entrancy issues if we touch global state.
    // TODO: Handle `clone` specially because the child thread wakes up with a fresh stack
    //       and cannot pop the registers we saved here.

    const sys_nr = regs.rax;
    const sys: linux.SYS = @enumFromInt(sys_nr);
    const arg1 = regs.rdi;
    const arg2 = regs.rsi;
    const arg3 = regs.rdx;
    const arg4 = regs.r10;
    const arg5 = regs.r8;
    const arg6 = regs.r9;

    std.debug.print("Got syscall {s}\n", .{@tagName(sys)});
    // For now, we just pass through everything.
    // In the future, we will switch on `sys` to handle mmap, mprotect, etc.
    const result = std.os.linux.syscall6(sys, arg1, arg2, arg3, arg4, arg5, arg6);

    // Write result back to the saved RAX so it is restored to the application.
    regs.rax = result;
}

/// Assembly trampoline that saves state and calls the Zig handler.
pub fn syscall_entry() callconv(.naked) void {
    asm volatile (
        \\ .global syscall_entry
        \\ .type syscall_entry, @function
        \\ syscall_entry:
        \\     # Respect the Red Zone (128 bytes)
        \\     sub $128, %rsp
        \\
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
        \\     # Restore Red Zone and Return
        \\     add $128, %rsp
        \\     ret
    );
}
