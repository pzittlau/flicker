# Project Flicker: Universal Load-Time Binary Rewriting

Flicker is a binary rewriting infrastructure designed for native amd64 Linux applications. Its
primary objective is to enable universal instrumentation-the ability to patch any instruction-with
minimal performance overhead.

Current approaches to binary rewriting force a difficult trade-off between coverage, performance,
and complexity. Flicker addresses this by operating at load-time, combining the transparency of
load-time injection with control-flow agnostic patching techniques. This architecture supports
statically linked executables, dynamically linked libraries, and Just-In-Time (JIT) compiled code
within a single unified framework.

## The Landscape of Binary Rewriting

To understand Flicker's position, it is helpful to look at the two dominant approaches: dynamic and
static rewriting.

Dynamic Binary Translation (DBT) tools, such as DynamoRIO or Pin, execute programs inside a virtual
machine-like environment. They act as interpreters that disassemble and translate code blocks on the
fly. This allows them to handle JIT code and shared libraries natively because they see the
instruction stream as it executes. However, this flexibility incurs significant overhead, often
slowing execution by 20% to 50% because the engine must constantly disassemble and translate code.

Static Binary Rewriting involves modifying the binary on disk before execution. While potentially
fast, this approach faces the theoretically undecidable problem of disassembly. Identifying all jump
targets in a stripped binary is reducible to the halting problem. If an instruction is moved to
insert a patch, existing jump targets break. Static tools often lift code to an Intermediate
Representation (IR) to manage this, but this adds complexity and brittleness.

## The Flicker Architecture: Load-Time Rewriting

Flicker pursues a third path: load-time binary rewriting. This occurs after the executable is mapped
into memory but before the entry point is executed. By implementing a custom user-space loader, the
system gains total control over the process lifecycle without incurring the runtime overhead of a
DBT engine.

The key advantage of this approach is the ability to use `mmap` to allocate trampoline pages
directly near the target code. This removes the need to hijack binary sections to embed loader and
trampoline information, which is a common limitation of static rewriting tools.

### The Patching Mechanism

To solve the static rewriting issue of shifting addresses, Flicker adopts the methodology used by
E9Patch. The core invariant is that the size of the code section never changes, and instructions are
never moved unless evicted to a trampoline. This makes the patching process control-flow agnostic;
valid jump targets remain valid because addresses do not shift.

Flicker applies patches using a hierarchy of tactics ordered by invasiveness. Ideally, if an
instruction is five bytes or larger, it is replaced with a standard 32-bit relative jump to a
trampoline. If the instruction is smaller than five bytes, the system attempts "Instruction
Punning," where it finds a jump offset that overlaps with the bytes of the following instructions to
form a valid target. If punning fails, the system tries using instruction prefixes to shift the jump
bytes (Padded Jumps).

When these non-destructive methods fail, Flicker employs eviction strategies. "Successor Eviction"
moves the following instruction to a trampoline to create space for the patch. If that is
insufficient, "Neighbor Eviction" searches for a neighboring instruction up to 128 bytes away,
evicting it to create a hole that can stage a short jump to the trampoline. As a final fallback to
guarantee 100% coverage, the system can insert an invalid instruction to trap execution, though this
comes at a performance cost.

### Universal Coverage via Induction

Flicker treats code discovery as an inductive problem, ensuring support for static executables,
dynamic libraries, and JIT code.

The base case is a statically linked executable. Flicker acts as the OS loader: it reads ELF
headers, maps segments, performs a linear scan of the executable sections, and applies patches
before jumping to the entry point. This relies on the assumption that modern compilers produce
tessellated code with no gaps.

The inductive step covers JIT code and dynamic libraries. on Linux, generating executable code
mostly follows a pattern: memory is mapped, code is written, and then `mprotect` is called to make
it executable. Flicker intercepts all `mprotect` and `mmap` calls. When a page transitions to
executable status, the system scans the buffer and applies patches before the kernel finalizes the
permissions.

This logic extends recursively to dynamic libraries. Because the dynamic loader (`ld.so`) uses
`mmap` and `mprotect` to load libraries (such as libc or libGL), intercepting the loader's system
calls allows Flicker to automatically patch every library loaded, including those loaded manually
via `dlopen`.

## System Integration and Edge Cases

Binary rewriting at this level encounters specific OS behaviors that require precise handling to
avoid crashes.

### Thread Creation and Stack Switching

The `clone` syscall, creates a thread with a fresh stack. If a patch intercepts `clone`, the
trampoline runs on the parent's stack. When `clone` returns, the child thread wakes up inside the
trampoline at the instruction following the syscall. The child then attempts to run the trampoline
epilogue to restore registers, but it does so using its new, empty stack, reading garbage data and
crashing.

To resolve this, the trampoline checks the return value. If it is the parent, execution proceeds
normally. If it is the child, the trampoline immediately jumps back to the original code, skipping
stack restoration.

### Signal Handling

When a signal handler returns, it calls `rt_sigreturn`, telling the kernel to restore the CPU state
from a `ucontext` struct saved on the stack. If a trampoline modifies the stack pointer to save
context, `rt_sigreturn` is called while the stack pointer is modified. The kernel then looks for
`ucontext` at the wrong address, corrupting the process state. Flicker handles this by detecting
`rt_sigreturn` and restoring the stack pointer to its exact pre-trampoline value before executing
the syscall.

### The vDSO and Concurrency

The virtual Dynamic Shared Object (vDSO) allows fast syscalls in user space. Flicker locates the
vDSO via the `AT_SYSINFO` auxiliary vector and patches it like any other shared library. Regarding
concurrency, a race condition exists where one thread executes JIT code while another modifies it.
Flicker mitigates this by intercepting the `mprotect` call while the page is still writable but not
yet executable, patching the code safely before the kernel atomically updates the permissions.
