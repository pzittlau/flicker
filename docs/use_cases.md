# Use Cases for Flicker

Flicker's architecture, load-time binary rewriting without control-flow recovery, uniquely positions
it to handle scenarios where source code is unavailable (legacy/commercial software) and performance
is critical. Unlike Dynamic Binary Translation (DBT) tools like Valgrind or QEMU, which incur high
overhead due to JIT compilation/emulation, Flicker patches code to run natively.

Below are possible use cases categorized by domain.

## High Performance Computing (HPC) & Optimization

### Approximate Computing and Mixed-Precision Analysis

Scientific simulations often default to double precision (64-bit) for safety, even when single
(32-bit) or half (16-bit) precision would yield accurate results with significantly higher
performance. But rewriting massive legacy Fortran/C++ codebases to test precision sensitivity is
impractical.

Flicker could instrument floating-point instructions to perform "Shadow Execution," running
operations in both double and single precision to log divergence. Alternatively, it can mask lower
bits of registers to simulate low-precision hardware.

Unlike compiler-based approaches that change the whole binary, Flicker can apply these patches
selectively to specific "hot" functions at load-time, preserving accuracy in sensitive setup/solver
phases while optimizing the bulk computation.

### Profiling Memory Access Patterns (False Sharing)

In multi-threaded HPC applications, performance often degrades due to "False Sharing", where multiple
threads modify independent variables that happen to reside on the same CPU cache line, causing cache
thrashing.

Sampling profilers (like `perf`) provide statistical approximations but often miss precise
interaction timings. Source-level instrumentation disrupts compiler optimizations.

Flicker could instrument memory store instructions (`MOV` etc.) to record effective addresses. By
aggregating this data, it can generate heatmaps of cache line access density, precisely identifying
false sharing or inefficient strided access patterns in optimized binaries.

### Low-Overhead I/O Tracing

Parallel MPI jobs often inadvertently stress parallel filesystems (Lustre, GPFS) by performing
excessive small writes or metadata operations.

Tools like `strace` force a context switch for every syscall, slowing down the application so much
that the race conditions or I/O storms disappear (Heisenbugs).

By intercepting I/O syscalls (`write`, `read`, `open`, ...) inside the process memory, Flicker could
aggregate I/O statistics (e.g., "Rank 7 performed 50,000 writes of 4 bytes") with negligible
overhead, providing a lightweight alternative to `strace` for high-throughput jobs.

### MPI Communication Profiling

HPC performance is often bound by network latency between nodes. Profiling tools like Vampir are
heavy and costly. Flicker can patch shared library exports (like MPI_Send or MPI_Recv) at load-time.
This allows lightweight logging of message sizes and latencies without recompiling the application
or linking against special profiling libraries.

## Security and Hardening

### Coverage-Guided Fuzzing (Closed Source)

Fuzzing requires feedback on which code paths are executed to be effective. But for closed-source
software, researchers typically use QEMU-mode in AFL. QEMU translates instructions dynamically,
resulting in slow execution speeds (often 2-10x slower than native).

Flicker could inject coverage instrumentation (updating a shared memory bitmap on branch targets)
directly into the binary at load time. This would allow closed-source binaries to be fuzzed at
near-native speeds, significantly increasing the number of test cases run per second.

### Software Shadow Stacks

Return-Oriented Programming (ROP) attacks exploit buffer overflows to overwrite return addresses on
the stack.

Hardware enforcement (Intel CET/AMD Shadow Stack) requires modern CPUs (Intel 11th Gen+, Zen 3+) and
recent kernels (Linux 6.6+). Older systems remain vulnerable.

Flicker could instrument `CALL` and `RET` instructions to implement a Software Shadow Stack. On
`CALL`, the return address is pushed to a secure, isolated stack region. On `RET`, the address on
the stack is compared against the shadow stack. If they mismatch, the program terminates, preventing
ROP chains.

### Binary-Only Address Sanitizer (ASan)

Memory safety errors (buffer overflows, use-after-free) in C/C++ are often found with ASan or
Valgrind. ASan requires recompilation. Valgrind works on binaries but slows execution by 20x-50x,
making it unusable for large datasets.

Flicker could intercept allocator calls (`malloc`/`free`) to poison "red zones" around memory and
instrument memory access instructions to check these zones. This provides ASan-like capabilities for
legacy binaries with significantly lower overhead than Valgrind.

## Systems and Maintenance

### Hardware Feature Emulation (Forward Compatibility)

HPC clusters are often heterogeneous, with older nodes lacking newer instruction sets (e.g.,
AVX-512, AMX). A binary compiled for a newer architecture will crash with `SIGILL` on an older node.

Flicker could detect these instructions and patch them to jump to a software emulation routine or a
scalar fallback implementation. This allows binaries optimized for the latest hardware to run
(albeit slower) on legacy nodes for testing or resource-filling purposes.

### Fault Injection

To certify software for mission-critical environments, developers must verify how it handles
hardware errors.

Flicker could instrument instructions to probabilistically flip bits in registers or memory
("Bit-flip injection"), or intercept syscalls to return error codes (e.g., returning `ENOSPC` on
`write`). It can also simulate malfunctioning or intermittent devices by corrupting buffers returned
by `read`. This allows testing error recovery paths without physical hardware damage.

### Record/Replay Engine

Debugging non-deterministic bugs (race conditions) is difficult because they are hard to reproduce.
By intercepting all sources of non-determinism (syscalls, `rdtsc`, atomic instructions, signals),
Flicker could record a trace of an execution. This trace can be replayed later to force the exact
same execution path, allowing developers to debug the error state interactively.
