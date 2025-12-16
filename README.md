# Flicker

Flicker is a universal load-time binary rewriter for native AMD64 Linux applications. It maps the
target executable into memory, performs a linear scan disassembly, and applies patches using a
hierarchy of tactics, allowing for instrumentation, debugging, and hook injection.

This approach allows Flicker to maintain control over the process lifecycle, enabling it to handle
Statically linked executables, Dynamically linked executables (via interpreter loading), and System
calls (e.g., intercepting `readlink`, `clone`).

It tries to offer a middle ground that aims for native execution speeds with the flexibility of
dynamic instrumentation.

## Work In Progress

This project is currently in active development.

Already supported are Statically linked executables, basic dynamically linked executables (via
`PT_INTERP` loading), and basic syscall interception

Full `dlopen` support, JIT handling, signal handling, and a plugin system are pending.

## Build

Flicker uses the Zig build system. Ensure you have Zig 0.15.1 installed.

To build the release binary:
```bash
zig build -Doptimize=ReleaseSafe
```

To run the test suite (includes various static/dynamic executables):
```bash
zig build test
```

The compiled binary will be located at `zig-out/bin/flicker`.

## Usage

Flicker acts as a loader wrapper. Pass the target executable and its arguments directly to Flicker.

```bash
./flicker <executable> [args...]
# Example: Running 'ls' through Flicker
./zig-out/bin/flicker ls -la
```

## How it Works

### The Loader

Flicker does not use `LD_PRELOAD`. Instead, it maps the target ELF binary into memory. If the binary
is dynamically linked, Flicker parses the `PT_INTERP` header, locates the dynamic linker (mostly
`ld-linux.so`), and maps that as well. It then rewrites the Auxiliary Vector (`AT_PHDR`, `AT_ENTRY`,
`AT_BASE`) on the stack to trick the C runtime into accepting the manually loaded environment.

### Patching Engine

Before transferring control to the entry point, Flicker scans executable segments for instructions
that require instrumentation. It allocates "Trampolines" - executable memory pages located within
±2GB of the target instruction.

To overwrite an instruction with a 5-byte jump (`jmp rel32`) without corrupting adjacent code or
breaking jump targets, Flicker uses a Back-to-Front scanning approach and a constraint solver to
find valid bytes for "instruction punning."

### Syscall Interception

Flicker can replace `syscall` opcodes with jumps to a custom handler. This handler emulates the
syscall logic or modifies arguments.

Special handling detects `clone` syscalls to ensure the child thread (which wakes up with a fresh
stack) does not crash when attempting to restore the parent's register state.

Path Spoofing: Intercepts readlink on `/proc/self/exe` to return the path of the target binary
rather than the Flicker loader.

## License

Apache License 2.0
