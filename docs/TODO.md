## General things

### Thread-locals

Right now we don't use any thread-local stuff in zig. This means that the application can freely
decide what to do with the `fs` segment. If we need some thread-locals in the future we have to
carefully think about how to do it.

If `FSGSBASE` is available we can swap out the segment real fast. If not we would need to fallback
to `arch_prctl` which is of course a lot slower. Fortunately `FSGSBASE` is available since Intel
IvyBridge(2012) and AMD Zen 2 Family 17H(2019) and Linux 5.9(2020).

## Major things

- [x] `clone`: with and without stack switching
- [x] `clone3`: with and without stack switching
- [x] `fork`: likely there is nothing to be done here but just to be sure, check again
- [x] `rt_sigreturn`: we can't use the normal `syscall` interception because we push something onto
      the stack, so `ucontext` isn't on top anymore.
- [x] `/proc/self/exe`: intercept calls to `readlink`/`readlinkat` with that as argument
- [ ] `auxv`: check if that is setup correctly and completely
- [ ] JIT support: intercept `mmap`, `mprotect` and `mremap` that change pages to be executable
- [ ] `SIGILL` patching fallback
- [ ] `vdso` handling

## Minor things

- [ ] Cleanup: When a JIT engine frees code, our trampolines are "zombies", so over time we leak
      memory and also reduce the patching percentage
- [ ] Ghost page edge case: In all patch strategies, if a range spans multiple pages and we `mmap`
    the first one but can't `mmap` the second one we just let the first one mapped. It would be better
    to unmap them
- [ ] Re-entrancy for `patchRegion`
    - when a signal comes, while we are in that function, and we need to patch something due to the
      signal we will deadlock
- [ ] strict disassembly mode: currently we warn on disassembly error, provide a flag to stop instead
- [ ] Separate stack for flicker
    - when the application is run with a small stack (`sigaltstack`, goroutines) we might overflow
      especially for the `patchRegion` call
    - either one global stack for all to use(with a mutex) or a thread-local stack (though using
    `fs` has other problems)
- [ ] `exec`: option to persist across `exec` calls, useful for things like `make`
- [ ] `prctl`/`arch_prctl`: check if/what we need to intercept and change
- [ ] `seccomp`: check what we need to intercept and change
- [ ] `modify_ldt`: check what we need to intercept and change
- [ ] `set_tid_address`: check what we need to intercept and change
- [ ] performance optimizations for patched code? Peephole might be possible
