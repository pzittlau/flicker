const std = @import("std");
const p = std.posix;

const page_size_min = std.heap.page_size_min;

pub const backend = switch (@import("builtin").is_test) {
    true => testing,
    false => posix,
};

// TODO: Maybe log?
pub const testing = struct {
    pub fn mmap(
        ptr: [*]align(page_size_min) u8,
        length: usize,
        prot: u32,
        flags: p.MAP,
        fd: p.fd_t,
        offset: u64,
    ) p.MMapError![]align(page_size_min) u8 {
        _ = .{ ptr, length, prot, flags, fd, offset };
        return ptr[0..length];
    }
    pub fn mprotect(memory: []align(page_size_min) u8, protection: u32) p.MProtectError!void {
        _ = .{ memory, protection };
    }
    pub fn munmap(memory: []align(page_size_min) const u8) void {
        _ = memory;
    }
};

pub const posix = struct {
    pub fn mmap(
        ptr: ?[*]align(page_size_min) u8,
        length: usize,
        prot: u32,
        flags: p.MAP,
        fd: p.fd_t,
        offset: u64,
    ) p.MMapError![]align(page_size_min) u8 {
        return p.mmap(ptr, length, prot, flags, fd, offset);
    }
    pub fn mprotect(memory: []align(page_size_min) u8, protection: u32) p.MProtectError!void {
        return p.mprotect(memory, protection);
    }
    pub fn munmap(memory: []align(page_size_min) const u8) void {
        p.munmap(memory);
    }
};
