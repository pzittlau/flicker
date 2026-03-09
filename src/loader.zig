const std = @import("std");
const elf = std.elf;
const mem = std.mem;
const posix = std.posix;

const log = std.log.scoped(.loader);
const page_size = std.heap.pageSize();

pub const UnfinishedReadError = error{UnfinishedRead};

pub const LoadResult = struct {
    base: usize,
    size: usize,
};

/// Loads all `PT_LOAD` segments of an ELF file into memory.
///
/// For `ET_EXEC` (non-PIE), segments are mapped at their fixed virtual addresses (`p_vaddr`).
/// For `ET_DYN` (PIE), segments are mapped at a random base address chosen by the kernel.
///
/// It handles zero-initialized(e.g., .bss) sections by mapping anonymous memory and only reading
/// `p_filesz` bytes from the file, ensuring `p_memsz` bytes are allocated.
pub fn loadStaticElf(ehdr: elf.Header, file_reader: *std.fs.File.Reader) !LoadResult {
    // NOTE: In theory we could also just look at the first and last loadable segment because the
    // ELF spec mandates these to be in ascending order of `p_vaddr`, but better be safe than sorry.
    // https://gabi.xinuos.com/elf/08-pheader.html#:~:text=ascending%20order
    const minva, const maxva = bounds: {
        var minva: u64 = std.math.maxInt(u64);
        var maxva: u64 = 0;
        var phdrs = ehdr.iterateProgramHeaders(file_reader);
        while (try phdrs.next()) |phdr| {
            if (phdr.p_type != elf.PT_LOAD) continue;
            minva = @min(minva, phdr.p_vaddr);
            maxva = @max(maxva, phdr.p_vaddr + phdr.p_memsz);
        }
        minva = mem.alignBackward(usize, minva, page_size);
        maxva = mem.alignForward(usize, maxva, page_size);
        log.debug("Calculated bounds: minva=0x{x}, maxva=0x{x}", .{ minva, maxva });
        break :bounds .{ minva, maxva };
    };

    // Check, that the needed memory region can be allocated as a whole. We do this
    const dynamic = ehdr.type == elf.ET.DYN;
    log.debug("ELF type is {s}", .{if (dynamic) "DYN" else "EXEC (static)"});
    const hint = if (dynamic) null else @as(?[*]align(page_size) u8, @ptrFromInt(minva));
    log.debug("mmap pre-flight hint: {*}", .{hint});
    const base = try posix.mmap(
        hint,
        maxva - minva,
        posix.PROT.WRITE,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .FIXED_NOREPLACE = !dynamic },
        -1,
        0,
    );
    log.debug("Pre-flight reservation at: {*}, size: 0x{x}", .{ base.ptr, base.len });

    var phdrs = ehdr.iterateProgramHeaders(file_reader);
    var phdr_idx: u32 = 0;
    errdefer posix.munmap(base);
    while (try phdrs.next()) |phdr| : (phdr_idx += 1) {
        if (phdr.p_type != elf.PT_LOAD) continue;
        if (phdr.p_memsz == 0) continue;

        const offset = phdr.p_vaddr & (page_size - 1);
        const size = mem.alignForward(usize, phdr.p_memsz + offset, page_size);
        var start = mem.alignBackward(usize, phdr.p_vaddr, page_size);
        const base_for_dyn = if (dynamic) @intFromPtr(base.ptr) else 0;
        start += base_for_dyn;
        log.debug(
            "  - phdr[{}]: mapping 0x{x} - 0x{x} (vaddr=0x{x}, dyn_base=0x{x})",
            .{ phdr_idx, start, start + size, phdr.p_vaddr, base_for_dyn },
        );
        const ptr: []align(page_size) u8 = @as([*]align(page_size) u8, @ptrFromInt(start))[0..size];
        // TODO: we should likely just use mmap instead because then not touched memory isn't loaded
        // unnecessarily
        try file_reader.seekTo(phdr.p_offset);
        if (try file_reader.read(ptr[offset..][0..phdr.p_filesz]) != phdr.p_filesz)
            return UnfinishedReadError.UnfinishedRead;

        const protections = elfToMmapProt(phdr.p_flags);
        try posix.mprotect(ptr, protections);
    }
    log.debug("loadElf returning base: 0x{x}, size: 0x{x}", .{ @intFromPtr(base.ptr), base.len });
    return .{ .base = @intFromPtr(base.ptr), .size = base.len };
}

/// Converts ELF program header protection flags to mmap protection flags.
pub fn elfToMmapProt(elf_prot: u64) u32 {
    var result: u32 = posix.PROT.NONE;
    if ((elf_prot & elf.PF_R) != 0) result |= posix.PROT.READ;
    if ((elf_prot & elf.PF_W) != 0) result |= posix.PROT.WRITE;
    if ((elf_prot & elf.PF_X) != 0) result |= posix.PROT.EXEC;
    return result;
}
