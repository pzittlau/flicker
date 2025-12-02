const std = @import("std");
const builtin = @import("builtin");

const elf = std.elf;
const mem = std.mem;
const posix = std.posix;
const testing = std.testing;

const log = std.log.scoped(.flicker);
const Patcher = @import("Patcher.zig");

const assert = std.debug.assert;

pub const std_options: std.Options = .{
    .log_level = .info,
    .log_scope_levels = &.{
        .{ .scope = .disassembler, .level = .info },
        .{ .scope = .patcher, .level = .debug },
        .{ .scope = .patch_location_iterator, .level = .warn },
        .{ .scope = .flicker, .level = .info },
    },
};
const page_size = std.heap.pageSize();
const max_interp_path_length = 128;
const help =
    \\Usage:
    \\  ./flicker [loader_flags] <executable> [args...]
    \\Flags:
    \\  -h  print this help
    \\
;

const UnfinishedReadError = error{UnfinishedRead};

var patcher: Patcher = undefined;

pub fn main() !void {
    // Parse arguments
    var arg_index: u64 = 1; // Skip own name
    while (arg_index < std.os.argv.len) : (arg_index += 1) {
        const arg = mem.sliceTo(std.os.argv[arg_index], '0');
        if (arg[0] != '-') break;
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{help});
            return;
        }
        // TODO: Handle loader flags when/if we need them
    } else {
        std.debug.print("No executable given.\n", .{});
        std.debug.print("{s}", .{help});
        return;
    }

    // Initialize patcher
    patcher = try Patcher.init(std.heap.page_allocator); // TODO: allocator

    // Map file into memory
    const file = try lookupFile(mem.sliceTo(std.os.argv[arg_index], 0));
    var file_buffer: [128]u8 = undefined;
    var file_reader = file.reader(&file_buffer);
    log.info("--- Loading executable: {s} ---", .{std.os.argv[arg_index]});
    const ehdr = try elf.Header.read(&file_reader.interface);
    const base = try loadStaticElf(ehdr, &file_reader);
    const entry = ehdr.entry + if (ehdr.type == .DYN) base else 0;
    log.info("Executable loaded: base=0x{x}, entry=0x{x}", .{ base, entry });

    // Check for dynamic linker
    var maybe_interp_base: ?usize = null;
    var maybe_interp_entry: ?usize = null;
    var phdrs = ehdr.iterateProgramHeaders(&file_reader);
    while (try phdrs.next()) |phdr| {
        if (phdr.p_type != elf.PT_INTERP) continue;

        var interp_path: [max_interp_path_length]u8 = undefined;
        try file_reader.seekTo(phdr.p_offset);
        if (try file_reader.read(interp_path[0..phdr.p_filesz]) != phdr.p_filesz)
            return UnfinishedReadError.UnfinishedRead;
        assert(interp_path[phdr.p_filesz - 1] == 0); // Must be zero terminated
        log.info("Found interpreter path: {s}", .{interp_path[0 .. phdr.p_filesz - 1]});
        const interp = try std.fs.cwd().openFile(
            interp_path[0 .. phdr.p_filesz - 1],
            .{ .mode = .read_only },
        );

        log.info("--- Loading interpreter ---", .{});
        var interp_buffer: [128]u8 = undefined;
        var interp_reader = interp.reader(&interp_buffer);
        const interp_ehdr = try elf.Header.read(&interp_reader.interface);
        assert(interp_ehdr.type == elf.ET.DYN);
        const interp_base = try loadStaticElf(interp_ehdr, &interp_reader);
        maybe_interp_base = interp_base;
        maybe_interp_entry = interp_ehdr.entry + if (interp_ehdr.type == .DYN) interp_base else 0;
        log.info(
            "Interpreter loaded: base=0x{x}, entry=0x{x}",
            .{ interp_base, maybe_interp_entry.? },
        );
        interp.close();
    }

    var i: usize = 0;
    const auxv = std.os.linux.elf_aux_maybe.?;
    while (auxv[i].a_type != elf.AT_NULL) : (i += 1) {
        // TODO: look at other auxv types and check if we need to change them.
        auxv[i].a_un.a_val = switch (auxv[i].a_type) {
            elf.AT_PHDR => base + ehdr.phoff,
            elf.AT_PHENT => ehdr.phentsize,
            elf.AT_PHNUM => ehdr.phnum,
            elf.AT_BASE => maybe_interp_base orelse auxv[i].a_un.a_val,
            elf.AT_ENTRY => entry,
            elf.AT_EXECFN => @intFromPtr(std.os.argv[arg_index]),
            else => auxv[i].a_un.a_val,
        };
    }

    // The stack layout provided by the kernel is:
    // argc, argv..., NULL, envp..., NULL, auxv...
    // We need to shift this block of memory to remove the loader's own arguments before we jump to
    // the new executable.
    // The end of the block is one entry past the AT_NULL entry in auxv.
    const end_of_auxv = &auxv[i + 1];
    const dest_ptr = @as([*]u8, @ptrCast(std.os.argv.ptr));
    const src_ptr = @as([*]u8, @ptrCast(&std.os.argv[arg_index]));
    const len = @intFromPtr(end_of_auxv) - @intFromPtr(src_ptr);
    log.debug(
        "Copying stack from {*} to {*} with length 0x{x}",
        .{ src_ptr, dest_ptr, len },
    );
    assert(@intFromPtr(dest_ptr) < @intFromPtr(src_ptr));
    std.mem.copyForwards(u8, dest_ptr[0..len], src_ptr[0..len]);

    // `std.os.argv.ptr` points to the argv pointers. The word just before it is argc and also the
    // start of the stack.
    const argc: [*]usize = @as([*]usize, @ptrCast(@alignCast(&std.os.argv.ptr[0]))) - 1;
    argc[0] = std.os.argv.len - arg_index;
    log.debug("new argc: {x}", .{argc[0]});

    const final_entry = maybe_interp_entry orelse entry;
    log.info("Trampolining to final entry: 0x{x} with sp: {*}", .{ final_entry, argc });
    trampoline(final_entry, argc);
}

/// Loads all `PT_LOAD` segments of an ELF file into memory.
///
/// For `ET_EXEC` (non-PIE), segments are mapped at their fixed virtual addresses (`p_vaddr`).
/// For `ET_DYN` (PIE), segments are mapped at a random base address chosen by the kernel.
///
/// It handles zero-initialized(e.g., .bss) sections by mapping anonymous memory and only reading
/// `p_filesz` bytes from the file, ensuring `p_memsz` bytes are allocated.
fn loadStaticElf(ehdr: elf.Header, file_reader: *std.fs.File.Reader) !usize {
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
        try file_reader.seekTo(phdr.p_offset);
        if (try file_reader.read(ptr[offset..][0..phdr.p_filesz]) != phdr.p_filesz)
            return UnfinishedReadError.UnfinishedRead;

        const protections = elfToMmapProt(phdr.p_flags);
        if (protections & posix.PROT.EXEC > 0) {
            log.info("Patching executable segment", .{});
            try patcher.patchRegion(ptr);
        }
        try posix.mprotect(ptr, protections);
    }
    log.debug("loadElf returning base: 0x{x}", .{@intFromPtr(base.ptr)});
    return @intFromPtr(base.ptr);
}

/// Converts ELF program header protection flags to mmap protection flags.
fn elfToMmapProt(elf_prot: u64) u32 {
    var result: u32 = posix.PROT.NONE;
    if ((elf_prot & elf.PF_R) != 0) result |= posix.PROT.READ;
    if ((elf_prot & elf.PF_W) != 0) result |= posix.PROT.WRITE;
    if ((elf_prot & elf.PF_X) != 0) result |= posix.PROT.EXEC;
    return result;
}

/// Opens the file by either opening via a (absolute or relative) path or searching through `PATH`
/// for a file with the name.
// TODO: support paths starting with ~
fn lookupFile(path_or_name: []const u8) !std.fs.File {
    // If filename contains a slash ("/"), then it is interpreted as a pathname.
    if (std.mem.indexOfScalarPos(u8, path_or_name, 0, '/')) |_| {
        const fd = try posix.open(path_or_name, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        return .{ .handle = fd };
    }

    // If it has no slash we need to look it up in PATH.
    if (posix.getenvZ("PATH")) |env_path| {
        var paths = std.mem.tokenizeScalar(u8, env_path, ':');
        while (paths.next()) |p| {
            var dir = std.fs.openDirAbsolute(p, .{}) catch continue;
            defer dir.close();
            const fd = posix.openat(dir.fd, path_or_name, .{
                .ACCMODE = .RDONLY,
                .CLOEXEC = true,
            }, 0) catch continue;
            return .{ .handle = fd };
        }
    }

    return error.FileNotFound;
}

/// This function performs the final jump into the loaded program (amd64)
// TODO: support more architectures
fn trampoline(entry: usize, sp: [*]usize) noreturn {
    asm volatile (
        \\ mov %[sp], %%rsp
        \\ jmp *%[entry]
        : // No outputs
        : [entry] "r" (entry),
          [sp] "r" (sp),
        : .{ .rsp = true, .memory = true });
    unreachable;
}

test {
    _ = @import("AddressAllocator.zig");
    _ = @import("Range.zig");
    _ = @import("PatchLocationIterator.zig");
}
