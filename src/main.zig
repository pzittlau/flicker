const std = @import("std");
const builtin = @import("builtin");

const elf = std.elf;
const mem = std.mem;
const posix = std.posix;
const testing = std.testing;

const log = std.log.scoped(.flicker);
const Patcher = @import("Patcher.zig");
const loader = @import("loader.zig");

const assert = std.debug.assert;

pub const std_options: std.Options = .{
    .log_level = .info,
    .log_scope_levels = &.{
        .{ .scope = .disassembler, .level = .info },
        .{ .scope = .patcher, .level = .debug },
        .{ .scope = .flicker, .level = .info },
        .{ .scope = .loader, .level = .info },
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

/// This needs to be a public global, such that it has a static memory location. This is needed
/// for the syscall interception, in particular for patching new maps of the `mmap` call.
pub var patcher: Patcher = undefined;
pub var target_exec_path_buf: [std.fs.max_path_bytes]u8 = @splat(0);
pub var target_exec_path: []const u8 = undefined;

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

    const file = try lookupFile(mem.sliceTo(std.os.argv[arg_index], 0));

    patcher = try .init(std.heap.page_allocator);

    // Resolve the absolute path of the target executable for /proc/self/exe spoofing
    const fd_path = try std.fmt.bufPrint(&target_exec_path_buf, "/proc/self/fd/{d}", .{file.handle});
    target_exec_path = try std.fs.readLinkAbsolute(fd_path, &target_exec_path_buf);
    log.debug("Resolved target executable path: {s}", .{target_exec_path});

    try bootstrapMemoryMap(&patcher);
    // TODO:
    // block until `mmap_min_addr`
    // block all entries in `proc/self/maps`

    // Map file into memory
    var file_buffer: [128]u8 = undefined;
    var file_reader = file.reader(&file_buffer);
    log.info("--- Loading executable: {s} ---", .{std.os.argv[arg_index]});
    const ehdr = try elf.Header.read(&file_reader.interface);
    const load_result = try loader.loadStaticElf(ehdr, &file_reader);
    const base = load_result.base;
    const entry = ehdr.entry + if (ehdr.type == .DYN) base else 0;
    log.info("Executable loaded: base=0x{x}, entry=0x{x}", .{ base, entry });
    try patcher.address_allocator.block(.fromPtr(@ptrFromInt(base), load_result.size));
    try patchLoadedElf(load_result.base);

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
        const interp_result = try loader.loadStaticElf(interp_ehdr, &interp_reader);
        const interp_base = interp_result.base;
        maybe_interp_base = interp_base;
        maybe_interp_entry = interp_ehdr.entry + if (interp_ehdr.type == .DYN) interp_base else 0;
        log.info(
            "Interpreter loaded: base=0x{x}, entry=0x{x}",
            .{ interp_base, maybe_interp_entry.? },
        );
        try patcher.address_allocator.block(.fromPtr(@ptrFromInt(interp_base), interp_result.size));
        try patchLoadedElf(interp_base);
        interp.close();
    }

    var i: usize = 0;
    const auxv = std.os.linux.elf_aux_maybe.?;
    while (auxv[i].a_type != elf.AT_NULL) : (i += 1) {
        auxv[i].a_un.a_val = switch (auxv[i].a_type) {
            elf.AT_PHDR => base + ehdr.phoff,
            elf.AT_PHENT => ehdr.phentsize,
            elf.AT_PHNUM => ehdr.phnum,
            elf.AT_BASE => maybe_interp_base orelse auxv[i].a_un.a_val,
            elf.AT_ENTRY => entry,
            elf.AT_EXECFN => @intFromPtr(std.os.argv[arg_index]),
            elf.AT_SYSINFO_EHDR => blk: {
                const vdso_base = auxv[i].a_un.a_val;
                log.info("Found vDSO at 0x{x}", .{vdso_base});
                try patchLoadedElf(vdso_base);
                break :blk vdso_base;
                // NOTE: We do not need to block this, because it's already done by the initial
                // `/proc/self/maps` pass.
            },
            elf.AT_EXECFD => {
                @panic("Got AT_EXECFD auxv value");
                // TODO: handle AT_EXECFD, when needed
                // The SysV ABI Specification says:
                // > At process creation the system may pass control to an interpreter program. When
                // > this happens, the system places either an entry of type AT_EXECFD or one of
                // > type AT_PHDR in the auxiliary vector. The entry for type AT_EXECFD uses the
                // > a_val member to contain a file descriptor open to read the application
                // > program’s object file.
            },
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

fn patchLoadedElf(base: usize) !void {
    const ehdr = @as(*const elf.Ehdr, @ptrFromInt(base));
    if (!mem.eql(u8, ehdr.e_ident[0..4], elf.MAGIC)) return error.InvalidElfMagic;

    const phoff = ehdr.e_phoff;
    const phnum = ehdr.e_phnum;
    const phentsize = ehdr.e_phentsize;

    var i: usize = 0;
    while (i < phnum) : (i += 1) {
        const phdr_ptr = base + phoff + (i * phentsize);
        const phdr = @as(*const elf.Phdr, @ptrFromInt(phdr_ptr));

        if (phdr.p_type != elf.PT_LOAD) continue;
        if ((phdr.p_flags & elf.PF_X) == 0) continue;

        // Determine VMA
        // For ET_EXEC, p_vaddr is absolute.
        // For ET_DYN, p_vaddr is offset from base.
        const vaddr = if (ehdr.e_type == elf.ET.DYN) base + phdr.p_vaddr else phdr.p_vaddr;
        const memsz = phdr.p_memsz;

        // TODO: does this really need to be aligned
        const page_start = mem.alignBackward(usize, vaddr, page_size);
        const page_end = mem.alignForward(usize, vaddr + memsz, page_size);
        const size = page_end - page_start;

        const region = @as([*]align(page_size) u8, @ptrFromInt(page_start))[0..size];

        try patcher.patchRegion(region);
        try posix.mprotect(region, loader.elfToMmapProt(phdr.p_flags));
    }
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

fn bootstrapMemoryMap(p: *Patcher) !void {
    {
        var min_addr: u64 = 0x10000;
        if (std.fs.openFileAbsolute("/proc/sys/vm/mmap_min_addr", .{})) |file| {
            defer file.close();
            var buf: [32]u8 = undefined;
            if (file.readAll(&buf)) |len| {
                const trimmed = std.mem.trim(u8, buf[0..len], " \n\r\t");
                if (std.fmt.parseInt(u64, trimmed, 10)) |val| {
                    min_addr = val;
                } else |_| {}
            } else |_| {}
        } else |_| {}
        try p.address_allocator.block(.{ .start = 0, .end = @intCast(min_addr) });
    }

    {
        var maps_file = try std.fs.openFileAbsolute("/proc/self/maps", .{});
        defer maps_file.close();
        var buf: [512]u8 = undefined;
        var reader = maps_file.reader(&buf);
        while (true) {
            const line = reader.interface.takeDelimiterInclusive('\n') catch |err| switch (err) {
                error.EndOfStream => break,
                error.ReadFailed => |e| return reader.err orelse e,
                else => |e| return e,
            };
            std.debug.print("{s}", .{line});
            const dash = mem.indexOfScalar(u8, line, '-') orelse continue;
            const space = mem.indexOfScalar(u8, line, ' ') orelse continue;
            assert(space > dash);
            const start = std.fmt.parseInt(u64, line[0..dash], 16) catch unreachable;
            const end = std.fmt.parseInt(u64, line[dash + 1 .. space], 16) catch unreachable;
            // TODO: remove when Range is `u64`
            try p.address_allocator.block(.{
                .start = @as(u63, @truncate(start)),
                .end = @as(u63, @truncate(end)),
            });
        }
    }
}

test {
    _ = @import("Patcher.zig");
}

// TODO: make this be passed in from the build system
const bin_path = "zig-out/bin/";
fn getTestExePath(comptime name: []const u8) []const u8 {
    return bin_path ++ "test_" ++ name;
}
const flicker_path = bin_path ++ "flicker";

test "nolibc_nopie_exit" {
    try testHelper(&.{ flicker_path, getTestExePath("nolibc_nopie_exit") }, "");
}
test "nolibc_pie_exit" {
    try testHelper(&.{ flicker_path, getTestExePath("nolibc_pie_exit") }, "");
}
test "libc_pie_exit" {
    try testHelper(&.{ flicker_path, getTestExePath("libc_pie_exit") }, "");
}

test "nolibc_nopie_helloWorld" {
    try testHelper(&.{ flicker_path, getTestExePath("nolibc_nopie_helloWorld") }, "Hello World!\n");
}
test "nolibc_pie_helloWorld" {
    try testHelper(&.{ flicker_path, getTestExePath("nolibc_pie_helloWorld") }, "Hello World!\n");
}
test "libc_pie_helloWorld" {
    try testHelper(&.{ flicker_path, getTestExePath("libc_pie_helloWorld") }, "Hello World!\n");
}

test "nolibc_nopie_printArgs" {
    try testPrintArgs("nolibc_nopie_printArgs");
}
test "nolibc_pie_printArgs" {
    try testPrintArgs("nolibc_pie_printArgs");
}
test "libc_pie_printArgs" {
    try testPrintArgs("libc_pie_printArgs");
}

test "nolibc_nopie_readlink" {
    try testReadlink("nolibc_nopie_readlink");
}
test "nolibc_pie_readlink" {
    try testReadlink("nolibc_pie_readlink");
}
test "libc_pie_readlink" {
    try testReadlink("libc_pie_readlink");
}

test "nolibc_nopie_clone_raw" {
    try testHelper(
        &.{ flicker_path, getTestExePath("nolibc_nopie_clone_raw") },
        "Child: Hello\nParent: Goodbye\n",
    );
}
test "nolibc_pie_clone_raw" {
    try testHelper(
        &.{ flicker_path, getTestExePath("nolibc_pie_clone_raw") },
        "Child: Hello\nParent: Goodbye\n",
    );
}

test "nolibc_nopie_clone_no_new_stack" {
    try testHelper(
        &.{ flicker_path, getTestExePath("nolibc_nopie_clone_no_new_stack") },
        "Child: Hello\nParent: Goodbye\n",
    );
}
test "nolibc_pie_clone_no_new_stack" {
    try testHelper(
        &.{ flicker_path, getTestExePath("nolibc_pie_clone_no_new_stack") },
        "Child: Hello\nParent: Goodbye\n",
    );
}

test "nolibc_nopie_fork" {
    try testHelper(
        &.{ flicker_path, getTestExePath("nolibc_nopie_fork") },
        "Child: I'm alive!\nParent: Child died.\n",
    );
}
test "nolibc_pie_fork" {
    try testHelper(
        &.{ flicker_path, getTestExePath("nolibc_pie_fork") },
        "Child: I'm alive!\nParent: Child died.\n",
    );
}
test "libc_pie_fork" {
    try testHelper(
        &.{ flicker_path, getTestExePath("libc_pie_fork") },
        "Child: I'm alive!\nParent: Child died.\n",
    );
}

test "nolibc_nopie_signal_handler" {
    try testHelper(
        &.{ flicker_path, getTestExePath("nolibc_nopie_signal_handler") },
        "In signal handler\nSignal handled successfully\n",
    );
}
test "nolibc_pie_signal_handler" {
    try testHelper(
        &.{ flicker_path, getTestExePath("nolibc_pie_signal_handler") },
        "In signal handler\nSignal handled successfully\n",
    );
}

test "nolibc_nopie_vdso_clock" {
    try testHelper(
        &.{ flicker_path, getTestExePath("nolibc_nopie_vdso_clock") },
        "Time gotten\n",
    );
}
test "nolibc_pie_vdso_clock" {
    try testHelper(
        &.{ flicker_path, getTestExePath("nolibc_pie_vdso_clock") },
        "Time gotten\n",
    );
}
test "libc_pie_vdso_clock" {
    try testHelper(
        &.{ flicker_path, getTestExePath("libc_pie_vdso_clock") },
        "Time gotten\n",
    );
}

test "echo" {
    try testHelper(&.{ "echo", "Hello", "There" }, "Hello There\n");
}

fn testPrintArgs(comptime name: []const u8) !void {
    const exe_path = getTestExePath(name);
    const loader_argv: []const []const u8 = &.{ flicker_path, exe_path, "foo", "bar", "baz hi" };
    const target_argv = loader_argv[1..];
    const expected_stout = try mem.join(testing.allocator, " ", target_argv);
    defer testing.allocator.free(expected_stout);
    try testHelper(loader_argv, expected_stout);
}

fn testReadlink(comptime name: []const u8) !void {
    const exe_path = getTestExePath(name);
    const loader_argv: []const []const u8 = &.{ flicker_path, exe_path };
    const cwd_path = try std.fs.cwd().realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(cwd_path);
    const expected_path = try std.fs.path.join(testing.allocator, &.{ cwd_path, exe_path });
    defer testing.allocator.free(expected_path);
    try testHelper(loader_argv, expected_path);
}

fn testHelper(
    argv: []const []const u8,
    expected_stdout: []const u8,
) !void {
    const result = try std.process.Child.run(.{
        .allocator = testing.allocator,
        .argv = argv,
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);
    errdefer std.log.err("term: {}", .{result.term});
    errdefer std.log.err("stdout: {s}", .{result.stdout});
    errdefer std.log.err("stderr: {s}", .{result.stderr});

    try testing.expectEqualStrings(expected_stdout, result.stdout);
    try testing.expect(result.term == .Exited);
    try testing.expectEqual(0, result.term.Exited);
}
