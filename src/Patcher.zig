const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const math = std.math;
const mem = std.mem;
const posix = std.posix;
const zydis = @import("zydis").zydis;
const disassembler = @import("disassembler.zig");

const log = std.log.scoped(.patcher);
const AddressAllocator = @import("AddressAllocator.zig");
const InstructionFormatter = disassembler.InstructionFormatter;
const InstructionIterator = disassembler.InstructionIterator;
const PatchLocationIterator = @import("PatchLocationIterator.zig");
const PatchByte = PatchLocationIterator.PatchByte;
const Range = @import("Range.zig");

const assert = std.debug.assert;

const page_size = 4096;
const jump_rel32: u8 = 0xe9;
const jump_rel32_size = 5;
const jump_rel8: u8 = 0xeb;
const jump_rel8_size = 2;
const max_ins_bytes = 15;
// Based on the paper 'x86-64 Instruction Usage among C/C++ Applications' by 'Akshintala et al.'
// it's '4.25' bytes, so 4 is good enough. (https://oscarlab.github.io/papers/instrpop-systor19.pdf)
const avg_ins_bytes = 4;

// TODO: Find an invalid instruction to use.
// const invalid: u8 = 0xaa;
const int3: u8 = 0xcc;
const nop: u8 = 0x90;

// Prefixes for Padded Jumps (Tactic T1)
const prefix_fs: u8 = 0x64;
const prefix_gs: u8 = 0x65;
const prefix_ss: u8 = 0x36;
const prefixes = [_]u8{ prefix_fs, prefix_gs, prefix_ss };

const Patcher = @This();

gpa: mem.Allocator,
flicken: std.StringArrayHashMapUnmanaged(Flicken) = .empty,
address_allocator: AddressAllocator = .empty,
/// Tracks the base addresses of pages we have mmap'd for Flicken.
allocated_pages: std.AutoHashMapUnmanaged(u64, void) = .empty,

pub fn init(gpa: mem.Allocator) !Patcher {
    var flicken: std.StringArrayHashMapUnmanaged(Flicken) = .empty;
    try flicken.ensureTotalCapacity(gpa, 8);
    flicken.putAssumeCapacity("nop", .{ .name = "nop", .bytes = &.{} });
    return .{
        .gpa = gpa,
        .flicken = flicken,
    };
}

pub fn deinit(patcher: *Patcher) void {
    _ = patcher;
}

/// Flicken name and bytes have to be valid for the lifetime it's used. If a trampoline with the
/// name is already registered it gets overwritten.
/// NOTE: The name "nop" is reserved and always has the ID 0.
pub fn addFlicken(patcher: *Patcher, trampoline: Flicken) !FlickenId {
    assert(!mem.eql(u8, "nop", trampoline.name));
    try patcher.flicken.ensureUnusedCapacity(patcher.gpa, 1);
    errdefer comptime unreachable;

    const gop = patcher.flicken.getOrPutAssumeCapacity(trampoline.name);
    if (gop.found_existing) {
        log.warn("addTrampoline: Overwriting existing trampoline: {s}", .{trampoline.name});
    }
    gop.key_ptr.* = trampoline.name;
    gop.value_ptr.* = trampoline;
    return @enumFromInt(gop.index);
}

pub const Flicken = struct {
    name: []const u8,
    bytes: []const u8,

    pub fn size(flicken: *const Flicken) u64 {
        return flicken.bytes.len + jump_rel32_size;
    }
};

pub const FlickenId = enum(u64) {
    /// The nop flicken is special. It just does the patched instruction and immediately jumps back
    /// to the normal instruction stream. It **cannot** be changed.
    /// The bytes are always empty, meaning that `bytes.len == 0`.
    /// It also needs special handling when constructing the patches, because it's different for
    /// each instruction.
    nop = 0,
    _,
};

/// Must point to first byte of an instruction.
pub const PatchRequest = struct {
    /// What to patch with.
    flicken: FlickenId,
    /// Offset within the region.
    offset: u64,
    /// Number of bytes of instruction.
    size: u8,
    /// A byte slice from the start of the offset to the end of the region. This isn't necessary to
    /// have but makes this more accessible.
    bytes: []u8,

    pub fn desc(_: void, lhs: PatchRequest, rhs: PatchRequest) bool {
        return @intFromPtr(lhs.bytes.ptr) > @intFromPtr(rhs.bytes.ptr);
    }

    pub fn format(
        self: @This(),
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try writer.print(
            ".{{ .address = 0x{x}, .bytes = 0x{x}, .flicken = {} }}",
            .{ @intFromPtr(self.bytes.ptr), self.bytes, @intFromEnum(self.flicken) },
        );
    }
};

pub fn patchRegion(patcher: *Patcher, region: []align(page_size) u8) !void {
    {
        // Block the region, such that we don't try to allocate there anymore.
        const start: i64 = @intCast(@intFromPtr(region.ptr));
        try patcher.address_allocator.block(
            patcher.gpa,
            .{ .start = start, .end = start + @as(i64, @intCast(region.len)) },
            page_size,
        );
    }

    var arena_impl = std.heap.ArenaAllocator.init(patcher.gpa);
    const arena = arena_impl.allocator();
    defer arena_impl.deinit();
    var patch_requests: std.ArrayListUnmanaged(PatchRequest) = .empty;

    {
        // Get where to patch.
        var instruction_iterator = InstructionIterator.init(region);
        while (instruction_iterator.next()) |instruction| {
            // TODO: handle RIP relative instructions/operands somehow.
            // Maybe use `ZydisCalcAbsoluteAddress`?
            const should_patch: bool = instruction.instruction.mnemonic == zydis.ZYDIS_MNEMONIC_SYSCALL;
            if (should_patch) {
                const offset = instruction.address - @intFromPtr(region.ptr);
                const request: PatchRequest = .{
                    .flicken = .nop,
                    .offset = offset,
                    .size = instruction.instruction.length,
                    .bytes = region[offset..],
                };
                try patch_requests.append(arena, request);
            }
        }
        log.info("patchRegion: Got {} patch requests", .{patch_requests.items.len});
    }

    // Sort patch requests in descending order by address, such that we patch from back to front.
    mem.sortUnstable(PatchRequest, patch_requests.items, {}, PatchRequest.desc);

    {
        // Check for duplicate patch requests and undefined IDs
        var last_offset: ?u64 = null;
        for (patch_requests.items, 0..) |request, i| {
            if (last_offset != null and last_offset.? == request.offset) {
                var buffer: [256]u8 = undefined;
                const fmt = disassembler.formatBytes(request.bytes, &buffer);
                log.err(
                    "patchRegion: Found duplicate patch requests for instruction: {s}",
                    .{fmt},
                );
                log.err("patchRegion: request 1: {f}", .{patch_requests.items[i - 1]});
                log.err("patchRegion: request 2: {f}", .{patch_requests.items[i]});
                return error.DuplicatePatchRequest;
            }
            last_offset = request.offset;

            if (@as(u64, @intFromEnum(request.flicken)) >= patcher.flicken.count()) {
                var buffer: [256]u8 = undefined;
                const fmt = disassembler.formatBytes(
                    request.bytes[0..request.size],
                    &buffer,
                );
                log.err(
                    "patchRegion: Usage of undefined flicken in request {f} for instruction: {s}",
                    .{ request, fmt },
                );
                return error.undefinedFlicken;
            }
        }
    }

    {
        // Apply patches.
        try posix.mprotect(region, posix.PROT.READ | posix.PROT.WRITE);
        defer posix.mprotect(region, posix.PROT.READ | posix.PROT.EXEC) catch
            @panic("patchRegion: mprotect back to R|X failed. Can't continue");

        // PERF: A set of the pages for the patches/flicken we made writable. This way we don't
        // repeatedly change call `mprotect` on the same page to switch it from R|W to R|X and back.
        // At the end we `mprotect` all pages in this set back to being R|X.
        var pages_made_writable: std.AutoHashMapUnmanaged(u64, void) = .empty;
        for (patch_requests.items) |request| {
            const flicken: Flicken = if (request.flicken == .nop)
                .{ .name = "nop", .bytes = request.bytes[0..request.size] }
            else
                patcher.flicken.entries.get(@intFromEnum(request.flicken)).value;

            var pii = PatchInstructionIterator.init(
                request.bytes,
                request.size,
                flicken.size(),
            );
            pii: while (try pii.next(patcher.gpa, &patcher.address_allocator)) |allocated_range| {
                // Ensure `allocated_range` is mapped R|W.
                const start, const end = pageRange(allocated_range);
                const protection = posix.PROT.READ | posix.PROT.WRITE;
                var page_addr = start;
                while (page_addr < end) : (page_addr += page_size) {
                    // If the page is already writable, skip it.
                    if (pages_made_writable.get(page_addr)) |_| continue;
                    // If we mapped it already we have to do mprotect, else mmap.
                    const gop = try patcher.allocated_pages.getOrPut(patcher.gpa, page_addr);
                    if (gop.found_existing) {
                        const ptr: [*]align(page_size) u8 = @ptrFromInt(page_addr);
                        try posix.mprotect(ptr[0..page_addr], protection);
                    } else {
                        const addr = posix.mmap(
                            @ptrFromInt(page_addr),
                            page_size,
                            protection,
                            .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .FIXED_NOREPLACE = true },
                            -1,
                            0,
                        ) catch |err| switch (err) {
                            error.MappingAlreadyExists => {
                                // If the mapping exists this means that the someone else
                                // (executable, OS, dynamic loader,...) allocated something there.
                                // We block this so we don't try this page again in the future,
                                // saving a bunch of syscalls.
                                try patcher.address_allocator.block(
                                    patcher.gpa,
                                    .{ .start = @intCast(page_addr), .end = @intCast(page_addr + page_size) },
                                    page_size,
                                );
                                // PERF: In theory we could set a flag and do the continue outside
                                // of this inner loop. This would make this a bit faster, since
                                // notice a bunch of pages being allocated, instead of just one by
                                // one. But in practice the Flicken only rarely cross page
                                // bounderies.
                                continue :pii;
                            },
                            else => {
                                log.err("{}", .{err});
                                @panic("TODO: error handling for mmap.");
                            },
                        };
                        assert(@as(u64, @intFromPtr(addr.ptr)) == page_addr);
                        // `gop.value_ptr.* = {};` not needed because it's void.
                    }
                    try pages_made_writable.put(arena, page_addr, {});
                }

                // Now the patching for the patch request can't fail anymore.
                const flicken_addr: [*]u8 = @ptrFromInt(allocated_range.getStart(u64));
                const flicken_slice = flicken_addr[0..flicken.size()];

                const jump_to_offset: i32 = blk: {
                    const from: i64 = @intCast(@intFromPtr(&request.bytes[
                        pii.num_prefixes + jump_rel32_size
                    ]));
                    const to = allocated_range.start;
                    break :blk @intCast(to - from);
                };
                const jump_back_offset: i32 = blk: {
                    const from = allocated_range.end;
                    const to: i64 = @intCast(@intFromPtr(&request.bytes[request.size]));
                    break :blk @intCast(to - from);
                };
                // The jumps have to be in the opposite direction.
                assert(math.sign(jump_to_offset) * math.sign(jump_back_offset) < 0);

                // Write to the trampoline first, because for the `nop` flicken `flicken.bytes`
                // points to `request.bytes` which we overwrite in the next step.
                @memcpy(flicken_addr, flicken.bytes);
                flicken_slice[flicken.bytes.len] = jump_rel32;
                const jump_back_location = flicken_slice[flicken.bytes.len + 1 ..][0..4];
                mem.writeInt(i32, jump_back_location, jump_back_offset, .little);

                @memcpy(request.bytes[0..pii.num_prefixes], prefixes[0..pii.num_prefixes]);
                request.bytes[pii.num_prefixes] = jump_rel32;
                mem.writeInt(
                    i32,
                    request.bytes[pii.num_prefixes + 1 ..][0..4],
                    jump_to_offset,
                    .little,
                );
                // Pad remaining with int3.
                const patch_end_index = pii.num_prefixes + jump_rel32_size;
                if (patch_end_index < request.size) {
                    @memset(request.bytes[patch_end_index..request.size], int3);
                }

                break;
            }
        }
        // Change pages back to R|X.
        var iter = pages_made_writable.keyIterator();
        const protection = posix.PROT.READ | posix.PROT.EXEC;
        while (iter.next()) |page_addr| {
            const ptr: [*]align(page_size) u8 = @ptrFromInt(page_addr.*);
            try posix.mprotect(ptr[0..page_size], protection);
        }

        log.info("patchRegion: Finished applying patches", .{});
    }

    // TODO: statistics
}

/// Only used for debugging.
fn printMaps() !void {
    const path = "/proc/self/maps";
    var reader = try std.fs.cwd().openFile(path, .{});
    var buffer: [1024 * 1024]u8 = undefined;
    const size = try reader.readAll(&buffer);
    std.debug.print("\n{s}\n", .{buffer[0..size]});
}

/// Returns a tuple of the aligned addresses of the start and end pages the given range touches.
fn pageRange(range: Range) struct { u64, u64 } {
    const start_page = mem.alignBackward(u64, range.getStart(u64), page_size);
    const end_page = mem.alignForward(u64, range.getEnd(u64), page_size);
    assert(end_page != start_page);
    assert(end_page > start_page);
    return .{ start_page, end_page };
}

const PatchInstructionIterator = struct {
    bytes: []const u8, // first byte is first byte of instruction to patch.
    instruction_size: u8,
    flicken_size: u64,

    // Internal state
    num_prefixes: u8,
    pli: PatchLocationIterator,
    valid_range: Range,

    fn init(
        bytes: []const u8,
        instruction_size: u8,
        flicken_size: u64,
    ) PatchInstructionIterator {
        const patch_bytes = getPatchBytes(bytes, instruction_size, 0);
        var pli = PatchLocationIterator.init(patch_bytes, @intFromPtr(&bytes[5]));
        const valid_range = pli.next() orelse Range{ .start = 0, .end = 0 };
        return .{
            .bytes = bytes,
            .instruction_size = instruction_size,
            .flicken_size = flicken_size,
            .num_prefixes = 0,
            .pli = pli,
            .valid_range = valid_range,
        };
    }

    fn next(
        pii: *PatchInstructionIterator,
        gpa: mem.Allocator,
        address_allocator: *AddressAllocator,
    ) !?Range {
        // TODO: This is basically a state machine here, so maybe use labeled switch instead for
        // clarity.
        while (true) {
            if (try address_allocator.allocate(
                gpa,
                pii.flicken_size,
                pii.valid_range,
            )) |allocated_range| {
                assert(allocated_range.size() == pii.flicken_size);
                return allocated_range;
            }

            // Valid range is used up, so get a new one from the pli.
            if (pii.pli.next()) |valid_range| {
                pii.valid_range = valid_range;
                continue;
            }

            // PLI is used up, so increase the number of prefixes.
            if (pii.num_prefixes < @min(pii.instruction_size, prefixes.len)) {
                pii.num_prefixes += 1;
                const patch_bytes = getPatchBytes(pii.bytes, pii.instruction_size, pii.num_prefixes);
                pii.pli = PatchLocationIterator.init(
                    patch_bytes,
                    @intFromPtr(&pii.bytes[pii.num_prefixes + 5]),
                );
                if (pii.pli.next()) |valid_range| {
                    pii.valid_range = valid_range;
                    continue;
                }
                // If the new pli is empty immediately, we loop again to try the next prefix count.
                continue;
            }

            // We've used up the iterator at this point.
            return null;
        }
        comptime unreachable;
    }

    fn getPatchBytes(instruction_bytes: []const u8, instruction_size: u8, num_prefixes: u8) [4]PatchByte {
        const offset_location = instruction_bytes[num_prefixes + 1 ..][0..4]; // +1 for e9
        var patch_bytes: [4]PatchByte = undefined;
        for (&patch_bytes, offset_location, num_prefixes + 1..) |*patch_byte, offset_byte, i| {
            if (i < instruction_size) {
                patch_byte.* = .free;
            } else {
                patch_byte.* = .{ .used = offset_byte };
            }
        }
        return patch_bytes;
    }
};
