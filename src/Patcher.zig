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

pub const FlickenId = enum(u64) { nop = 0, _ };

pub const PatchRequest = struct {
    /// Must point to first byte of an instruction.
    flicken: FlickenId,
    /// Bytes of the instruction. Can be used to get the address of the instruction.
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
            const should_patch: bool = instruction.instruction.attributes & zydis.ZYDIS_ATTRIB_HAS_LOCK > 0;
            if (should_patch) {
                const start = instruction.address - @intFromPtr(region.ptr);
                const request: PatchRequest = .{
                    .bytes = region[start..][0..instruction.instruction.length],
                    .flicken = .nop,
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
        var last_address: ?[*]u8 = null;
        for (patch_requests.items, 0..) |request, i| {
            if (last_address) |last| {
                if (last == request.bytes.ptr) {
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
            }
            last_address = request.bytes.ptr;

            if (@as(u64, @intFromEnum(request.flicken)) >= patcher.flicken.count()) {
                var buffer: [256]u8 = undefined;
                const fmt = disassembler.formatBytes(request.bytes, &buffer);
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
            const flicken = patcher.flicken.entries.get(@intFromEnum(request.flicken)).value;
            if (request.bytes.len < 5) continue; // TODO:

            var iter = PatchLocationIterator.init(
                .{ .free, .free, .free, .free },
                @intFromPtr(request.bytes.ptr),
            );
            while (iter.next()) |valid_range| {
                const patch_range = try patcher.address_allocator.allocate(
                    patcher.gpa,
                    flicken.size(),
                    valid_range,
                ) orelse continue;
                assert(patch_range.size() == flicken.size());

                {
                    // Map patch_range as R|W.
                    const start_page = mem.alignBackward(u64, patch_range.getStart(u64), page_size);
                    const end_page = mem.alignBackward(u64, patch_range.getEnd(u64), page_size);
                    const protection = posix.PROT.READ | posix.PROT.WRITE;
                    var page_addr = start_page;
                    while (page_addr <= end_page) : (page_addr += page_size) {
                        // If the page is already writable we don't need to do anything;
                        if (pages_made_writable.get(page_addr)) |_| continue;

                        const gop = try patcher.allocated_pages.getOrPut(patcher.gpa, page_addr);
                        if (gop.found_existing) {
                            const ptr: [*]align(page_size) u8 = @ptrFromInt(page_addr);
                            try posix.mprotect(ptr[0..page_size], protection);
                        } else {
                            const addr = try posix.mmap(
                                @ptrFromInt(page_addr),
                                page_size,
                                protection,
                                .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .FIXED_NOREPLACE = true },
                                -1,
                                0,
                            );
                            assert(@as(u64, @intFromPtr(addr.ptr)) == page_addr);
                            // `gop.value_ptr.* = {};` is not needed because it's void.
                        }
                        try pages_made_writable.put(patcher.gpa, page_addr, {});
                    }
                }

                const flicken_addr: [*]u8 = @ptrFromInt(patch_range.getStart(u64));
                const flicken_slice = flicken_addr[0 .. flicken.bytes.len + 5];

                const jump_to_offset: i32 = blk: {
                    const from: i64 = @intCast(@intFromPtr(request.bytes.ptr) + jump_rel32_size);
                    const to = patch_range.start;
                    break :blk @intCast(to - from);
                };
                request.bytes[0] = jump_rel32;
                mem.writeInt(i32, request.bytes[1..5], jump_to_offset, .little);
                for (request.bytes[5..]) |*b| {
                    b.* = int3;
                }

                const jump_back_offset: i32 = blk: {
                    const from = patch_range.end;
                    const to: i64 = @intCast(@intFromPtr(request.bytes.ptr) + request.bytes.len);
                    break :blk @intCast(to - from);
                };
                @memcpy(flicken_addr, flicken.bytes);
                flicken_slice[flicken.bytes.len] = jump_rel32;
                mem.writeInt(i32, flicken_slice[flicken.bytes.len + 1 ..][0..4], jump_back_offset, .little);

                // The jumps have to be in the opposite direction.
                assert(math.sign(jump_to_offset) * math.sign(jump_back_offset) < 0);
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
