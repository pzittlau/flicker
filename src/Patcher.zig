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
            .{ @intFromPtr(self.bytes.ptr), self.bytes[0..self.size], @intFromEnum(self.flicken) },
        );
    }
};

pub const Statistics = struct {
    /// Direct jumps
    jump: u64,
    /// Punning - index represents number of prefixes used
    punning: [4]u64,
    /// Successor Eviction
    successor_eviction: u64,
    /// Neighbor Eviction
    neighbor_eviction: u64,
    /// Failed to patch
    failed: u64,

    pub const empty = mem.zeroes(Statistics);

    pub fn punningSum(statistics: *const Statistics) u64 {
        return statistics.punning[0] + statistics.punning[1] +
            statistics.punning[2] + statistics.punning[3];
    }

    pub fn successful(statistics: *const Statistics) u64 {
        return statistics.jump + statistics.punningSum() +
            statistics.successor_eviction + statistics.neighbor_eviction;
    }

    pub fn total(statistics: *const Statistics) u64 {
        return statistics.successful() + statistics.failed;
    }

    pub fn add(self: *Statistics, other: *const Statistics) void {
        self.jump += other.jump;
        for (0..self.punning.len) |i| {
            self.punning[i] += other.punning[i];
        }
        self.successor_eviction += other.successor_eviction;
        self.neighbor_eviction += other.neighbor_eviction;
        self.failed += other.failed;
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
            const should_patch = instruction.instruction.attributes & zydis.ZYDIS_ATTRIB_HAS_LOCK > 0 or
                instruction.instruction.mnemonic == zydis.ZYDIS_MNEMONIC_SYSCALL;
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
                const fmt = disassembler.formatBytes(request.bytes);
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
                const fmt = disassembler.formatBytes(request.bytes[0..request.size]);
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

        var stats = Statistics.empty;
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
            // TODO: There is a "Ghost Page" edge case here. If `pii.next()` returns a range that
            // spans multiple pages (Pages A and B), we might successfully mmap Page A but fail to
            // mmap Page B. The loop will `continue` to the next candidate range, leaving Page A
            // mapped. While harmless (it becomes an unused executable page), it is technically a
            // memory leak. A future fix should track "current attempt" pages separately and unmap
            // them on failure.
            while (try pii.next(patcher.gpa, &patcher.address_allocator)) |allocated_range| {
                try pages_made_writable.ensureUnusedCapacity(arena, touchedPageCount(allocated_range));
                patcher.ensureRangeWritable(allocated_range, &pages_made_writable) catch |err| switch (err) {
                    error.MappingAlreadyExists => continue,
                    else => {
                        log.err("{}", .{err});
                        @panic("Unexpected Error");
                    },
                };

                applyPatch(request, flicken, allocated_range, pii.num_prefixes);

                );

                if (request.size >= 5) {
                    assert(pii.num_prefixes == 0);
                    stats.jump += 1;
                } else {
                    stats.punning[pii.num_prefixes] += 1;
                }
                break;
            } else {
                stats.failed += 1;
            }
        }
        // Change pages back to R|X.
        var iter = pages_made_writable.keyIterator();
        const protection = posix.PROT.READ | posix.PROT.EXEC;
        while (iter.next()) |page_addr| {
            const ptr: [*]align(page_size) u8 = @ptrFromInt(page_addr.*);
            try posix.mprotect(ptr[0..page_size], protection);
        }

        log.info("{}", .{stats});
        log.info("{}", .{stats.successful()});
        log.info("{}", .{stats.total()});
        log.info("patchRegion: Finished applying patches", .{});
    }
}

fn applyPatch(
    request: PatchRequest,
    flicken: Flicken,
    allocated_range: Range,
    num_prefixes: u8,
) void {
    const flicken_addr: [*]u8 = @ptrFromInt(allocated_range.getStart(u64));
    const flicken_slice = flicken_addr[0..flicken.size()];

    const jump_to_offset: i32 = blk: {
        const from: i64 = @intCast(@intFromPtr(&request.bytes[
            num_prefixes + jump_rel32_size
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

    // Write to the trampoline first, because for the `nop` flicken `flicken.bytes` points to
    // `request.bytes` which we overwrite in the next step.
    @memcpy(flicken_addr, flicken.bytes);
    if (request.flicken == .nop) {
        const instr_bytes = request.bytes[0..request.size];
        const instr = disassembler.disassembleInstruction(instr_bytes);
        relocateInstruction(
            instr.?,
            @intCast(allocated_range.start),
            flicken_slice[0..request.size],
        );
    }
    flicken_slice[flicken.bytes.len] = jump_rel32;
    const jump_back_location = flicken_slice[flicken.bytes.len + 1 ..][0..4];
    mem.writeInt(i32, jump_back_location, jump_back_offset, .little);

    @memcpy(request.bytes[0..num_prefixes], prefixes[0..num_prefixes]);
    request.bytes[num_prefixes] = jump_rel32;
    mem.writeInt(
        i32,
        request.bytes[num_prefixes + 1 ..][0..4],
        jump_to_offset,
        .little,
    );
    // Pad remaining with int3.
    const patch_end_index = num_prefixes + jump_rel32_size;
    if (patch_end_index < request.size) {
        @memset(request.bytes[patch_end_index..request.size], int3);
    }
}

/// Only used for debugging.
fn printMaps() !void {
    const path = "/proc/self/maps";
    var reader = try std.fs.cwd().openFile(path, .{});
    var buffer: [1024 * 1024]u8 = undefined;
    const size = try reader.readAll(&buffer);
    std.debug.print("\n{s}\n", .{buffer[0..size]});
}

/// Returns the number of pages that the given range touches.
fn touchedPageCount(range: Range) u32 {
    const start_page = mem.alignBackward(u64, range.getStart(u64), page_size);
    // alignBackward on (end - 1) handles the exclusive upper bound correctly
    const end_page = mem.alignBackward(u64, range.getEnd(u64) - 1, page_size);
    return @intCast((end_page - start_page) / page_size + 1);
}

/// Ensure `range` is mapped R|W. Assumes `pages_made_writable` has enough free capacity.
fn ensureRangeWritable(
    patcher: *Patcher,
    range: Range,
    pages_made_writable: *std.AutoHashMapUnmanaged(u64, void),
) !void {
    const start_page = mem.alignBackward(u64, range.getStart(u64), page_size);
    const end_page = mem.alignBackward(u64, range.getEnd(u64) - 1, page_size);
    const protection = posix.PROT.READ | posix.PROT.WRITE;
    var page_addr = start_page;
    while (page_addr <= end_page) : (page_addr += page_size) {
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
                    return err;
                },
                else => return err,
            };
            assert(@as(u64, @intFromPtr(addr.ptr)) == page_addr);
            // `gop.value_ptr.* = {};` not needed because it's void.
        }
        pages_made_writable.putAssumeCapacityNoClobber(page_addr, {});
    }
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
        const State = enum {
            allocation,
            range,
            prefix,
        };
        blk: switch (State.allocation) {
            .allocation => {
                if (try address_allocator.allocate(
                    gpa,
                    pii.flicken_size,
                    pii.valid_range,
                )) |allocated_range| {
                    assert(allocated_range.size() == pii.flicken_size);
                    return allocated_range;
                } else {
                    continue :blk .range;
                }
            },
            .range => {
                // Valid range is used up, so get a new one from the pli.
                if (pii.pli.next()) |valid_range| {
                    pii.valid_range = valid_range;
                    continue :blk .allocation;
                } else {
                    continue :blk .prefix;
                }
            },
            .prefix => {
                if (pii.num_prefixes < @min(pii.instruction_size, prefixes.len)) {
                    pii.num_prefixes += 1;
                    const patch_bytes = getPatchBytes(pii.bytes, pii.instruction_size, pii.num_prefixes);
                    pii.pli = PatchLocationIterator.init(
                        patch_bytes,
                        @intFromPtr(&pii.bytes[pii.num_prefixes + 5]),
                    );
                    continue :blk .range;
                } else {
                    return null;
                }
            },
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

/// Fixes RIP-relative operands in an instruction that has been moved to a new address.
fn relocateInstruction(
    instruction: disassembler.BundledInstruction,
    address: u64,
    buffer: []u8,
) void {
    const instr = instruction.instruction;
    // Iterate all operands
    var i: u8 = 0;
    while (i < instr.operand_count) : (i += 1) {
        const operand = &instruction.operands[i];
        var result_address: u64 = 0;

        // Check for RIP-relative memory operand
        const is_rip_rel = operand.type == zydis.ZYDIS_OPERAND_TYPE_MEMORY and
            operand.unnamed_0.mem.base == zydis.ZYDIS_REGISTER_RIP;
        // Check for relative immediate (e.g. JMP rel32)
        const is_rel_imm = operand.type == zydis.ZYDIS_OPERAND_TYPE_IMMEDIATE and
            operand.unnamed_0.imm.is_relative == zydis.ZYAN_TRUE;
        if (!is_rip_rel and !is_rel_imm) return;

        // We have to apply a relocation
        const status = zydis.ZydisCalcAbsoluteAddress(
            instr,
            operand,
            instruction.address,
            &result_address,
        );
        assert(zydis.ZYAN_SUCCESS(status));

        const new_disp: i32 = blk: {
            const next_rip: i64 = @intCast(address + instr.length);
            const new_disp = @as(i64, @intCast(result_address)) - next_rip;
            if (new_disp > math.maxInt(i32) or new_disp < math.minInt(i32)) {
                // TODO: Handle relocation overflow (e.g. by expanding instruction or failing gracefully)
                @panic("RelocationOverflow while relocating instruction");
            }
            break :blk @intCast(new_disp);
        };

        var offset: u16 = 0;
        if (is_rip_rel) {
            offset = instr.raw.disp.offset;
        } else {
            assert(is_rel_imm);
            // For relative immediate, find the matching raw immediate. This loop works because
            // x86-64 instructions can have at most one *relative* immediate (branch target).
            var found = false;
            for (&instr.raw.imm) |*imm| {
                if (imm.is_relative == zydis.ZYAN_TRUE) {
                    offset = imm.offset;
                    found = true;
                    break;
                }
            }
            assert(found);
        }

        assert(offset != 0);
        assert(offset + 4 <= buffer.len);
        mem.writeInt(i32, buffer[offset..][0..4], new_disp, .little);
    }
}
