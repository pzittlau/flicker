const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const math = std.math;
const mem = std.mem;
const posix = std.posix;
const zydis = @import("zydis").zydis;
const dis = @import("disassembler.zig");

const log = std.log.scoped(.patcher);
const AddressAllocator = @import("AddressAllocator.zig");
const InstructionFormatter = dis.InstructionFormatter;
const InstructionIterator = dis.InstructionIterator;
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
    /// have but makes things more accessible.
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

    pub fn punningSum(stats: *const Statistics) u64 {
        return stats.punning[0] + stats.punning[1] +
            stats.punning[2] + stats.punning[3];
    }

    pub fn successful(stats: *const Statistics) u64 {
        return stats.jump + stats.punningSum() +
            stats.successor_eviction + stats.neighbor_eviction;
    }

    pub fn total(stats: *const Statistics) u64 {
        return stats.successful() + stats.failed;
    }

    pub fn percentage(stats: *const Statistics) f64 {
        if (stats.total() == 0) return 1;
        const s: f64 = @floatFromInt(stats.successful());
        const t: f64 = @floatFromInt(stats.total());
        return s / t;
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

/// Scans a memory region for instructions that require patching and applies the patches
/// using a hierarchy of tactics (Direct/Punning -> Successor Eviction -> Neighbor Eviction).
///
/// The region is processed Back-to-Front to ensure that modifications (punning) only
/// constrain instructions that have already been processed or are locked.
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
    // We save the bytes where instructions start to be able to disassemble them on the fly. This is
    // necessary for the neighbor eviction, since we can't just iterate forwards from a target
    // instruction and disassemble happily. This is because some bytes may already be the patched
    // ones which means that we might disassemble garbage or something different that wasn't there
    // before. This means that we would need to stop disassembling on the first byte that is locked,
    // which kind of defeats the purpose of neighbor eviction.
    var instruction_starts = try std.DynamicBitSetUnmanaged.initEmpty(arena, region.len);

    {
        // Get where to patch.
        var instruction_iterator = InstructionIterator.init(region);
        while (instruction_iterator.next()) |instruction| {
            const offset = instruction.address - @intFromPtr(region.ptr);
            instruction_starts.set(offset);

            const should_patch = instruction.instruction.mnemonic == zydis.ZYDIS_MNEMONIC_SYSCALL or
                instruction.instruction.attributes & zydis.ZYDIS_ATTRIB_HAS_LOCK > 0;
            if (should_patch) {
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
                const fmt = dis.formatBytes(request.bytes);
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
                const fmt = dis.formatBytes(request.bytes[0..request.size]);
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
        // Used to track which bytes have been modified or used for constraints (punning),
        // to prevent future patches (from neighbor/successor eviction) from corrupting them.
        var locked_bytes = try std.DynamicBitSetUnmanaged.initEmpty(arena, region.len);
        // PERF: A set of the pages for the patches/flicken we made writable. This way we don't
        // repeatedly change call `mprotect` on the same page to switch it from R|W to R|X and back.
        // At the end we `mprotect` all pages in this set back to being R|X.
        var pages_made_writable: std.AutoHashMapUnmanaged(u64, void) = .empty;

        requests: for (patch_requests.items) |request| {
            for (0..request.size) |i| {
                if (locked_bytes.isSet(request.offset + i)) {
                    log.warn("patchRegion: Skipping request at offset 0x{x} because it is locked", .{request.offset});
                    stats.failed += 1;
                    continue :requests;
                }
            }

            if (try patcher.attemptDirectOrPunning(
                request,
                arena,
                &locked_bytes,
                &pages_made_writable,
                &stats,
            )) {
                continue :requests;
            }

            if (try patcher.attemptSuccessorEviction(
                request,
                arena,
                &locked_bytes,
                &pages_made_writable,
                &stats,
            )) {
                continue :requests;
            }

            if (try patcher.attemptNeighborEviction(
                request,
                arena,
                &locked_bytes,
                &pages_made_writable,
                &instruction_starts,
                &stats,
            )) {
                continue :requests;
            }

            stats.failed += 1;
        }

        // Change pages back to R|X.
        var iter = pages_made_writable.keyIterator();
        const protection = posix.PROT.READ | posix.PROT.EXEC;
        while (iter.next()) |page_addr| {
            const ptr: [*]align(page_size) u8 = @ptrFromInt(page_addr.*);
            try posix.mprotect(ptr[0..page_size], protection);
        }

        assert(stats.total() == patch_requests.items.len);
        log.info("{}", .{stats});
        log.info("patched: {}/{}: {:2.2}%", .{
            stats.successful(),
            stats.total(),
            stats.percentage() * 100,
        });
        log.info("patchRegion: Finished applying patches", .{});
    }
}

fn attemptDirectOrPunning(
    patcher: *Patcher,
    request: PatchRequest,
    arena: mem.Allocator,
    locked_bytes: *std.DynamicBitSetUnmanaged,
    pages_made_writable: *std.AutoHashMapUnmanaged(u64, void),
    stats: *Statistics,
) !bool {
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
    while (pii.next(&patcher.address_allocator, .exhaustive)) |allocated_range| {
        try pages_made_writable.ensureUnusedCapacity(arena, touchedPageCount(allocated_range));
        patcher.ensureRangeWritable(
            allocated_range,
            pages_made_writable,
        ) catch |err| switch (err) {
            error.MappingAlreadyExists => continue,
            else => return err,
        };

        applyPatch(
            request,
            flicken,
            allocated_range,
            pii.num_prefixes,
        ) catch |err| switch (err) {
            error.RelocationOverflow => continue,
            else => return err,
        };

        try patcher.address_allocator.block(patcher.gpa, allocated_range, 0);
        const lock_size = jump_rel32_size + pii.num_prefixes;
        locked_bytes.setRangeValue(
            .{ .start = request.offset, .end = request.offset + lock_size },
            true,
        );

        if (request.size >= 5) {
            assert(pii.num_prefixes == 0);
            stats.jump += 1;
        } else {
            stats.punning[pii.num_prefixes] += 1;
        }
        return true;
    }
    return false;
}

fn attemptSuccessorEviction(
    patcher: *Patcher,
    request: PatchRequest,
    arena: mem.Allocator,
    locked_bytes: *std.DynamicBitSetUnmanaged,
    pages_made_writable: *std.AutoHashMapUnmanaged(u64, void),
    stats: *Statistics,
) !bool {
    // Disassemble Successor and create request and flicken for it.
    const succ_instr = dis.disassembleInstruction(request.bytes[request.size..]) orelse return false;
    const succ_request = PatchRequest{
        .flicken = .nop,
        .size = succ_instr.instruction.length,
        .bytes = request.bytes[request.size..],
        .offset = request.offset + request.size,
    };
    const succ_flicken = Flicken{
        .name = "nop",
        .bytes = succ_request.bytes[0..succ_request.size],
    };

    for (0..succ_request.size) |i| {
        if (locked_bytes.isSet(succ_request.offset + i)) return false;
    }

    // Save original bytes for reverting the change.
    var succ_orig_bytes: [15]u8 = undefined;
    @memcpy(
        succ_orig_bytes[0..succ_request.size],
        succ_request.bytes[0..succ_request.size],
    );

    var succ_pii = PatchInstructionIterator.init(
        succ_request.bytes,
        succ_request.size,
        succ_flicken.size(),
    );
    while (succ_pii.next(&patcher.address_allocator, .greedy)) |succ_range| {
        // Ensure bytes match original before retry.
        assert(mem.eql(
            u8,
            succ_request.bytes[0..succ_request.size],
            succ_orig_bytes[0..succ_request.size],
        ));

        try pages_made_writable.ensureUnusedCapacity(arena, touchedPageCount(succ_range));
        patcher.ensureRangeWritable(
            succ_range,
            pages_made_writable,
        ) catch |err| switch (err) {
            error.MappingAlreadyExists => continue,
            else => return err,
        };

        applyPatch(
            succ_request,
            succ_flicken,
            succ_range,
            succ_pii.num_prefixes,
        ) catch |err| switch (err) {
            error.RelocationOverflow => continue,
            else => return err,
        };

        // Now that the successor is patched, we can patch the original request.
        const flicken: Flicken = if (request.flicken == .nop)
            .{ .name = "nop", .bytes = request.bytes[0..request.size] }
        else
            patcher.flicken.entries.get(@intFromEnum(request.flicken)).value;

        var orig_pii = PatchInstructionIterator.init(
            request.bytes,
            request.size,
            flicken.size(),
        );
        while (orig_pii.next(&patcher.address_allocator, .greedy)) |orig_range| {
            if (succ_range.touches(orig_range)) continue;
            try pages_made_writable.ensureUnusedCapacity(arena, touchedPageCount(orig_range));
            patcher.ensureRangeWritable(
                orig_range,
                pages_made_writable,
            ) catch |err| switch (err) {
                error.MappingAlreadyExists => continue,
                else => return err,
            };

            applyPatch(
                request,
                flicken,
                orig_range,
                orig_pii.num_prefixes,
            ) catch |err| switch (err) {
                error.RelocationOverflow => continue,
                else => return err,
            };

            try patcher.address_allocator.block(patcher.gpa, succ_range, 0);
            try patcher.address_allocator.block(patcher.gpa, orig_range, 0);
            const lock_size = request.size + jump_rel32_size + succ_pii.num_prefixes;
            locked_bytes.setRangeValue(
                .{ .start = request.offset, .end = request.offset + lock_size },
                true,
            );
            stats.successor_eviction += 1;
            return true;
        }

        // We couldn't patch with the bytes. So revert to original ones.
        @memcpy(
            succ_request.bytes[0..succ_request.size],
            succ_orig_bytes[0..succ_request.size],
        );
    }
    return false;
}

fn attemptNeighborEviction(
    patcher: *Patcher,
    request: PatchRequest,
    arena: mem.Allocator,
    locked_bytes: *std.DynamicBitSetUnmanaged,
    pages_made_writable: *std.AutoHashMapUnmanaged(u64, void),
    instruction_starts: *const std.DynamicBitSetUnmanaged,
    stats: *Statistics,
) !bool {
    // Valid neighbors must be within [-128, 127] range for a short jump.
    // Since we patch back-to-front, we only look at neighbors *after* the current instruction
    // (higher address) to avoid evicting an instruction we haven't processed/patched yet.
    const start_offset = request.offset + 2;
    const end_offset = @min(
        start_offset + 128,
        request.bytes.len + request.offset,
    );

    neighbor: for (start_offset..end_offset) |neighbor_offset| {
        if (!instruction_starts.isSet(neighbor_offset)) continue;

        const victim_bytes_all = request.bytes[neighbor_offset - request.offset ..];

        // PERF: We could also search for the next set bit in instruction_starts
        const victim_instr = dis.disassembleInstruction(victim_bytes_all) orelse continue;
        const victim_size = victim_instr.instruction.length;
        const victim_bytes = victim_bytes_all[0..victim_size];

        for (0..victim_size) |i| {
            if (locked_bytes.isSet(neighbor_offset + i)) {
                continue :neighbor;
            }
        }

        // Save original bytes to revert if constraints cannot be solved.
        var victim_orig_bytes: [15]u8 = undefined;
        @memcpy(victim_orig_bytes[0..victim_size], victim_bytes);

        // OUTER LOOP: J_Patch
        // Iterate possible offsets 'k' inside the victim for the patch jump.
        var k: u8 = 1;
        while (k < victim_size) : (k += 1) {
            const target: i64 = @intCast(neighbor_offset + k);
            const source: i64 = @intCast(request.offset + 2);
            const disp = target - source;
            if (disp > 127 or disp < -128) continue;

            const patch_flicken: Flicken = if (request.flicken == .nop)
                .{ .name = "nop", .bytes = request.bytes[0..request.size] }
            else
                patcher.flicken.entries.get(@intFromEnum(request.flicken)).value;

            // Constraints for J_Patch:
            // Bytes [0 .. victim_size - k] are free (inside victim).
            // Bytes [victim_size - k .. ] are used (outside victim, immutable).
            var patch_pii = PatchInstructionIterator.init(
                victim_bytes_all[k..],
                @intCast(victim_size - k),
                patch_flicken.size(),
            );

            while (patch_pii.next(&patcher.address_allocator, .greedy)) |patch_range| {
                // J_Patch MUST NOT use prefixes, because it's punned inside J_Victim.
                // Adding prefixes would shift J_Patch relative to J_Victim, making constraints harder.
                if (patch_pii.num_prefixes > 0) break;

                try pages_made_writable.ensureUnusedCapacity(arena, touchedPageCount(patch_range));
                patcher.ensureRangeWritable(patch_range, pages_made_writable) catch |err| switch (err) {
                    error.MappingAlreadyExists => continue,
                    else => return err,
                };

                // Tentatively write J_Patch to memory to set constraints for J_Victim.
                // We only need to write the bytes of J_Patch that land inside the victim.
                {
                    const jmp_target = patch_range.start;
                    const jmp_source: i64 = @intCast(@intFromPtr(&victim_bytes_all[k]) + 5);
                    const rel32: i32 = @intCast(jmp_target - jmp_source);
                    victim_bytes_all[k] = jump_rel32;
                    mem.writeInt(i32, victim_bytes_all[k + 1 ..][0..4], rel32, .little);
                }

                // INNER LOOP: J_Victim
                // Constraints:
                // Bytes [0 .. k] are free (before J_Patch).
                // Bytes [k .. ] are used (overlap J_Patch).
                const victim_flicken = Flicken{
                    .name = "nop",
                    .bytes = victim_orig_bytes[0..victim_size],
                };

                var victim_pii = PatchInstructionIterator.init(
                    victim_bytes_all,
                    k,
                    victim_flicken.size(),
                );

                while (victim_pii.next(&patcher.address_allocator, .greedy)) |victim_range| {
                    if (patch_range.touches(victim_range)) continue;

                    try pages_made_writable.ensureUnusedCapacity(arena, touchedPageCount(victim_range));
                    patcher.ensureRangeWritable(victim_range, pages_made_writable) catch |err| switch (err) {
                        error.MappingAlreadyExists => continue,
                        else => return err,
                    };

                    // SUCCESS! Commit everything.

                    // 1. Write Patch Trampoline (J_Patch target)
                    {
                        const trampoline: [*]u8 = @ptrFromInt(patch_range.getStart(u64));
                        var reloc_info: ?RelocInfo = null;
                        if (request.flicken == .nop) {
                            reloc_info = .{
                                .instr = dis.disassembleInstruction(patch_flicken.bytes).?,
                                .old_addr = @intFromPtr(request.bytes.ptr),
                            };
                        }
                        commitTrampoline(
                            trampoline,
                            patch_flicken.bytes,
                            reloc_info,
                            @intFromPtr(request.bytes.ptr) + request.size,
                        ) catch |err| switch (err) {
                            error.RelocationOverflow => continue,
                            else => return err,
                        };
                    }

                    // 2. Write Victim Trampoline (J_Victim target)
                    {
                        const trampoline: [*]u8 = @ptrFromInt(victim_range.getStart(u64));
                        commitTrampoline(
                            trampoline,
                            victim_orig_bytes[0..victim_size],
                            .{
                                .instr = dis.disassembleInstruction(victim_orig_bytes[0..victim_size]).?,
                                .old_addr = @intFromPtr(victim_bytes_all.ptr),
                            },
                            @intFromPtr(victim_bytes_all.ptr) + victim_size,
                        ) catch |err| switch (err) {
                            error.RelocationOverflow => continue,
                            else => return err,
                        };
                    }

                    // 3. Write J_Victim (overwrites head of J_Patch which is fine)
                    commitJump(
                        victim_bytes_all.ptr,
                        @intCast(victim_range.start),
                        victim_pii.num_prefixes,
                        k, // Total size for padding is limited to k to preserve J_Patch tail
                    );

                    // 4. Write J_Short at request
                    request.bytes[0] = jump_rel8;
                    request.bytes[1] = @intCast(disp);
                    if (request.size > 2) {
                        @memset(request.bytes[2..request.size], int3);
                    }

                    // 5. Locking
                    try patcher.address_allocator.block(patcher.gpa, patch_range, 0);
                    try patcher.address_allocator.block(patcher.gpa, victim_range, 0);

                    locked_bytes.setRangeValue(
                        .{ .start = request.offset, .end = request.offset + request.size },
                        true,
                    );
                    // Lock victim range + any extension of J_Patch
                    const j_patch_end = neighbor_offset + k + 5;
                    const lock_end = @max(neighbor_offset + victim_size, j_patch_end);
                    locked_bytes.setRangeValue(
                        .{ .start = neighbor_offset, .end = lock_end },
                        true,
                    );

                    stats.neighbor_eviction += 1;
                    return true;
                }

                // Revert J_Patch write for next iteration
                @memcpy(victim_bytes, victim_orig_bytes[0..victim_size]);
            }
        }
    }

    return false;
}

/// Applies a standard patch (T1/B1/B2) where the instruction is replaced by a jump to a trampoline.
///
/// This handles the logic of writing the trampoline content (including relocation) and
/// overwriting the original instruction with a `JMP` (plus prefixes/padding).
fn applyPatch(
    request: PatchRequest,
    flicken: Flicken,
    allocated_range: Range,
    num_prefixes: u8,
) !void {
    const flicken_addr: [*]u8 = @ptrFromInt(allocated_range.getStart(u64));

    // Commit Trampoline
    var reloc_info: ?RelocInfo = null;
    if (request.flicken == .nop) {
        reloc_info = .{
            .instr = dis.disassembleInstruction(request.bytes[0..request.size]).?,
            .old_addr = @intFromPtr(request.bytes.ptr),
        };
    }

    const ret_addr = @intFromPtr(request.bytes.ptr) + request.size;
    try commitTrampoline(flicken_addr, flicken.bytes, reloc_info, ret_addr);

    // Commit Jump (Patch)
    commitJump(request.bytes.ptr, @intCast(allocated_range.start), num_prefixes, request.size);
}

const RelocInfo = struct {
    instr: dis.BundledInstruction,
    old_addr: u64,
};

/// Helper to write code into a trampoline.
///
/// It copies the original bytes (or flicken content), relocates any RIP-relative instructions
/// to be valid at the new address, and appends a jump back to the instruction stream.
fn commitTrampoline(
    trampoline_ptr: [*]u8,
    content: []const u8,
    reloc_info: ?RelocInfo,
    return_addr: u64,
) !void {
    @memcpy(trampoline_ptr[0..content.len], content);

    if (reloc_info) |info| {
        try relocateInstruction(
            info.instr,
            @intFromPtr(trampoline_ptr),
            trampoline_ptr[0..content.len],
        );
    }

    // Write jump back
    trampoline_ptr[content.len] = jump_rel32;
    const jump_src = @intFromPtr(trampoline_ptr) + content.len + jump_rel32_size;
    const jump_disp: i32 = @intCast(@as(i64, @intCast(return_addr)) - @as(i64, @intCast(jump_src)));
    mem.writeInt(i32, trampoline_ptr[content.len + 1 ..][0..4], jump_disp, .little);
}

/// Helper to overwrite an instruction with a jump to a trampoline.
///
/// It handles writing optional prefixes (padding), the `0xE9` opcode, the relative offset,
/// and fills any remaining bytes of the original instruction with `INT3` to prevent
/// execution of garbage bytes.
fn commitJump(
    from_ptr: [*]u8,
    to_addr: u64,
    num_prefixes: u8,
    total_size: usize,
) void {
    const prefixes_slice = from_ptr[0..num_prefixes];
    @memcpy(prefixes_slice, prefixes[0..num_prefixes]);

    from_ptr[num_prefixes] = jump_rel32;

    const jump_src = @intFromPtr(from_ptr) + num_prefixes + jump_rel32_size;
    const jump_disp: i32 = @intCast(@as(i64, @intCast(to_addr)) - @as(i64, @intCast(jump_src)));
    mem.writeInt(i32, from_ptr[num_prefixes + 1 ..][0..4], jump_disp, .little);

    const patch_end_index = num_prefixes + jump_rel32_size;
    if (patch_end_index < total_size) {
        @memset(from_ptr[patch_end_index..total_size], int3);
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

    pub const Strategy = enum {
        /// Iterates through all possible ranges.
        /// Useful for finding the optimal allocation (fewest prefixes).
        exhaustive,
        /// Try one allocation per found valid_range. Dramatically faster.
        greedy,
    };

    fn next(
        pii: *PatchInstructionIterator,
        address_allocator: *AddressAllocator,
        strategy: Strategy,
    ) ?Range {
        const State = enum {
            allocation,
            range,
            prefix,
        };
        blk: switch (State.allocation) {
            .allocation => {
                if (address_allocator.findAllocation(
                    pii.flicken_size,
                    pii.valid_range,
                )) |allocated_range| {
                    assert(allocated_range.size() == pii.flicken_size);
                    // Advancing the valid range, such that the next call to `findAllocation` won't
                    // find the same range again.
                    switch (strategy) {
                        .exhaustive => pii.valid_range.start = allocated_range.start + 1,
                        .greedy => pii.valid_range.start = pii.valid_range.end,
                    }
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
    instruction: dis.BundledInstruction,
    address: u64,
    buffer: []u8,
) !void {
    const instr = instruction.instruction;
    // Iterate all operands
    for (0..instr.operand_count) |i| {
        const operand = &instruction.operands[i];

        // Check for RIP-relative memory operand
        const is_rip_rel = operand.type == zydis.ZYDIS_OPERAND_TYPE_MEMORY and
            operand.unnamed_0.mem.base == zydis.ZYDIS_REGISTER_RIP;
        // Check for relative immediate (e.g. JMP rel32)
        const is_rel_imm = operand.type == zydis.ZYDIS_OPERAND_TYPE_IMMEDIATE and
            operand.unnamed_0.imm.is_relative == zydis.ZYAN_TRUE;
        if (!is_rip_rel and !is_rel_imm) continue;

        // We have to apply a relocation
        var result_address: u64 = 0;
        const status = zydis.ZydisCalcAbsoluteAddress(
            instr,
            operand,
            instruction.address,
            &result_address,
        );
        assert(zydis.ZYAN_SUCCESS(status)); // TODO: maybe return an error instead

        // Calculate new displacement relative to the new address
        // The instruction length remains the same.
        const next_rip: i64 = @intCast(address + instr.length);
        const new_disp = @as(i64, @intCast(result_address)) - next_rip;

        var offset: u16 = 0;
        var size_bits: u8 = 0;

        if (is_rip_rel) {
            offset = instr.raw.disp.offset;
            size_bits = instr.raw.disp.size;
        } else {
            assert(is_rel_imm);
            // For relative immediate, find the matching raw immediate.
            var found = false;
            for (&instr.raw.imm) |*imm| {
                if (imm.is_relative == zydis.ZYAN_TRUE) {
                    offset = imm.offset;
                    size_bits = imm.size;
                    found = true;
                    break;
                }
            }
            assert(found);
        }

        assert(offset != 0);
        assert(size_bits != 0);
        const size_bytes = size_bits / 8;

        if (offset + size_bytes > buffer.len) {
            return error.RelocationFail;
        }

        const fits = switch (size_bits) {
            8 => new_disp >= math.minInt(i8) and new_disp <= math.maxInt(i8),
            16 => new_disp >= math.minInt(i16) and new_disp <= math.maxInt(i16),
            32 => new_disp >= math.minInt(i32) and new_disp <= math.maxInt(i32),
            64 => true,
            else => unreachable,
        };

        if (!fits) {
            return error.RelocationOverflow;
        }

        const ptr = buffer[offset..];
        switch (size_bits) {
            8 => ptr[0] = @as(u8, @bitCast(@as(i8, @intCast(new_disp)))),
            16 => mem.writeInt(u16, ptr[0..2], @bitCast(@as(i16, @intCast(new_disp))), .little),
            32 => mem.writeInt(u32, ptr[0..4], @bitCast(@as(i32, @intCast(new_disp))), .little),
            64 => mem.writeInt(u64, ptr[0..8], @bitCast(@as(i64, @intCast(new_disp))), .little),
            else => unreachable,
        }
    }
}
