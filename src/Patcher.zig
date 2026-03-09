const std = @import("std");
const math = std.math;
const mem = std.mem;
const posix = std.posix;
const testing = std.testing;

const dis = @import("disassembler.zig");
const reloc = @import("relocation.zig");
const syscalls = @import("syscalls.zig");
const zydis = @import("zydis").zydis;

const AddressAllocator = @import("AddressAllocator.zig");
const backend = @import("backend.zig").backend;
const Range = @import("Range.zig");
const Statistics = @import("Statistics.zig");

const assert = std.debug.assert;
const page_size = std.heap.pageSize();
const log = std.log.scoped(.patcher);

const j_rel32: u8 = 0xe9;
const j_rel32_size = 5;
const j_rel8: u8 = 0xeb;
const j_rel8_size = 2;

// TODO: Find an invalid instruction to use.
// const invalid: u8 = 0xaa;
const int3: u8 = 0xcc;
const nop: u8 = 0x90;

// Prefixes for Padded Jumps (Tactic T1)
const prefixes = [_]u8{
    // prefix_fs,
    0x64,
    // prefix_gs,
    0x65,
    // prefix_ss,
    0x36,
};

/// As of the SysV ABI: 'The kernel destroys registers %rcx and %r11."
/// So we put the address of the function to call into %r11.
// TODO: Don't we need to save the red zone here, because we push the return address onto the stack
// with the `call r11` instruction?
var syscall_flicken_bytes = [_]u8{
    0x49, 0xBB, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, // mov r11 <imm>
    0x41, 0xff, 0xd3, // call r11
};

const Patcher = @This();

mutex: std.Thread.Mutex = .{},
address_allocator: AddressAllocator,
flicken_templates: std.StringArrayHashMapUnmanaged(Flicken) = .empty,

pub fn init(allocator: mem.Allocator) !Patcher {
    var patcher: Patcher = .{
        .address_allocator = .{ .child_allocator = allocator },
    };

    try patcher.flicken_templates.ensureTotalCapacity(
        patcher.address_allocator.allocator(),
        page_size / @sizeOf(Flicken),
    );
    patcher.flicken_templates.putAssumeCapacity("nop", .{ .name = "nop", .bytes = &.{} });
    mem.writeInt(
        u64,
        syscall_flicken_bytes[2..][0..8],
        @intFromPtr(&syscalls.syscallEntry),
        .little,
    );
    patcher.flicken_templates.putAssumeCapacity(
        "syscall",
        .{ .name = "syscall", .bytes = &syscall_flicken_bytes },
    );

    return patcher;
}

pub fn deinit(patcher: *Patcher) void {
    const allocator = patcher.address_allocator.allocator();
    patcher.flicken_templates.deinit(allocator);
    patcher.address_allocator.deinit();
}

pub const Flicken = struct {
    name: []const u8,
    bytes: []const u8,

    pub fn size(flicken: *const Flicken) u64 {
        return flicken.bytes.len + j_rel32_size;
    }
};

pub const FlickenId = enum(u32) {
    /// The nop flicken is special. It just does the patched instruction and immediately jumps back
    /// to the normal instruction stream. It **cannot** be changed.
    /// The bytes are always empty, meaning that `bytes.len == 0`.
    /// It also needs special handling when constructing the patches, because it's different for
    /// each instruction.
    nop = 0,
    /// TODO: docs
    syscall = 1,
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
    /// The bytes of the original code, starting at this instruction.
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

/// Scans a memory region for instructions that require patching and applies the patches using a
/// hierarchy of tactics (Direct/Punning -> Successor Eviction -> Neighbor Eviction).
///
/// Assert that the region is already mapped as R|W. The caller is responsible for changing it to
/// the desired protection after patching is done.
pub fn patchRegion(patcher: *Patcher, region: []align(page_size) u8) !void {
    log.info(
        "patchRegion: 0x{x} - 0x{x}",
        .{ @intFromPtr(region.ptr), @intFromPtr(&region[region.len - 1]) },
    );

    patcher.mutex.lock();
    defer patcher.mutex.unlock();

    // Make the application code writable so we can inject our jumps.
    try backend.mprotect(region, posix.PROT.READ | posix.PROT.WRITE);

    try patcher.address_allocator.block(.fromPtr(region.ptr, region.len));

    var arena_impl = std.heap.ArenaAllocator.init(patcher.address_allocator.allocator());
    const arena = arena_impl.allocator();
    defer arena_impl.deinit();

    var patch_requests: std.ArrayListUnmanaged(PatchRequest) = .empty;
    var instruction_starts: std.DynamicBitSetUnmanaged = try .initEmpty(arena, region.len);

    {
        log.info("patchRegion: Collecting patch requests", .{});
        var instruction_iter = dis.InstructionIterator.init(region);
        while (instruction_iter.next()) |instruction| {
            const offset = instruction.address - @intFromPtr(region.ptr);
            instruction_starts.set(offset);

            const is_syscall = instruction.instruction.mnemonic == zydis.ZYDIS_MNEMONIC_SYSCALL;
            const should_patch = is_syscall;
            if (should_patch) {
                const request: PatchRequest = .{
                    .flicken = if (is_syscall) .syscall else .nop,
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
                log.err("  request 1: {f}", .{patch_requests.items[i - 1]});
                log.err("  request 2: {f}", .{patch_requests.items[i]});
                return error.DuplicatePatchRequest;
            }
            last_offset = request.offset;

            if (@as(u64, @intFromEnum(request.flicken)) >= patcher.flicken_templates.count()) {
                const fmt = dis.formatBytes(request.bytes[0..request.size]);
                log.err(
                    "patchRegion: Usage of undefined flicken in request {f} for instruction: {s}",
                    .{ request, fmt },
                );
                return error.UndefinedFlicken;
            }
        }
    }

    // Used to track which bytes have been modified or used for constraints (punning), to
    // prevent future patches (neighbor/successor eviction) from corrupting them.
    var locked_bytes = try std.DynamicBitSetUnmanaged.initEmpty(arena, region.len);
    // A set of the pages for the patches/flicken we made writable. This way we don't repeatedly
    // change call `mprotect` on the same page to switch it from R|W to R|X and back. At the end
    // we `mprotect` all pages in this set back to being R|X.
    var pages_made_writable: std.AutoHashMapUnmanaged(u64, void) = .empty;
    var stats: Statistics = .empty;
    requests: for (patch_requests.items) |request| {
        for (0..request.size) |i| {
            if (locked_bytes.isSet(request.offset + i)) {
                log.warn(
                    "patchRegion: Skipping request at offset 0x{x} because it is locked",
                    .{request.offset},
                );
                continue :requests;
            }
        }

        const result = patcher.patchRequest(request, region, instruction_starts, locked_bytes) catch |err| {
            log.err("patchRegion: Failed to patch request at offset 0x{x}: {}", .{ request.offset, err });
            stats.failed += 1;
            continue;
        };

        switch (result.tactic) {
            .jump => stats.jump += 1,
            .punning => |n| stats.punning[n] += 1,
            .successor_eviction => stats.successor_eviction += 1,
            .neighbor_eviction => stats.neighbor_eviction += 1,
        }

        // Now nothing should error anymore, so we "commit" the patches
        for (result.patches) |p| {
            if (p.kind == .empty) continue;

            if (p.trampoline_addr != 0 and p.trampoline_len > 0) {
                try patcher.address_allocator.block(.{
                    .start = @intCast(p.trampoline_addr),
                    .end = @intCast(p.trampoline_addr + p.trampoline_len),
                });

                const start_page = mem.alignBackward(u64, p.trampoline_addr, page_size);
                const end_page = mem.alignForward(u64, p.trampoline_addr + p.trampoline_len, page_size);

                {
                    var page = start_page;
                    const prot = posix.PROT.READ | posix.PROT.WRITE;
                    const flags: posix.MAP = .{
                        .TYPE = .PRIVATE,
                        .ANONYMOUS = true,
                        .FIXED_NOREPLACE = true,
                    };
                    while (page < end_page) : (page += page_size) {
                        const gop = try pages_made_writable.getOrPut(arena, page);
                        if (gop.found_existing) continue;

                        const ptr: [*]align(page_size) u8 = @ptrFromInt(page);
                        _ = backend.mmap(ptr, page_size, prot, flags, -1, 0) catch |err| switch (err) {
                            error.MappingAlreadyExists => {
                                try backend.mprotect(ptr[0..page_size], prot);
                            },
                            else => return err,
                        };
                    }
                }

                const dest: [*]u8 = @ptrFromInt(p.trampoline_addr);
                @memcpy(dest[0..p.trampoline_len], p.trampoline_bytes[0..p.trampoline_len]);
            }

            if (p.source_addr != 0 and p.source_len > 0) {
                const dest: [*]u8 = @ptrFromInt(p.source_addr);
                @memcpy(dest[0..p.source_len], p.source_bytes[0..p.source_len]);
            }

            if (p.lock_len > 0) {
                locked_bytes.setRangeValue(
                    .{ .start = p.lock_offset, .end = p.lock_offset + p.lock_len },
                    true,
                );
            }
        }
    }

    var iter = pages_made_writable.keyIterator();
    const prot = posix.PROT.READ | posix.PROT.EXEC;
    while (iter.next()) |page_addr| {
        const ptr: [*]align(page_size) u8 = @ptrFromInt(page_addr.*);
        try backend.mprotect(ptr[0..page_size], prot);
    }

    log.info("{}", .{stats});
    log.info("patched: {}/{}: {d:.2}%", .{
        stats.successful(),
        stats.total(),
        stats.percentage() * 100.0,
    });
}

pub const Tactic = union(enum) {
    jump,
    punning: u8,
    successor_eviction,
    neighbor_eviction,
};

pub const PatchResult = struct {
    patches: [2]Patch,
    tactic: Tactic,
};

/// Informations to "commit" a patch.
pub const Patch = struct {
    kind: enum { empty, active } = .empty,

    /// Information for the jump overwrite
    source_addr: u64 = 0,
    source_bytes: [15]u8 = undefined,
    source_len: u8 = 0,

    /// Information for the trampoline
    trampoline_addr: u64 = 0,
    trampoline_bytes: [128]u8 = undefined,
    trampoline_len: u8 = 0,

    /// Offset inside the region to lock so future patches don't touch them.
    lock_offset: u64 = 0,
    lock_len: u64 = 0,
};

fn patchRequest(
    patcher: *Patcher,
    /// What to patch.
    request: PatchRequest,
    /// Where to patch it.
    region: []align(page_size) u8,
    /// Needed to get the size of instructions for the successor and neighbor eviction.
    instruction_starts: std.DynamicBitSetUnmanaged,
    /// Needed to not repeatedly patch the same instructions with successor and neighbor eviction.
    locked_bytes: std.DynamicBitSetUnmanaged,
) !PatchResult {
    if (try attemptDirectOrPunning(patcher, request, region, locked_bytes)) |result| {
        return result;
    }
    if (try attemptSuccessorEviction(patcher, request, region, locked_bytes)) |result| {
        return result;
    }
    if (try attemptNeighborEviction(patcher, request, region, instruction_starts, locked_bytes)) |result| {
        return result;
    }
    return error.PatchFailed;
}

fn attemptDirectOrPunning(
    patcher: *Patcher,
    request: PatchRequest,
    region: []align(page_size) u8,
    locked_bytes: std.DynamicBitSetUnmanaged,
) !?PatchResult {
    const flicken: Flicken = if (request.flicken == .nop)
        .{ .name = "nop", .bytes = request.bytes[0..request.size] }
    else
        patcher.flicken_templates.values()[@intFromEnum(request.flicken)];

    const flicken_size = flicken.size(); // bytes.len + 5
    const source_addr = @intFromPtr(region.ptr) + request.offset;

    for (0..prefixes.len + 1) |num_prefixes_usize| {
        const num_prefixes: u8 = @intCast(num_prefixes_usize);

        // Tactics T1 pads with prefixes. 5 is the size of `jmp rel32`.
        const lock_size = j_rel32_size + num_prefixes;
        if (request.offset + lock_size > region.len) continue;
        if (num_prefixes + 1 > request.size) continue;

        for (0..lock_size) |i| {
            if (locked_bytes.isSet(request.offset + i)) {
                return null;
            }
        }

        // Construct bitwise constraint if our jump spills over the instruction bounds
        var mask: u32 = 0;
        var pattern: u32 = 0;
        for (0..4) |i| {
            const byte_offset = num_prefixes + 1 + i;
            if (byte_offset >= request.size) {
                const existing_byte = request.bytes[byte_offset];
                mask |= @as(u32, 0xFF) << @intCast(i * 8);
                pattern |= @as(u32, existing_byte) << @intCast(i * 8);
            }
        }

        const jump_source = source_addr + num_prefixes + j_rel32_size;

        const alloc_request = AddressAllocator.Request{
            .source = jump_source,
            .size = flicken_size,
            .valid_range = .{
                // TODO: calculate from flicken size
                // TODO: use relocation information if needed
                .start = @max(0, @as(i64, @intCast(source_addr)) - 0x7FFF0000), // ~2GB
                .end = @as(i64, @intCast(source_addr)) + 0x7FFF0000,
            },
            .mask = mask,
            .pattern = pattern,
        };

        const tramp_range = patcher.address_allocator.findAllocation(alloc_request) orelse continue;
        var patch = Patch{ .kind = .active };

        // Populate Trampoline
        patch.trampoline_addr = @intCast(tramp_range.start);
        patch.trampoline_len = @intCast(flicken_size);
        @memcpy(patch.trampoline_bytes[0..flicken.bytes.len], flicken.bytes);

        // Relocate if NOP
        if (request.flicken == .nop) {
            const instr = dis.disassembleInstruction(request.bytes[0..request.size]).?;
            const reloc_info = reloc.RelocInfo{
                .instr = instr,
                .old_addr = source_addr,
            };
            reloc.relocateInstruction(
                reloc_info.instr,
                patch.trampoline_addr,
                patch.trampoline_bytes[0..flicken.bytes.len],
            ) catch |err| switch (err) {
                // TODO: when we use relocation information to restrict the range for the request
                // this shouldn't happen anymore.
                error.RelocationOverflow => continue, // try next prefix/hole
                else => return err,
            };
        }

        // Jump back from trampoline to original stream
        const ret_addr = source_addr + request.size;
        const tramp_jump_source = patch.trampoline_addr + flicken.bytes.len + j_rel32_size;
        const tramp_disp: i32 = @intCast(@as(i64, @intCast(ret_addr)) - @as(i64, @intCast(tramp_jump_source)));

        patch.trampoline_bytes[flicken.bytes.len] = j_rel32;
        mem.writeInt(i32, patch.trampoline_bytes[flicken.bytes.len + 1 ..][0..4], tramp_disp, .little);

        // Populate Source Jump
        patch.source_addr = source_addr;
        patch.source_len = @intCast(@max(request.size, lock_size));
        @memset(patch.source_bytes[0..patch.source_len], int3); // Clean padding

        if (num_prefixes > 0) {
            @memcpy(patch.source_bytes[0..num_prefixes], prefixes[0..num_prefixes]);
        }
        patch.source_bytes[num_prefixes] = j_rel32;
        const source_disp: i32 = @intCast(tramp_range.start - @as(i64, @intCast(jump_source)));
        mem.writeInt(i32, patch.source_bytes[num_prefixes + 1 ..][0..4], source_disp, .little);

        patch.lock_offset = request.offset;
        patch.lock_len = lock_size;

        const tactic: Tactic = if (num_prefixes == 0 and request.size >= 5)
            .jump
        else
            .{ .punning = num_prefixes };
        return .{ .patches = .{ patch, .{} }, .tactic = tactic };
    }
    return null;
}

test "attemptDirectOrPunning - Direct Jump (>= 5 bytes)" {
    var patcher = try Patcher.init(testing.allocator);
    defer patcher.deinit();

    // Simulate code memory at a known location
    var region: [1024]u8 align(page_size) = undefined;
    @memset(&region, nop);
    // Put a 5-byte instruction at offset 0: mov eax, 1 (B8 01 00 00 00)
    const instr = "\xB8\x01\x00\x00\x00";
    @memcpy(region[0..instr.len], instr);

    const source_addr = @intFromPtr(&region);

    // Block everything except a hole at offset 0x2000
    try patcher.address_allocator.block(.{ .start = 0, .end = @intCast(source_addr + 0x2000) });
    try patcher.address_allocator.block(.{
        .start = @intCast(source_addr + 0x3000),
        .end = @intCast(source_addr + 0x10000000),
    });

    const request = PatchRequest{
        .flicken = .nop,
        .offset = 0,
        .size = instr.len,
        .bytes = region[0..],
    };

    var locked_bytes = try std.DynamicBitSetUnmanaged.initEmpty(testing.allocator, region.len);
    defer locked_bytes.deinit(testing.allocator);

    const patch_opt = try attemptDirectOrPunning(&patcher, request, &region, locked_bytes);
    try testing.expect(patch_opt != null);
    const patch = patch_opt.?.patches[0];

    try testing.expectEqual(.active, patch.kind);

    try testing.expectEqual(source_addr, patch.source_addr);
    try testing.expectEqual(5, patch.source_len);
    try testing.expectEqual(0xE9, patch.source_bytes[0]);

    try testing.expectEqual(source_addr + 0x2000, patch.trampoline_addr);

    // Trampoline bytes should be [B8 01 00 00 00][E9 xx xx xx xx]
    try testing.expectEqual(instr.len + 5, patch.trampoline_len);
    try testing.expectEqualSlices(u8, instr, patch.trampoline_bytes[0..5]);
    try testing.expectEqual(0xE9, patch.trampoline_bytes[5]);
}

test "attemptDirectOrPunning - Punning (< 5 bytes)" {
    var patcher = try Patcher.init(testing.allocator);
    defer patcher.deinit();

    var region: [1024]u8 align(page_size) = undefined;
    @memset(&region, nop);
    // Put a 2-byte instruction at offset 0: xor eax, eax (31 C0)
    // Followed by 3 bytes of a successor we MUST pun into: 0xAA 0xBB 0xCC
    const instr = "\x31\xC0\x11\x22\x33";
    @memcpy(region[0..instr.len], instr);
    const target_addr = @intFromPtr(&region) + 5 + 0x33221100;

    try patcher.address_allocator.block(.{ .start = 0, .end = @intCast(target_addr) });
    try patcher.address_allocator.block(.{
        .start = @intCast(target_addr + 100),
        .end = math.maxInt(i64),
    });

    const request = PatchRequest{
        .flicken = .nop,
        .offset = 0,
        .size = 2,
        .bytes = region[0..],
    };

    var locked_bytes = try std.DynamicBitSetUnmanaged.initEmpty(testing.allocator, region.len);
    defer locked_bytes.deinit(testing.allocator);

    const patch_opt = try attemptDirectOrPunning(&patcher, request, &region, locked_bytes);
    try testing.expect(patch_opt != null);

    const p = patch_opt.?.patches[0];

    try testing.expectEqual(5, p.source_len); // 5 bytes overwritten
    try testing.expectEqual(0xE9, p.source_bytes[0]);

    // The jump offset MUST exactly match the 3 bytes we spilled into!
    try testing.expectEqual(0x11, p.source_bytes[2]);
    try testing.expectEqual(0x22, p.source_bytes[3]);
    try testing.expectEqual(0x33, p.source_bytes[4]);
    try testing.expectEqual(target_addr, p.trampoline_addr);
}

fn attemptSuccessorEviction(
    patcher: *Patcher,
    request: PatchRequest,
    region: []align(page_size) u8,
    locked_bytes: std.DynamicBitSetUnmanaged,
) !?PatchResult {
    const k = request.size;
    assert(k < 5);
    assert(k > 0);

    const source_addr = @intFromPtr(region.ptr) + request.offset;
    const succ_offset = request.offset + k;
    if (succ_offset >= region.len) return null;

    // Disassemble the Successor Instruction
    const succ_instr_bundle = dis.disassembleInstruction(region[succ_offset..]) orelse return null;
    const succ_size = succ_instr_bundle.instruction.length;

    // The total physical bytes we will overwrite.
    // k + 5 covers both jumps. We may need to pad up to the end of the successor.
    const lock_size = @max(k + 5, k + succ_size);
    if (request.offset + lock_size > region.len) return null;

    for (0..lock_size) |i| {
        if (locked_bytes.isSet(request.offset + i)) {
            return null;
        }
    }

    const flicken: Flicken = if (request.flicken == .nop)
        .{ .name = "nop", .bytes = request.bytes[0..request.size] }
    else
        patcher.flicken_templates.values()[@intFromEnum(request.flicken)];
    const flicken_size = flicken.size();

    const succ_flicken = Flicken{
        .name = "nop",
        .bytes = region[succ_offset .. succ_offset + succ_size],
    };
    const succ_flicken_size = succ_flicken.size();

    const jump_source1 = source_addr + j_rel32_size;
    const jump_source2 = source_addr + k + j_rel32_size;

    // If the successor jump (5 bytes) spills over the successor instruction bounds, we must
    // constrain R2 to not corrupt the instruction after the successor.
    var r2_mask: u32 = 0;
    var r2_pattern: u32 = 0;
    for (0..4) |i| {
        if (1 + i >= succ_size) {
            const existing_byte = region[succ_offset + 1 + i];
            r2_mask |= @as(u32, 0xFF) << @intCast(i * 8);
            r2_pattern |= @as(u32, existing_byte) << @intCast(i * 8);
        }
    }

    // Both requests look in the ~2GB window.
    // TODO: Adjust window using RIP-relative relocation information
    const window: i64 = 0x7FFF0000;
    const valid_range1 = Range{
        .start = @max(0, @as(i64, @intCast(jump_source1)) - window),
        .end = @as(i64, @intCast(jump_source1)) + window,
    };
    const valid_range2 = Range{
        .start = @max(0, @as(i64, @intCast(jump_source2)) - window),
        .end = @as(i64, @intCast(jump_source2)) + window,
    };

    const r1 = AddressAllocator.Request{
        .source = jump_source1,
        .size = flicken_size,
        .valid_range = valid_range1,
        .mask = 0,
        .pattern = 0,
    };
    const r2 = AddressAllocator.Request{
        .source = jump_source2,
        .size = succ_flicken_size,
        .valid_range = valid_range2,
        .mask = r2_mask,
        .pattern = r2_pattern,
    };

    const coupled_alloc = patcher.address_allocator.findCoupledAllocation(k, r1, r2) orelse return null;
    const tramp1_range = coupled_alloc[0];
    const tramp2_range = coupled_alloc[1];

    var patch1 = Patch{ .kind = .active };
    var patch2 = Patch{ .kind = .active };

    // Populate Successor Trampoline
    patch2.trampoline_addr = @intCast(tramp2_range.start);
    patch2.trampoline_len = @intCast(succ_flicken_size);
    @memcpy(patch2.trampoline_bytes[0..succ_size], succ_flicken.bytes);

    const reloc_info2 = reloc.RelocInfo{
        .instr = succ_instr_bundle,
        .old_addr = source_addr + k,
    };
    reloc.relocateInstruction(
        reloc_info2.instr,
        patch2.trampoline_addr,
        patch2.trampoline_bytes[0..succ_size],
    ) catch |err| switch (err) {
        error.RelocationOverflow => return null,
        else => return err,
    };

    const tramp2_jump_source = patch2.trampoline_addr + succ_size + j_rel32_size;
    const tramp2_disp: i32 = @intCast(@as(i64, @intCast(source_addr + k + succ_size)) - @as(i64, @intCast(tramp2_jump_source)));
    patch2.trampoline_bytes[succ_size] = j_rel32;
    mem.writeInt(i32, patch2.trampoline_bytes[succ_size + 1 ..][0..4], tramp2_disp, .little);

    // Populate Original Trampoline and Source Replacements
    patch1.trampoline_addr = @intCast(tramp1_range.start);
    patch1.trampoline_len = @intCast(flicken_size);
    @memcpy(patch1.trampoline_bytes[0..flicken.bytes.len], flicken.bytes);

    if (request.flicken == .nop) {
        const instr_bundle = dis.disassembleInstruction(request.bytes[0..k]).?;
        const reloc_info1 = reloc.RelocInfo{
            .instr = instr_bundle,
            .old_addr = source_addr,
        };
        reloc.relocateInstruction(
            reloc_info1.instr,
            patch1.trampoline_addr,
            patch1.trampoline_bytes[0..flicken.bytes.len],
        ) catch |err| switch (err) {
            error.RelocationOverflow => return null,
            else => return err,
        };
    }

    // T1 returns to the Successor's jump (which is at source_addr + k)
    const tramp1_jump_source: i64 = @intCast(patch1.trampoline_addr + flicken.bytes.len + j_rel32_size);
    const tramp1_disp: i32 = @intCast(@as(i64, @intCast(source_addr + k)) -
        @as(i64, @intCast(tramp1_jump_source)));
    patch1.trampoline_bytes[flicken.bytes.len] = j_rel32;
    mem.writeInt(i32, patch1.trampoline_bytes[flicken.bytes.len + 1 ..][0..4], tramp1_disp, .little);

    // Populate the overlapping jumps in the original code stream
    // Because they physically overlap, Patch 1 handles both J1 and J2 writing.
    patch1.source_addr = source_addr;
    patch1.source_len = @intCast(lock_size);
    @memset(patch1.source_bytes[0..lock_size], int3);

    // Write Successor Jump First
    patch1.source_bytes[k] = j_rel32;
    const rel2: i32 = @intCast(tramp2_range.start - @as(i64, @intCast(jump_source2)));
    mem.writeInt(i32, patch1.source_bytes[k + 1 ..][0..4], rel2, .little);

    // Write Original Jump Over The Top
    patch1.source_bytes[0] = j_rel32;
    const rel1: i32 = @intCast(tramp1_range.start - @as(i64, @intCast(jump_source1)));
    mem.writeInt(i32, patch1.source_bytes[1..][0..4], rel1, .little);

    patch1.lock_offset = request.offset;
    patch1.lock_len = lock_size;

    return .{ .patches = .{ patch1, patch2 }, .tactic = .successor_eviction };
}

test "attemptSuccessorEviction - K=2" {
    var patcher = try Patcher.init(testing.allocator);
    defer patcher.deinit();

    var region: [1024]u8 align(page_size) = undefined;
    @memset(&region, nop);

    // Instruction 1 (J1): xor eax, eax (31 C0) -> 2 bytes
    // Instruction 2 (J2): mov eax, 1 (B8 01 00 00 00) -> 5 bytes
    const instr = "\x31\xC0\xB8\x01\x00\x00\x00";
    @memcpy(region[0..instr.len], instr);

    const request = PatchRequest{
        .flicken = .nop,
        .offset = 0,
        .size = 2,
        .bytes = region[0..],
    };

    const source_addr = @intFromPtr(&region);

    // We block the immediate area to force the solver to search for a coupled solution.
    try patcher.address_allocator.block(.{ .start = 0, .end = @intCast(source_addr + 0x2000) });

    var locked_bytes = try std.DynamicBitSetUnmanaged.initEmpty(testing.allocator, region.len);
    defer locked_bytes.deinit(testing.allocator);

    var instruction_starts = try std.DynamicBitSetUnmanaged.initEmpty(testing.allocator, region.len);
    defer instruction_starts.deinit(testing.allocator);
    instruction_starts.set(0);
    instruction_starts.set(2);

    const patches_opt = try attemptSuccessorEviction(&patcher, request, &region, locked_bytes);
    try testing.expect(patches_opt != null);
    const patches = patches_opt.?.patches;

    try testing.expectEqual(.active, patches[0].kind);
    try testing.expectEqual(.active, patches[1].kind);

    const p1 = patches[0];
    try testing.expectEqual(source_addr, p1.source_addr);

    // k=2, succ_size=5 -> lock_size = max(2+5, 2+5) = 7
    try testing.expectEqual(7, p1.source_len);

    // Verify mathematical overlap worked
    try testing.expectEqual(0xE9, p1.source_bytes[0]); // J1 Opcode
    try testing.expectEqual(0xE9, p1.source_bytes[2]); // J2 Opcode is perfectly preserved!

    const rel1 = mem.readInt(i32, p1.source_bytes[1..5], .little);
    const rel2 = mem.readInt(i32, p1.source_bytes[3..7], .little);

    // The top 2 bytes of rel1 MUST exactly match the bottom 2 bytes of rel2
    const u_rel1: u32 = @bitCast(rel1);
    const u_rel2: u32 = @bitCast(rel2);
    try testing.expectEqual((u_rel1 >> 16) & 0xFFFF, u_rel2 & 0xFFFF);
}

fn attemptNeighborEviction(
    patcher: *Patcher,
    request: PatchRequest,
    region: []align(page_size) u8,
    instruction_starts: std.DynamicBitSetUnmanaged,
    locked_bytes: std.DynamicBitSetUnmanaged,
) !?PatchResult {
    // Neighbor Eviction requires at least 2 bytes for the short jump (0xEB <disp>)
    if (request.size < 2) return null;

    const source_addr = @intFromPtr(region.ptr) + request.offset;
    const start_offset = request.offset + 2;
    // Valid short jump displacement is [-128, 127]. We only look forward to avoid evicting
    // instructions we haven't patched yet.
    const end_offset = @min(start_offset + 128, region.len);

    const flicken: Flicken = if (request.flicken == .nop)
        .{ .name = "nop", .bytes = request.bytes[0..request.size] }
    else
        patcher.flicken_templates.values()[@intFromEnum(request.flicken)];
    const flicken_size = flicken.size();

    neighbor: for (start_offset..end_offset) |neighbor_offset| {
        if (!instruction_starts.isSet(neighbor_offset)) continue;

        const victim_bytes_all = region[neighbor_offset..];
        const victim_instr_bundle = dis.disassembleInstruction(victim_bytes_all) orelse continue;
        const victim_size = victim_instr_bundle.instruction.length;

        for (0..victim_size) |i| {
            if (locked_bytes.isSet(neighbor_offset + i)) continue :neighbor;
        }

        const neighbor_addr = source_addr + (neighbor_offset - request.offset);

        // Try to split the victim instruction at offset `k`
        var k: u8 = 1;
        while (k < victim_size) : (k += 1) {
            const victim_lock_size = @max(victim_size, k + j_rel32_size);
            if (neighbor_offset + victim_lock_size > region.len) continue;

            // Calculate short jump displacement (from end of original instruction to J_P)
            const target_offset: i64 = @intCast(neighbor_offset + k);
            const source_end_offset: i64 = @intCast(request.offset + 2);
            const disp = target_offset - source_end_offset;
            if (disp > 127 or disp < -128) continue;

            // Ensure our J_P spill doesn't corrupt already locked bytes
            for (victim_size..victim_lock_size) |i| {
                if (locked_bytes.isSet(neighbor_offset + i)) continue;
            }

            // Build constraint for J_P (the Patch jump)
            var rp_mask: u32 = 0;
            var rp_pattern: u32 = 0;
            for (0..4) |i| {
                const byte_offset = k + 1 + i;
                if (byte_offset >= victim_size) {
                    const existing_byte = region[neighbor_offset + byte_offset];
                    rp_mask |= @as(u32, 0xFF) << @intCast(i * 8);
                    rp_pattern |= @as(u32, existing_byte) << @intCast(i * 8);
                }
            }

            const jump_source_V = neighbor_addr + j_rel32_size;
            const jump_source_P = neighbor_addr + k + j_rel32_size;

            // Look in the ~2GB window
            const window: i64 = 0x7FFF0000;
            const r_V = AddressAllocator.Request{
                .source = jump_source_V,
                .size = victim_size + j_rel32_size,
                .valid_range = .{
                    .start = @max(0, @as(i64, @intCast(jump_source_V)) - window),
                    .end = @as(i64, @intCast(jump_source_V)) + window,
                },
                .mask = 0,
                .pattern = 0,
            };
            const r_P = AddressAllocator.Request{
                .source = jump_source_P,
                .size = flicken_size,
                .valid_range = .{
                    .start = @max(0, @as(i64, @intCast(jump_source_P)) - window),
                    .end = @as(i64, @intCast(jump_source_P)) + window,
                },
                .mask = rp_mask,
                .pattern = rp_pattern,
            };

            const coupled_alloc = patcher.address_allocator.findCoupledAllocation(k, r_V, r_P) orelse continue;
            const tramp_V_range = coupled_alloc[0];
            const tramp_P_range = coupled_alloc[1];

            var patch1 = Patch{ .kind = .active };
            var patch2 = Patch{ .kind = .active };

            // Patch 1: Original Short Jump + Flicken Trampoline
            patch1.source_addr = source_addr;
            patch1.source_len = request.size;
            @memset(patch1.source_bytes[0..patch1.source_len], int3);
            patch1.source_bytes[0] = j_rel8;
            patch1.source_bytes[1] = @intCast(disp);

            patch1.trampoline_addr = @intCast(tramp_P_range.start);
            patch1.trampoline_len = @intCast(flicken_size);
            @memcpy(patch1.trampoline_bytes[0..flicken.bytes.len], flicken.bytes);

            if (request.flicken == .nop) {
                const reloc_info_p = reloc.RelocInfo{
                    .instr = dis.disassembleInstruction(request.bytes[0..request.size]).?,
                    .old_addr = source_addr,
                };
                reloc.relocateInstruction(
                    reloc_info_p.instr,
                    patch1.trampoline_addr,
                    patch1.trampoline_bytes[0..flicken.bytes.len],
                ) catch |err| switch (err) {
                    error.RelocationOverflow => continue,
                    else => return err,
                };
            }

            const tramp_P_jump_source = patch1.trampoline_addr + flicken.bytes.len + j_rel32_size;
            const tramp_P_disp: i32 = @intCast(@as(i64, @intCast(source_addr + request.size)) - @as(i64, @intCast(tramp_P_jump_source)));
            patch1.trampoline_bytes[flicken.bytes.len] = j_rel32;
            mem.writeInt(i32, patch1.trampoline_bytes[flicken.bytes.len + 1 ..][0..4], tramp_P_disp, .little);

            patch1.lock_offset = request.offset;
            patch1.lock_len = request.size;

            // Patch 2: Victim Coupled Jump + Victim Trampoline
            patch2.source_addr = neighbor_addr;
            patch2.source_len = @intCast(victim_lock_size);
            @memset(patch2.source_bytes[0..patch2.source_len], int3);

            // Write J_P (The jump targeted by our short jump) at offset k
            patch2.source_bytes[k] = j_rel32;
            const rel_P: i32 = @intCast(tramp_P_range.start - @as(i64, @intCast(jump_source_P)));
            mem.writeInt(i32, patch2.source_bytes[k + 1 ..][0..4], rel_P, .little);

            // Write J_V (The victim's jump) at offset 0
            patch2.source_bytes[0] = j_rel32;
            const rel_V: i32 = @intCast(tramp_V_range.start - @as(i64, @intCast(jump_source_V)));
            mem.writeInt(i32, patch2.source_bytes[1..][0..4], rel_V, .little);

            patch2.trampoline_addr = @intCast(tramp_V_range.start);
            patch2.trampoline_len = @intCast(victim_size + j_rel32_size);
            @memcpy(patch2.trampoline_bytes[0..victim_size], victim_bytes_all[0..victim_size]);

            const reloc_info_v = reloc.RelocInfo{
                .instr = victim_instr_bundle,
                .old_addr = neighbor_addr,
            };
            reloc.relocateInstruction(
                reloc_info_v.instr,
                patch2.trampoline_addr,
                patch2.trampoline_bytes[0..victim_size],
            ) catch |err| switch (err) {
                error.RelocationOverflow => continue,
                else => return err,
            };

            const tramp_V_jump_source = patch2.trampoline_addr + victim_size + j_rel32_size;
            const tramp_V_disp: i32 = @intCast(@as(i64, @intCast(neighbor_addr + victim_size)) - @as(i64, @intCast(tramp_V_jump_source)));
            patch2.trampoline_bytes[victim_size] = j_rel32;
            mem.writeInt(i32, patch2.trampoline_bytes[victim_size + 1 ..][0..4], tramp_V_disp, .little);

            patch2.lock_offset = neighbor_offset;
            patch2.lock_len = victim_lock_size;

            return PatchResult{ .patches = .{ patch1, patch2 }, .tactic = .neighbor_eviction };
        }
    }
    return null;
}

test "attemptNeighborEviction - Valid Neighbor Found" {
    var patcher = try Patcher.init(testing.allocator);
    defer patcher.deinit();

    var region: [1024]u8 align(page_size) = undefined;
    @memset(&region, 0);

    // Target (I): xor eax, eax (31 C0) -> 2 bytes [Offset 0]
    // Padding: NOP NOP (90 90) -> 2 bytes [Offset 2]
    // Neighbor (N): mov eax, 1 (B8 01 00 00 00) -> 5 bytes [Offset 4]
    const instr = "\x31\xC0\x90\x90\xB8\x01\x00\x00\x00";
    @memcpy(region[0..instr.len], instr);

    const source_addr = @intFromPtr(&region);

    const request = PatchRequest{
        .flicken = .nop,
        .offset = 0,
        .size = 2,
        .bytes = region[0..],
    };

    // Block immediate area to trigger the complex coupled solver logic.
    try patcher.address_allocator.block(.{ .start = 0, .end = @intCast(source_addr + 0x2000) });

    var locked_bytes = try std.DynamicBitSetUnmanaged.initEmpty(testing.allocator, region.len);
    defer locked_bytes.deinit(testing.allocator);

    var instruction_starts = try std.DynamicBitSetUnmanaged.initEmpty(testing.allocator, region.len);
    defer instruction_starts.deinit(testing.allocator);
    instruction_starts.set(0);
    instruction_starts.set(2);
    instruction_starts.set(3);
    instruction_starts.set(4); // Neighbor starts here

    const patches_opt = try attemptNeighborEviction(&patcher, request, &region, instruction_starts, locked_bytes);
    try testing.expect(patches_opt != null);
    const patches = patches_opt.?.patches;

    try testing.expectEqual(.active, patches[0].kind);
    try testing.expectEqual(.active, patches[1].kind);

    const p1 = patches[0];
    const p2 = patches[1];

    // Verify Patch 1 (The short jump)
    try testing.expectEqual(source_addr, p1.source_addr);
    try testing.expectEqual(2, p1.source_len);
    try testing.expectEqual(0xEB, p1.source_bytes[0]);

    // Displacement should jump to the hole created at offset 4.
    // Short jump origin is end of instruction (offset 2).
    // Target is `neighbor_offset + k`. Assume it chose k=2 for the overlap: 4 + 2 = 6.
    // disp = 6 - 2 = 4.
    const expected_disp = p1.source_bytes[1];
    const target_offset = 2 + @as(i8, @bitCast(expected_disp));
    try testing.expect(target_offset > 4 and target_offset < 9);

    // Verify Patch 2 (The overlapping jumps in the neighbor's location)
    try testing.expectEqual(source_addr + 4, p2.source_addr);
    try testing.expectEqual(0xE9, p2.source_bytes[0]); // J_V starts with 0xE9

    const k = target_offset - 4;
    try testing.expectEqual(0xE9, p2.source_bytes[@intCast(k)]); // J_P starts with 0xE9 exactly where the short jump points!
}
