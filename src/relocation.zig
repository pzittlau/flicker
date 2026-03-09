const dis = @import("disassembler.zig");
const std = @import("std");
const math = std.math;
const mem = std.mem;
const zydis = @import("zydis").zydis;

const assert = std.debug.assert;

pub const RelocInfo = struct {
    instr: dis.BundledInstruction,
    old_addr: u64,
};

/// Fixes RIP-relative operands in an instruction that has been moved to a new address.
pub fn relocateInstruction(
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
