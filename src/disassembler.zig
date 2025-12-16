const std = @import("std");
const mem = std.mem;
const zydis = @import("zydis").zydis;

const log = std.log.scoped(.disassembler);
const assert = std.debug.assert;

pub const InstructionIterator = struct {
    /// Maximum number of warnings to print per iterator before suppressing.
    pub var max_warnings: u64 = 3;

    decoder: zydis.ZydisDecoder,
    bytes: []const u8,
    instruction: zydis.ZydisDecodedInstruction,
    operands: [zydis.ZYDIS_MAX_OPERAND_COUNT]zydis.ZydisDecodedOperand,
    warnings: usize = 0,

    pub fn init(bytes: []const u8) InstructionIterator {
        var decoder: zydis.ZydisDecoder = undefined;
        const status = zydis.ZydisDecoderInit(
            &decoder,
            zydis.ZYDIS_MACHINE_MODE_LONG_64,
            zydis.ZYDIS_STACK_WIDTH_64,
        );
        if (!zydis.ZYAN_SUCCESS(status)) @panic("Zydis decoder init failed");
        return .{
            .decoder = decoder,
            .bytes = bytes,
            .instruction = undefined,
            .operands = undefined,
        };
    }

    pub fn next(iterator: *InstructionIterator) ?BundledInstruction {
        var status = zydis.ZydisDecoderDecodeFull(
            &iterator.decoder,
            iterator.bytes.ptr,
            iterator.bytes.len,
            &iterator.instruction,
            &iterator.operands,
        );
        var address: u64 = @intFromPtr(iterator.bytes.ptr);

        while (!zydis.ZYAN_SUCCESS(status)) {
            if (status == zydis.ZYDIS_STATUS_NO_MORE_DATA) {
                log.debug("next: Got status: NO_MORE_DATA. Iterator completed.", .{});
                return null;
            }

            // TODO: handle common padding bytes
            // TODO: add a flag to instead return an error
            iterator.warnings += 1;
            if (iterator.warnings <= max_warnings) {
                const err_desc = switch (status) {
                    zydis.ZYDIS_STATUS_ILLEGAL_LOCK => "ILLEGAL_LOCK",
                    zydis.ZYDIS_STATUS_DECODING_ERROR => "DECODING_ERROR",
                    zydis.ZYDIS_STATUS_INVALID_MAP => "INVALID_MAP",
                    else => "UNKNOWN",
                };
                log.warn(
                    "next: Got status: {s} (0x{x}). Byte stepping, for next instruction begin",
                    .{ err_desc, status },
                );
                if (iterator.warnings == max_warnings) {
                    log.warn("next: Suppressing further warnings for this disassembly.", .{});
                }
            }

            log.debug(
                "next: skipping byte at address: 0x{x}, byte: 0x{x}",
                .{ address, iterator.bytes[0] },
            );

            iterator.bytes = iterator.bytes[1..];
            status = zydis.ZydisDecoderDecodeFull(
                &iterator.decoder,
                iterator.bytes.ptr,
                iterator.bytes.len,
                &iterator.instruction,
                &iterator.operands,
            );
            address = @intFromPtr(iterator.bytes.ptr);
        }

        iterator.bytes = iterator.bytes[iterator.instruction.length..];
        return .{
            .address = address,
            .instruction = &iterator.instruction,
            .operands = iterator.operands[0..iterator.instruction.operand_count_visible],
        };
    }
};

pub const BundledInstruction = struct {
    address: u64,
    instruction: *const zydis.ZydisDecodedInstruction,
    operands: []const zydis.ZydisDecodedOperand,
};

/// Disassemble `bytes` and format them into the given buffer. Useful for error reporting or
/// debugging purposes. On error return an empty string.
/// This function is not threadsafe.
pub fn formatBytes(bytes: []const u8) []u8 {
    const instr = disassembleInstruction(bytes) orelse return "";
    return formatInstruction(instr);
}

/// Format the given instruction into the buffer. On error return an empty string.
/// This function is not threadsafe.
pub fn formatInstruction(instruction: BundledInstruction) []u8 {
    // Static variable to initialize the formatter only once and have a valid address for the
    // buffer.
    const static = struct {
        var initialized = false;
        var formatter: zydis.ZydisFormatter = undefined;
        var buffer: [256]u8 = undefined;
    };
    if (!static.initialized) {
        const status = zydis.ZydisFormatterInit(&static.formatter, zydis.ZYDIS_FORMATTER_STYLE_ATT);
        if (!zydis.ZYAN_SUCCESS(status)) @panic("Zydis formatter init failed");
    }
    const status = zydis.ZydisFormatterFormatInstruction(
        &static.formatter,
        instruction.instruction,
        instruction.operands.ptr,
        instruction.instruction.operand_count_visible,
        &static.buffer,
        static.buffer.len,
        instruction.address,
        null,
    );
    if (zydis.ZYAN_SUCCESS(status)) {
        return mem.sliceTo(&static.buffer, 0);
    } else {
        return "";
    }
}

/// Disassemble the first instruction at bytes. On error return `null`.
/// This function is not threadsafe.
pub fn disassembleInstruction(bytes: []const u8) ?BundledInstruction {
    // Static variable to initialize the decoder only once and have a valid address for the
    // instruction and operands.
    const static = struct {
        var initialized = false;
        var decoder: zydis.ZydisDecoder = undefined;
        var instruction: zydis.ZydisDecodedInstruction = undefined;
        var operands: [zydis.ZYDIS_MAX_OPERAND_COUNT]zydis.ZydisDecodedOperand = undefined;
    };
    if (!static.initialized) {
        const status = zydis.ZydisDecoderInit(
            &static.decoder,
            zydis.ZYDIS_MACHINE_MODE_LONG_64,
            zydis.ZYDIS_STACK_WIDTH_64,
        );
        if (!zydis.ZYAN_SUCCESS(status)) @panic("Zydis decoder init failed");
        static.initialized = true;
    }
    const status = zydis.ZydisDecoderDecodeFull(
        &static.decoder,
        bytes.ptr,
        bytes.len,
        &static.instruction,
        &static.operands,
    );
    if (zydis.ZYAN_SUCCESS(status)) {
        return .{
            .address = @intFromPtr(bytes.ptr),
            .instruction = &static.instruction,
            .operands = &static.operands,
        };
    } else {
        return null;
    }
}
