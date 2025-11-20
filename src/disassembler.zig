const std = @import("std");
const mem = std.mem;
const zydis = @import("zydis").zydis;

const log = std.log.scoped(.disassembler);

pub const InstructionIterator = struct {
    decoder: zydis.ZydisDecoder,
    bytes: []const u8,
    instruction: zydis.ZydisDecodedInstruction,
    operands: [zydis.ZYDIS_MAX_OPERAND_COUNT]zydis.ZydisDecodedOperand,

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
            // TODO: handle common padding bytes
            switch (status) {
                zydis.ZYDIS_STATUS_NO_MORE_DATA => {
                    log.info("next: Got status: NO_MORE_DATA. Iterator completed.", .{});
                    return null;
                },
                zydis.ZYDIS_STATUS_ILLEGAL_LOCK => log.warn("next: Got status: ILLEGAL_LOCK. " ++
                    "Byte stepping, to find next valid instruction begin", .{}),
                zydis.ZYDIS_STATUS_DECODING_ERROR => log.warn("next: Got status: DECODING_ERROR. " ++
                    "Byte stepping, to find next valid instruction begin", .{}),
                else => log.warn("next: Got unknown status: 0x{x}. Byte stepping, to find next " ++
                    "valid instruction begin", .{status}),
            }
            // TODO: add a flag to instead return an error
            log.debug(
                "next: instruction length: {}, address: 0x{x}, bytes: 0x{x}",
                .{
                    iterator.instruction.length,
                    address,
                    iterator.bytes[0..iterator.instruction.length],
                },
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

pub const InstructionFormatter = struct {
    formatter: zydis.ZydisFormatter,

    pub fn init() InstructionFormatter {
        var formatter: zydis.ZydisFormatter = undefined;
        const status = zydis.ZydisFormatterInit(&formatter, zydis.ZYDIS_FORMATTER_STYLE_ATT);
        if (!zydis.ZYAN_SUCCESS(status)) @panic("Zydis formatter init failed");

        return .{
            .formatter = formatter,
        };
    }

    pub fn format(
        formatter: *const InstructionFormatter,
        instruction: BundledInstruction,
        buffer: []u8,
    ) []u8 {
        const status = zydis.ZydisFormatterFormatInstruction(
            &formatter.formatter,
            instruction.instruction,
            instruction.operands.ptr,
            instruction.instruction.operand_count_visible,
            buffer.ptr,
            buffer.len,
            instruction.address,
            null,
        );
        if (!zydis.ZYAN_SUCCESS(status)) {
            @panic("wow");
        }
        return mem.sliceTo(buffer, 0);
    }
};

/// Disassemble `bytes` and format them into the given buffer. Useful for error reporting or
/// debugging purposes.
/// This function should not be called in a tight loop as it's intentionally inefficient due tue
/// having a simple API.
pub fn formatBytes(bytes: []const u8, buffer: []u8) []u8 {
    var iter = InstructionIterator.init(bytes);

    const instr = iter.next() orelse return buffer[0..0];
    const formatter = InstructionFormatter.init();
    return formatter.format(instr, buffer);
}
