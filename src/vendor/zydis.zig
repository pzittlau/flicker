// Separate module to always compile it with a release mode.
pub const zydis = @cImport({
    @cInclude("Zydis.h");
});
