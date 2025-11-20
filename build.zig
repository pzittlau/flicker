const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Separate module to always compile it with a release mode.
    const zydis = b.createModule(.{
        .root_source_file = b.path("src/vendor/zydis.zig"),
        // .optimize = if (optimize == .Debug) .ReleaseSafe else optimize,
        .optimize = .ReleaseFast,
        .target = target,
        .link_libc = false,
        .link_libcpp = false,
    });
    zydis.addCMacro("ZYAN_NO_LIBC", "1");
    zydis.addIncludePath(b.path("src/vendor/"));
    zydis.addCSourceFile(.{
        .file = b.path("src/vendor/Zydis.c"),
        .flags = &.{"-g"},
        .language = .c,
    });

    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .optimize = optimize,
        .target = target,
        .link_libc = false,
        .link_libcpp = false,
        .imports = &.{.{ .name = "zydis", .module = zydis }},
    });

    const exe = b.addExecutable(.{
        .name = "flicker",
        .root_module = mod,
    });
    exe.pie = true;
    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const exe_tests = b.addTest(.{ .root_module = mod });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
}
