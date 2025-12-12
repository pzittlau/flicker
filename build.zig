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
        .use_llvm = true,
    });
    exe.pie = true;
    exe.lto = if (optimize == .Debug) .none else .full;
    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    try compileTestApplications(b, target, optimize, false, false);
    try compileTestApplications(b, target, optimize, false, true);
    try compileTestApplications(b, target, optimize, true, true);

    const exe_tests = b.addTest(.{ .root_module = mod });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(b.getInstallStep());
    test_step.dependOn(&run_exe_tests.step);
}

pub fn compileTestApplications(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    comptime link_libc: bool,
    comptime pie: bool,
) !void {
    // Compile test applications
    const test_path = "src/test/";
    const test_prefix = prefix: {
        const p1 = "test_" ++ if (link_libc) "libc_" else "nolibc_";
        const p2 = p1 ++ if (pie) "pie_" else "nopie_";
        break :prefix p2;
    };
    var test_dir = try std.fs.cwd().openDir(test_path, .{ .iterate = true });
    defer test_dir.close();
    var iterator = test_dir.iterate();
    while (try iterator.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".zig")) continue;

        const name = try std.mem.concat(b.allocator, u8, &.{
            test_prefix, entry.name[0 .. entry.name.len - 4], // strip .zig suffix
        });
        const test_executable = b.addExecutable(.{
            .name = name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(b.pathJoin(&.{ test_path, entry.name })),
                .optimize = optimize,
                .target = target,
                .link_libc = link_libc,
                .link_libcpp = false,
                .pic = pie,
            }),
            .linkage = if (link_libc) .dynamic else .static,
            .use_llvm = true,
            .use_lld = true,
        });
        test_executable.pie = pie;
        b.installArtifact(test_executable);
    }
}
