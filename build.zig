const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const sanitize = b.option(bool, "sanitize", "Enable ASAN/UBSAN/LSAN in debug builds") orelse true;
    const sanitize_c = if (sanitize and optimize == .Debug) std.zig.SanitizeC.full else std.zig.SanitizeC.off;

    const base_c_flags = &[_][]const u8{
        "-std=c2x",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Werror",
    };

    const c_flags = base_c_flags;

    const lib_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .sanitize_c = sanitize_c,
    });
    lib_module.addIncludePath(b.path("include"));
    lib_module.addCSourceFile(.{ .file = b.path("src/client.c"), .flags = c_flags });

    const lib = b.addLibrary(.{
        .name = "websocket_client",
        .linkage = .static,
        .root_module = lib_module,
    });
    b.installArtifact(lib);

    const example_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .sanitize_c = sanitize_c,
    });
    example_module.addIncludePath(b.path("include"));
    example_module.addCSourceFile(.{ .file = b.path("examples/test.c"), .flags = c_flags });

    const example = b.addExecutable(.{
        .name = "ws_test",
        .root_module = example_module,
    });
    example.linkLibrary(lib);
    example.linkSystemLibrary("ssl");
    example.linkSystemLibrary("crypto");

    b.installArtifact(example);

    const run_example = b.addRunArtifact(example);
    if (b.args) |args| {
        run_example.addArgs(args);
    }

    const run_step = b.step("run-example", "Run websocket example client");
    run_step.dependOn(&run_example.step);
}
