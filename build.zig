const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const sanitize = b.option(bool, "sanitize", "Enable ASAN/UBSAN/LSAN in debug builds") orelse true;
    const sanitize_c = if (sanitize and optimize == .Debug) std.zig.SanitizeC.full else std.zig.SanitizeC.off;

    const c_flags = &[_][]const u8{
        "-std=c23",
        "-D_POSIX_C_SOURCE=200809L",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Werror",
        "-fstack-protector-strong",
        "-U_FORTIFY_SOURCE",
        "-D_FORTIFY_SOURCE=3",
        "-fPIE",
    };

    const lib_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .sanitize_c = sanitize_c,
    });
    lib_module.addIncludePath(b.path("include"));
    lib_module.addCSourceFile(.{ .file = b.path("src/websocket_client.c"), .flags = c_flags });

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
    example_module.addCSourceFile(.{ .file = b.path("examples/simple.c"), .flags = c_flags });

    const example = b.addExecutable(.{
        .name = "ws_simple",
        .root_module = example_module,
    });
    example.linkLibrary(lib);
    example.linkSystemLibrary("wolfssl");
    if (target.result.os.tag == .linux) {
        example.pie = true;
        example.link_z_relro = true;
        example.link_z_lazy = false;
    }

    b.installArtifact(example);

    const run_example = b.addRunArtifact(example);
    if (b.args) |args| {
        run_example.addArgs(args);
    }

    const run_step = b.step("run-example", "Run websocket example client");
    run_step.dependOn(&run_example.step);
}
