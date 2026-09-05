// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

/*
Usage:

 * option 1 - Run this command in the terminal to build the project:
  /path/to/icpp build.cc
  or
  /path/to/icpp build.cc Debug ; if you want to build in Debug mode.

 * option 2 - Run this script directly in VSCode with "ICPP - Run" command,
  the log of the building process can be found in OUTOUT panel of ICPP channel.
*/

#include <icpp.hpp>

#if 1 // change to 0 to only print the command without executing it.
#define command(fmt, ...) std::system(std::format(fmt, __VA_ARGS__).c_str())
#else
#define command(fmt, ...) std::println(fmt, __VA_ARGS__);
#endif

#if __WIN__
#define EXTRA_CMAKE                                                            \
  " -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl "

bool patch_string(std::string_view infile, std::string_view pattern,
                  std::string_view replace) {
  std::stringstream buffer;
  {
    // read file
    buffer << std::ifstream(fs::path(infile), std::ios::in | std::ios::binary)
                  .rdbuf();
  }

  std::string_view patch_magic =
      "/* Patched by AetherBinary to link the LLVM.dll */\n";
  std::string content = buffer.str();
  if (content.starts_with(patch_magic))
    return false;

  size_t pos = 0;
  while ((pos = content.find(pattern, pos)) != std::string::npos) {
    // do the replacement
    content.replace(pos, pattern.length(), replace);
    pos += replace.length();
  }

  fs::path temp_file = infile;
  temp_file.replace_extension(".tmp");
  {
    // write file
    std::ofstream outf(temp_file,
                       std::ios::out | std::ios::binary | std::ios::trunc);
    outf.write(patch_magic.data(), patch_magic.size());
    outf.write(content.data(), content.size());
  }

  // rename the temp as the original file
  fs::rename(temp_file, infile);
  return true;
}

// AetherBinary links to LLVM.dll, the LLVM_ABI will cause problem
// on Windows with linkage issues, so we remove its LLVM_ABI attribute
// before building or after installing...
void patch_llvm_abi(std::string_view file) {
  std::println("Patching LLVM_ABI declaration in {}...", file);
  if (patch_string(file, " LLVM_ABI ", " /*LLVM_ABI*/ "))
    std::println("Finished patching.");
  else
    std::println("Ignored, it's already been patched.");
}

void patch_undef_llvm_abi(std::string_view file) {
  std::println("Patching LLVM_ABI declaration in {}...", file);
  if (patch_string(file, "#if !defined(LLVM_ABI)",
                   R"(
#undef LLVM_ABI
#undef LLVM_TEMPLATE_ABI
#define LLVM_ABI
#define LLVM_TEMPLATE_ABI

#if !defined(LLVM_ABI))"))
    std::println("Finished patching.");
  else
    std::println("Ignored, it's already been patched.");
}

void patch_error_id(std::string_view file) {
  std::println("Patching LLVM_ABI declaration in {}...", file);
  if (patch_string(file, "static char ID;",
                   "__declspec(dllimport) static char ID;"))
    std::println("Finished patching.");
  else
    std::println("Ignored, it's already been patched.");
}

void patch_float_sema(std::string_view file) {
  std::println("Patching fltSemantics declaration in {}...", file);
  if (patch_string(file, "LLVM_ABI static const fltSemantics",
                   "__declspec(dllimport) static const fltSemantics"))
    std::println("Finished patching.");
  else
    std::println("Ignored, it's already been patched.");
}
#elif __linux__
std::string extra_cmake(std::string_view icpp_dir) {
  return std::format(
      " -DCMAKE_C_COMPILER={}/bin/clang -DCMAKE_CXX_COMPILER={}/bin/clang++ ",
      icpp_dir, icpp_dir);
}
#define EXTRA_CMAKE extra_cmake(icpp_dir.string())
#else
#define EXTRA_CMAKE ""
#endif

// quote the path with double quotes, to avoid issues with spaces in the path.
std::string dqpath(const fs::path &p, const fs::path &child = "") {
  return "\"" + (child.empty() ? p : p / child).string() + "\"";
}

int main(int argc, const char *argv[]) {
  auto icpp_dir = fs::path(icpp::program()).parent_path().parent_path();
  auto script_path = fs::absolute(argv[0]);
  std::println("Running build script {}...", script_path.string());

  // set the library path of icpp's c++ runtime, so that llvm's table-gen can
  // run normally
#if __WIN__
  icpp::set_env(
      "PATH", std::format("{}/bin;{}", icpp_dir.string(), std::getenv("PATH")));
#elif __LINUX__
  icpp::set_env("LD_LIBRARY_PATH",
                std::format("{}/lib", icpp_dir.string()).c_str());
#endif
  auto script_dir = script_path.parent_path();

  std::println("Phase 1: Build LLVM...");

  auto llvm_build_dir = script_dir / "build-llvm";
  auto llvm_cmake_dir = script_dir / "cmake" / "llvm";
  auto llvm_install_dir = llvm_build_dir / "install";
  if (fs::exists(llvm_install_dir)) {
    std::println("LLVM has already been built and installed.");
  } else {
#if __WIN__
    // pre-build patch
    patch_llvm_abi(script_dir.string() +
                   "/third/llvm-project/llvm/include/llvm/"
                   "ExecutionEngine/Orc/BacktraceTools.h");
#endif

    command("cmake -S {} -B {} -G Ninja -DICPP_INSTALL_DIR={} {}",
            dqpath(llvm_cmake_dir), dqpath(llvm_build_dir), dqpath(icpp_dir),
            EXTRA_CMAKE);

    command("cmake --build {} --target install", dqpath(llvm_build_dir));

#if __WIN__
    // post-install patch
    patch_float_sema(llvm_install_dir.string() + "/include/llvm/ADT/APFloat.h");
    patch_error_id(llvm_install_dir.string() + "/include/llvm/Support/Error.h");
    patch_undef_llvm_abi(llvm_install_dir.string() +
                         "/include/llvm/Support/Compiler.h");

#endif
  }

  std::println("Phase 2: Build AetherBinary...");

  auto build_type = "Release";
  if (argc > 1) {
    build_type = argv[1];
#if __WIN__
    build_type = "RelWithDebInfo";
#endif
  }

  auto aether_binary_build_dir =
      script_dir / (std::string("build") + "-" + build_type);
  if (!fs::exists(aether_binary_build_dir / "build.ninja"))
    command("cmake -S {} -B {} -G Ninja -DCMAKE_BUILD_TYPE={} "
            "-DCMAKE_PREFIX_PATH={} -DCMAKE_INSTALL_PREFIX={} "
            "-DLLVM_BUILD_DIR={} -DICPP_INSTALL_DIR={} {}",
            dqpath(script_dir), dqpath(aether_binary_build_dir), build_type,
            dqpath(llvm_build_dir, "install"),
            dqpath(aether_binary_build_dir, "install"),
            dqpath(llvm_build_dir, "llvm"), dqpath(icpp_dir), EXTRA_CMAKE);
  command("cmake --build {} --target install", dqpath(aether_binary_build_dir));

  std::println("Build completed.");
  return 0;
}
