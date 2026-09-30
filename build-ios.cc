// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

/*
Build AetherBinary for iOS in one go, usage: icpp build-ios.cc [Debug]
*/

#include <icpp.hpp>

namespace {

bool command(std::string_view proc, const icpp::strings &args) {
  std::string cmd{proc};
  for (auto &a : args)
    cmd += " " + a;

  std::println("{}", cmd);
#if 1
  return std::system(cmd.data()) == 0;
#else
  return true;
#endif
}

icpp::strings common_args(std::string_view thisdir) {
  icpp::strings args;
  auto toolchain =
      (fs::path(thisdir) / "third/ios-cmake/ios.toolchain.cmake").string();
  args.push_back(std::format("-DCMAKE_TOOLCHAIN_FILE={}", toolchain));
  args.push_back(std::format("-DCMAKE_CROSSCOMPILING=TRUE"));
  args.push_back("-G");
  args.push_back("Ninja");
  args.push_back("-DCMAKE_MACOSX_BUNDLE=NO");
  args.push_back("-DPLATFORM=OS64");
  args.push_back("-DDEPLOYMENT_TARGET=16.5");
  args.push_back("-Wno-deprecated");
  return args;
}

bool patch_string(std::string_view infile, std::string_view pattern,
                  std::string_view replace) {
  std::stringstream buffer;
  {
    // read file
    buffer << std::ifstream(fs::path(infile), std::ios::in | std::ios::binary)
                  .rdbuf();
  }

  std::string content = buffer.str();
  std::size_t pos = 0;
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
    outf.write(content.data(), content.size());
  }

  // rename the temp as the original file
  fs::rename(temp_file, infile);
  return true;
}

void patch_build_ninja(std::string_view ninja) {
  // iPhoneSDK doesn't provide these libraries
  patch_string(ninja, "-latomic", " ");
  patch_string(ninja, "-lrt", " ");
}

} // namespace

int main(int argc, const char *argv[]) {
  auto thisfile = fs::absolute(argv[0]);
  auto thisdir = thisfile.parent_path().string();
  auto type = argc > 1 ? argv[1] : "Release";
  std::string_view builddir{"build-ios"};

  // build LLVM
  auto build_llvm = std::format("{}/{}-llvm", thisdir, builddir);
  if (!fs::exists(fs::path(build_llvm) / "llvm/lib/libLLVM.dylib")) {
    auto args = common_args(thisdir);
    args.push_back(std::format(
        "-DLLVM_TABLEGEN={}/build-llvm/llvm/bin/llvm-tblgen", thisdir));
    args.push_back("-B");
    args.push_back(build_llvm);
    args.push_back(thisdir + "/cmake/llvm");
    if (!command("cmake", args))
      return -1;
    patch_build_ninja(build_llvm + "/build.ninja");
    if (!command("cmake", {"--build", build_llvm, "--target", "LLVM"}))
      return -1;
    // construct an install package from host one for iOS as the official LLVM's
    // cmake script doesn't support it
    auto installdir = build_llvm + "/install";
    std::system(
        std::format(
            "cd {0}; mkdir -p {1}/lib; cp -r build-llvm/install/bin {1}/; cp "
            "-r build-llvm/install/include {1}/; "
            "cp -r build-llvm/install/lib/cmake {1}/lib/; cp "
            "{1}/../llvm/lib/*.dylib {1}/lib/; cp {1}/../llvm/lib/*.a "
            "{1}/lib/; touch {1}/lib/libLTO.dylib",
            thisdir, installdir)
            .data());
  }

  // build AetherBinary
  auto build_aebi = std::format("{}/{}.{}", thisdir, builddir, type);
  auto ninja = (fs::path(build_aebi) / "build.ninja").string();
  if (!fs::exists(ninja)) {
    auto args = common_args(thisdir);
    args.push_back(std::format("-DCMAKE_BUILD_TYPE={}", type));
    args.push_back(std::format("-DCMAKE_PREFIX_PATH={}/install", build_llvm));
    args.push_back(std::format("-DLLVM_BUILD_DIR={}/llvm", build_llvm));
    args.push_back(std::format("-DCMAKE_INSTALL_PREFIX={}", build_aebi));
    args.push_back("-B");
    args.push_back(build_aebi);
    args.push_back(thisdir);
    if (!command("cmake", args))
      return -1;
    patch_build_ninja(ninja);
  }
  return command("cmake",
                 icpp::strings{"--build", build_aebi, "--target", "install"})
             ? 0
             : -1;
}
