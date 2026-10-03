// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

/*
Build AetherBinary for Android in one go, usage:
  icpp build-android.cc -ndk=/path/to/android-ndk -icpp=/path/to/icpp
       [-type=Release -arch=arm64-v8a]
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

std::string toolchain_file(std::string_view ndk) {
  return std::format("{}/build/cmake/android.toolchain.cmake", ndk);
}

std::string get_host_triple() {
  return std::string{icpp::arch} +
#if __WIN__
         "-pc-windows-msvc"
#elif __LINUX__
         "-pc-linux-gnu"
#else
         "-apple-darwin"

#endif
      ;
}

icpp::strings common_args(std::string_view ndk, std::string_view type,
                          std::string_view arch, std::string_view libcxx_dir) {
  std::string link_flags = std::format("-nostdlib++ -L{}/lib", libcxx_dir);
  icpp::strings args;
  args.push_back(std::format("-DCMAKE_TOOLCHAIN_FILE={}", toolchain_file(ndk)));
  args.push_back(std::format("-DCMAKE_BUILD_TYPE={}", type));
  args.push_back("-DCMAKE_CROSSCOMPILING=TRUE");
  args.push_back("-DLLVM_COMPILER_CHECKED=TRUE");
  args.push_back("-DANDROID_STL=none");
  args.push_back("-G");
  args.push_back("Ninja");
  args.push_back("-DANDROID_PLATFORM=25");
  args.push_back(std::format("-DANDROID_ABI={}", arch));
  args.push_back(
      std::format("-DCMAKE_CXX_FLAGS=\"-nostdinc++ -nostdlib++ -fPIC "
                  "-I{}/include/c++/v1\"",
                  libcxx_dir));
  args.push_back(std::format("-DCMAKE_EXE_LINKER_FLAGS=\"{}\"", link_flags));
  args.push_back(std::format("-DCMAKE_SHARED_LINKER_FLAGS=\"{}\"", link_flags));
  args.push_back("-DCMAKE_CXX_STANDARD_LIBRARIES=\"-Wl,-Bdynamic -lc++ "
                 "-lc++abi -lunwind\"");
  args.push_back("-Wno-deprecated");
  return args;
}

void install_llvm(std::string_view thisdir, std::string_view installdir) {
  auto base_path = fs::path(thisdir);
  auto install_path = fs::path(installdir);

  fs::copy(base_path / "build-llvm/install", install_path,
           fs::copy_options::recursive | fs::copy_options::overwrite_existing);

  auto llvm_lib_src = install_path.parent_path() / "llvm/lib";
  auto lib_dest = install_path / "lib";

  if (fs::exists(llvm_lib_src)) {
    for (const auto &entry : fs::directory_iterator(llvm_lib_src)) {
      auto ext = entry.path().extension();
      if (ext == ".so" || ext == ".a") {
        fs::copy_file(entry.path(), lib_dest / entry.path().filename(),
                      fs::copy_options::overwrite_existing);
      }
    }
  }

  auto header_src =
      install_path.parent_path() / "llvm/include/llvm/Config/abi-breaking.h";
  auto header_dest = install_path / "include/llvm/Config/abi-breaking.h";
  fs::copy_file(header_src, header_dest, fs::copy_options::overwrite_existing);
}

} // namespace

int main(int argc, const char *argv[]) {
  if (argc == 1) {
    std::println("Usage: {} -ndk=/path/to/ndk -icpp=/path/to/icpp "
                 "[-type=Release|Debug] [-arch=arm64-v8a|x86_64]\n",
                 argv[0]);
    return 0;
  }
  std::string_view ndk, icpp, type{"Release"}, arch{"arm64-v8a"};
  for (int i = 1; i < argc; ++i) {
    std::string_view arg{argv[i]};
    if (arg.starts_with("-ndk="))
      ndk = arg.substr(5);
    else if (arg.starts_with("-icpp="))
      icpp = arg.substr(6);
    else if (arg.starts_with("-type="))
      type = arg.substr(6);
    else if (arg.starts_with("-arch="))
      arch = arg.substr(6);
  }
  if (ndk.empty() || icpp.empty()) {
    std::println(
        "Error: -ndk for android ndk and -icpp for icpp project are required.");
    return 1;
  }

  // build libcxx
  auto cxxconf = fs::path(icpp) / "cmake/cxxconf";
  auto libcxx_build = cxxconf / std::format("build-{}", arch);
  auto libcxx = libcxx_build / "lib/libc++.so";
  if (!fs::exists(libcxx)) {
    auto toolchain = toolchain_file(ndk);
    std::vector<const char *> args;
    args.push_back(toolchain.data());
    args.push_back(arch.data());
    icpp::exec_source((cxxconf / "android.cc").string(), (int)args.size(),
                      args.data());
    if (!command("cmake", {"--build", libcxx_build.string()}))
      return -1;
  }

  // build LLVM
  auto thisfile = fs::absolute(argv[0]);
  auto thisdir = thisfile.parent_path().string();
  auto build_llvm = std::format("{}/build-android-{}-llvm", thisdir, arch);
  if (!fs::exists(fs::path(build_llvm) / "llvm/lib/libLLVM.so")) {
    auto args = common_args(ndk, "Release", arch, libcxx_build.string());
    args.push_back(std::format(
        "-DLLVM_TABLEGEN={}/build-llvm/llvm/bin/llvm-tblgen" EXE_EXT, thisdir));
    args.push_back(std::format("-DLLVM_HOST_TRIPLE={}", get_host_triple()));
    args.push_back("-DLLVM_ENABLE_LIBCXX=ON");
    args.push_back("-DLLVM_INCLUDE_TESTS=OFF");
    args.push_back("-DHAVE_CXX_ATOMICS64_WITHOUT_LIB=ON");
    args.push_back("-DHAVE_CXX_ATOMICS_WITHOUT_LIB=ON");
    args.push_back("-B");
    args.push_back(build_llvm);
    args.push_back(thisdir + "/cmake/llvm");
    if (!command("cmake", args))
      return -1;
    if (!command("cmake", {"--build", build_llvm, "--target", "LLVM"}))
      return -1;
    // construct an install package from host one for Android as the official
    // LLVM's cmake script doesn't support it
    install_llvm(thisdir, build_llvm + "/install");
  }

  // build AetherBinary
  auto build_aebi = std::format("{}/build-android-{}-{}", thisdir, arch, type);
  auto ninja = (fs::path(build_aebi) / "build.ninja").string();
  if (!fs::exists(ninja)) {
    auto args = common_args(ndk, type, arch, libcxx_build.string());
    args.push_back(std::format("-DCMAKE_PREFIX_PATH={}/install", build_llvm));
    args.push_back(std::format("-DLLVM_BUILD_DIR={}/llvm", build_llvm));
    args.push_back(
        std::format("-DCMAKE_INSTALL_PREFIX={}/install", build_aebi));
    args.push_back("-B");
    args.push_back(build_aebi);
    args.push_back(thisdir);
    if (!command("cmake", args))
      return -1;
  }
  return command("cmake",
                 icpp::strings{"--build", build_aebi, "--target", "install"})
             ? 0
             : -1;
}
