// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

#pragma once

#include "../include/AetherBinary.h"
#include "../include/Disassembler.h"
#include <icpp.hpp>

#if __APPLE__
static const char *aether_name = "libAetherBinary.dylib";
static const char *lib_dir = "lib";
#elif __linux__
static const char *aether_name = "libAetherBinary.so";
static const char *lib_dir = "lib";
#else
static const char *aether_name = "AetherBinary.dll";
static const char *lib_dir = "bin";
#endif

import std;
namespace fs = std::filesystem;

static bool load_libraries(std::string_view script_file) {
  auto script_path = fs::absolute(script_file);
  auto script_dir = script_path.parent_path();
  auto proj_dir = script_dir.parent_path();
  for (std::string_view type :
       {"build-Debug", "build-RelWithDebInfo", "build-Release"}) {
    auto libaether = proj_dir / type / aether_name;
    if (fs::exists(libaether)) {
      if (icpp::load_library(libaether.string()))
        break;
      std::println("Failed to load {}", libaether.string());
      return false;
    }
  }
  return true;
}
