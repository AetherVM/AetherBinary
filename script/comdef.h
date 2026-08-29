// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

#pragma once

#include "include/AetherOther.h"

#include <icpp.hpp>

#define BINENV "AetherBinary"

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

static bool load_libraries(std::string_view script_file,
                           aether::analyze_log_t log_print = std::printf) {
  auto script_path = fs::absolute(script_file);
  auto script_dir = script_path.parent_path();
  for (auto libname : {aether_name}) {
    auto lib = script_dir / lib_dir / libname;
    if (!icpp::load_library(lib.string())) {
      log_print("Failed to load %s", lib.string().c_str());
      return false;
    }
  }
  aether::setAnalyzeCallback(log_print, nullptr);
  return true;
}
