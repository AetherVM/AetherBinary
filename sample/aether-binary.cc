// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

/*
Usage: /path/to/icpp aether-binary.cc /path/to/file
  e.g.: /path/to/icpp aether-binary.cc binary/ios-arm64
*/

#include "aether-comm.h"

int main(int argc, const char *argv[]) {
  if (argc < 2) {
    std::println("Usage: {} /path/to/binary", argv[0]);
    return 1;
  }
  // load LLVM and AetherBinary libraries, so we can use their APIs directly
  // within ICPP runtime environment.
  if (!load_libraries(argv[0]))
    return -1;

  // load and dump the input binary file
  auto bin = aether::New(argv[1]);
  if (!bin) {
    std::println("Failed to parse {}", argv[1]);
    return -1;
  }
  bin->dump();
  aether::Delete(bin);
  return 0;
}
