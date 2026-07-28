// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

/*
Usage: /path/to/icpp aether-asm.cc arch asm-code
  e.g.: /path/to/icpp aether-asm.cc arm64 "mov x16, #0; svc #80"
*/

#include "aether-comm.h"

static std::vector<std::string> string_split(std::string_view str,
                                             std::string_view split) {
  std::vector<std::string> result;
  size_t start = 0;
  size_t end = str.find(split, start);
  while (end != std::string_view::npos) {
    // Extract the substring from 'start' to 'end'
    result.emplace_back(str.substr(start, end - start));

    // Move 'start' past the splitter
    start = end + split.length();

    // Find the next occurrence of the splitter
    end = str.find(split, start);
  }
  // Add the last part of the string (or the whole string if no splitter was
  // found)
  result.emplace_back(str.substr(start));
  return result;
}

int main(int argc, const char *argv[]) {
  if (argc < 3) {
    std::println("Usage: {} arm64|arm|thumb|x86|x86_64 asm-code", argv[0]);
    return 1;
  }
  // load LLVM and AetherBinary libraries, so we can use their APIs directly
  // within ICPP runtime environment.
  if (!load_libraries(argv[0]))
    return -1;

  aether::Disassembler diser(argv[1]);
  if (!diser.ready()) {
    std::println("Failed to initialize the disassembler for {}", argv[1]);
    return -1;
  }
  auto insns = string_split(argv[2], ";");
  for (auto &inst : insns) {
    unsigned char binopcode[20];
    auto error = diser.assemble(inst.data(), binopcode);
    std::string stropcode;
    if (binopcode[0]) {
      for (auto o = 1; o <= binopcode[0]; o++)
        stropcode += std::format("{:02x} ", binopcode[o]);
    } else {
      stropcode = "?? ??";
    }
    std::println("{:16} {}", stropcode, inst);
  }
  return 0;
}
