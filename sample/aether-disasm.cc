// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

/*
Usage: /path/to/icpp aether-disasm.cc arch hex-byte-string
  e.g.: /path/to/icpp aether-disasm.cc x86_64 90
*/

#include "aether-comm.h"

static std::vector<uint8_t> hex_to_bytes(std::string_view hex) {
  std::vector<uint8_t> bytes;
  if (hex.length() % 2 != 0) {
    std::println("Hex string must have an even length.");
    return bytes;
  }
  bytes.reserve(hex.length() / 2);

  auto hex_char_to_val = [](char ch) -> int {
    if (ch >= '0' && ch <= '9')
      return ch - '0';
    if (ch >= 'A' && ch <= 'F')
      return ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f')
      return ch - 'a' + 10;
    std::println("Invalid character found in hex string: {}", ch);
    return 0;
  };

  for (size_t i = 0; i < hex.length(); i += 2) {
    int high_nibble = hex_char_to_val(hex[i]);
    int low_nibble = hex_char_to_val(hex[i + 1]);
    bytes.push_back(static_cast<uint8_t>((high_nibble << 4) | low_nibble));
  }

  return bytes;
}

int main(int argc, const char *argv[]) {
  if (argc < 3) {
    std::println("Usage: {} arm64|arm|thumb|x86|x86_64 hex-byte-string",
                 argv[0]);
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
  auto bytes = hex_to_bytes(argv[2]);
  if (!bytes.size()) {
    return -1;
  }
  for (auto i = 0; i < bytes.size();) {
    std::string asmcode;
    auto opclen = diser.disassemble(&bytes[i], bytes.size() - i, asmcode);
    if (!opclen) {
      std::println("Failed to disassemble at offset 0x{:x}: {}", i, asmcode);
      return -1;
    }
    std::string opcode;
    for (auto o = i; o < i + opclen; o++)
      opcode += std::format("{:x} ", bytes[o]);
    std::println("0x{:04x}: {:16} {}", i, opcode, asmcode);
    i += opclen;
  }
  return 0;
}
