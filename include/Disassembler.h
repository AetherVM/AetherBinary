// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

#pragma once

#include <map>
#include <string>

#include "AetherRegister.h"
#include "CommDef.h"

namespace llvm {
class MCInst;
class raw_ostream;
} // namespace llvm

namespace aether {

typedef bool (*Symbolizer_t)(void *context, llvm::MCInst &inst,
                             llvm::raw_ostream &os, unsigned long long addr,
                             unsigned long long value, int instlen,
                             bool branch);

class __AETHER_API__ Disassembler {
public:
  static Symbolizer_t Symbolizer;
  static void *Symcontext;

public:
  Disassembler(const char *arch);
  Disassembler(const char *arch, const char *triple);
  ~Disassembler();

  bool ready() { return m_ctx != nullptr; }

  int disassemble(unsigned int mc, unsigned long long addr = 0);
  int disassemble(unsigned int mc, std::string &text,
                  unsigned long long addr = 0);
  int disassemble(const unsigned char *mc, int size,
                  unsigned long long addr = 0);
  int disassemble(const unsigned char *mc, int size, std::string &text,
                  unsigned long long addr = 0);
  int disassemble(unsigned int mc, llvm::MCInst &inst,
                  unsigned long long addr = 0);
  int disassemble(const unsigned char *mc, int size, llvm::MCInst &inst,
                  unsigned long long addr = 0);
  int disassemble(const char *asmcode, llvm::MCInst &inst,
                  unsigned long long addr = 0);
  void print(llvm::MCInst &inst);
  void print(llvm::MCInst &inst, std::string &text, int oplen = 0,
             unsigned long long addr = 0);
  uint64_t branchTarget(const unsigned char *mc, uint64_t addr,
                        llvm::MCInst &inst, int oplen,
                        const void *gprs = nullptr, bool *isptr = nullptr);
  uint64_t branchTarget(const unsigned char *mc, uint64_t addr,
                        int *oplen = nullptr, const void *gprs = nullptr,
                        bool *isptr = nullptr);
  bool hitCondA64(const uint64_t *gprs, int n, int z, int c, int v, unsigned mc,
                  llvm::MCInst &inst);
  bool hitCondA32(const uint64_t *gprs, int n, int z, int c, int v, int t,
                  unsigned mc, llvm::MCInst &inst, int oplen);
  bool hitCondA64(const uint64_t *gprs, int n, int z, int c, int v,
                  unsigned mc);
  bool hitCondA32(const uint64_t *gprs, int n, int z, int c, int v, int t,
                  unsigned mc);
  bool hitCondX64(const uint64_t *gprs, uint64_t flags, unsigned char *mc);
  std::string demangle(const char *sym);

  std::string assemble(const char *asmcode, unsigned char opcode[20],
                       bool cache = true);

#define SIMDImm LogicalImm
  enum ImmOperandType {
    ShiftedReg,
    LogicalImm,
    NormalImm,
  };
  struct ImmOperand {
    ImmOperandType type;
    unsigned long long imm;
  };
  static ImmOperand operandImm(unsigned int opcode, unsigned int imm);

  int name(unsigned opc, char str[32]);
  int maxopc();

  uint64_t dstAddr; // destinate address for b/bl/cb/tb/call/jmp

private:
  void *m_ctx;
  const char *m_arch;
  std::map<std::string, std::string> m_asmcache;
};

class Disymboler {
public:
  Disymboler(void *ctx, Symbolizer_t callback) {
    Disassembler::Symbolizer = callback;
    Disassembler::Symcontext = ctx;
  }
  ~Disymboler() {
    Disassembler::Symbolizer = nullptr;
    Disassembler::Symcontext = nullptr;
  }
};

} // namespace aether
