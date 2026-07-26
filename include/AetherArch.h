// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

#pragma once

#include "AetherMeta.h"

#include <set>

namespace aether {

class Disassembler;
class Binary;

class __AETHER_API__ Machine {
public:
  Machine() {}
  virtual ~Machine() {}

  ArchType archType() const { return m_arch; }

  void analyzeFunc(bool hasfnstarts, Disassembler *diser, const char *opbuff,
                   addr_t start, addr_t end, std::set<addr_t> &newfunc,
                   bool thumb = false, std::set<addr_t> *datas = nullptr);
  void analyzeFunc(Disassembler *diser, bool isobj, const char *opbuff,
                   const char *opbuffend, Function &func, Function *lastfunc,
                   Binary *bin, bool thumb = false,
                   std::set<addr_t> *datas = nullptr);

  virtual int defaultSize() = 0;
  virtual bool isCallReg(void *llvminst) = 0;
  virtual bool isCallMem(void *llvminst) = 0;
  virtual bool isCallPcrel(void *llvminst) = 0;
  virtual bool isJumpReg(void *llvminst) = 0;
  virtual bool isJumpPcrel(void *llvminst) = 0;
  bool isCall(void *llvminst) {
    return isCallPcrel(llvminst) || isCallMem(llvminst) || isCallReg(llvminst);
  }

  virtual InsnType insnType(void *llvminst, OpcodeInfo *opinfo = nullptr) = 0;
  virtual addr_t callee(void *llvminst, int opclen, addr_t pc) = 0;
  virtual addr_t jumpee(void *llvminst, int opclen, addr_t pc) = 0;
  virtual addr_t dstAddr(void *llvminst, int opclen, addr_t pc);

protected:
  ArchType m_arch;
};

class __AETHER_API__ MachineX86 : public Machine {
public:
  MachineX86() { m_arch = X86_64; }
  virtual ~MachineX86() {}

  virtual int defaultSize() { return 1; }

  virtual bool isCallReg(void *llvminst);
  virtual bool isCallMem(void *llvminst);
  virtual bool isCallPcrel(void *llvminst);
  virtual bool isJumpReg(void *llvminst);
  virtual bool isJumpPcrel(void *llvminst);
  virtual InsnType insnType(void *llvminst, OpcodeInfo *opinfo = nullptr);
  virtual addr_t callee(void *llvminst, int opclen, addr_t pc);
  virtual addr_t jumpee(void *llvminst, int opclen, addr_t pc);
};

class __AETHER_API__ MachineARM64 : public Machine {
public:
  MachineARM64() { m_arch = ARM64; }
  virtual ~MachineARM64() {}

  virtual int defaultSize() { return 4; }

  virtual bool isCallReg(void *llvminst);
  virtual bool isCallMem(void *llvminst);
  virtual bool isCallPcrel(void *llvminst);
  virtual bool isJumpReg(void *llvminst);
  virtual bool isJumpPcrel(void *llvminst);
  virtual InsnType insnType(void *llvminst, OpcodeInfo *opinfo = nullptr);
  virtual addr_t callee(void *llvminst, int opclen, addr_t pc);
  virtual addr_t jumpee(void *llvminst, int opclen, addr_t pc);
  virtual addr_t dstAddr(void *llvminst, int opclen, addr_t pc);
};

class __AETHER_API__ MachineARM : public Machine {
public:
  MachineARM() { m_arch = ARM; }
  virtual ~MachineARM() {}

  virtual int defaultSize() { return 4; }

  virtual bool isCallReg(void *llvminst);
  virtual bool isCallMem(void *llvminst);
  virtual bool isCallPcrel(void *llvminst);
  virtual bool isJumpReg(void *llvminst);
  virtual bool isJumpPcrel(void *llvminst);
  virtual InsnType insnType(void *llvminst, OpcodeInfo *opinfo = nullptr);
  virtual addr_t callee(void *llvminst, int opclen, addr_t pc);
  virtual addr_t jumpee(void *llvminst, int opclen, addr_t pc);
  virtual addr_t dstAddr(void *llvminst, int opclen, addr_t pc);
};

} // namespace aether
