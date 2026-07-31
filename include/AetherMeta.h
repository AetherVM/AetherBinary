// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

#pragma once

#include <map>
#include <set>
#include <string>
#include <vector>

#include "CommDef.h"

namespace aether {

enum FileType {
  UnsupportFile,
  MachO,
  ELF,
  PE,
};

enum FormatType {
  Raw,
  Object,
  Executable,
  Library,
};

enum ArchType {
  UnsupportArch,
  ARMV5TE,
  ARM,
  ARM64,
  X86,
  X86_64,
};

enum SectType {
  TEXT,
  DATA,
};

enum InsnType {
  IDATA,
  NORMAL,
  JUMP,
  JCOND,
  CALL,
  RET,
  TRAP,
  SYSCALL,
};

struct __AETHER_API__ Section {
  std::string name;
  SectType type;
  size_t foff;
  size_t size;
  addr_t addr;

  void dump() const;
};
typedef std::map<addr_t, Section> Sections;
typedef std::map<addr_t, const char *> SectionBuffs;

struct __AETHER_API__ Import {
  std::string name;
  size_t foff; // got/lazyptr fileoff
  int lib;

  void dump() const;
};
typedef std::vector<Import> Imports;

struct ImportInfos {
  std::vector<std::string> libs;
  std::vector<std::string> importfns;
  std::vector<size_t> importfoffs;
};

struct ExportInfos {
  std::vector<std::string> exports;
  std::vector<addr_t> exportrvas;
};

struct Insinfo;
typedef std::vector<Insinfo> Insinfos;
typedef std::vector<int> Insrefs;
typedef std::map<int, int> Loops;
typedef std::set<addr_t> Addresses;
struct Insinfo {
  struct {
    unsigned short type;
    unsigned short oplen;
  } info;
  int fnoff;
  Insrefs comins;
  Insrefs gouts;

  bool operator<(const Insinfo &I) const { return fnoff < I.fnoff; }
  const char *typeString() const;
};

struct OpcodeInfo {
  bool vfp;
  bool pcrel;
  bool lrref;
  bool synclock;   // like arm64 ldxr
  bool syncunlock; // like stxr/clrex
  bool acquire;    // like arm64 ldar
  bool release;    // like stlr
  bool bcc;        // b.cond
  bool tbznz;      // tbz/tbnz
  bool cbznz;      // cbz/cbnz
  bool ldstrui;    // ldr/str uimm
  bool keeprv;     // keep register value unchanged
};

struct __AETHER_API__ Function {
  std::string name;
  addr_t start;
  addr_t end;
  Insinfos insns;
  Loops loops;
  Insrefs rets;    // return s
  Addresses getpc; // call $+5
  Addresses difs;  // data in functions
  Addresses jdsts; // jump destination in functions
  int flags;       // MFF_xxx

  Function() {
    start = INVALID_ADDR;
    end = INVALID_ADDR;
    flags = 0;
  }

  Function(const Function &F) {
    name = F.name;
    start = F.start;
    end = F.end;
    insns = F.insns;
    loops = F.loops;
    rets = F.rets;   // return s
    getpc = F.getpc; // call $+5
    difs = F.difs;   // data in functions
    jdsts = F.jdsts; // jump destination in functions
    flags = F.flags; // MFF_xxx
  }

  bool isData() const {
    return insns.size() == 1 && insns[0].info.type == IDATA;
  }

  void reset() {
    insns.clear();
    loops.clear();
    rets.clear();
    getpc.clear();
    difs.clear();
    jdsts.clear();
  }

  bool operator<(const Function &F) const { return start < F.start; }
  bool operator==(const Function &F) const { return start == F.start; }

  Function &operator=(const Function &F) {
    name = F.name;
    start = F.start;
    end = F.end;
    insns = F.insns;
    loops = F.loops;
    rets = F.rets;   // return s
    getpc = F.getpc; // call $+5
    difs = F.difs;   // data in functions
    jdsts = F.jdsts; // jump destination in functions
    flags = F.flags; // MFF_xxx
    return *this;
  }

  void dump() const;
};
typedef std::map<addr_t, Function> Functions;
typedef std::map<addr_t, Function *> ImportFunctions;

} // namespace aether
