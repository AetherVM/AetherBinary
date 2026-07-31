// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

#pragma once

#include <assert.h>
#include <memory>
#include <string.h>

#include "AetherArch.h"
#include "AetherFile.h"
#include "AetherMeta.h"

namespace llvm {
namespace object {
class Binary;
}
class MemoryBuffer;
} // namespace llvm

namespace aether {

typedef void (*analyze_progress_t)(const char *prefix, int cur, int max,
                                   int &tmp);
typedef int (*analyze_log_t)(const char *format, ...);

class __AETHER_API__ Binary {
public:
  Binary();
  virtual ~Binary();

  bool isCode(addr_t addr) const;
  bool isTextCode(addr_t addr) const;
  const Function *addrFunc(addr_t addr, bool eq = false) const;
  const Section *addrSect(addr_t addr) const;
  const Section *nameSect(const char *name) const;
  const char *addrBuff(addr_t addr) const;

  bool valid() const;
  bool load(const char *dbpath);
  bool save(const char *dbpath, bool compress = false);
  void dump() const;
  void dump(addr_t start, addr_t end = 0) const;
  const char *triple(bool thumb = false) const;
  const char *arch(bool thumb = false) const;
  static const char *arch(ArchType arch, bool thumb = false);

  void holdBuffer(void *llvmbin, void *filebuff);

  FileType fileType() const { return m_filetype; }
  const char *fileTypeString() const;

  FormatType formatType() const;

  ArchType archType() const { return m_archtype; }
  const char *archTypeString() const;
  int defaultInsnSize() const;

  Disassembler *diser() const { return m_diser; }

  Disassembler *diserThumb() const { return m_diserthumb; }

  unsigned fileHash() const { return m_filehash; }

  const Sections &sections() const { return m_sects; }

  const SectionBuffs &sectBuffers() const { return m_sectbuffs; }

  const Functions &functions() const { return m_funcs; }
  Functions &functions() { return m_funcs; }

  const Imports &imports() const { return m_imports; }

  const ImportFunctions &importFunctions() const { return m_impfuncs; }

  std::vector<const char *> importLibs() const;
  std::vector<const char *> importMachOLibs() const;
  std::vector<const char *> importELFLibs() const;
  std::vector<const char *> importPELibs() const;

  void readObj(std::string &outs) const;

  unsigned importStubsStart() const { return m_imp_stubs_index; }

  addr_t imageBase() const { return m_baseaddr; }

  llvm::object::Binary *llvmBinary() const { return m_llvmbin; }

  const char *filePath() const;
  const char *fileBuffer(size_t &size) const;

  virtual bool analyze(const void *llvmbin);
  virtual bool isArm64e() const { return false; }
  virtual bool hasFuncStarts() const { return false; }

  void funcAnalyze(Disassembler *diser, const char *fnbuff, Function &func);
  addr_t rewriteFunction(addr_t rtbase, addr_t entry, Function *fn,
                         char *fnbuff, const char *fnrawbuff, const void *regs,
                         std::map<int, int> &rvamap);

  InsnType opcodeType(Disassembler *diser, const char *opcode, ArchType arch,
                      int *size = nullptr, OpcodeInfo *opinfo = nullptr);
  std::vector<std::set<int>>
  matchTemplate(const std::vector<const char *> *insns, int count,
                std::string &err);
  // for arm64
  uint32_t genBranchOpcode(addr_t from, addr_t to, bool call = false) const;
  // for x86
  void patchCallOffset(char *opcptr, addr_t from, addr_t to) const;
  void interateSymbols(void (*callback)(void *ctx, const char *name,
                                        addr_t addr),
                       void *ctx);

  static analyze_progress_t analyze_progress;
  static analyze_log_t analyze_log;

protected:
  bool init();
  virtual void initBaseAddr(const void *llvmbin) = 0;
  virtual void initImports(const void *llvmbin) = 0;
  void parseSymtab(const void *llvmbin, bool dwarf = false);
  void mergeFunc(std::set<addr_t> &newfunc);

  addr_t rewriteFunctionImpl(addr_t rtbase, addr_t entry, Function *fn,
                             char *fnbuff, const char *fnrawbuff,
                             const void *regs, std::map<int, int> &rvamap,
                             std::map<int, int> &rvaorig2new);

protected:
  FileType m_filetype;
  ArchType m_archtype;
  unsigned m_filehash;
  Sections m_sects;
  SectionBuffs m_sectbuffs;
  Functions m_funcs;
  Imports m_imports;
  ImportFunctions m_impfuncs;
  unsigned m_imp_stubs_index;
  addr_t m_baseaddr;

  Disassembler *m_diser;
  Disassembler *m_diserthumb;

private:
  size_t stringSize();
  size_t insnSize();

protected:
  llvm::MemoryBuffer *m_filebuff;
  int m_fileoff; // for fat file, it's the offset for the real macho
  llvm::object::Binary *m_llvmbin;
};

__AETHER_API__ void setAnalyzeCallback(analyze_log_t log,
                                       analyze_progress_t prog);
__AETHER_API__ Binary *New(const char *path, const char *triple = nullptr,
                           bool analyze = true);
__AETHER_API__ Binary *New(std::string_view objbuf,
                           std::string_view name = "memory-object",
                           bool analyze = true);
__AETHER_API__ Binary *New(std::unique_ptr<llvm::MemoryBuffer> buff,
                           bool analyze = true);
__AETHER_API__ void Delete(Binary *bin);

__AETHER_API__ void compressDBFile(const char *dbpath);
__AETHER_API__ AebiFile *uncompressDBFile(const char *dbpath);
__AETHER_API__ bool compressBuffer(const char *buff, int size,
                                   std::string *out);
__AETHER_API__ bool uncompressBuffer(const char *buff, int size, int realsize,
                                     std::string *out);

__AETHER_API__ const char *getVersion();

} // namespace aether
