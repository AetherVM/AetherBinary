// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

#include "AetherPE.h"
#include "AetherBinaryPriv.hpp"

#include <llvm/DebugInfo/PDB/IPDBRawSymbol.h>
#include <llvm/DebugInfo/PDB/IPDBSession.h>
#include <llvm/DebugInfo/PDB/IPDBSourceFile.h>
#include <llvm/DebugInfo/PDB/PDB.h>
#include <llvm/DebugInfo/PDB/PDBSymbolCompiland.h>
#include <llvm/Object/COFF.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>

#if defined(_WIN32)
#include <Windows.h>
#endif

#define obj ((object::COFFObjectFile *)llvmbin)

using namespace llvm;

namespace aether {

PEBinary::PEBinary() { m_filetype = PE; }

PEBinary::~PEBinary() {
  if (m_attach)
    return;

  if (m_llvmbin) {
    delete (object::COFFObjectFile *)m_llvmbin;
    m_llvmbin = nullptr;
  }
}

void PEBinary::initBaseAddr(const void *llvmbin) {
  if (obj->is64()) {
    const object::pe32plus_header *pehdr;
#if LLVM_VERSION_MAJOR >= 11
    pehdr = obj->getPE32PlusHeader();
#else
    pehdr = obj->getPE32PlusHeader(pehdr);
#endif
    m_baseaddr = pehdr ? (uint64_t)pehdr->ImageBase : 0ull;
  } else {
    const object::pe32_header *pehdr;
#if LLVM_VERSION_MAJOR >= 11
    pehdr = obj->getPE32Header();
#else
    pehdr = obj->getPE32Header(pehdr);
#endif
    m_baseaddr = pehdr ? (uint32_t)pehdr->ImageBase : 0u;
  }
}

void PEBinary::initImports(const void *llvmbin) {}

std::vector<const char *> Binary::importPELibs() const {
  std::vector<const char *> result;
  return result;
}

bool PEBinary::analyze(const void *llvmbin) {
  if (!Binary::analyze(llvmbin)) {
    return false;
  }
  auto mbr = objbase->getMemoryBufferRef();
  if (m_sects.size() == 1) {
    // fix .obj sections
    uint64_t textoff = 0;
    m_sects.clear();
    m_sectbuffs.clear();
    for (auto sect : objbase->sections()) {
      StringRef buff, name;
#if LLVM_VERSION_MAJOR >= 11
      auto expBuff = sect.getContents();
      auto expName = sect.getName();
      if (expBuff && expName) {
        buff = expBuff.get();
        name = expName.get();
      } else {
        abort();
      }
#else
      sect.getContents(buff);
      sect.getName(name);
#endif
      int align = 4;
      if (archType() == ARM64 || archType() == X86_64) {
        align = 8;
      }
      while (textoff % align) {
        textoff++;
      }

      auto &newsect =
          m_sects.insert(std::make_pair(textoff, Section())).first->second;
      newsect.addr = textoff;
      newsect.foff = (buff.data() == nullptr)
                         ? textoff
                         : (buff.data() - mbr.getBufferStart());
      newsect.size = sect.getSize();
      if (!newsect.size) {
        // give it a fake size to differ addr/foff
        newsect.size = 8;
      }
      if (sect.isText()) {
        newsect.type = TEXT;
      } else {
        newsect.type = DATA;
      }
      newsect.name = name.data();

      m_sectbuffs.insert(
          std::make_pair(textoff, mbr.getBufferStart() + newsect.foff));
      textoff += newsect.size;
    }
    parseSymtab(llvmbin);
  }

  for (auto &exp : obj->export_directories()) {
    uint32_t rva;
    auto err = exp.getExportRVA(rva);
    if (err) {
      continue;
    }
    addr_t fnaddr = m_baseaddr + rva;
    if (!isCode(fnaddr)) {
      continue;
    }
    StringRef name;
#if LLVM_VERSION_MAJOR >= 22
    err = exp.getSymbolName(name);
    if (err) {
      continue;
    }
#else
    exp.getSymbolName(name);
#endif
    auto &newfunc =
        m_funcs.insert(std::make_pair(fnaddr, Function())).first->second;
    newfunc.start = fnaddr;
    if (name.size()) {
      newfunc.name = name.data();
      newfunc.flags |= MFF_EXPORT;
    } else {
      strfmt(newfunc.name, "expt_" ADDRFMT "", newfunc.start);
    }
  }

#if defined(_WIN32)
  static bool coinited = false;
  if (!coinited) {
    coinited = true;
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  }
  auto rawpath = mbr.getBufferIdentifier();
  auto stemname = sys::path::stem(rawpath);
  auto pdbpath =
      (sys::path::parent_path(rawpath) + "/" + stemname + ".pdb").str();
  if (!sys::fs::exists(pdbpath)) {
    return true;
  }
  std::unique_ptr<pdb::IPDBSession> session;
  auto err = pdb::loadDataForPDB(pdb::PDB_ReaderType::DIA, pdbpath, session);
  if (err) {
    return true;
  }
  std::unique_ptr<pdb::IPDBEnumSourceFiles> srcfiles =
      session->getAllSourceFiles();
  if (!srcfiles) {
    return true;
  }
  int prog = 1, progtmp;
  char progprefix[128];
  sprintf(progprefix, AETHER_LIB_NAME " is parsing %s's pdb symbols",
          stemname.data());
  uint32_t srccount = srcfiles->getChildCount();
  for (uint32_t i = 0; i < srccount; i++) {
    auto src = srcfiles->getChildAtIndex(i);
    auto filename = src->getFileName();
    analyze_progress(progprefix, prog++, (int)srccount, progtmp);
    // .c .cc .cpp .cxx
    bool issrc = false;
    if (*(short *)(filename.data() + filename.size() - 2) == *(short *)".c" ||
        *(short *)(filename.data() + filename.size() - 3) == *(short *)".c" ||
        *(short *)(filename.data() + filename.size() - 4) == *(short *)".c") {
      issrc = true;
    }
    if (!issrc) {
      continue;
    }
    std::unique_ptr<pdb::IPDBEnumChildren<pdb::PDBSymbolCompiland>>
        symcompilands = src->getCompilands();
    for (uint32_t j = 0; j < symcompilands->getChildCount(); j++) {
      auto sym = symcompilands->getChildAtIndex(j);
      auto symchilds = sym->findAllChildren(pdb::PDB_SymType::Function);
      for (uint32_t k = 0; k < symchilds->getChildCount(); k++) {
        auto pdbsym = symchilds->getChildAtIndex(k);
        const pdb::IPDBRawSymbol &rawsym = pdbsym->getRawSymbol();
        auto va = m_baseaddr + rawsym.getVirtualAddress();
        auto found = m_funcs.find(va);
        if (found == m_funcs.end()) {
          found = m_funcs.insert({va, Function()}).first;
        }
        found->second.start = va;
        found->second.name = rawsym.getName();
      }
    }
  }
#endif
  return true;
}

PEX32Binary::PEX32Binary() { m_archtype = X86; }

PEX32Binary::~PEX32Binary() {}

bool PEX32Binary::analyze(const void *llvmbin) {
  if (!PEBinary::analyze(llvmbin)) {
    return false;
  }
  BinaryCommop<PEX32Binary> commop(this);
  return commop.analyze(
      llvmbin, m_llvmbin->getMemoryBufferRef().getBufferIdentifier().data(),
      objbase->isRelocatableObject());
}

PEX64Binary::PEX64Binary() { m_archtype = X86_64; }

PEX64Binary::~PEX64Binary() {}

bool PEX64Binary::analyze(const void *llvmbin) {
  if (!PEX32Binary::analyze(llvmbin)) {
    return false;
  }
  return true;
}

PEARM64Binary::PEARM64Binary() { m_archtype = ARM64; }

PEARM64Binary::~PEARM64Binary() {}

bool PEARM64Binary::analyze(const void *llvmbin) {
  if (!PEBinary::analyze(llvmbin)) {
    return false;
  }
  BinaryCommop<PEARM64Binary> commop(this);
  return commop.analyze(
      llvmbin, m_llvmbin->getMemoryBufferRef().getBufferIdentifier().data(),
      objbase->isRelocatableObject());
}

} // namespace aether
