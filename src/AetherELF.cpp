// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

#include "AetherELF.h"
#include "AetherBinaryPriv.hpp"
#include "Disassembler.h"

#include <llvm/Object/ELFObjectFile.h>

#define obj ((object::ELFObjectFileBase *)llvmbin)
#define obj32 ((object::ELF32LEObjectFile *)llvmbin)
#define obj64 ((object::ELF64LEObjectFile *)llvmbin)

#define is32Bits() (isa<object::ELF32LEObjectFile>(obj))

using namespace llvm;

namespace aether {

ELFBinary::ELFBinary() { m_filetype = ELF; }

ELFBinary::~ELFBinary() {
  if (m_attach)
    return;

  if (m_llvmbin) {
    if (isa<object::ELF32LEObjectFile>(
            (object::ELFObjectFileBase *)m_llvmbin)) {
      delete (object::ELF32LEObjectFile *)m_llvmbin;
    } else {
      delete (object::ELF64LEObjectFile *)m_llvmbin;
    }
    m_llvmbin = nullptr;
  }
}

template <typename ELFFILE> static addr_t get_baseaddr(const ELFFILE &elffile) {
  addr_t minsegaddr = -1;
  auto phdrs = elffile.program_headers();
  if (!phdrs || !phdrs.get().size()) {
    return 0;
  }
  for (auto p : phdrs.get()) {
    if (p.p_type == ELF::PT_LOAD) {
      if (minsegaddr > p.p_vaddr) {
        minsegaddr = p.p_vaddr;
      }
    }
  }
  return minsegaddr & ~(0x1000 - 1);
}

void ELFBinary::initBaseAddr(const void *llvmbin) {
#if LLVM_VERSION_MAJOR >= 14
  if (is32Bits()) {
    m_baseaddr = get_baseaddr(obj32->getELFFile());
  } else {
    m_baseaddr = get_baseaddr(obj64->getELFFile());
  }
#else
  if (is32Bits()) {
    m_baseaddr = get_baseaddr(*obj32->getELFFile());
  } else {
    m_baseaddr = get_baseaddr(*obj64->getELFFile());
  }
#endif
}

template <typename BIN, typename ELF_REL, typename ELF_SYM>
static void initELFImports(BIN *bin, Functions &funcs, Imports &imps,
                           ImportFunctions &impfuncs, const char *relplt,
                           const char *reldyn, int pltaddroff, int pltentsz,
                           Binary *manabin) {
#if LLVM_VERSION_MAJOR >= 14
  auto Obj = &bin->getELFFile();
#else
  auto Obj = bin->getELFFile();
#endif
  std::vector<object::SectionRef> sects;
  for (auto sect : bin->sections()) {
    sects.push_back(sect);
  }
  for (auto sref : sects) {
    StringRef name;
#if LLVM_VERSION_MAJOR >= 11
    auto expName = sref.getName();
    if (!expName) {
      continue;
    }
    name = expName.get();
#else
    std::error_code err = sref.getName(name);
    if (err) {
      continue;
    }
#endif
    if (name != relplt) {
      continue;
    }
    auto relaplthdr = bin->getSection(sref.getRawDataRefImpl());
    object::SectionRef pltsect;
    if (0 && relaplthdr->sh_info) {
      pltsect = sects[relaplthdr->sh_info];
    } else {
      bool valid = false;
      for (auto si : sects) {
        StringRef siname;
#if LLVM_VERSION_MAJOR >= 11
        auto expSiname = si.getName();
        if (!expSiname) {
          continue;
        }
        siname = expSiname.get();
#else
        std::error_code err = si.getName(siname);
        if (err) {
          continue;
        }
#endif
        if (siname == ".plt") {
          pltsect = si;
          valid = true;
          break;
        }
      }
      if (!valid) {
        return;
      }
    }
    addr_t pltaddr = pltsect.getAddress() + pltaddroff;
    if (!pltaddroff) {
      auto sect = manabin->addrSect(pltaddr);
      if (!sect)
        return;
      const char *pltbuff = manabin->addrBuff(pltaddr);
      MCInst inst;
      addr_t addr12pc_addr2 = 0;
      int discount = 0;
      for (addr_t curaddr = pltaddr;; pltbuff += 4, curaddr += 4) {
        manabin->diser()->disassemble(*(int *)pltbuff, inst);
        if (inst.getOpcode() == ::ARM::ADDri) {
          auto opr0 = inst.getOperand(0);
          auto opr1 = inst.getOperand(1);
          if (opr0.getReg() == ::ARM::R12 && opr1.getReg() == ::ARM::PC) {
            pltaddr = addr12pc_addr2;
            addr12pc_addr2 = curaddr;
            if (pltaddr && addr12pc_addr2) {
              pltaddroff = (int)(pltaddr - pltsect.getAddress());
              pltentsz = (int)(addr12pc_addr2 - pltaddr);
              break;
            }
          }
        }
        if (discount++ > 20) {
          // cannot dynamically calc, set to default value
          pltaddroff = 0x14;
          pltentsz = 0xC;
          pltaddr = pltsect.getAddress() + pltaddroff;
          break;
        }
      }
    }
    StringRef relapltbuff;
#if LLVM_VERSION_MAJOR >= 11
    auto expRelapltbuff = sref.getContents();
    if (!expRelapltbuff) {
      return;
    }
    relapltbuff = expRelapltbuff.get();
#else
    sref.getContents(relapltbuff);
#endif
    auto symtab = sects[relaplthdr->sh_link];
    auto expSymtabbuff = symtab.getContents();
    if (!expSymtabbuff)
      return;
    auto symtabhdr = bin->getSection(symtab.getRawDataRefImpl());
    if (!symtabhdr->sh_entsize)
      return;
    auto symcount = symtabhdr->sh_size / symtabhdr->sh_entsize;
    ELF_SYM *syms = (ELF_SYM *)expSymtabbuff.get().data();
    auto expELFSymTab = Obj->getSection(relaplthdr->sh_link);
    if (!expELFSymTab)
      return;
    Expected<StringRef> StrTableOrErr =
        Obj->getStringTableForSymtab(*expELFSymTab.get());
    if (!StrTableOrErr)
      return;
    const char *strtab = StrTableOrErr.get().data();
    ELF_REL *relaptr = (ELF_REL *)relapltbuff.data();
    for (addr_t r = 0; r < relaplthdr->sh_size / relaplthdr->sh_entsize; r++) {
      int sidx = relaptr[r].getSymbol(false);
      if (sidx < 0 || sidx >= (int)symcount) {
        continue;
      }
      const char *name = strtab + syms[sidx].st_name;
      auto &newfunc =
          funcs.insert(std::make_pair(pltaddr, Function())).first->second;
      newfunc.start = pltaddr;
      newfunc.name = name;
      newfunc.name = "plt." + newfunc.name;
      newfunc.flags |= MFF_IMPORT;
      pltaddr += pltentsz;

      imps.emplace_back(Import());
      auto imp = imps.rbegin();
      imp->foff = relaptr[r].r_offset;
      imp->name = name;
      imp->lib = 0;
    }
    break;
  }
  for (auto sref : sects) {
    StringRef name;
#if LLVM_VERSION_MAJOR >= 11
    auto expName = sref.getName();
    if (!expName) {
      continue;
    }
    name = expName.get();
#else
    std::error_code err = sref.getName(name);
    if (err) {
      continue;
    }
#endif
    if (name != reldyn) {
      continue;
    }
    auto relaplthdr = bin->getSection(sref.getRawDataRefImpl());
    if (relaplthdr->sh_type == ELF::SHT_ANDROID_RELA) {
      // we don't parse android rela currently
      break;
    }
    StringRef relapltbuff;
#if LLVM_VERSION_MAJOR >= 11
    auto expRelapltbuff = sref.getContents();
    if (!expRelapltbuff) {
      return;
    }
    relapltbuff = expRelapltbuff.get();
#else
    sref.getContents(relapltbuff);
#endif
    auto symtab = sects[relaplthdr->sh_link];
    auto expSymtabbuff = symtab.getContents();
    if (!expSymtabbuff)
      return;
    auto symtabhdr = bin->getSection(symtab.getRawDataRefImpl());
    if (!symtabhdr->sh_entsize)
      return;
    auto symcount = symtabhdr->sh_size / symtabhdr->sh_entsize;
    ELF_SYM *syms = (ELF_SYM *)expSymtabbuff.get().data();
    auto expELFSymTab = Obj->getSection(relaplthdr->sh_link);
    if (!expELFSymTab)
      return;
    Expected<StringRef> StrTableOrErr =
        Obj->getStringTableForSymtab(*expELFSymTab.get());
    if (!StrTableOrErr)
      return;
    const char *strtab = StrTableOrErr.get().data();
    ELF_REL *relaptr = (ELF_REL *)relapltbuff.data();
    for (addr_t r = 0; r < relaplthdr->sh_size / relaplthdr->sh_entsize; r++) {
      int sidx = relaptr[r].getSymbol(false);
      if (sidx < 0 || sidx >= (int)symcount) {
        continue;
      }
      const char *name = strtab + syms[sidx].st_name;
      imps.emplace_back(Import());
      auto imp = imps.rbegin();
      imp->foff = relaptr[r].r_offset;
      imp->name = name;
      imp->lib = 0;
    }
    break;
  }
}

template <typename BIN, typename ELF_SYM>
static void parseELFObjSymtab(BIN *bin, Functions &funcs, addr_t textoff) {
#if LLVM_VERSION_MAJOR >= 14
  auto Obj = &bin->getELFFile();
#else
  auto Obj = bin->getELFFile();
#endif
  std::vector<object::SectionRef> sects;
  for (auto sect : bin->sections()) {
    sects.push_back(sect);
  }
  object::SectionRef strtab, symtab;
  int foundcount = 0;
  for (auto sref : sects) {
    StringRef name;
#if LLVM_VERSION_MAJOR >= 11
    auto expName = sref.getName();
    if (!expName) {
      continue;
    }
    name = expName.get();
#else
    std::error_code err = sref.getName(name);
    if (err) {
      continue;
    }
#endif
    if (name == ".strtab") {
      strtab = sref;
      foundcount++;
    } else if (name == ".symtab") {
      symtab = sref;
      foundcount++;
    }
    if (foundcount < 2) {
      continue;
    }

    auto expSymtabbuff = symtab.getContents();
    if (!expSymtabbuff)
      return;
    auto symtabhdr = bin->getSection(symtab.getRawDataRefImpl());
    if (!symtabhdr->sh_entsize)
      return;
    auto symcount = symtabhdr->sh_size / symtabhdr->sh_entsize;
    ELF_SYM *syms = (ELF_SYM *)expSymtabbuff.get().data();

    auto expStrtabbuff = strtab.getContents();
    if (!expStrtabbuff)
      return;
    const char *strtab = expStrtabbuff.get().data();

    for (addr_t sidx = 0; sidx < symcount; sidx++) {
      if (syms[sidx].getType() != ELF::STT_FUNC) {
        continue;
      }
      if (syms[sidx].isUndefined()) {
        continue;
      }
      auto expSymsect = Obj->getSection(syms[sidx].st_shndx);
      if (!expSymsect)
        continue;
      addr_t addr =
          expSymsect.get()->sh_offset - textoff + syms[sidx].getValue();
      const char *name = strtab + syms[sidx].st_name;
      auto &newfunc =
          funcs.insert(std::make_pair(addr, Function())).first->second;
      newfunc.start = addr;
      newfunc.name = name;
    }
    break;
  }
}

void ELFBinary::initImports(const void *llvmbin) {
  int pltaddroff, pltentsz;
  switch (obj->getArch()) {
  case Triple::aarch64:
    pltaddroff = 0x20;
    break;
  case Triple::arm:
    // dynamically calc pltaddroff in initELFImports
    pltaddroff = 0;
    break;
  default:
    pltaddroff = 0x10;
    break;
  }
  switch (obj->getArch()) {
  case Triple::arm:
    // dynamically calc pltentsz in initELFImports
    pltentsz = 0;
    break;
  default:
    pltentsz = 0x10;
    break;
  }
  if (is32Bits()) {
    initELFImports<object::ELF32LEObjectFile,
                   object::ELF32LEObjectFile::Elf_Rel,
                   object::ELF32LEObjectFile::Elf_Sym>(
        obj32, m_funcs, m_imports, m_impfuncs, ".rel.plt", ".rel.dyn",
        pltaddroff, pltentsz, this);
  } else {
    initELFImports<object::ELF64LEObjectFile,
                   object::ELF64LEObjectFile::Elf_Rela,
                   object::ELF64LEObjectFile::Elf_Sym>(
        obj64, m_funcs, m_imports, m_impfuncs, ".rela.plt", ".rela.dyn",
        pltaddroff, pltentsz, this);
  }
  // change foff(init is address) to real file offset
  for (auto &imp : m_imports) {
    auto sect = addrSect(imp.foff);
    if (sect) {
      imp.foff = sect->foff + imp.foff - sect->addr;
    }
  }
}

template <typename BIN, typename ADDR>
static void initELFFnSections(BIN *elf, Functions &funcs,
                              const Sections &sects) {
#if LLVM_VERSION_MAJOR >= 14
  auto dyns = elf->getELFFile().dynamicEntries();
#else
  auto dyns = elf->getELFFile()->dynamicEntries();
#endif
  if (dyns) {
    for (auto &d : dyns.get()) {
      if (d.getTag() == ELF::DT_INIT) {
        ADDR start = (ADDR)d.getPtr();
        if (elf->getArch() == Triple::arm || elf->getArch() == Triple::thumb) {
          start &= ~1;
        }
        auto &newfunc =
            funcs.insert(std::make_pair(start, Function())).first->second;
        newfunc.start = (ADDR)d.getPtr();
        newfunc.name = "DT_Init";
        break;
      }
    }
  }
#if LLVM_VERSION_MAJOR >= 14
  auto elfhdr = &elf->getELFFile().getHeader();
#else
  auto elfhdr = elf->getELFFile()->getHeader();
#endif
  if (elfhdr->e_entry) {
    auto start = (ADDR)elfhdr->e_entry;
    auto addr = start;
    if (elf->getArch() == Triple::arm || elf->getArch() == Triple::thumb) {
      start &= ~1;
    }
    auto &newfunc =
        funcs.insert(std::make_pair(start, Function())).first->second;
    newfunc.start = addr;
    newfunc.name = "elf_entry";
  }
  static const char *fnsects[] = {
      ".preinit_array",
      ".init_array",
      ".fini_array",
  };
  for (auto &s : sects) {
    for (size_t i = 0; i < sizeof(fnsects) / sizeof(fnsects[i]); i++) {
      if (s.second.name == fnsects[i]) {
#if LLVM_VERSION_MAJOR >= 14
        ADDR *fnptr = (ADDR *)(elf->getELFFile().base() + s.second.foff);
#else
        ADDR *fnptr = (ADDR *)(elf->getELFFile()->base() + s.second.foff);
#endif
        for (size_t f = 0; f < s.second.size / sizeof(ADDR); f++) {
          if (fnptr[f] != (ADDR)-1 && fnptr[f]) {
            char fname[32];
            ADDR start = fnptr[f];
            if (elf->getArch() == Triple::arm ||
                elf->getArch() == Triple::thumb) {
              start &= ~1;
            }
            auto &newfunc =
                funcs.insert(std::make_pair(start, Function())).first->second;
            snprintf(fname, sizeof(fname), "%s_%ld", s.second.name.data(), f);
            newfunc.start = fnptr[f];
            newfunc.name = fname;
          }
        }
        break;
      }
    }
  }
}

template <typename T>
std::vector<const char *> import_elflibs(const Binary *bin, T *elf) {
  std::vector<const char *> result;
  auto sect = bin->nameSect(".dynstr");
  if (!sect)
    return result;
#if LLVM_VERSION_MAJOR >= 14
  auto dyns = elf->getELFFile().dynamicEntries();
#else
  auto dyns = elf->getELFFile()->dynamicEntries();
#endif
  if (!dyns) {
    return result;
  }
  auto sectbuff = bin->addrBuff(sect->addr);
  for (auto &d : dyns.get()) {
    if (d.getTag() == ELF::DT_NEEDED) {
      result.push_back(sectbuff + d.getVal());
    }
  }
  return result;
}

std::vector<const char *> Binary::importELFLibs() const {
  void *llvmbin = m_llvmbin;
  if (is32Bits()) {
    return import_elflibs(this, (object::ELF32LEObjectFile *)llvmbin);
  } else {
    return import_elflibs(this, (object::ELF64LEObjectFile *)llvmbin);
  }
}

ImportInfos ELFBinary::parseImports() {
  ImportInfos iinfos;
  auto libs = importELFLibs();
  void *llvmbin = m_llvmbin;
  for (uint32_t i = 0; i < libs.size(); i++) {
    iinfos.libs.push_back(libs[i]);
  }
  if (!m_imports.size()) {
    initImports(llvmbin);
  }
  for (auto &i : m_imports) {
    iinfos.importfns.push_back(i.name);
    iinfos.importfoffs.push_back(i.foff);
  }
  return iinfos;
}

template <typename T> ExportInfos parse_elfexps(const Binary *bin, T *elf) {
  ExportInfos result;
  for (auto &sym : elf->getDynamicSymbolIterators()) {
    auto typeExp = sym.getType();
    if (!typeExp) {
      continue;
    }
    if (typeExp.get() == object::SymbolRef::ST_Unknown) {
      continue;
    }
#if LLVM_VERSION_MAJOR >= 11
    auto flagExp = sym.getFlags();
    if (!flagExp) {
      continue;
    }
    auto flags = flagExp.get();
#else
    auto flags = sym.getFlags();
#endif
    if ((flags & object::BasicSymbolRef::SF_Undefined) ||
        (flags & object::BasicSymbolRef::SF_Common) ||
        (flags & object::BasicSymbolRef::SF_FormatSpecific)) {
      continue;
    }
    if (!(flags & object::BasicSymbolRef::SF_Exported)) {
      continue;
    }
    auto erraddr = sym.getAddress();
    if (!erraddr) {
      continue;
    }
    auto addr = erraddr.get();
    if (flags & object::BasicSymbolRef::SF_Thumb) {
      addr |= 1;
    } else if (bin->archType() == ARM && bin->isCode(addr) && (addr & 1)) {
      // it may be GNU_IFUNC
      continue;
    }

    auto errname = sym.getName();
    if (errname && errname.get().size() &&
        strstr(errname.get().data(), "_ARRAY__") == nullptr) {
      result.exports.push_back(errname.get().data());
      result.exportrvas.push_back(addr - bin->imageBase());
    }
  }
  return result;
}

ExportInfos ELFBinary::parseExports() {
  void *llvmbin = m_llvmbin;
  if (!llvmbin)
    return ExportInfos();
  if (m_baseaddr == INVALID_ADDR) {
    initBaseAddr(llvmbin);
  }
  if (is32Bits()) {
    return parse_elfexps(this, (object::ELF32LEObjectFile *)llvmbin);
  } else {
    return parse_elfexps(this, (object::ELF64LEObjectFile *)llvmbin);
  }
}

extern void log_newfunc(Function *fn);

Function *ELFBinary::getOrInsertFunction(addr_t addr, const char *name,
                                         bool *exist, const Section **sect) {
  *exist = false;
  *sect = addrSect(addr);

  void *llvmbin = m_llvmbin;
  auto start = addr;
  if (obj->getArch() == Triple::arm || obj->getArch() == Triple::thumb) {
    start &= ~1;
  }
  auto found = m_funcs.find(start);
  if (found == m_funcs.end()) {
    found = m_funcs.insert({start, Function()}).first;
    found->second.start = addr;
    if (name) {
      found->second.name = name;
    } else {
      char tmpname[32];
      snprintf(tmpname, sizeof(tmpname), AETHER_ANOYPREFIX ADDRFMT, start);
      found->second.name = tmpname;
    }
  } else {
    if (name) {
      found->second.name = name;
    }
    *exist = true;
  }
  log_newfunc(&found->second);
  return &found->second;
}

template <typename ELFOBJ, typename ELFFILE>
void ELFBinary::analyzePrograms(const ELFOBJ *elfobj, const ELFFILE *elffile) {
  auto expPhdrs = elffile->program_headers();
  if (!expPhdrs) {
    return;
  }
  auto phdrs = expPhdrs.get();
  if (!phdrs.size()) {
    return;
  }
  std::vector<typename ELFFILE::Elf_Phdr> loadsegs;
  typename ELFFILE::Elf_Phdr dynamic;
  dynamic.p_offset = 0;
  for (auto &ph : phdrs) {
    if (ph.p_type == ELF::PT_LOAD) {
      loadsegs.push_back(ph);
    } else if (ph.p_type == ELF::PT_DYNAMIC) {
      dynamic = ph;
    }
  }
  if (!loadsegs.size() || !dynamic.p_offset) {
    return;
  }

  bool valid = true;
  auto addr2foff = [&valid, &loadsegs](typename ELFFILE::Elf_Addr addr) {
    for (auto &ph : loadsegs) {
      if (ph.p_vaddr <= addr && addr < ph.p_vaddr + ph.p_memsz) {
        return ph.p_offset + addr - ph.p_vaddr;
      }
    }
    valid = false;
    return addr - addr;
  };
  typename ELFFILE::Elf_Dyn *dynptr =
      (typename ELFFILE::Elf_Dyn *)(elffile->base() + dynamic.p_offset);
  typename ELFFILE::Elf_Dyn *initarr = nullptr;
  typename ELFFILE::Elf_Dyn *initarrsz = nullptr;
  typename ELFFILE::Elf_Dyn *finiarr = nullptr;
  typename ELFFILE::Elf_Dyn *finiarrsz = nullptr;
  typename ELFFILE::Elf_Dyn *strtab = nullptr;
  typename ELFFILE::Elf_Dyn *strsz = nullptr;
  typename ELFFILE::Elf_Dyn *symtab = nullptr;
  typename ELFFILE::Elf_Dyn *hash = nullptr;
  bool exist;
  const Section *sect;
  std::set<addr_t> oosaddrs; // out of section address
  for (int i = 0; i < (int)(dynamic.p_filesz / sizeof(dynptr[0])); i++) {
    switch (dynptr[i].d_tag) {
    // case ELF::DT_INIT: already processed by initELFFnSections
    case ELF::DT_FINI: {
      addr_t fnaddr = imageBase() + dynptr[i].d_un.d_ptr;
      getOrInsertFunction(fnaddr, "DT_Fini", &exist, &sect);
      if (!sect) {
        oosaddrs.insert(fnaddr);
      }
      break;
    }
    case ELF::DT_INIT_ARRAY:
      initarr = &dynptr[i];
      break;
    case ELF::DT_INIT_ARRAYSZ:
      initarrsz = &dynptr[i];
      break;
    case ELF::DT_FINI_ARRAY:
      finiarr = &dynptr[i];
      break;
    case ELF::DT_FINI_ARRAYSZ:
      finiarrsz = &dynptr[i];
      break;
    case ELF::DT_STRTAB:
      strtab = &dynptr[i];
      break;
    case ELF::DT_STRSZ:
      strsz = &dynptr[i];
      break;
    case ELF::DT_SYMTAB:
      symtab = &dynptr[i];
      break;
    case ELF::DT_HASH:
      hash = &dynptr[i];
      break;
    default:
      break;
    }
  }
  if (initarr && initarrsz) {
    typename ELFFILE::Elf_Addr *addrptr =
        (typename ELFFILE::Elf_Addr *)(elffile->base() +
                                       addr2foff(initarr->d_un.d_ptr));
    if (!valid)
      return;
    for (size_t i = 0; i < initarrsz->d_un.d_val / sizeof(addrptr[0]); i++) {
      if (addrptr[i] == (typename ELFFILE::Elf_Addr) - 1 || addrptr[i] == 0) {
        continue;
      }
      char name[32];
      snprintf(name, sizeof(name), "DT_InitArray_%d", (unsigned)i);
      getOrInsertFunction(addrptr[i], name, &exist, &sect);
      if (!sect) {
        oosaddrs.insert(addrptr[i]);
      }
    }
  }
  if (finiarr && finiarrsz) {
    typename ELFFILE::Elf_Addr *addrptr =
        (typename ELFFILE::Elf_Addr *)(elffile->base() +
                                       addr2foff(finiarr->d_un.d_ptr));
    if (!valid)
      return;
    for (size_t i = 0; i < finiarrsz->d_un.d_val / sizeof(addrptr[0]); i++) {
      if (addrptr[i] == (typename ELFFILE::Elf_Addr) - 1 || addrptr[i] == 0) {
        continue;
      }
      char name[32];
      snprintf(name, sizeof(name), "DT_FiniArray_%d", (unsigned)i);
      getOrInsertFunction(addrptr[i], name, &exist, &sect);
      if (!sect) {
        oosaddrs.insert(addrptr[i]);
      }
    }
  }
  if (!symtab || !strtab || !hash) {
    return;
  }
  const char *strs = (char *)(elffile->base() + addr2foff(strtab->d_un.d_ptr));
  StringRef strtabref(strs, strsz->d_un.d_val);
  typename ELFFILE::Elf_Sym *syms =
      (typename ELFFILE::Elf_Sym *)(elffile->base() +
                                    addr2foff(symtab->d_un.d_ptr));
  typename ELFFILE::Elf_Hash *hashs =
      (typename ELFFILE::Elf_Hash *)(elffile->base() +
                                     addr2foff(hash->d_un.d_ptr));
  if (!valid)
    return;
  for (size_t i = 0; i < hashs->nchain; i++) {
    if (syms[i].isUndefined()) {
      continue;
    }
    if (syms[i].getType() != ELF::STT_FUNC) {
      continue;
    }
    auto expName = syms[i].getName(strtabref);
    if (expName) {
      getOrInsertFunction(syms[i].getValue(), expName.get().data(), &exist,
                          &sect);
    } else {
      getOrInsertFunction(syms[i].getValue(), nullptr, &exist, &sect);
    }
    if (!sect) {
      oosaddrs.insert(syms[i].getValue());
    }
  }
  std::set<typename ELFFILE::Elf_Phdr *> newsect;
  for (auto &a : oosaddrs) {
    for (auto &ph : loadsegs) {
      if (ph.p_vaddr <= a && a < ph.p_vaddr + ph.p_memsz) {
        newsect.insert(&ph);
        break;
      }
    }
    if (newsect.size() == loadsegs.size()) {
      break;
    }
  }
  // create section for oos function
  for (auto ph : newsect) {
    auto sit = m_sects.insert({ph->p_vaddr, Section()}).first;
    auto sptr = &sit->second;
    char tmpname[32];
    snprintf(tmpname, sizeof(tmpname), "LOAD_%x", (int)ph->p_vaddr);
    sptr->addr = ph->p_vaddr;
    sptr->foff = ph->p_offset;
    sptr->size = ph->p_filesz;
    sptr->type = TEXT;
    sptr->name = tmpname;
    m_sectbuffs.insert({ph->p_vaddr, (char *)elffile->base() + ph->p_offset});
  }
}

bool ELFBinary::analyze(const void *llvmbin) {
  if (!Binary::analyze(llvmbin)) {
    return false;
  }
  if (m_sects.size() == 1) {
    // fix .o sections
    uint64_t textoff = 0;
    size_t bufsz;
    const char *bufstart = fileBuffer(bufsz);
    m_sects.clear();
    m_sectbuffs.clear();
    for (auto sect : objbase->sections()) {
      if (!sect.getSize()) {
        continue;
      }
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
      if (name == ".text") {
        textoff = buff.data() - bufstart;
        break;
      }
    }
    for (auto sect : objbase->sections()) {
      if (!sect.getSize()) {
        continue;
      }
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

      uint64_t foff = buff.data() - bufstart;
      uint64_t addr = foff - textoff;
      if (m_sects.find(addr) != m_sects.end()) {
        continue;
      }
      auto &newsect =
          m_sects.insert(std::make_pair(addr, Section())).first->second;
      newsect.addr = addr;
      newsect.foff = foff;
      if (newsect.foff > bufsz) {
        // ignore the invalid section
        m_sects.erase(m_sects.find(addr));
        continue;
      }
      newsect.size = sect.getSize();
      if (sect.isText()) {
        newsect.type = TEXT;
      } else {
        newsect.type = DATA;
      }
      if (name.data())
        newsect.name = name.data();
      else
        strfmt(newsect.name, "sect_%x", newsect.addr);

      m_sectbuffs.insert(std::make_pair(addr, buff.data()));
    }
    if (is32Bits()) {
      parseELFObjSymtab<object::ELF32LEObjectFile,
                        object::ELF32LEObjectFile::Elf_Sym>(
          (object::ELF32LEObjectFile *)llvmbin, m_funcs, textoff);
    } else {
      parseELFObjSymtab<object::ELF64LEObjectFile,
                        object::ELF64LEObjectFile::Elf_Sym>(
          (object::ELF64LEObjectFile *)llvmbin, m_funcs, textoff);
    }
  } else {
    if (is32Bits()) {
      initELFFnSections<object::ELF32LEObjectFile, uint32_t>(
          (object::ELF32LEObjectFile *)llvmbin, m_funcs, m_sects);
    } else {
      initELFFnSections<object::ELF64LEObjectFile, uint64_t>(
          (object::ELF64LEObjectFile *)llvmbin, m_funcs, m_sects);
    }
  }
  // validate sections
  for (auto sect : objbase->sections()) {
    // always analyze now, no need to check section name validation.
    break;
    if (!sect.getSize()) {
      continue;
    }
    StringRef name;
#if LLVM_VERSION_MAJOR >= 11
    auto expName = sect.getName();
    if (expName) {
      name = expName.get();
    } else {
      return true;
    }
#else
    sect.getName(name);
#endif
    if (!name.data()) {
      // the file maybe encryted, stop analyzing
      return true;
    }
  }

  // traval symtab
  auto *elf = (object::ELF64LEObjectFile *)llvmbin;
  for (auto &sym : elf->getDynamicSymbolIterators()) {
#if LLVM_VERSION_MAJOR >= 11
    auto flagExp = sym.getFlags();
    if (!flagExp) {
      continue;
    }
    auto flags = flagExp.get();
#else
    auto flags = sym.getFlags();
#endif
    if ((flags & object::BasicSymbolRef::SF_Undefined) ||
        (flags & object::BasicSymbolRef::SF_Common) ||
        (flags & object::BasicSymbolRef::SF_FormatSpecific)) {
      continue;
    }
    auto erraddr = sym.getAddress();
    if (!erraddr || !isCode(erraddr.get())) {
      continue;
    }
    auto addr = erraddr.get();
    auto start = addr;
    if (flags & object::BasicSymbolRef::SF_Thumb) {
      start &= ~1;
      addr |= 1;
    } else if (archType() == ARM && (start & 1)) {
      auto found = m_funcs.find(start & ~1);
      if (found != m_funcs.end()) {
        // it's GNU_IFUNC
        continue;
      }
      start &= ~1;
      addr |= 1;
    }
    auto found = m_funcs.find(start);
    if (found != m_funcs.end()) {
      auto errname = sym.getName();
      if (errname && errname.get().size()) {
        if (strstr(found->second.name.data(), "_resolver")) {
          // it's a gnu ifunc, no need to reset name.
          continue;
        }
        found->second.name = errname.get().data();
      }
      log_newfunc(&found->second);
      continue;
    }
    auto &newfunc =
        m_funcs.insert(std::make_pair(start, Function())).first->second;
    newfunc.start = addr;
    if (flags & object::BasicSymbolRef::SF_Exported) {
      newfunc.flags |= MFF_EXPORT;
    }
    auto errname = sym.getName();
    if (errname && errname.get().size()) {
      newfunc.name = errname.get().data();
    } else {
      strfmt(newfunc.name, AETHER_ANOYPREFIX "" ADDRFMT "", start);
    }
    log_newfunc(&newfunc);
  }
  // traval got
  const Section *secttext = nullptr, *gotsect = nullptr;
  for (auto &s : sections()) {
    if (s.second.name == ".text") {
      secttext = &s.second;
    } else if (s.second.name == ".got") {
      gotsect = &s.second;
    }
  }
  if (secttext && gotsect) {
    const char *gotbuff = sectBuffers().find(gotsect->addr)->second;
    if (is32Bits()) {
      const uint32_t *gotptr = (uint32_t *)gotbuff;
      for (size_t i = 0; i < gotsect->size / 4; i++, gotptr++) {
        if (secttext->addr <= *gotptr &&
            *gotptr < secttext->addr + secttext->size) {
          auto start = *gotptr;
          if (archType() == ARM) {
            start &= ~1;
          }
          if (m_funcs.find(start) != m_funcs.end()) {
            continue;
          }
          auto &newfunc =
              m_funcs.insert(std::make_pair(start, Function())).first->second;
          newfunc.start = *gotptr;
          strfmt(newfunc.name, AETHER_ANOYPREFIX "" ADDRFMT "", start);
        }
      }
    } else {
      const uint64_t *gotptr = (uint64_t *)gotbuff;
      for (size_t i = 0; i < gotsect->size / 8; i++, gotptr++) {
        if (secttext->addr <= *gotptr &&
            *gotptr < secttext->addr + secttext->size) {
          if (m_funcs.find(*gotptr) != m_funcs.end()) {
            continue;
          }
          auto &newfunc =
              m_funcs.insert(std::make_pair(*gotptr, Function())).first->second;
          newfunc.start = *gotptr;
          strfmt(newfunc.name, AETHER_ANOYPREFIX "" ADDRFMT "", newfunc.start);
        }
      }
    }
  }
  // parse program header and pt_dynamic
#if LLVM_VERSION_MAJOR >= 14
  if (is32Bits()) {
    analyzePrograms(obj32, &obj32->getELFFile());
  } else {
    analyzePrograms(obj64, &obj64->getELFFile());
  }
#else
  if (is32Bits()) {
    analyzePrograms(obj32, obj32->getELFFile());
  } else {
    analyzePrograms(obj64, obj64->getELFFile());
  }
#endif
  return true;
}

ELFX32Binary::ELFX32Binary() { m_archtype = X86; }

ELFX32Binary::~ELFX32Binary() {}

bool ELFX32Binary::analyze(const void *llvmbin) {
  if (!ELFBinary::analyze(llvmbin)) {
    return false;
  }
  BinaryCommop<ELFX32Binary> commop(this);
  return commop.analyze(
      llvmbin, m_llvmbin->getMemoryBufferRef().getBufferIdentifier().data(),
      objbase->isRelocatableObject());
}

ELFX64Binary::ELFX64Binary() { m_archtype = X86_64; }

ELFX64Binary::~ELFX64Binary() {}

bool ELFX64Binary::analyze(const void *llvmbin) {
  if (!ELFX32Binary::analyze(llvmbin)) {
    return false;
  }
  return true;
}

ELFARM64Binary::ELFARM64Binary() { m_archtype = ARM64; }

ELFARM64Binary::~ELFARM64Binary() {}

bool ELFARM64Binary::analyze(const void *llvmbin) {
  if (!ELFBinary::analyze(llvmbin)) {
    return false;
  }
  BinaryCommop<ELFARM64Binary> commop(this);
  return commop.analyze(
      llvmbin, m_llvmbin->getMemoryBufferRef().getBufferIdentifier().data(),
      objbase->isRelocatableObject());
}

ELFARMBinary::ELFARMBinary() { m_archtype = ARM; }

ELFARMBinary::~ELFARMBinary() {}

bool ELFARMBinary::analyze(const void *llvmbin) {
  if (!ELFBinary::analyze(llvmbin)) {
    return false;
  }
  BinaryCommop<ELFARMBinary> commop(this);
  return commop.analyze(
      llvmbin, m_llvmbin->getMemoryBufferRef().getBufferIdentifier().data(),
      objbase->isRelocatableObject());
}

} // namespace aether
