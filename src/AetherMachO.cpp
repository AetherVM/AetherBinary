// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

#include "AetherMachO.h"
#include "AetherBinaryPriv.hpp"
#include "Disassembler.h"

#include <llvm/BinaryFormat/MachO.h>
#include <llvm/DebugInfo/DWARF/DWARFContext.h>
#include <llvm/Object/MachO.h>

#include "MachOTrie.hpp"

#define ENABLE_ENCRYPT_FLAG 0
#define obj ((object::MachOObjectFile *)llvmbin)

using namespace llvm;

namespace aether {

void log_newfunc(Function *fn);

MachOBinary::MachOBinary() {
  m_filetype = MachO;
  m_hasfnstarts = false;
}

MachOBinary::~MachOBinary() {
  if (m_llvmbin) {
    delete (object::MachOObjectFile *)m_llvmbin;
    m_llvmbin = nullptr;
  }
}

void MachOBinary::initBaseAddr(const void *llvmbin) {
  for (auto lc : obj->load_commands()) {
    const char *segname = 0;
    addr_t segaddr = 0;
    if (lc.C.cmd == MachO::LC_SEGMENT) {
      MachO::segment_command *seglc = (MachO::segment_command *)lc.Ptr;
      segname = seglc->segname;
      segaddr = seglc->vmaddr;
    } else if (lc.C.cmd == MachO::LC_SEGMENT_64) {
      MachO::segment_command_64 *seglc = (MachO::segment_command_64 *)lc.Ptr;
      segname = seglc->segname;
      segaddr = seglc->vmaddr;
    }
    if (segname && strcmp(segname, "__TEXT") == 0) {
      m_baseaddr = segaddr;
      return;
    }
  }
  m_baseaddr = 0; // object file
}

void MachOBinary::parseSymptrs(const void *llvmbin, void *sect,
                               int gotindsymidx,
                               std::map<unsigned, size_t> &symidxes) {
  object::section_iterator &gotsect = *(object::section_iterator *)sect;
  auto dataExp = gotsect->getContents();
  if (!dataExp)
    return;
  StringRef data = dataExp.get();
  size_t fsz;
  const char *filebuff = fileBuffer(fsz);
  size_t ptrsz = obj->is64Bit() ? 8 : 4;
  auto symtablc = obj->getSymtabLoadCommand();
  for (int i = 0; i < (int)(gotsect->getSize() / ptrsz); i++) {
    unsigned symidx = (unsigned)obj->getIndirectSymbolTableEntry(
        obj->getDysymtabLoadCommand(), gotindsymidx + i);
    if (symidx >= symtablc.nsyms) {
      continue;
    }
    auto sym = obj->getSymbolByIndex(symidx);
#if LLVM_VERSION_MAJOR >= 11
    auto flagExp = sym->getFlags();
    if (!flagExp) {
      continue;
    }
    auto flags = flagExp.get();
#else
    auto flags = sym->getFlags();
#endif
    if (!(flags & object::SymbolRef::SF_Undefined)) {
      continue;
    }
    auto errSymname = obj->getSymbolName(sym->getRawDataRefImpl());
    if (!errSymname) {
      continue;
    }
    symidxes.insert(std::make_pair(symidx, m_imports.size()));
    MachO::nlist_64 raw = obj->getSymbol64TableEntry(sym->getRawDataRefImpl());
    Import imp;
    imp.lib = MachO::GET_LIBRARY_ORDINAL(raw.n_desc);
    imp.name = errSymname.get().data();
    imp.foff = data.data() - filebuff + i * ptrsz;
    m_imports.emplace_back(imp);
  }
}

void MachOBinary::initImports(const void *llvmbin) {
  object::section_iterator stubsect = obj->section_end();
  object::section_iterator gotsect = obj->section_end();
  object::section_iterator lasect = obj->section_end();
  int stubindsymidx = 0, gotindsymidx = 0, laindsymidx = 0, stubsz = 0;
  std::map<unsigned, size_t> symidxes;
  for (auto sect : obj->sections()) {
    int indsymidx = 0, flags = 0, reserved2;
    if (obj->is64Bit()) {
      MachO::section_64 rawsect = obj->getSection64(sect.getRawDataRefImpl());
      flags = rawsect.flags;
      indsymidx = rawsect.reserved1;
      reserved2 = rawsect.reserved2;
    } else {
      MachO::section rawsect = obj->getSection(sect.getRawDataRefImpl());
      flags = rawsect.flags;
      indsymidx = rawsect.reserved1;
      reserved2 = rawsect.reserved2;
    }
    if ((flags & MachO::SECTION_TYPE) == MachO::S_SYMBOL_STUBS) {
      stubindsymidx = indsymidx;
      stubsz = reserved2;
      stubsect = object::section_iterator(sect);
    } else if ((flags & MachO::SECTION_TYPE) ==
               MachO::S_NON_LAZY_SYMBOL_POINTERS) {
      gotindsymidx = indsymidx;
      gotsect = object::section_iterator(sect);
    } else if ((flags & MachO::SECTION_TYPE) == MachO::S_LAZY_SYMBOL_POINTERS) {
      laindsymidx = indsymidx;
      lasect = object::section_iterator(sect);
    }
  }
  if (gotsect != obj->section_end()) {
    parseSymptrs(llvmbin, &gotsect, gotindsymidx, symidxes);
  }
  if (lasect != obj->section_end()) {
    parseSymptrs(llvmbin, &lasect, laindsymidx, symidxes);
  }
  m_imp_stubs_index = (unsigned)m_imports.size();
  if (stubsect == obj->section_end()) {
    return;
  }
  for (int i = 0; i < (int)stubsect->getSize() / stubsz; i++) {
    addr_t addr = stubsect->getAddress() + i * stubsz;
    auto &newfunc =
        m_funcs.insert(std::make_pair(addr, Function())).first->second;
    newfunc.flags |= MFF_IMPORT;
    newfunc.start = addr;
    log_newfunc(&newfunc);

    auto symidx = obj->getIndirectSymbolTableEntry(
        obj->getDysymtabLoadCommand(), stubindsymidx + i);
    if (symidx >= obj->getSymtabLoadCommand().nsyms) {
      strfmt(newfunc.name, "imp.swift_" ADDRFMT "", addr);
      continue;
    }
    auto sym = obj->getSymbolByIndex(symidx);
    auto errSymname = obj->getSymbolName(sym->getRawDataRefImpl());
    if (errSymname) {
      newfunc.name = std::string("imp.") + errSymname.get().data();
    } else {
      strfmt(newfunc.name, "stub." ADDRFMT "", addr);
    }

    auto sifound = symidxes.find(symidx);
    if (sifound != symidxes.end()) {
      continue;
    }
    symidxes.insert(std::make_pair(symidx, m_imports.size()));

    MachO::nlist_64 raw = obj->getSymbol64TableEntry(sym->getRawDataRefImpl());
    Import imp;
    imp.lib = MachO::GET_LIBRARY_ORDINAL(raw.n_desc);
    imp.name = errSymname.get().data();
    imp.foff = 0;
    m_imports.push_back(imp);
  }
}

bool MachOBinary::isEncrypted() {
#if ENABLE_ENCRYPT_FLAG
  void *llvmbin = m_llvmbin;
  for (auto &lc : obj->load_commands()) {
    if (lc.C.cmd == MachO::LC_ENCRYPTION_INFO_64) {
      auto lcptr = (MachO::encryption_info_command_64 *)lc.Ptr;
      return lcptr->cryptid == 1;
    } else if (lc.C.cmd == MachO::LC_ENCRYPTION_INFO) {
      auto lcptr = (MachO::encryption_info_command *)lc.Ptr;
      return lcptr->cryptid == 1;
    }
  }
#endif
  return false;
}

bool MachOBinary::hasObjc() {
  for (auto &s : m_sects) {
    if (strstr(s.second.name.data(), "objc")) {
      return true;
    }
  }
  return false;
}

static const uint32_t mask_adrp = ~0x60FFFFFF;
static const uint32_t adrptmp = 0x90000000;

static inline bool is_adrp(uint32_t opcode, int reg) {
  if ((opcode & mask_adrp) == adrptmp)
    return (opcode & 0x1f) == reg;
  return false;
}

void MachOBinary::parseObjcStubs() {
  if (archType() != ARM64)
    return;
  const Section *sectselref = nullptr, *sectselname = nullptr;
  const Section *sectocstub = nullptr;
  for (auto &s : m_sects) {
    if (s.second.name == "__objc_selrefs")
      sectselref = &s.second;
    else if (s.second.name == "__objc_methname")
      sectselname = &s.second;
    else if (s.second.name == "__objc_stubs")
      sectocstub = &s.second;
  }
  if (!sectocstub)
    return;
  /*
   __objc_stubs:0000000000006780 _objc_msgSend$addOperation_   ; CODE XREF:
   _main+504↑p
   __objc_stubs:0000000000006780                               ; _main+520↑p ...
   __objc_stubs:0000000000006780   ADRP            X1,
   #selRef_addOperation_@PAGE
   __objc_stubs:0000000000006784   LDR             X1,
   [X1,#selRef_addOperation_@PAGEOFF]
   __objc_stubs:0000000000006788   ADRP            X16, #_objc_msgSend_ptr@PAGE
   __objc_stubs:000000000000678C   LDR             X16,
   [X16,#_objc_msgSend_ptr@PAGEOFF]
   __objc_stubs:0000000000006790   BR              X16 ; _objc_msgSend

   __objc_stubs:0000000000006780   ADRP            X1,
   #selRef_addOperation_@PAGE
   __objc_stubs:0000000000006784   LDR             X1,
   [X1,#selRef_addOperation_@PAGEOFF]
   __objc_stubs:0000000000006788   B               _objc_msgSend
   */
  auto opcptr = (uint32_t *)addrBuff(sectocstub->addr);
  auto selrefptr = addrBuff(sectselref->addr);
  auto selnameptr = addrBuff(sectselname->addr);
  auto opcstart = opcptr;
  auto opcend = opcptr + sectocstub->size / 4;
  for (;; opcptr += 3) {
    for (; !is_adrp(*opcptr, 1) && opcptr < opcend; opcptr++)
      ;
    if (opcptr >= opcend)
      break;
    auto addr = sectocstub->addr + 4 * (opcptr - opcstart);
    MCInst instadrp, instldr;
    if (m_diser->disassemble(opcptr[0], instadrp) != 4 ||
        m_diser->disassemble(opcptr[1], instldr) != 4)
      continue;
    int64_t imm = instadrp.getOperand(1).getImm();
    int64_t page = (addr + (imm << 12)) & ~((1 << 12) - 1);
    auto selrefaddr = (addr_t)(page + instldr.getOperand(2).getImm() * 8);
    if (selrefaddr < sectselref->addr ||
        selrefaddr >= sectselref->addr + sectselref->size)
      continue;
    auto selrefbuf = selrefptr + selrefaddr - sectselref->addr;
    auto refaddr = imageBase() + *(uint32_t *)selrefbuf;
    if (refaddr < sectselname->addr ||
        refaddr >= sectselname->addr + sectselname->size)
      continue;
    auto selname = selnameptr + refaddr - sectselname->addr;
    auto &newfunc =
        m_funcs.insert(std::make_pair(addr, Function())).first->second;
    newfunc.flags |= MFF_IMPORT;
    newfunc.start = addr;
    strfmt(newfunc.name, "_objc_%s", selname);
    log_newfunc(&newfunc);
  }
}

std::vector<const char *> Binary::importMachOLibs() const {
  std::vector<const char *> result;
  void *llvmbin = m_llvmbin;
  for (uint32_t i = 0; i < obj->getLibraryCount(); i++) {
    StringRef name;
    obj->getLibraryShortNameByIndex(i, name);

    const char *fullpath = name.data();
    while (true) {
      if (fullpath[0] == '@') {
        break;
      }
      int magic = *(int *)fullpath;
      if (magic == *(int *)"/usr" || magic == *(int *)"/Sys") {
        break;
      }
      fullpath--;
    }
    result.push_back(fullpath);
  }
  return result;
}

ImportInfos MachOBinary::parseImports() {
  ImportInfos iinfos;
  void *llvmbin = m_llvmbin;
  for (uint32_t i = 0; i < obj->getLibraryCount(); i++) {
    StringRef name;
    obj->getLibraryShortNameByIndex(i, name);

    const char *fullpath = name.data();
    while (true) {
      if (fullpath[0] == '@') {
        break;
      }
      int magic = *(int *)fullpath;
      if (magic == *(int *)"/usr" || magic == *(int *)"/Sys") {
        break;
      }
      fullpath--;
    }
    iinfos.libs.push_back(fullpath);
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

int MachOBinary::platformType() {
  void *llvmbin = m_llvmbin;
  MachO::PlatformType ptype = (MachO::PlatformType)0;
  for (auto &lc : obj->load_commands()) {
    if (lc.C.cmd == MachO::LC_BUILD_VERSION) {
      auto buildlc = obj->getBuildVersionLoadCommand(lc);
      ptype = (MachO::PlatformType)buildlc.platform;
      break;
    } else if (lc.C.cmd == MachO::LC_VERSION_MIN_IPHONEOS) {
      ptype = MachO::PLATFORM_IOS;
      break;
    }
  }
  return ptype;
}

bool MachOBinary::analyze(const void *llvmbin) {
  if (!Binary::analyze(llvmbin)) {
    return false;
  }
  // add header section for executable macho
  size_t hdrsectsz = 0;
  if (imageBase()) {
    size_t bufsz, textoff = m_sects.begin()->second.foff;
    const char *bufstart = fileBuffer(bufsz);
    auto &hdrsect =
        m_sects.insert(std::make_pair(imageBase(), Section())).first->second;
    hdrsect.addr = imageBase();
    hdrsect.foff = 0;
    hdrsect.size = textoff;
    hdrsect.type = TEXT;
    hdrsect.name = "HEADER";
    m_sectbuffs.insert(std::make_pair(imageBase(), bufstart));
    hdrsectsz = hdrsect.size;
  }

  // check whether is encrypted macho
#if ENABLE_ENCRYPT_FLAG
  for (auto &lc : obj->load_commands()) {
    if (lc.C.cmd == MachO::LC_ENCRYPTION_INFO) {
      auto lcenc = obj->getEncryptionInfoCommand(lc);
      if (lcenc.cryptid) {
        return false;
      }
      break;
    }
    if (lc.C.cmd == MachO::LC_ENCRYPTION_INFO_64) {
      auto lcenc = obj->getEncryptionInfoCommand64(lc);
      if (lcenc.cryptid) {
        return false;
      }
      break;
    }
  }
#endif

  // traval export
  auto exptrie = obj->getDyldInfoExportsTrie();
  std::vector<mach_o::trie::Entry> expsyms;
  if (exptrie.size()) {
    try {
      mach_o::trie::parseTrie((uint8_t *)exptrie.data(),
                              (uint8_t *)(exptrie.data() + exptrie.size()),
                              expsyms);
    } catch (...) {
    }
  }
  for (auto &lc : obj->load_commands()) {
    if (lc.C.cmd == MachO::LC_MAIN) {
      auto lcentry = obj->getEntryPointCommand(lc);
      auto name = lcentry.entryoff < hdrsectsz ? "_main.lc" : "_main";
      expsyms.push_back({name, lcentry.entryoff, 0, 0, nullptr});
      break;
    }
  }
  for (auto entry : expsyms) {
    if (entry.address == 0) {
      //__mh_execute_header
      continue;
    }
    entry.address += m_baseaddr;
    if (!isCode(entry.address)) {
      continue;
    }

    auto found = m_funcs.find(entry.address);
    if (found != m_funcs.end()) {
      if (strncmp(found->second.name.c_str(), AETHER_ANOYPREFIX, 5) == 0) {
        found->second.name = entry.name;
      }
      found->second.flags |= MFF_EXPORT;
      continue;
    }
    addr_t start = entry.address;
    switch (archType()) {
    case ARMV5TE:
    case ARM:
      start &= ~1;
      break;

    default:
      break;
    }
    auto &newfunc =
        m_funcs.insert(std::make_pair(start, Function())).first->second;
    newfunc.start = entry.address;
    newfunc.name = entry.name;
    newfunc.flags |= MFF_EXPORT;
    log_newfunc(&newfunc);
  }

  for (auto &lc : obj->load_commands()) {
    if (lc.C.cmd == MachO::LC_FUNCTION_STARTS) {
      auto ledlc = obj->getLinkeditDataLoadCommand(lc);
      auto address = imageBase();
      size_t fsize;
      auto ptr = (const uint8_t *)fileBuffer(fsize) + ledlc.dataoff;
      auto end = ptr + ledlc.datasize;
      try {
        while (ptr < end) {
          auto offset = mach_o::trie::read_uleb128(ptr, end);
          address += offset;
          if (m_funcs.find(address) == m_funcs.end()) {
            char name[36];
            snprintf(name, sizeof(name), AETHER_ANOYPREFIX ADDRFMT, address);
            auto &newfunc = m_funcs.insert(std::make_pair(address, Function()))
                                .first->second;
            newfunc.start = address;
            newfunc.name = name;
            log_newfunc(&newfunc);
          }
        }
      } catch (const char *msg) {
        puts(msg);
      }
      m_hasfnstarts = true;
      break;
    }
  }
  parseObjcStubs();
  if (!m_hasfnstarts)
    parseSwiftFunctions();
  for (auto &s : m_sects) {
    auto &sect = s.second;
    if (sect.name.length() > 16)
      sect.name = std::string(sect.name.data(), 16);
    if (sect.name == "__mod_init_func" || sect.name == "__mod_term_func") {
      auto ptr = (addr_t *)addrBuff(sect.addr);
      auto flag = strstr(sect.name.data(), "init") ? MFF_CTOR : MFF_DTOR;
      for (size_t i = 0; i < sect.size / 8; i++) {
        if (ptr[i]) {
          auto addr = imageBase() + (ptr[i] & 0xFFFFFFFF);
          char name[36];
          snprintf(name, sizeof(name), AETHER_ANOYPREFIX ADDRFMT, addr);
          auto &newfunc =
              m_funcs.insert(std::make_pair(addr, Function())).first->second;
          newfunc.start = addr;
          newfunc.name = name;
          newfunc.flags = flag;
          log_newfunc(&newfunc);
        }
      }
    } else if (sect.name == "__init_offsets") {
      auto ptr = (uint32_t *)addrBuff(sect.addr);
      for (size_t i = 0; i < sect.size / 4; i++) {
        if (ptr[i]) {
          auto addr = imageBase() + ptr[i];
          char name[36];
          snprintf(name, sizeof(name), AETHER_ANOYPREFIX ADDRFMT, addr);
          auto &newfunc =
              m_funcs.insert(std::make_pair(addr, Function())).first->second;
          newfunc.start = addr;
          newfunc.name = name;
          newfunc.flags = MFF_CTOR;
          log_newfunc(&newfunc);
        }
      }
    }
  }
#ifndef _WIN32
  std::string dwarf(filePath());
  auto last_slash = dwarf.find_last_of('/');
  if (last_slash != std::string::npos) {
    dwarf.insert(last_slash, ".dSYM/Contents/Resources/DWARF");
    parseDwarf(dwarf);
  }
#endif
  return true;
}

void MachOBinary::parseSwiftFunctions() {
  static const char *osmethsects[] = {
      "__objc_methlist",
      "__constg_swiftt",
      "__swift5_typeref",
  };
  auto addnewfn = [this](addr_t addr) {
    if (addr % 4)
      return;
    char name[36];
    snprintf(name, sizeof(name), AETHER_ANOYPREFIX "swift_" ADDRFMT, addr);
    auto &newfunc =
        m_funcs.insert(std::make_pair(addr, Function())).first->second;
    newfunc.start = addr;
    newfunc.name = name;
    log_newfunc(&newfunc);
  };
  size_t fsize;
  auto fbuff = fileBuffer(fsize);
  for (auto &sit : sections()) {
    auto sect = &sit.second;
    auto sbuff = fbuff + sect->foff;
    auto saddr = sect->addr;
    if (sect->name == "__const" || sect->name == "__data") {
      for (size_t j = 0; j < sect->size / 4; j++, sbuff += 4, saddr += 4) {
        auto offset = *(int *)sbuff;
        auto refaddr = (int64_t)saddr + offset;
        auto uiptr = (uint32_t *)sbuff;
        bool aroundzero = false;
        for (int i = -0x50 / 4; i < 0x50 / 4; i++) {
          if ((uiptr[i] & 0xff00ff00) == 0) {
            aroundzero = true;
            break;
          }
        }
        if (aroundzero && isTextCode(refaddr)) {
          addnewfn(refaddr);
        }
      }
      continue;
    }
    for (size_t i = 0; i < sizeof(osmethsects) / sizeof(osmethsects[0]); i++) {
      if (sect->name.find(osmethsects[i]) != std::string::npos) {
        if (strstr(osmethsects[i], "typeref")) {
          auto ptr16 = reinterpret_cast<const uint16_t *>(sbuff);
          for (size_t t = 0; t < sect->size / sizeof(ptr16[0]);
               t++, ptr16++, saddr += 2) {
            /*
            __swift5_typeref:0000000100256E38  DCW 0x7FF
            __swift5_typeref:0000000100256E3A  DCD 0xFFDB24C2
            __swift5_typeref:0000000100256E3E  DCW 0
            __swift5_typeref:0000000100C24DEE  DCW 0x9FF
            __swift5_typeref:0000000100C24DF0  DCD 0xFF55390C
            __swift5_typeref:0000000100C24DF4  DCW 0
             */
            if ((ptr16[0] == 0x07ff || ptr16[0] == 0x09ff) && ptr16[3] == 0x0) {
              ptr16 += 1;
              saddr += 2;

              auto offset = *(int *)ptr16;
              auto refaddr = (int64_t)saddr + offset;
              if (isTextCode(refaddr)) {
                addnewfn(refaddr);
              }

              ptr16 += 2;
              saddr += 4;
            }
          }
          break;
        }

        for (size_t j = 0; j < sect->size / 4; j++, sbuff += 4, saddr += 4) {
          auto offset = *(int *)sbuff;
          if (offset >= 0)
            continue;
          auto refaddr = (int64_t)saddr + offset;
          if (isTextCode(refaddr)) {
            addnewfn(refaddr);
          }
        }
        break;
      }
    }
  }
}

void MachOBinary::parseDwarf(const std::string &path) {
  auto BinaryOrErr = object::createBinary(path);
  if (!BinaryOrErr)
    return;

  auto &Bin = *BinaryOrErr->getBinary();
  auto *Obj = dyn_cast<object::MachOObjectFile>(&Bin);
  if (!Obj)
    return;

  parseSymtab(Obj, true);

  auto Dwarf = DWARFContext::create(*Obj);
  for (const auto &cu : Dwarf->compile_units()) {
    for (unsigned i = 0; i < cu->getNumDIEs(); i++) {
      auto Entry = cu->getDIEAtIndex(i);
      if (Entry.getTag() == dwarf::DW_TAG_subprogram) { // Function tag
        auto Name = Entry.find(dwarf::DW_AT_name);
        auto LowPC = Entry.find(dwarf::DW_AT_low_pc);
        if (Name && LowPC) {
          auto FuncName = Name->getAsCString();
          auto LowPCVal = LowPC->getAsAddress();
          auto &newfunc = m_funcs.insert(std::make_pair(*LowPCVal, Function()))
                              .first->second;
          newfunc.start = *LowPCVal;
          newfunc.name = *FuncName;
          log_newfunc(&newfunc);
        }
      }
    }
  }
}

MachOARM64Binary::MachOARM64Binary() { m_archtype = ARM64; }

MachOARM64Binary::~MachOARM64Binary() {}

bool MachOARM64Binary::analyze(const void *llvmbin) {
  if (!MachOBinary::analyze(llvmbin)) {
    return false;
  }
  BinaryCommop<MachOARM64Binary> commop(this);
  return commop.analyze(
      llvmbin, m_llvmbin->getMemoryBufferRef().getBufferIdentifier().data(),
      objbase->isRelocatableObject());
}

bool MachOARM64Binary::isArm64e() const {
  for (auto &s : m_sects) {
    if (strstr(s.second.name.data(), "__auth")) {
      return true;
    }
  }
  return false;
}

MachOARMBinary::MachOARMBinary() { m_archtype = ARM; }

MachOARMBinary::~MachOARMBinary() {}

bool MachOARMBinary::analyze(const void *llvmbin) {
  if (!MachOBinary::analyze(llvmbin)) {
    return false;
  }
  BinaryCommop<MachOARMBinary> commop(this);
  return commop.analyze(
      llvmbin, m_llvmbin->getMemoryBufferRef().getBufferIdentifier().data(),
      objbase->isRelocatableObject());
}

MachOX32Binary::MachOX32Binary() { m_archtype = X86; }

MachOX32Binary::~MachOX32Binary() {}

bool MachOX32Binary::analyze(const void *llvmbin) {
  if (!MachOBinary::analyze(llvmbin)) {
    return false;
  }
  BinaryCommop<MachOX32Binary> commop(this);
  return commop.analyze(
      llvmbin, m_llvmbin->getMemoryBufferRef().getBufferIdentifier().data(),
      objbase->isRelocatableObject());
}

MachOX64Binary::MachOX64Binary() { m_archtype = X86_64; }

MachOX64Binary::~MachOX64Binary() {}

bool MachOX64Binary::analyze(const void *llvmbin) {
  if (!MachOX32Binary::analyze(llvmbin)) {
    return false;
  }
  return true;
}

} // namespace aether
