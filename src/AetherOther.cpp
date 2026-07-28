// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

#include "AetherOther.h"
#include "AetherCommop.h"

#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/MemoryBuffer.h>

namespace llvm {
void initDebugCounterOptions() {}
void initGraphWriterOptions() {}
void initSignalsOptions() {}
void initStatisticOptions() {}
void initTimerOptions() {}
void initWithColorOptions() {}
void initDebugOptions() {}
void initRandomSeedOptions() {}
} // namespace llvm

using namespace llvm;

namespace aether {

template <typename T> static void loadLoops(Loops &loops, const T *ml, int nl) {
  for (int i = 0; i < nl; i++) {
    loops.insert(std::make_pair(ml[i].from, ml[i].to));
  }
}

template <typename T>
static void loadIndexs(Insrefs &idxs, const T *list, int nl) {
  idxs.reserve(nl);
  for (int i = 0; i < nl; i++) {
    idxs.push_back(list[i]);
  }
}

bool AebiBinary::analyze(const void *llvmbin) {
  const AebiFile *mfhdr = (AebiFile *)llvmbin;
  if (mfhdr->magic != AETHER_FILE_ANA ||
      mfhdr->version != AETHER_FILE_VERSION) {
    return false;
  }
  // header
  m_filehash = mfhdr->filehash;
  m_archtype = (ArchType)mfhdr->info.arch;
  m_baseaddr = mfhdr->baseaddr;
  m_filetype = (FileType)mfhdr->info.filetype;
  if (!init()) {
    return false;
  }
  // section
  for (int i = 0; i < (int)mfhdr->info.nsect; i++) {
    const AebiSect *ms = mfhdr->sect(i);
    auto &newsect =
        m_sects.insert(std::make_pair(ms->addr, Section())).first->second;
    newsect.addr = ms->addr;
    newsect.foff = ms->fileoff;
    newsect.size = ms->size;
    newsect.type = (SectType)ms->info.type;
    newsect.name = mfhdr->string(ms->info.name);
  }
  int prog = 1, progtmp;
  char progprefix[128];
  snprintf(progprefix, sizeof(progprefix),
           AETHER_LIB_NAME " is loading analyzed functions");
  // function
  for (int i = 0; i < (int)mfhdr->nfunc; i++) {
    analyze_progress(progprefix, prog++, (int)mfhdr->nfunc, progtmp);

    const AebiFunc *mf = mfhdr->func(i);
    auto &newfunc =
        m_funcs.insert(std::make_pair(mfhdr->address(mf->rvastart), Function()))
            .first->second;
    newfunc.start = mfhdr->address(mf->rvastart) | mf->info.thumb;
    newfunc.end = mfhdr->address(mf->rvaend);
    newfunc.name = mfhdr->string(mf->name);
    newfunc.flags = mf->info.flags;
    // loops
    switch (mf->sizeofIndex()) {
    case 1:
      loadLoops(newfunc.loops, mfhdr->loop1(mf, 0), mf->info.nloop);
      break;
    case 2:
      loadLoops(newfunc.loops, mfhdr->loop2(mf, 0), mf->info.nloop);
      break;
    case 4:
      loadLoops(newfunc.loops, mfhdr->loop4(mf, 0), mf->info.nloop);
      break;
    default:
      break;
    }
    // instruction
    newfunc.insns.resize(mf->ninsn);
    for (int n = 0; n < (int)mf->ninsn; n++) {
      const AebiInsn *mi = mfhdr->insn(mf, n);
#if 0
      addr_t insnaddr = mf->rvastart + mi->fnoff;
      if (insnaddr == 0 || insnaddr == 0) {
        puts("debug me.");
      }
#endif
      Insinfo &newinsn = newfunc.insns[n];
      newinsn.fnoff = mi->fnoff;
      newinsn.info.oplen = mi->opcodeSize();
      newinsn.info.type = mi->type;
      // goouts & comins
      switch (mf->sizeofIndex()) {
      case 1:
        loadIndexs(newinsn.gouts, mfhdr->index1(mi->gooff), mi->ngout);
        loadIndexs(newinsn.comins, mfhdr->index1(mf->cominOffset(mi)),
                   mi->ncomin);
        break;
      case 2:
        loadIndexs(newinsn.gouts, mfhdr->index2(mi->gooff), mi->ngout);
        loadIndexs(newinsn.comins, mfhdr->index2(mf->cominOffset(mi)),
                   mi->ncomin);
        break;
      case 4:
        loadIndexs(newinsn.gouts, mfhdr->index4(mi->gooff), mi->ngout);
        loadIndexs(newinsn.comins, mfhdr->index4(mf->cominOffset(mi)),
                   mi->ncomin);
        break;
      default:
        break;
      }
    }
  }
  return true;
}

bool AebiBinary::initLLVM(const char *buff, int size) {
  auto membuff = MemoryBuffer::getMemBuffer(StringRef(buff, size), "", false);
  if (!membuff) {
    return false;
  }
  MemoryBufferRef buffref(*membuff);
  auto errOrBin = object::createBinary(buffref);
  if (!errOrBin) {
    return false;
  }
  holdBuffer(errOrBin.get().release(), membuff.release());
  return true;
}

bool AnyBinary::analyze(const void *llvmbin) {
  const char *filepath = filePath();
  const char *name = strrchr(filePath(), '/');
  if (!name)
    name = strrchr(filePath(), '\\');
  if (name)
    name++;
  else
    name = filepath;

  analyze_log(AETHER_LIB_NAME
              ": %s is not code file, create an any file section instead.\n",
              name);
  m_baseaddr = 0;
  size_t bufsz;
  const char *bufstart = fileBuffer(bufsz);
  auto &newsect =
      m_sects.insert(std::make_pair(imageBase(), Section())).first->second;
  newsect.addr = imageBase();
  newsect.foff = 0;
  newsect.size = bufsz;
  newsect.type = DATA;
  newsect.name = name;
  m_sectbuffs.insert(std::make_pair(imageBase(), bufstart));
  return true;
}

} // namespace aether
