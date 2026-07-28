// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

#include "Disassembler.h"
#include "AetherArch.h"
#include "AetherBinaryPriv.hpp"
#include "AetherCommop.h"

#include "llvm-c/Target.h"
#include "llvm/Config/config.h"
#if LLVM_VERSION_MAJOR >= 17
#include "llvm/TargetParser/Triple.h"
#else
#include "llvm/ADT/Triple.h"
#endif
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#if LLVM_VERSION_MAJOR < 11
#include "llvm/MC/MCELFStreamer.h"
#endif
#include "llvm/Demangle/Demangle.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCParser/MCAsmParser.h"
#include "llvm/MC/MCParser/MCParsedAsmOperand.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/MC/MCTargetOptionsCommandFlags.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#if LLVM_VERSION_MAJOR >= 14
#include "llvm/MC/TargetRegistry.h"
#else
#include "llvm/Support/TargetRegistry.h"
#endif
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

int llvm_mc_main(int argc, char **argv, raw_pwrite_stream *rawos, void *ctx);

namespace aether {

Symbolizer_t Disassembler::Symbolizer = NULL;
void *Disassembler::Symcontext = NULL;

static const Target *GetTarget(const char *ArchName, std::string &TripleName,
                               bool update) {
  static bool init_llvm = false;
  if (!init_llvm) {
    init_llvm = true;
    // Initialize All target infos
#define init_target(name)                                                      \
  LLVMInitialize##name##Target();                                              \
  LLVMInitialize##name##TargetMC();                                            \
  LLVMInitialize##name##TargetInfo();                                          \
  LLVMInitialize##name##AsmPrinter();                                          \
  LLVMInitialize##name##AsmParser();                                           \
  LLVMInitialize##name##Disassembler();
    init_target(AArch64);
    init_target(ARM);
    init_target(X86);
  }
  // Figure out the target triple.
  if (TripleName.empty())
    ; // TripleName = sys::getDefaultTargetTriple();
  Triple TheTriple(Triple::normalize(TripleName));

  // Get the target specific parser.
  std::string Error;
  const Target *TheTarget =
      TargetRegistry::lookupTarget(ArchName, TheTriple, Error);
  if (!TheTarget) {
    errs() << Error;
    return nullptr;
  }

  // Update the triple name and return the found target.
  if (update) {
    TripleName = TheTriple.getTriple();
  }
  return TheTarget;
}

class MCSymbolizerStub : public MCSymbolizer {
public:
  MCSymbolizerStub(MCContext &Ctx, std::unique_ptr<MCRelocationInfo> RelInfo)
      : MCSymbolizer(Ctx, std::move(RelInfo)) {}
  ~MCSymbolizerStub() {}

  virtual bool tryAddingSymbolicOperand(MCInst &Inst, raw_ostream &cStream,
                                        int64_t Value, uint64_t Address,
                                        bool IsBranch, uint64_t Offset,
                                        uint64_t InstSize) {
    if (Disassembler::Symbolizer) {
      return Disassembler::Symbolizer(Disassembler::Symcontext, Inst, cStream,
                                      Address, Value, (int)(Offset + InstSize),
                                      IsBranch);
    }
    return false;
  }

#if LLVM_VERSION_MAJOR >= 17
  virtual bool tryAddingSymbolicOperand(MCInst &Inst, raw_ostream &cStream,
                                        int64_t Value, uint64_t Address,
                                        bool IsBranch, uint64_t Offset,
                                        uint64_t OpSize, uint64_t InstSize) {
    return tryAddingSymbolicOperand(Inst, cStream, Value, Address, IsBranch,
                                    Offset, InstSize);
  }
#endif

  virtual void tryAddingPcLoadReferenceComment(raw_ostream &cStream,
                                               int64_t Value,
                                               uint64_t Address) {
    if (Disassembler::Symbolizer) {
      MCInst Inst;
      Inst.setOpcode(0);
      Disassembler::Symbolizer(Disassembler::Symcontext, Inst, cStream, Address,
                               Value, 0, false);
    }
  }
};

#if LLVM_VERSION_MAJOR < 11
class AssembleStreamer : public MCELFStreamer {
  MCCodeEmitter *m_emitter;
  MCObjectWriter *m_OS;

public:
  AssembleStreamer(MCContext &Context, MCAsmBackend *TAB, MCObjectWriter *OS,
                   MCCodeEmitter *Emitter)
      : m_OS(OS), MCELFStreamer(Context, std::unique_ptr<MCAsmBackend>(TAB),
                                std::unique_ptr<MCObjectWriter>(OS),
                                std::unique_ptr<MCCodeEmitter>(Emitter)) {
    m_emitter = Emitter;
  }

protected:
  virtual void EmitInstToData(const MCInst &Inst,
                              const MCSubtargetInfo &STI) override {
    // virtual void EmitInstruction(const MCInst &Inst, const
    // MCSubtargetInfo &STI) override {
    SmallVector<MCFixup, 4> Fixups;
    m_emitter->encodeInstruction(Inst, outs(), Fixups, STI);
  }
};
#endif

void AssembleDiagHandlerTy(const SMDiagnostic &smd, void *Context) {
  fprintf(stderr, "%s\n", smd.getMessage().data());
}

class hack_raw_fd_ostream : public raw_fd_ostream {
  std::string &m_outs;

public:
  hack_raw_fd_ostream(std::string &outs)
      : raw_fd_ostream(0, false), m_outs(outs) {}

  void write_impl(const char *Ptr, size_t Size) override {
    pwrite_impl(Ptr, Size, 0);
  }

  void pwrite_impl(const char *Ptr, size_t Size, uint64_t Offset) override {
    m_outs += std::string(Ptr, Size);
  }
};

class ToolOutputString {
  hack_raw_fd_ostream OS;

public:
  ToolOutputString(std::string &outs) : OS(outs) {}

  /// Return the contained raw_fd_ostream.
  hack_raw_fd_ostream &os() { return OS; }
};

struct DisassemblerContext {
  std::string TripleName;
  const llvm::Target *Target;

  MCRegisterInfo *MRI;
  MCAsmInfo *MAI;
  MCDisassembler *MDIS;
  MCInstrInfo *MII;
  MCSubtargetInfo *STI;
  MCInstPrinter *Printer;
  MCContext *MCCTX;

  MCStreamer *Str;
#if LLVM_VERSION_MAJOR >= 14
  SourceMgr SrcMgr;
  MCObjectFileInfo *MOFI;
#else
  MCObjectFileInfo MOFI;
#endif
  MCInstPrinter *IP;
  ToolOutputString TOS;
  std::string TOSstr;

public:
  DisassemblerContext(const char *arch, const char *usrtriple) : TOS(TOSstr) {
    if (usrtriple) {
      TripleName = usrtriple;
      Target = GetTarget(arch, TripleName, false);
    } else if (strstr(arch, "thumb")) {
      TripleName = "thumbv8-apple-ios";
      Target = GetTarget(arch, TripleName, false);
    } else if (strcmp(arch, "arm") == 0) {
      TripleName = "armv8-apple-ios";
      Target = GetTarget(arch, TripleName, false);
    } else if (strstr(arch, "arm64") || strstr(arch, "aarch64")) {
      TripleName = "arm64v8.5a-apple-ios";
      Target = GetTarget(arch, TripleName, false);
    } else {
      arch = "x86-64"; // reset to x86_64 anyway

      Triple triple;
      triple.setArch(Triple::x86_64);
      triple.setVendor(Triple::Apple);
      triple.setOS(Triple::Darwin);
      triple.setObjectFormat(Triple::MachO);
      triple.setEnvironment(Triple::Itanium);
      TripleName = triple.getTriple();
      Target = GetTarget(arch, TripleName, true);
    }
    if (Target == nullptr) {
      return;
    }

    const char *features = "";
    if (strstr(arch, "arm64") || strstr(arch, "aarch64")) {
      features = "+all";
    }

    Triple triple(TripleName);

#if LLVM_VERSION_MAJOR >= 22
    MRI = Target->createMCRegInfo(triple);
#else
    MRI = Target->createMCRegInfo(TripleName);
#endif

#if LLVM_VERSION_MAJOR >= 22
    MCTargetOptions mctops;
    MAI = Target->createMCAsmInfo(*MRI, triple, mctops);
#elif LLVM_VERSION_MAJOR >= 11
    MCTargetOptions mctops;
    MAI = Target->createMCAsmInfo(*MRI, TripleName, mctops);
#else
    MAI = Target->createMCAsmInfo(*MRI, TripleName);
#endif

    MII = Target->createMCInstrInfo();

#if LLVM_VERSION_MAJOR >= 22
    STI = Target->createMCSubtargetInfo(triple, "", features);
#else
    STI = Target->createMCSubtargetInfo(TripleName, "", features);
#endif

#if LLVM_VERSION_MAJOR >= 14
    MCTargetOptions MCOptions = mc::InitMCTargetOptionsFromFlags();
    MCOptions.ShowMCEncoding = true; // force it to show the opcode we need
#if LLVM_VERSION_MAJOR >= 22
    MCOptions.AsmVerbose = true;
#endif
    MCCTX = new MCContext(triple, MAI, MRI, STI, &SrcMgr, &MCOptions);
    MOFI = Target->createMCObjectFileInfo(*MCCTX, true, true);
    MCCTX->setObjectFileInfo(MOFI);
#else
    MCTargetOptions MCOptions;
    MCCTX = new MCContext(MAI, MRI, &MOFI);
    MOFI.InitMCObjectFileInfo(triple, true, *MCCTX);
#endif

    std::unique_ptr<MCRelocationInfo> RelInfo(new MCRelocationInfo(*MCCTX));
    std::unique_ptr<MCSymbolizer> symbolizer(
        new MCSymbolizerStub(*MCCTX, std::move(RelInfo)));
    MDIS = Target->createMCDisassembler(*STI, *MCCTX);
    MDIS->setSymbolizer(std::move(symbolizer));

    Printer =
        Target->createMCInstPrinter(Triple(TripleName), 0, *MAI, *MII, *MRI);
    Printer->setPrintImmHex(true);

    std::unique_ptr<MCAsmBackend> MAB(
        Target->createMCAsmBackend(*STI, *MRI, MCOptions));
#if LLVM_VERSION_MAJOR >= 17
    std::unique_ptr<MCCodeEmitter> MCE(
        Target->createMCCodeEmitter(*MII, *MCCTX));
#else
    std::unique_ptr<MCCodeEmitter> MCE(
        Target->createMCCodeEmitter(*MII, *MRI, *MCCTX));
#endif

#if LLVM_VERSION_MAJOR >= 22
    IP = Target->createMCInstPrinter(Triple(TripleName), 0, *MAI, *MII, *MRI);
    Str = Target->createAsmStreamer(
        *MCCTX, std::make_unique<formatted_raw_ostream>(TOS.os()),
        std::unique_ptr<MCInstPrinter>(IP), std::move(MCE), std::move(MAB));
#else
    IP = Target->createMCInstPrinter(Triple(TripleName), 0, *MAI, *MII, *MRI);
    Str = Target->createAsmStreamer(
        *MCCTX, std::make_unique<formatted_raw_ostream>(TOS.os()),
        /*asmverbose*/ true, /*useDwarfDirectory*/ true, IP, std::move(MCE),
        std::move(MAB), true);
#endif
  }

  MCTargetAsmParser *createTempMCTargetAsmParser(MCAsmParser *MAP) {
    MCTargetOptions topt;
#if LLVM_VERSION_MAJOR >= 11
#else
    topt.SanitizeAddress = 0;
#endif
    return Target->createMCAsmParser(*STI, *MAP, *MII, topt);
  }

  ~DisassemblerContext() {
    if (Target == nullptr) {
      return;
    }

    delete MRI;
    delete MAI;
    delete MDIS;
    delete MII;
    delete STI;
    // delete IP;
    delete Printer;
    delete Str;
    delete MCCTX;
#if LLVM_VERSION_MAJOR >= 14
    delete MOFI;
#endif
  }
};

extern const llvm::Target *diser_getTarget(void *ctx) {
  return ((DisassemblerContext *)ctx)->Target;
}

extern MCRegisterInfo *diser_getMCRegInfo(void *ctx) {
  return ((DisassemblerContext *)ctx)->MRI;
}
extern MCAsmInfo *diser_createMCAsmInfo(void *ctx) {
  return ((DisassemblerContext *)ctx)->MAI;
}
extern MCInstrInfo *diser_createMCInstrInfo(void *ctx) {
  return ((DisassemblerContext *)ctx)->MII;
}
extern MCSubtargetInfo *diser_createMCSubtargetInfo(void *ctx) {
  return ((DisassemblerContext *)ctx)->STI;
}
extern MCInstPrinter *diser_createMCInstPrinter(void *ctx) {
  return ((DisassemblerContext *)ctx)->IP;
}
extern MCStreamer *diser_createAsmStreamer(void *ctx) {
  return ((DisassemblerContext *)ctx)->Str;
}

Disassembler::Disassembler(const char *arch) : Disassembler(arch, nullptr) {}

Disassembler::Disassembler(const char *arch, const char *triple) {
  static std::map<std::string, DisassemblerContext *> cache;

  m_arch = arch;
  auto found = cache.find(arch);
  if (found != cache.end()) {
    m_ctx = found->second;
    return;
  }

  DisassemblerContext *ctx = new DisassemblerContext(m_arch, triple);
  if (ctx->Target == nullptr) {
    m_ctx = nullptr;
  } else {
    m_ctx = ctx;
    cache.insert({arch, ctx});
  }
  dstAddr = INVALID_ADDR;
}

Disassembler::~Disassembler() {}

void Disassembler::print(llvm::MCInst &inst) {
  DisassemblerContext *ctx = (DisassemblerContext *)m_ctx;
#if LLVM_VERSION_MAJOR >= 11
  ctx->Printer->printInst(&inst, 0, "", *ctx->STI, outs());
#else
  ctx->Printer->printInst(&inst, outs(), "", *ctx->STI);
#endif
}

void Disassembler::print(llvm::MCInst &inst, std::string &text, int oplen,
                         unsigned long long addr) {
  DisassemblerContext *ctx = (DisassemblerContext *)m_ctx;
  raw_string_ostream out(text);
#if LLVM_VERSION_MAJOR >= 11
  ctx->Printer->printInst(&inst, 0, "", *ctx->STI, out);
#else
  ctx->Printer->printInst(&inst, out, "", *ctx->STI);
#endif

  dstAddr = INVALID_ADDR;
  if (oplen) {
    switch (ctx->STI->getTargetTriple().getArch()) {
    case Triple::aarch64: {
      MachineARM64 m;
      dstAddr = m.dstAddr(&inst, oplen, addr);
      break;
    }
    case Triple::thumb:
    case Triple::arm: {
      MachineARM m;
      dstAddr = m.dstAddr(&inst, oplen, addr);
      break;
    }
    case Triple::x86_64:
    case Triple::x86: {
      MachineX86 m;
      dstAddr = m.dstAddr(&inst, oplen, addr);
      break;
    }
    default:
      break;
    }
  }
}

static const char *parseOpcode(const char *asmcode, unsigned char opcode[20]) {
  // encoding: [0xe0,0x87,0x40,0xa9]
  const char *start = strstr(asmcode, "g: [0");
  opcode[0] = 0;
  if (start == nullptr) {
    return nullptr;
  }
  start += 4;

  unsigned char *optr = &opcode[1];
  for (opcode[0] = 0;;) {
    optr[opcode[0]] = (unsigned char)strtoul(start, (char **)&start, 16);
    opcode[0]++;
    if (start[0] == ']') {
      break;
    } else {
      start++;
    }
  }
  return start;
}

std::string Disassembler::assemble(const char *asmcode,
                                   unsigned char opcode[20]) {
  auto found = m_asmcache.find(asmcode);
  if (found != m_asmcache.end()) {
    opcode[0] = (uint8_t)found->second.size();
    memcpy(&opcode[1], found->second.data(), found->second.size());
    return "";
  }

  DisassemblerContext *ctx = (DisassemblerContext *)m_ctx;
  std::string triple("-triple-aebi=");
  if (ctx->TripleName == "x86-none-linux-android" ||
      ctx->TripleName == "x86-pc-windows-msvc") {
    triple += "i386-apple-macosx";
  } else {
    triple += ctx->TripleName;
  }
  const char *argv[] = {
      AETHER_LIB_NAME,
      "-show-encoding-aebi",
      triple.c_str(),
      asmcode,
  };
  opcode[0] = 0;
  std::string &outs = ctx->TOSstr;
  outs.clear();
  llvm_mc_main(sizeof(argv) / sizeof(argv[0]), (char **)&argv[0],
               &ctx->TOS.os(), ctx);
  ctx->TOS.os().flush();

  if (outs.length()) {
    parseOpcode(outs.c_str(), opcode);
    m_asmcache.insert(std::make_pair(
        asmcode, std::string(&opcode[1], &opcode[1] + opcode[0])));
  }
  return outs;
}

int Disassembler::disassemble(unsigned int mc, std::string &text,
                              unsigned long long addr) {
  DisassemblerContext *ctx = (DisassemblerContext *)m_ctx;
  ArrayRef<uint8_t> Data((uint8_t *)&mc, sizeof(mc));
  uint64_t Size;
  MCInst Inst;

  MCDisassembler::DecodeStatus S;
  S = ctx->MDIS->getInstruction(Inst, Size, Data, addr,
#if LLVM_VERSION_MAJOR < 11
                                errs(),
#endif
                                outs());
  switch (S) {
  case MCDisassembler::Fail:
  case MCDisassembler::SoftFail:
    text = "error machine code";
    break;
  case MCDisassembler::Success:
    print(Inst, text, (int)Size, addr);
    return (int)Size;
  default:
    break;
  }

  return 0;
}

int Disassembler::disassemble(unsigned int mc, unsigned long long addr) {
  DisassemblerContext *ctx = (DisassemblerContext *)m_ctx;
  ArrayRef<uint8_t> Data((uint8_t *)&mc, sizeof(mc));
  uint64_t Size;
  MCInst Inst;

  MCDisassembler::DecodeStatus S;
  S = ctx->MDIS->getInstruction(Inst, Size, Data, addr,
#if LLVM_VERSION_MAJOR < 11
                                errs(),
#endif
                                outs());
  switch (S) {
  case MCDisassembler::Fail:
  case MCDisassembler::SoftFail:
    printf("error machine code : %x\n", mc);
    break;
  case MCDisassembler::Success:
    print(Inst);
    outs() << '\n';
    return (int)Size;
  default:
    break;
  }

  return 0;
}

int Disassembler::disassemble(unsigned int mc, llvm::MCInst &inst,
                              unsigned long long addr) {
  DisassemblerContext *ctx = (DisassemblerContext *)m_ctx;
  ArrayRef<uint8_t> Data((uint8_t *)&mc, sizeof(mc));
  uint64_t Size;

  MCDisassembler::DecodeStatus S;
  S = ctx->MDIS->getInstruction(inst, Size, Data, addr,
#if LLVM_VERSION_MAJOR < 11
                                errs(),
#endif
                                outs());
  switch (S) {
  case MCDisassembler::Fail:
  case MCDisassembler::SoftFail:
    // printf("error machine code : %x\n", mc);
    break;
  case MCDisassembler::Success:
    return (int)Size;
  default:
    break;
  }

  return 0;
}

int Disassembler::disassemble(const unsigned char *mc, int size,
                              std::string &text, unsigned long long addr) {
  DisassemblerContext *ctx = (DisassemblerContext *)m_ctx;
  ArrayRef<uint8_t> Data((uint8_t *)mc, size);
  uint64_t Size;
  MCInst Inst;

  MCDisassembler::DecodeStatus S;
  S = ctx->MDIS->getInstruction(Inst, Size, Data, addr,
#if LLVM_VERSION_MAJOR < 11
                                errs(),
#endif
                                outs());
  switch (S) {
  case MCDisassembler::Fail:
  case MCDisassembler::SoftFail:
    text = "error machine code";
    break;
  case MCDisassembler::Success:
    print(Inst, text, (int)Size, addr);
    return (int)Size;
  default:
    break;
  }

  return 0;
}

int Disassembler::disassemble(const unsigned char *mc, int size,
                              llvm::MCInst &inst, unsigned long long addr) {
  DisassemblerContext *ctx = (DisassemblerContext *)m_ctx;
  ArrayRef<uint8_t> Data((uint8_t *)mc, size);
  uint64_t Size;

  MCDisassembler::DecodeStatus S;
  S = ctx->MDIS->getInstruction(inst, Size, Data, addr,
#if LLVM_VERSION_MAJOR < 11
                                errs(),
#endif
                                outs());
  switch (S) {
  case MCDisassembler::Fail:
  case MCDisassembler::SoftFail:
    break;
  case MCDisassembler::Success:
    return (int)Size;
  default:
    break;
  }

  return 0;
}

int Disassembler::disassemble(const unsigned char *mc, int size,
                              unsigned long long addr) {
  DisassemblerContext *ctx = (DisassemblerContext *)m_ctx;
  ArrayRef<uint8_t> Data((uint8_t *)mc, size);
  uint64_t Size;
  MCInst Inst;

  MCDisassembler::DecodeStatus S;
  S = ctx->MDIS->getInstruction(Inst, Size, Data, addr,
#if LLVM_VERSION_MAJOR < 11
                                errs(),
#endif
                                outs());
  switch (S) {
  case MCDisassembler::Fail:
  case MCDisassembler::SoftFail:
    // printf("error machine code : %p\n", mc);
    break;
  case MCDisassembler::Success:
    return (int)Size;
  default:
    break;
  }

  return 0;
}

int Disassembler::disassemble(const char *asmcode, llvm::MCInst &inst,
                              unsigned long long addr) {
  unsigned char opc[20];
  auto err = assemble(asmcode, &opc[0]);
  if (!opc[0]) {
    return 0;
  }
  return disassemble(&opc[1], opc[0], inst, addr);
}

int Disassembler::name(unsigned opc, char str[32]) {
  DisassemblerContext *ctx = (DisassemblerContext *)m_ctx;
  StringRef sname = ctx->Printer->getOpcodeName(opc);
  strcpy(str, sname.data());
  return (int)sname.size();
}

int Disassembler::maxopc() {
  DisassemblerContext *ctx = (DisassemblerContext *)m_ctx;
  return ctx->MII->getNumOpcodes();
}

static uint64_t x64reg_value(const void *gprs, unsigned reg) {
  const x64regs_t *rptr = (x64regs_t *)gprs;
  switch (reg) {
  case X86::NoRegister:
    return 0;
  case X86::EAX:
  case X86::RAX:
    return rptr->cax;
  case X86::ECX:
  case X86::RCX:
    return rptr->ccx;
  case X86::EDX:
  case X86::RDX:
    return rptr->cdx;
  case X86::EBX:
  case X86::RBX:
    return rptr->cbx;
  case X86::ESP:
  case X86::RSP:
    return rptr->csp;
  case X86::EBP:
  case X86::RBP:
    return rptr->cbp;
  case X86::ESI:
  case X86::RSI:
    return rptr->csi;
  case X86::EDI:
  case X86::RDI:
    return rptr->cdi;
  case X86::EIP:
  case X86::RIP:
    return rptr->cip;
  default:
    return (&rptr->r8)[reg - X86::R8];
  }
}

static uint64_t regContextLoadMem64(const void *gprs, MCInst &inst, int oplen) {
  // basereg + expimm*expreg + offimm
  // <MCOperand Reg:129> <MCOperand Imm:1> <MCOperand Reg:0> <MCOperand Imm:0>
  unsigned basereg = inst.getOperand(0).getReg();
  int64_t expimm = inst.getOperand(1).getImm();
  unsigned expreg = inst.getOperand(2).getReg();
  int64_t offimm = inst.getOperand(3).getImm();
  uint64_t memaddr = (uint64_t)(x64reg_value(gprs, basereg) +
                                expimm * x64reg_value(gprs, expreg) + offimm);
  if (basereg == X86::RIP || basereg == X86::EIP) {
    memaddr += oplen;
  }
  return memaddr;
}

uint64_t Disassembler::branchTarget(const unsigned char *mc, uint64_t addr,
                                    int *oplenptr, const void *gprs,
                                    bool *isptr) {
  MCInst inst;
  int oplen = disassemble(mc, 16, inst);
  if (oplenptr) {
    *oplenptr = oplen;
  }
  return branchTarget(mc, addr, inst, oplen, gprs, isptr);
}

uint64_t Disassembler::branchTarget(const unsigned char *mc, uint64_t addr,
                                    llvm::MCInst &inst, int oplen,
                                    const void *gprs, bool *isptr) {
  DisassemblerContext *ctx = (DisassemblerContext *)m_ctx;
  if (isptr) {
    *isptr = false;
  }

  dstAddr = 0;
  auto arch = ctx->STI->getTargetTriple().getArch();
  if (gprs) {
    switch (arch) {
    case Triple::aarch64: {
      switch (inst.getOpcode()) {
      case AArch64::BR:
      case AArch64::BRAA:
      case AArch64::BRAB:
      case AArch64::BRAAZ:
      case AArch64::BRABZ:
      case AArch64::BLR:
      case AArch64::BLRAA:
      case AArch64::BLRAB:
      case AArch64::BLRAAZ:
      case AArch64::BLRABZ: {
        auto reg = inst.getOperand(0).getReg();
        if (reg == AArch64::LR)
          dstAddr = *((uint64_t *)gprs + 30);
        else if (reg == AArch64::FP)
          dstAddr = *((uint64_t *)gprs + 29);
        else
          dstAddr = *((uint64_t *)gprs + reg - AArch64::X0);
        break;
      }
      default:
        break;
      }
      break;
    }
    case Triple::thumb:
    case Triple::arm: {
      switch (inst.getOpcode()) {
      case ARM::tBLXr:
      case ARM::BLX:
      case ARM::BX:
      case ARM::tBX:
        if (inst.getOperand(0).isReg()) {
          auto reg = inst.getOperand(0).getReg();
          if (reg == ARM::PC)
            dstAddr = addr;
          else if (reg == ARM::LR)
            dstAddr = *((uint64_t *)gprs + 13);
          else
            dstAddr = *((uint64_t *)gprs + reg - ARM::R0);
        }
        break;
      // <MCInst 771 <MCOperand Reg:14> <MCOperand Reg:84> <MCOperand
      // Reg:84> <MCOperand Imm:812> <MCOperand Imm:14> <MCOperand Reg:0>>
      case ARM::LDR_PRE_IMM:
        if (isptr) {
          *isptr = true;
          dstAddr = *((int64_t *)gprs + inst.getOperand(1).getReg() - ARM::R0) +
                    (int64_t)inst.getOperand(3).getImm();
        }
        break;
      default:
        break;
      }
      break;
    }
    case Triple::x86_64:
    case Triple::x86: {
      switch (inst.getOpcode()) {
      case X86::JMP32m:
      case X86::JMP64m:
        if (isptr) {
          *isptr = true;
          dstAddr = regContextLoadMem64(gprs, inst, oplen);
        }
        break;
      case X86::JMP32r:
      case X86::JMP64r:
      case X86::CALL32r:
      case X86::CALL64r:
        dstAddr = x64reg_value(gprs, inst.getOperand(0).getReg());
        break;
      default:
        break;
      }
      break;
    }
    default:
      break;
    }
  }
  if (!dstAddr && oplen) {
    switch (arch) {
    case Triple::aarch64: {
      MachineARM64 m;
      dstAddr = m.dstAddr(&inst, oplen, addr);
      break;
    }
    case Triple::thumb:
    case Triple::arm: {
      MachineARM m;
      dstAddr = m.dstAddr(&inst, oplen, addr);
      break;
    }
    case Triple::x86_64:
    case Triple::x86: {
      MachineX86 m;
      dstAddr = m.dstAddr(&inst, oplen, addr);
      break;
    }
    default:
      break;
    }
  }
  return dstAddr;
}

static int a64reg_index(unsigned llvmreg) {
  switch (llvmreg) {
  case AArch64::FP:
    return 29;
  case AArch64::LR:
    return 30;
  case AArch64::SP:
    return 31;
  default:
    return llvmreg - AArch64::X0;
  }
}

bool Disassembler::hitCondA64(const uint64_t *gprs, int n, int z, int c, int v,
                              unsigned mc) {
  MCInst inst;
  disassemble(mc, inst);
  return hitCondA64(gprs, n, z, c, v, mc, inst);
}

bool Disassembler::hitCondA64(const uint64_t *gprs, int n, int z, int c, int v,
                              unsigned mc, llvm::MCInst &inst) {
  int cond = 0;
  switch (inst.getOpcode()) {
  case AArch64::Bcc:
    cond = (int)inst.getOperand(0).getImm();
    break;
  case AArch64::CBZW:
    return (int)gprs[a64reg_index(inst.getOperand(0).getReg())] == 0;
  case AArch64::CBZX:
    return gprs[a64reg_index(inst.getOperand(0).getReg())] == 0;
  case AArch64::CBNZW:
    return (int)gprs[a64reg_index(inst.getOperand(0).getReg())] != 0;
  case AArch64::CBNZX:
    return gprs[a64reg_index(inst.getOperand(0).getReg())] != 0;
  case AArch64::TBZW:
    return ((int)gprs[a64reg_index(inst.getOperand(0).getReg())] &
            (1 << (int)inst.getOperand(1).getImm())) == 0;
  case AArch64::TBZX:
    return (gprs[a64reg_index(inst.getOperand(0).getReg())] &
            (1ll << inst.getOperand(1).getImm())) == 0;
  case AArch64::TBNZW:
    return ((int)gprs[a64reg_index(inst.getOperand(0).getReg())] &
            (1 << (int)inst.getOperand(1).getImm())) != 0;
  case AArch64::TBNZX:
    return (gprs[a64reg_index(inst.getOperand(0).getReg())] &
            (1ll << inst.getOperand(1).getImm())) != 0;
  default:
    return true;
  }
  int result = 0;
  switch ((int)cond >> 1) {
  case 0:
    result = z == 1;
    break;
  case 1:
    result = c == 1;
    break;
  case 2:
    result = n == 1;
    break;
  case 3:
    result = v == 1;
    break;
  case 4:
    result = c == 1 && z == 0;
    break;
  case 5:
    result = n == v;
    break;
  case 6:
    result = n == v && z == 0;
    break;
  default:
    result = 1;
    break;
  }
  if ((cond & 1) && cond != 0xF) {
    result = !result;
  }
  return result;
}

static inline uint32_t Bits32(const uint32_t bits, const uint32_t msbit,
                              const uint32_t lsbit) {
  return (bits >> lsbit) & ((1u << (msbit - lsbit + 1)) - 1);
}

// Create a mask that starts at bit zero and includes "bit"
static inline uint64_t MaskUpToBit(const uint64_t bit) {
  if (bit >= 63)
    return -1ll;
  return (1ull << (bit + 1ull)) - 1ull;
}

static inline uint64_t UnsignedBits(const uint64_t value, const uint64_t msbit,
                                    const uint64_t lsbit) {
  uint64_t result = value >> lsbit;
  result &= MaskUpToBit(msbit - lsbit);
  return result;
}

static uint32_t CurrentCond(int t, const uint32_t opcode, int oplen) {
  // arm mode
  if (!t)
    return (uint32_t)UnsignedBits(opcode, 31, 28);

  const uint32_t byte_size = oplen;
  if (byte_size == 2) {
    if (Bits32(opcode, 15, 12) == 0x0d && Bits32(opcode, 11, 8) != 0x0f)
      return Bits32(opcode, 11, 8);
  } else {
    if (Bits32(opcode, 31, 27) == 0x1e && Bits32(opcode, 15, 14) == 0x02 &&
        Bits32(opcode, 12, 12) == 0x00 && Bits32(opcode, 25, 22) <= 0x0d) {
      return Bits32(opcode, 25, 22);
    }
  }
  return UINT32_MAX;
}

bool Disassembler::hitCondA32(const uint64_t *gprs, int n, int z, int c, int v,
                              int t, unsigned mc) {
  MCInst inst;
  int oplen = disassemble(mc, inst);
  return hitCondA32(gprs, n, z, c, v, t, mc, inst, oplen);
}

bool Disassembler::hitCondA32(const uint64_t *gprs, int n, int z, int c, int v,
                              int t, unsigned mc, llvm::MCInst &inst,
                              int oplen) {
  const uint32_t cond = CurrentCond(t, mc, oplen);
  if (cond == UINT32_MAX)
    return false;

  bool result = false;
  switch (UnsignedBits(cond, 3, 1)) {
  case 0:
    result = z != 0;
    break;
  case 1:
    result = c != 0;
    break;
  case 2:
    result = n != 0;
    break;
  case 3:
    result = v != 0;
    break;
  case 4:
    result = (c != 0) && (z == 0);
    break;
  case 5:
    result = n == v;
    break;
  case 6:
    result = n == v && (z == 0);
    break;
  case 7:
    // Always execute (cond == 0b1110, or the special 0b1111 which gives
    // opcodes different meanings, but always means execution happens.
    return true;
  }

  if (cond & 1)
    result = !result;
  return result;
}

typedef enum ConditionTypeX64 {
  // must start from 0, see regContextHitCondFuncs
  CONDT_jae = 0,
  CONDT_ja,
  CONDT_jbe,
  CONDT_jb,
  CONDT_je,
  CONDT_jge,
  CONDT_jg,
  CONDT_jle,
  CONDT_jl,
  CONDT_jne,
  CONDT_jno,
  CONDT_jnp,
  CONDT_jns,
  CONDT_jo,
  CONDT_jp,
  CONDT_js,
  CONDT_jrcxz,
  CONDT_jecxz,
  CONDT_x64_end,
} ConditionTypeX64;

struct rflags_t {
  rfbits_t bit;
  const uint64_t *gpr;
};

// hit condition, see IntelArch.pdf/Page-588
#define flags fv.bit

static inline int cond_hit_ja(rflags_t &fv) {
  // Jump if above (CF=0 and ZF=0).
  return flags.CF == 0 && flags.ZF == 0;
}

static inline int cond_hit_jge(rflags_t &fv) {
  // Jump if greater or equal (SF=OF).
  return flags.SF == flags.OF;
}

static inline int cond_hit_jb(rflags_t &fv) {
  // Jump if below (CF=1).
  return flags.CF == 1;
}

static inline int cond_hit_jae(rflags_t &fv) {
  // Jump if above or equal (CF=0).
  return flags.CF == 0;
}

static inline int cond_hit_je(rflags_t &fv) {
  // Jump if equal (ZF=1).
  return flags.ZF == 1;
}

static inline int cond_hit_jne(rflags_t &fv) {
  // Jump if not equal (ZF=0).
  return flags.ZF == 0;
}

static inline int cond_hit_js(rflags_t &fv) {
  // Jump if sign (SF=1).
  return flags.SF == 1;
}

static inline int cond_hit_jl(rflags_t &fv) {
  // Jump if less (SF≠ OF).
  return flags.SF != flags.OF;
}

static inline int cond_hit_jle(rflags_t &fv) {
  // Jump if less or equal (ZF=1 or SF≠ OF).
  return flags.SF != flags.OF || flags.ZF == 1;
}

static inline int cond_hit_jbe(rflags_t &fv) {
  // Jump if below or equal (CF=1 or ZF=1).
  return flags.CF == 1 || flags.ZF == 1;
}

static inline int cond_hit_jg(rflags_t &fv) {
  // Jump if greater (ZF=0 and SF=OF).
  return flags.ZF == 0 && flags.SF == flags.OF;
}

static inline int cond_hit_jno(rflags_t &fv) {
  // Jump if not overflow (OF=0).
  return flags.OF == 0;
}

static inline int cond_hit_jnp(rflags_t &fv) {
  // Jump if not parity (PF=0).
  return flags.PF == 0;
}

static inline int cond_hit_jns(rflags_t &fv) {
  // Jump if not sign (SF=0).
  return flags.SF == 0;
}

static inline int cond_hit_jo(rflags_t &fv) {
  // Jump if overflow (OF=1).
  return flags.OF == 1;
}

static inline int cond_hit_jp(rflags_t &fv) {
  // Jump if parity (PF=1).
  return flags.PF == 1;
}

/*
 typedef struct {
 ULONG_PTR cax;
 ULONG_PTR ccx;
 ...
 */
static inline int cond_hit_jecxz(rflags_t &fv) {
  return (uint32_t)fv.gpr[1] == 0u;
}

static inline int cond_hit_jrcxz(rflags_t &fv) { return fv.gpr[1] == 0; }

#define COND_FUNC(cond) (void *)cond_hit_##cond

static const void *regContextHitCondFuncs[] = {
    COND_FUNC(jae),   COND_FUNC(ja),    COND_FUNC(jbe), COND_FUNC(jb),
    COND_FUNC(je),    COND_FUNC(jge),   COND_FUNC(jg),  COND_FUNC(jle),
    COND_FUNC(jl),    COND_FUNC(jne),   COND_FUNC(jno), COND_FUNC(jnp),
    COND_FUNC(jns),   COND_FUNC(jo),    COND_FUNC(jp),  COND_FUNC(js),
    COND_FUNC(jrcxz), COND_FUNC(jecxz),
};

static bool regContextHitCond(const uint64_t *gprs, uint64_t eflags,
                              ConditionTypeX64 cond) {
  rflags_t fv;
  fv.bit = *(rfbits_t *)&eflags;
  fv.gpr = gprs;
  if (cond < CONDT_x64_end) {
    return ((bool (*)(rflags_t &))regContextHitCondFuncs[cond])(fv);
  }
  switch (cond) {
  case CONDT_jae:
    return cond_hit_jae(fv);
  case CONDT_ja:
    return cond_hit_ja(fv);
  case CONDT_jbe:
    return cond_hit_jbe(fv);
  case CONDT_jb:
    return cond_hit_jb(fv);
  case CONDT_je:
    return cond_hit_je(fv);
  case CONDT_jge:
    return cond_hit_jge(fv);
  case CONDT_jg:
    return cond_hit_ja(fv);
  case CONDT_jle:
    return cond_hit_jle(fv);
  case CONDT_jl:
    return cond_hit_jl(fv);
  case CONDT_jne:
    return cond_hit_jne(fv);
  case CONDT_jno:
    return cond_hit_jno(fv);
  case CONDT_jnp:
    return cond_hit_jnp(fv);
  case CONDT_jns:
    return cond_hit_jns(fv);
  case CONDT_jo:
    return cond_hit_jo(fv);
  case CONDT_jp:
    return cond_hit_jp(fv);
  case CONDT_js:
    return cond_hit_js(fv);
  case CONDT_jecxz:
    return cond_hit_jecxz(fv);
  case CONDT_jrcxz:
    return cond_hit_jrcxz(fv);
  default:
    return false;
  }
  return false;
}

#define add_jcond_opr(cond)                                                    \
  {                                                                            \
    inst.addOperand(MCOperand::createImm(CONDT_##cond));                       \
    break;                                                                     \
  }

#define set_jcond_opr(cond)                                                    \
  {                                                                            \
    opr.setImm(CONDT_##cond);                                                  \
    break;                                                                     \
  }

bool Disassembler::hitCondX64(const uint64_t *gprs, uint64_t eflags,
                              unsigned char *mc) {
  MCInst inst;
  disassemble(mc, 16, inst);
  switch (inst.getOpcode()) {
#if LLVM_VERSION_MAJOR >= 11
  case X86::JCC_1:
  case X86::JCC_2:
  case X86::JCC_4: {
    MCOperand &opr = inst.getOperand(1);
    // see llvm/lib/Target/X86/MCTargetDesc/X86InstPrinterCommon.cpp
    switch (opr.getImm()) {
    default:
      return false;
    case 0:
      set_jcond_opr(jo);
    case 1:
      set_jcond_opr(jno);
    case 2:
      set_jcond_opr(jb);
    case 3:
      set_jcond_opr(jae);
    case 4:
      set_jcond_opr(je);
    case 5:
      set_jcond_opr(jne);
    case 6:
      set_jcond_opr(jbe);
    case 7:
      set_jcond_opr(ja);
    case 8:
      set_jcond_opr(js);
    case 9:
      set_jcond_opr(jns);
    case 0xa:
      set_jcond_opr(jp);
    case 0xb:
      set_jcond_opr(jnp);
    case 0xc:
      set_jcond_opr(jl);
    case 0xd:
      set_jcond_opr(jge);
    case 0xe:
      set_jcond_opr(jle);
    case 0xf:
      set_jcond_opr(jg);
    }
    break;
  }
#else
  case X86::JAE_1:
    add_jcond_opr(jae);
  case X86::JA_1:
    add_jcond_opr(ja);
  case X86::JBE_1:
    add_jcond_opr(jbe);
  case X86::JB_1:
    add_jcond_opr(jb);
  case X86::JE_1:
    add_jcond_opr(je);
  case X86::JGE_1:
    add_jcond_opr(jge);
  case X86::JG_1:
    add_jcond_opr(jg);
  case X86::JLE_1:
    add_jcond_opr(jle);
  case X86::JL_1:
    add_jcond_opr(jl);
  case X86::JNE_1:
    add_jcond_opr(jne);
  case X86::JNO_1:
    add_jcond_opr(jno);
  case X86::JNP_1:
    add_jcond_opr(jnp);
  case X86::JNS_1:
    add_jcond_opr(jns);
  case X86::JO_1:
    add_jcond_opr(jo);
  case X86::JP_1:
    add_jcond_opr(jp);
  case X86::JS_1:
    add_jcond_opr(js);
  case X86::JAE_2:
    add_jcond_opr(jae);
  case X86::JA_2:
    add_jcond_opr(ja);
  case X86::JBE_2:
    add_jcond_opr(jbe);
  case X86::JB_2:
    add_jcond_opr(jb);
  case X86::JE_2:
    add_jcond_opr(je);
  case X86::JGE_2:
    add_jcond_opr(jge);
  case X86::JG_2:
    add_jcond_opr(jg);
  case X86::JLE_2:
    add_jcond_opr(jle);
  case X86::JL_2:
    add_jcond_opr(jl);
  case X86::JNE_2:
    add_jcond_opr(jne);
  case X86::JNO_2:
    add_jcond_opr(jno);
  case X86::JNP_2:
    add_jcond_opr(jnp);
  case X86::JNS_2:
    add_jcond_opr(jns);
  case X86::JO_2:
    add_jcond_opr(jo);
  case X86::JP_2:
    add_jcond_opr(jp);
  case X86::JS_2:
    add_jcond_opr(js);
  case X86::JGE_4:
    add_jcond_opr(jge);
  case X86::JAE_4:
    add_jcond_opr(jae);
  case X86::JA_4:
    add_jcond_opr(ja);
  case X86::JBE_4:
    add_jcond_opr(jbe);
  case X86::JB_4:
    add_jcond_opr(jb);
  case X86::JE_4:
    add_jcond_opr(je);
  case X86::JG_4:
    add_jcond_opr(jg);
  case X86::JLE_4:
    add_jcond_opr(jle);
  case X86::JL_4:
    add_jcond_opr(jl);
  case X86::JNE_4:
    add_jcond_opr(jne);
  case X86::JNO_4:
    add_jcond_opr(jno);
  case X86::JNP_4:
    add_jcond_opr(jnp);
  case X86::JNS_4:
    add_jcond_opr(jns);
  case X86::JO_4:
    add_jcond_opr(jo);
  case X86::JP_4:
    add_jcond_opr(jp);
  case X86::JS_4:
    add_jcond_opr(js);
#endif
  case X86::JRCXZ:
    add_jcond_opr(jrcxz);
  case X86::JECXZ:
    add_jcond_opr(jecxz);
    break;
  default:
    return false;
  }
  return regContextHitCond(gprs, eflags,
                           (ConditionTypeX64)inst.getOperand(1).getImm());
}

std::string Disassembler::demangle(const char *sym) {
  return llvm::demangle(sym);
}

} // namespace aether
