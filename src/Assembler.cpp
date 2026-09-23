// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>

//===-- llvm-mc.cpp - Machine Code Hacking Driver ---------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This utility is a simple driver that allows command line hacking on machine
// code.
//
//===----------------------------------------------------------------------===//

#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCParser/AsmLexer.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetOptionsCommandFlags.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Compression.h"
#include "llvm/Support/FileUtilities.h"
#include "llvm/Support/FormattedStream.h"
#if LLVM_VERSION_MAJOR >= 19
#include "llvm/TargetParser/Host.h"
#else
#include "llvm/Support/Host.h"
#endif
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#if LLVM_VERSION_MAJOR >= 14
#include "llvm/MC/TargetRegistry.h"
#else
#include "llvm/Support/TargetRegistry.h"
#endif
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/WithColor.h"

using namespace llvm;

enum OutputFileType { OFT_Null, OFT_AssemblyFile, OFT_ObjectFile };

static std::unique_ptr<ToolOutputFile>
GetOutputStream(StringRef Path, sys::fs::OpenFlags Flags) {
  std::error_code EC;
  auto Out = std::make_unique<ToolOutputFile>(Path, EC, Flags);
  if (EC) {
    WithColor::error() << EC.message() << '\n';
    return nullptr;
  }

  return Out;
}

static std::string DwarfDebugFlags;
static void setDwarfDebugFlags(int argc, char **argv) {
  if (!getenv("RC_DEBUG_OPTIONS"))
    return;
  for (int i = 0; i < argc; i++) {
    DwarfDebugFlags += argv[i];
    if (i + 1 < argc)
      DwarfDebugFlags += " ";
  }
}

static std::string DwarfDebugProducer;
static void setDwarfDebugProducer() {
  if (!getenv("DEBUG_PRODUCER"))
    return;
  DwarfDebugProducer += getenv("DEBUG_PRODUCER");
}

static int AsLexInput(SourceMgr &SrcMgr, MCAsmInfo &MAI, raw_ostream &OS) {
  AsmLexer Lexer(MAI);
  Lexer.setBuffer(SrcMgr.getMemoryBuffer(SrcMgr.getMainFileID())->getBuffer());

  bool Error = false;
  while (Lexer.Lex().isNot(AsmToken::Eof)) {
    Lexer.getTok().dump(OS);
    OS << "\n";
    if (Lexer.getTok().getKind() == AsmToken::Error)
      Error = true;
  }

  return Error;
}

static int fillCommandLineSymbols(MCAsmParser &Parser) { return 0; }

namespace aether {
extern const llvm::Target *diser_getTarget(void *ctx);
extern MCRegisterInfo *diser_getMCRegInfo(void *ctx);
extern MCAsmInfo *diser_createMCAsmInfo(void *ctx);
extern MCInstrInfo *diser_createMCInstrInfo(void *ctx);
extern MCSubtargetInfo *diser_createMCSubtargetInfo(void *ctx);
extern MCInstPrinter *diser_createMCInstPrinter(void *ctx);
extern MCStreamer *diser_createAsmStreamer(void *ctx);
} // namespace aether

using namespace aether;

#define GetTarget(...) diser_getTarget(ctx)
#define TheTarget_createMCRegInfo(...) diser_getMCRegInfo(ctx)
#define TheTarget_createMCAsmInfo(...) diser_createMCAsmInfo(ctx)
#define TheTarget_createMCInstrInfo(...) diser_createMCInstrInfo(ctx)
#define TheTarget_createMCSubtargetInfo(...) diser_createMCSubtargetInfo(ctx)
#define TheTarget_createMCInstPrinter(...) diser_createMCInstPrinter(ctx)
#define TheTarget_createAsmStreamer(...) diser_createAsmStreamer(ctx)

#define USE_CACHE_INST 1

static int AssembleInput(void *ctx, const char *ProgName,
                         const Target *TheTarget, SourceMgr &SrcMgr,
                         MCContext &Ctx, MCStreamer &Str, MCAsmInfo &MAI,
                         MCSubtargetInfo &STI, MCInstrInfo &MCII,
                         MCTargetOptions const &MCOptions) {
  std::unique_ptr<MCAsmParser> Parser(createMCAsmParser(SrcMgr, Ctx, Str, MAI));
  std::unique_ptr<MCTargetAsmParser> TAP(
      TheTarget->createMCAsmParser(STI, *Parser, MCII, MCOptions));

  if (!TAP) {
    WithColor::error(errs(), ProgName)
        << "this target does not support assembly parsing.\n";
    return 1;
  }

  int SymbolResult = fillCommandLineSymbols(*Parser);
  if (SymbolResult)
    return SymbolResult;
  Parser->setShowParsedOperands(false);
  Parser->setTargetParser(*TAP);
  Parser->getLexer().setLexMasmIntegers(false);

  int Res = Parser->Run(false);

  return Res;
}

int llvm_mc_main(const char *triple, const char *asmcode,
                 raw_pwrite_stream *rawos, void *ctx) {
  // let aether::Disassembler do this
#if 0
  InitLLVM X(argc, argv);

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmParsers();
  llvm::InitializeAllDisassemblers();

  // Register the target printer for --version.
  cl::AddExtraVersionPrinter(TargetRegistry::printRegisteredTargetsForVersion);
  cl::ParseCommandLineOptions(argc, argv, "llvm machine code playground\n");
  setDwarfDebugFlags(argc, argv);
  setDwarfDebugProducer();
#endif

  MCTargetOptions MCOptions = mc::InitMCTargetOptionsFromFlags();
  MCOptions.ShowMCEncoding = true; // force it to show the opcode we need
#if LLVM_VERSION_MAJOR >= 22
  MCOptions.AsmVerbose = true;
#endif

  const char *ProgName = "AetherBinary";
  const Target *TheTarget = GetTarget(ProgName);
  if (!TheTarget)
    return 1;
  // Now that GetTarget() has (potentially) replaced TripleName, it's safe to
  // construct the Triple object.
  Triple TheTriple(triple);

  ErrorOr<std::unique_ptr<MemoryBuffer>> BufferPtr =
      // MemoryBuffer::getFileOrSTDIN(InputFilename)
      MemoryBuffer::getMemBuffer(asmcode);
  MemoryBuffer *Buffer = BufferPtr->get();

  SourceMgr SrcMgr;

  // Tell SrcMgr about this buffer, which is what the parser will pick up.
  SrcMgr.AddNewSourceBuffer(std::move(*BufferPtr), SMLoc());

#if USE_CACHE_INST
  MCRegisterInfo *MRI(TheTarget_createMCRegInfo(TripleName));
  assert(MRI && "Unable to create target register info!");

  MCAsmInfo *MAI(TheTarget_createMCAsmInfo(*MRI, TripleName, MCOptions));
  assert(MAI && "Unable to create target asm info!");
#else
  std::unique_ptr<MCRegisterInfo> MRI(TheTarget->createMCRegInfo(TripleName));
  assert(MRI && "Unable to create target register info!");

  std::unique_ptr<MCAsmInfo> MAI(
      TheTarget->createMCAsmInfo(*MRI, TripleName, MCOptions));
  assert(MAI && "Unable to create target asm info!");
#endif

#if LLVM_VERSION_MAJOR < 19
  MAI->setRelaxELFRelocations(RelaxELFRel);
#endif

#if 0
  if (CompressDebugSections != DebugCompressionType::None) {
    if (!zlib::isAvailable()) {
      WithColor::error(errs(), ProgName)
          << "build tools with zlib to enable -compress-debug-sections";
      return 1;
    }
    MAI->setCompressDebugSections(CompressDebugSections);
  }
#endif

  MAI->setPreserveAsmComments(false);

#if USE_CACHE_INST
  MCStreamer *Str = nullptr;
  MCInstrInfo *MCII(TheTarget_createMCInstrInfo());
  MCSubtargetInfo *STI(
      TheTarget_createMCSubtargetInfo(TripleName, MCPU, FeaturesStr));
#else
  std::unique_ptr<MCStreamer> Str;
  std::unique_ptr<MCInstrInfo> MCII(TheTarget->createMCInstrInfo());
  std::unique_ptr<MCSubtargetInfo> STI(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU, FeaturesStr));
  assert(STI && "Unable to create subtarget info!");
#endif

// FIXME: This is not pretty. MCContext has a ptr to MCObjectFileInfo and
// MCObjectFileInfo needs a MCContext reference in order to initialize itself.
#if LLVM_VERSION_MAJOR >= 14
#if USE_CACHE_INST
  MCContext Ctx(TheTriple, MAI, MRI, STI, &SrcMgr, &MCOptions);
#else
  MCContext Ctx(TheTriple, MAI.get(), MRI.get(), STI.get(), &SrcMgr,
                &MCOptions);
#endif
  bool PIC = true, LargeCodeModel = false;
  std::unique_ptr<MCObjectFileInfo> MOFI(
      TheTarget->createMCObjectFileInfo(Ctx, PIC, LargeCodeModel));
  Ctx.setObjectFileInfo(MOFI.get());
#else
  MCObjectFileInfo MOFI;
#if USE_CACHE_INST
  MCContext Ctx(MAI, MRI, &MOFI, &SrcMgr, &MCOptions);
#else
  MCContext Ctx(MAI.get(), MRI.get(), &MOFI, &SrcMgr, &MCOptions);
#endif
  MOFI.InitMCObjectFileInfo(TheTriple, PIC, Ctx, LargeCodeModel);
#endif

#if USE_CACHE_INST
#else
#if LLVM_VERSION_MAJOR < 22
  if (SaveTempLabels)
    Ctx.setAllowTemporaryLabels(false);
#endif

  Ctx.setGenDwarfForAssembly(GenDwarfForAssembly);
  // Default to 4 for dwarf version.
  unsigned DwarfVersion = MCOptions.DwarfVersion ? MCOptions.DwarfVersion : 4;
  if (DwarfVersion < 2 || DwarfVersion > 5) {
    errs() << ProgName << ": Dwarf version " << DwarfVersion
           << " is not supported." << '\n';
    return 1;
  }
  Ctx.setDwarfVersion(DwarfVersion);
  if (!DwarfDebugFlags.empty())
    Ctx.setDwarfDebugFlags(StringRef(DwarfDebugFlags));
  if (!DwarfDebugProducer.empty())
    Ctx.setDwarfDebugProducer(StringRef(DwarfDebugProducer));
  if (!DebugCompilationDir.empty())
    Ctx.setCompilationDir(DebugCompilationDir);
  else {
    // If no compilation dir is set, try to use the current directory.
    SmallString<128> CWD;
    if (!sys::fs::current_path(CWD))
      Ctx.setCompilationDir(CWD);
  }
  for (const auto &Arg : DebugPrefixMap) {
    const auto &KV = StringRef(Arg).split('=');
    Ctx.addDebugPrefixMapEntry(std::string(KV.first), std::string(KV.second));
  }
  if (!MainFileName.empty())
    Ctx.setMainFileName(MainFileName);
  if (GenDwarfForAssembly)
    Ctx.setGenDwarfRootFile(InputFilename, Buffer->getBuffer());

  sys::fs::OpenFlags Flags =
      (FileType == OFT_AssemblyFile) ? sys::fs::OF_Text : sys::fs::OF_None;
  std::unique_ptr<ToolOutputFile> Out = GetOutputStream(OutputFilename, Flags);

  std::unique_ptr<ToolOutputFile> DwoOut;
  if (!SplitDwarfFile.empty()) {
    if (FileType != OFT_ObjectFile) {
      WithColor::error() << "dwo output only supported with object files\n";
      return 1;
    }
    DwoOut = GetOutputStream(SplitDwarfFile, sys::fs::OF_None);
    if (!DwoOut)
      return 1;
  }
#endif

  std::unique_ptr<buffer_ostream> BOS;
  raw_pwrite_stream *OS = rawos;
  OutputFileType FileType = OFT_AssemblyFile;
  MCInstPrinter *IP = nullptr;
  if (FileType == OFT_AssemblyFile) {
#if USE_CACHE_INST
    IP = TheTarget_createMCInstPrinter(Triple(TripleName), OutputAsmVariant,
                                       *MAI, *MCII, *MRI);
#else
    IP = TheTarget->createMCInstPrinter(Triple(TripleName), OutputAsmVariant,
                                        *MAI, *MCII, *MRI);
#endif

    if (!IP) {
      WithColor::error()
          << "unable to create instruction printer for target triple '"
          << TheTriple.normalize() << ".\n";
      return 1;
    }

    // Set the display preference for hex vs. decimal immediates.
    IP->setPrintImmHex(true);

#if USE_CACHE_INST
    // Set up the AsmStreamer.
    MCCodeEmitter *CE = nullptr;
    MCAsmBackend *MAB(
        nullptr); // TheTarget_createMCAsmBackend(*STI, *MRI, MCOptions));
    // auto FOut = std::make_unique<formatted_raw_ostream>(*OS);
    Str = TheTarget_createAsmStreamer(Ctx, std::move(FOut), /*asmverbose*/ true,
                                      /*useDwarfDirectory*/ true, IP,
                                      std::move(CE), std::move(MAB), ShowInst);
#else
    // Set up the AsmStreamer.
#if LLVM_VERSION_MAJOR >= 17
    std::unique_ptr<MCCodeEmitter> CE(
        TheTarget->createMCCodeEmitter(*MCII, Ctx));
#else
    std::unique_ptr<MCCodeEmitter> CE(
        TheTarget->createMCCodeEmitter(*MCII, *MRI, Ctx));
#endif

    std::unique_ptr<MCAsmBackend> MAB(
        TheTarget->createMCAsmBackend(*STI, *MRI, MCOptions));
    auto FOut = std::make_unique<formatted_raw_ostream>(*OS);
    Str.reset(
        TheTarget->createAsmStreamer(Ctx, std::move(FOut), /*asmverbose*/ true,
                                     /*useDwarfDirectory*/ true, IP,
                                     std::move(CE), std::move(MAB), ShowInst));
#endif
  } else if (FileType == OFT_Null) {
    abort(); // Str.reset(TheTarget_createNullStreamer(Ctx));
  } else {
#if 0
    assert(FileType == OFT_ObjectFile && "Invalid file type!");

    if (!Out.os().supportsSeeking()) {
      BOS = std::make_unique<buffer_ostream>(Out.os());
      OS = BOS.get();
    }

    MCCodeEmitter *CE = TheTarget_createMCCodeEmitter(*MCII, *MRI, Ctx);
    MCAsmBackend *MAB = TheTarget_createMCAsmBackend(*STI, *MRI, MCOptions);
    Str = TheTarget_createMCObjectStreamer(
        TheTriple, Ctx, std::unique_ptr<MCAsmBackend>(MAB),
        DwoOut ? MAB->createDwoObjectWriter(*OS, DwoOut->os())
               : MAB->createObjectWriter(*OS),
        std::unique_ptr<MCCodeEmitter>(CE), *STI, MCOptions.MCRelaxAll,
        MCOptions.MCIncrementalLinkerCompatible,
        /*DWARFMustBeAtTheEnd*/ false);
    if (NoExecStack) Str->InitSections(true);
#else
    abort();
#endif
  }

  // Use Assembler information for parsing.
  Str->setUseAssemblerInfoForParsing(true);

  return AssembleInput(ctx, ProgName, TheTarget, SrcMgr, Ctx, *Str, *MAI, *STI,
                       *MCII, MCOptions);
}
