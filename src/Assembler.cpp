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

static mc::RegisterMCTargetOptionsFlags MOF;

static cl::opt<std::string>
    InputFilename(cl::Positional, cl::desc("<input file>"), cl::init("-"));
#if 0
static cl::opt<std::string> OutputFilename("o-aebi", cl::desc("Output filename"),
                                           cl::value_desc("filename"),
                                           cl::init("-"));
#endif
static cl::opt<std::string> SplitDwarfFile("split-dwarf-file-aebi",
                                           cl::desc("DWO output filename"),
                                           cl::value_desc("filename"));

static cl::opt<bool> ShowEncoding("show-encoding-aebi",
                                  cl::desc("Show instruction encodings"));

static cl::opt<bool> RelaxELFRel(
    "relax-relocations-aebi", cl::init(true),
    cl::desc("Emit R_X86_64_GOTPCRELX instead of R_X86_64_GOTPCREL"));

#if 0
static cl::opt<DebugCompressionType> CompressDebugSections(
    "compress-debug-sections-aebi", cl::ValueOptional,
    cl::init(DebugCompressionType::None),
    cl::desc("Choose DWARF debug sections compression:"),
    cl::values(clEnumValN(DebugCompressionType::None, "none", "No compression"),
               clEnumValN(DebugCompressionType::Z, "zlib",
                          "Use zlib compression"),
               clEnumValN(DebugCompressionType::GNU, "zlib-gnu",
                          "Use zlib-gnu compression (deprecated)")));
#endif

static cl::opt<bool>
    ShowInst("show-inst-aebi",
             cl::desc("Show internal instruction representation"));

static cl::opt<bool>
    ShowInstOperands("show-inst-operands-aebi",
                     cl::desc("Show instructions operands as parsed"));

static cl::opt<unsigned>
    OutputAsmVariant("output-asm-variant-aebi",
                     cl::desc("Syntax variant to use for output printing"));

static cl::opt<bool>
    PrintImmHex("print-imm-hex-aebi", cl::init(false),
                cl::desc("Prefer hex format for immediate values"));

static cl::list<std::string>
    DefineSymbol("defsym-aebi",
                 cl::desc("Defines a symbol to be an integer constant"));

static cl::opt<bool>
    PreserveComments("preserve-comments-aebi",
                     cl::desc("Preserve Comments in outputted assembly"));

enum OutputFileType { OFT_Null, OFT_AssemblyFile, OFT_ObjectFile };
static cl::opt<OutputFileType>
    FileType("filetype-aebi", cl::init(OFT_AssemblyFile),
             cl::desc("Choose an output file type:"),
             cl::values(clEnumValN(OFT_AssemblyFile, "asm",
                                   "Emit an assembly ('.s') file"),
                        clEnumValN(OFT_Null, "null",
                                   "Don't emit anything (for timing purposes)"),
                        clEnumValN(OFT_ObjectFile, "obj",
                                   "Emit a native object ('.o') file")));

static cl::list<std::string> IncludeDirs("I-aebi",
                                         cl::desc("Directory of include files"),
                                         cl::value_desc("directory"),
                                         cl::Prefix);

static cl::opt<std::string>
    ArchName("arch-aebi", cl::desc("Target arch to assemble for, "
                                   "see -version for available targets"));

static cl::opt<std::string>
    TripleName("triple-aebi", cl::desc("Target triple to assemble for, "
                                       "see -version for available targets"));

static cl::opt<std::string>
    MCPU("mcpu-aebi",
         cl::desc("Target a specific cpu type (-mcpu=help for details)"),
         cl::value_desc("cpu-name"), cl::init(""));

static cl::list<std::string>
    MAttrs("mattr-aebi", cl::CommaSeparated,
           cl::desc("Target specific attributes (-mattr=help for details)"),
           cl::value_desc("a1,+a2,-a3,..."));

static cl::opt<bool> PIC("position-independent-aebi",
                         cl::desc("Position independent"), cl::init(false));

static cl::opt<bool>
    LargeCodeModel("large-code-model-aebi",
                   cl::desc("Create cfi directives that assume the code might "
                            "be more than 2gb away"));

static cl::opt<bool>
    NoInitialTextSection("n-aebi", cl::desc("Don't assume assembly file starts "
                                            "in the text section"));

static cl::opt<bool>
    GenDwarfForAssembly("g-aebi",
                        cl::desc("Generate dwarf debugging info for assembly "
                                 "source files"));

static cl::opt<std::string>
    DebugCompilationDir("fdebug-compilation-dir-aebi",
                        cl::desc("Specifies the debug info's compilation dir"));

static cl::list<std::string>
    DebugPrefixMap("fdebug-prefix-map-aebi",
                   cl::desc("Map file source paths in debug info"),
                   cl::value_desc("= separated key-value pairs"));

static cl::opt<std::string> MainFileName(
    "main-file-name-aebi",
    cl::desc("Specifies the name we should consider the input file"));

#if LLVM_VERSION_MAJOR < 22
static cl::opt<bool> SaveTempLabels("save-temp-labels-aebi",
                                    cl::desc("Don't discard temporary labels"));
#endif

static cl::opt<bool> LexMasmIntegers(
    "masm-integers-aebi",
    cl::desc("Enable binary and hex masm integers (0b110 and 0ABCh)"));

static cl::opt<bool> NoExecStack("no-exec-stack-aebi",
                                 cl::desc("File doesn't need an exec stack"));

enum ActionType {
  AC_AsLex,
  AC_Assemble,
  AC_Disassemble,
  AC_MDisassemble,
};

static cl::opt<ActionType> Action(
    cl::desc("Action to perform:"), cl::init(AC_Assemble),
    cl::values(clEnumValN(AC_AsLex, "as-lex", "Lex tokens from a .s file"),
               clEnumValN(AC_Assemble, "assemble",
                          "Assemble a .s file (default)"),
               clEnumValN(AC_Disassemble, "disassemble",
                          "Disassemble strings of hex bytes"),
               clEnumValN(AC_MDisassemble, "mdis",
                          "Marked up disassembly of strings of hex bytes")));

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

static int fillCommandLineSymbols(MCAsmParser &Parser) {
  for (auto &I : DefineSymbol) {
    auto Pair = StringRef(I).split('=');
    auto Sym = Pair.first;
    auto Val = Pair.second;

    if (Sym.empty() || Val.empty()) {
      WithColor::error() << "defsym must be of the form: sym=value: " << I
                         << "\n";
      return 1;
    }
    int64_t Value;
    if (Val.getAsInteger(0, Value)) {
      WithColor::error() << "value is not an integer: " << Val << "\n";
      return 1;
    }
    Parser.getContext().setSymbolValue(Parser.getStreamer(), Sym, Value);
  }
  return 0;
}

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
  Parser->setShowParsedOperands(ShowInstOperands);
  Parser->setTargetParser(*TAP);
  Parser->getLexer().setLexMasmIntegers(LexMasmIntegers);

  int Res = Parser->Run(NoInitialTextSection);

  return Res;
}

int llvm_mc_main(int argc, char **argv, raw_pwrite_stream *rawos, void *ctx) {
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

  const char *ProgName = argv[0];
  const Target *TheTarget = GetTarget(ProgName);
  if (!TheTarget)
    return 1;
  // Now that GetTarget() has (potentially) replaced TripleName, it's safe to
  // construct the Triple object.
  Triple TheTriple(TripleName);

  ErrorOr<std::unique_ptr<MemoryBuffer>> BufferPtr =
      // MemoryBuffer::getFileOrSTDIN(InputFilename)
      MemoryBuffer::getMemBuffer(argv[3]);
  if (std::error_code EC = BufferPtr.getError()) {
    WithColor::error(errs(), ProgName)
        << InputFilename << ": " << EC.message() << '\n';
    return 1;
  }
  MemoryBuffer *Buffer = BufferPtr->get();

  SourceMgr SrcMgr;

  // Tell SrcMgr about this buffer, which is what the parser will pick up.
  SrcMgr.AddNewSourceBuffer(std::move(*BufferPtr), SMLoc());

  // Record the location of the include directories so that the lexer can find
  // it later.
  SrcMgr.setIncludeDirs(IncludeDirs);

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

  MAI->setPreserveAsmComments(PreserveComments);

  // Package up features to be passed to target/subtarget
  std::string FeaturesStr;
  if (MAttrs.size()) {
    SubtargetFeatures Features;
    for (unsigned i = 0; i != MAttrs.size(); ++i)
      Features.AddFeature(MAttrs[i]);
    FeaturesStr = Features.getString();
  }

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
          << TheTriple.normalize() << "' with assembly variant "
          << OutputAsmVariant << ".\n";
      return 1;
    }

    // Set the display preference for hex vs. decimal immediates.
    IP->setPrintImmHex(PrintImmHex);

#if USE_CACHE_INST
    // Set up the AsmStreamer.
    MCCodeEmitter *CE = nullptr;
    if (ShowEncoding)
      CE = nullptr; // TheTarget_createMCCodeEmitter(*MCII, *MRI, Ctx);
    else
      (void)CE;

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

  int Res = 1;
  bool disassemble = false;
  switch (Action) {
  case AC_AsLex:
    Res = AsLexInput(SrcMgr, *MAI, *OS);
    break;
  case AC_Assemble:
    Res = AssembleInput(ctx, ProgName, TheTarget, SrcMgr, Ctx, *Str, *MAI, *STI,
                        *MCII, MCOptions);
    break;
  case AC_MDisassemble:
    assert(IP && "Expected assembly output");
    IP->setUseMarkup(true);
    disassemble = true;
    break;
  case AC_Disassemble:
    disassemble = true;
    break;
  }
#if 0
  if (disassemble)
    Res = Disassembler::disassemble(*TheTarget, TripleName, *STI, *Str, *Buffer,
                                    SrcMgr, Ctx, *OS, MCOptions);
#else
  (void)disassemble;
#endif

#if USE_CACHE_INST
#else
  // Keep output if no errors.
  if (Res == 0) {
    Out->keep();
    if (DwoOut)
      DwoOut->keep();
  }

  ShowEncoding.reset();
  TripleName.reset();
  InputFilename.reset();
  OutputAsmVariant.reset();
#endif

  return Res;
}
