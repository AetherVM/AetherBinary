// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

#include "AetherArch.h"
#include "AetherBinary.h"
#include "AetherBinaryPriv.hpp"
#include "Disassembler.h"

using namespace llvm;

namespace aether {

static inline void insert_newfn(addr_t curaddr, std::set<addr_t> &newfn,
                                addr_t addr, bool hasjmpreg) {
#if 0
  if (addr == 0) {
    puts("debug me.");
  }
  printf("%lx : %lx\n", curaddr, addr);
  fflush(stdout);
#endif

  if (!hasjmpreg) {
    newfn.insert(addr);
  }
}

void Machine::analyzeFunc(bool hasfnstarts, Disassembler *diser,
                          const char *opbuff, addr_t start, addr_t end,
                          std::set<addr_t> &newfunc, bool thumb,
                          std::set<addr_t> *datas) {
  if (hasfnstarts && !datas)
    return;

  addr_t addr = start, jmpto = 0;
  bool hasjmpreg = hasfnstarts;
  InsnType lastitype = NORMAL;
  if (thumb) {
    addr &= ~1;
  }
  while (addr < end) {
#if 0
    if (addr == 0) {
      puts("debug me");
    }
#endif
    const char *curop = opbuff + addr - start;
    MCInst inst;
    int consumed = diser->disassemble((unsigned char *)curop, (int)(end - addr),
                                      inst, addr);
    if (consumed == 0) {
      lastitype = IDATA;
      addr += defaultSize();
      continue;
    }
    if (lastitype != NORMAL) {
      if ((inst.getOpcode() == AArch64::STPXpre &&
           inst.getOperand(3).getReg() == AArch64::SP) ||
          (inst.getOpcode() == AArch64::SUBXri &&
           inst.getOperand(0).getReg() == AArch64::SP)) {
        hasjmpreg = hasfnstarts;
        lastitype = NORMAL;
        insert_newfn(addr, newfunc, addr, hasjmpreg);
        continue;
      }
    }
    lastitype = insnType(&inst);
    if (isJumpReg(&inst)) {
      hasjmpreg = true;
    } else if (isCallPcrel(&inst) && inst.getOperand(0).getImm()) {
      addr_t target = callee(&inst, consumed, addr);
      if (target != INVALID_ADDR && target - addr > 6) {
        insert_newfn(addr, newfunc, target | thumb, false);
      }
    } else if (isJumpPcrel(&inst) && inst.getOperand(0).getImm()) {
      addr_t target = jumpee(&inst, consumed, addr);
      if (!(target >= start && target < end)) {
        insert_newfn(addr, newfunc, target | thumb, hasjmpreg);
        if (jmpto < addr) {
          insert_newfn(addr, newfunc, (addr + consumed) | thumb, hasjmpreg);
        }
      } else if (jmpto < target) {
        jmpto = target;
      }
    } else {
      if (lastitype == JCOND) {
        addr_t target = dstAddr(&inst, consumed, addr);
        if (jmpto < target) {
          jmpto = target;
        }
      } else if (lastitype == RET) {
        if (jmpto < addr) {
          insert_newfn(addr, newfunc, (addr + consumed) | thumb, hasjmpreg);
        }
      }
    }
    if (datas && m_arch == ARM64) {
      switch (inst.getOpcode()) {
      case AArch64::ADRP: {
        MCInst instadd;
        diser->disassemble((unsigned char *)curop + 4, 4, instadd, addr + 4);
        if (instadd.getOpcode() == AArch64::ADDXri &&
            instadd.getOperand(0).getReg() == inst.getOperand(0).getReg()) {
          auto adrp = (addr & ~(4096 - 1)) + 4096 * inst.getOperand(1).getImm();
          auto target = adrp + instadd.getOperand(2).getImm();
          datas->insert(target);
        }
        break;
      }
      case AArch64::ADR: {
        int64_t target = addr + (int64_t)inst.getOperand(1).getImm();
        datas->insert(target);
        break;
      }
      case AArch64::LDRSWl:
      case AArch64::LDRWl:
      case AArch64::LDRXl:
      case AArch64::LDRSl:
      case AArch64::LDRDl:
      case AArch64::LDRQl: {
        addr_t target = addr + inst.getOperand(1).getImm() * 4;
        datas->insert(target);
        break;
      }
      default:
        break;
      }
    }
    addr += consumed;
  }
}

static bool isDataInFunc(Binary *bin, Function &func, MCInst &inst,
                         addr_t inneraddr) {
  if (!bin->isCode(inneraddr)) {
    return false;
  }
  switch (bin->archType()) {
  case ARM:
    switch (inst.getOpcode()) {
    case ARM::tLDRpci:
    case ARM::t2LDRpci:
    case ARM::LDRi12:
    case ARM::VLDRD:
    case ARM::VLDRH:
    case ARM::VLDRS:
      return true;
    default:
      break;
    }
    break;
  case ARM64:
    switch (inst.getOpcode()) {
    case AArch64::LDRSWl:
    case AArch64::LDRWl:
    case AArch64::LDRXl:
    case AArch64::LDRSl:
    case AArch64::LDRDl:
    case AArch64::LDRQl:
      return true;
    default:
      break;
    }
  default:
    break;
  }
  auto tarfn = bin->addrFunc(inneraddr, true);
  // return false if inneraddr is a function
  return tarfn ? false : true;
}

static bool isNeverRetfunc(const Function *func) {
  if (!func)
    return false;

  const char *name = func->name.data();
  return strstr(name, ".abort") || strstr(name, "._abort") ||
         strstr(name, ".exit") || strstr(name, "._exit") ||
         strstr(name, "stack_chk_fail") || strstr(name, "_Exit");
}

static bool isUIMainfunc(const Function *func) {
  if (!func)
    return false;

  return strstr(func->name.data(), "_UIApplicationMain");
}

static int regIndex(const MCInst &inst, int i) {
  auto opr = inst.getOperand(i);
  switch (opr.getReg()) {
  case AArch64::FP:
    return 29;
  case AArch64::LR:
    return 30;
  default:
    return opr.getReg() - AArch64::X0;
  }
}

void Machine::analyzeFunc(Disassembler *diser, bool isobj, const char *opbuff,
                          const char *opbuffend, Function &func,
                          Function *lastfunc, Binary *bin, bool thumb,
                          std::set<addr_t> *datas) {
  addr_t addr = func.start, start = func.start;
  if (thumb) {
    addr &= ~1;
    start = addr;
    opbuff -= 1;
  }
  std::map<int, int> jmpfnoffmap, jmpidxmap;
  std::vector<std::pair<addr_t, unsigned>> callpop;
  addr_t maxjmp = 0, adrp = INVALID_ADDR, lastadr = INVALID_ADDR;
  addr_t adrptbl[31] = {0};
  std::map<addr_t, std::set<addr_t>> indjmps;
  unsigned adrpreg = 0;
  bool set_popreg = false, hitret = false;
  while (addr <
         func.end /*|| (!isobj && !(func.flags & MFF_IMPORT) && !hitret)*/) {
#if 0
    if (addr == 0) {
      puts("debug me");
    }
#endif
    int fnoff = (int)(addr - start);
    const char *curop = opbuff + fnoff;
    if (curop >= opbuffend)
      break;
    MCInst inst;
    int consumed = diser->disassemble((unsigned char *)curop, 16, inst, addr);
    Insinfo iinfo;
    iinfo.fnoff = fnoff;
    if (consumed == 0) {
      if (!isobj && func.difs.find(addr) != func.difs.end()) {
        Insinfo iinfo;
        iinfo.fnoff = fnoff;
        iinfo.info.type = IDATA;
        iinfo.info.oplen = 4;
        func.insns.push_back(iinfo);
        addr += iinfo.info.oplen;
        continue;
      } else if (lastfunc &&
                 lastfunc->difs.find(addr) != lastfunc->difs.end()) {
        Insinfo iinfo;
        iinfo.fnoff = fnoff;
        iinfo.info.type = IDATA;
        iinfo.info.oplen = 4;
        func.insns.push_back(iinfo);
        addr += iinfo.info.oplen;
        hitret = true;
        continue;
      }
      consumed = defaultSize();
      iinfo.info.type = IDATA;
      inst.setOpcode(-1);
    } else {
      iinfo.info.type = insnType(&inst);
      if (iinfo.info.type == RET || iinfo.info.type == TRAP) {
        hitret = true;
      }
    }
    iinfo.info.oplen = consumed;

    addr_t jmpaddr = INVALID_ADDR;
    if (iinfo.info.type == JUMP || iinfo.info.type == JCOND) {
      addr_t taraddr = jumpee(&inst, consumed, addr);
      if (taraddr < start || (int64_t)(taraddr - func.end) > 10 * 1024) {
        hitret = true;
      } else {
        jmpaddr = taraddr;
      }
    } else if (iinfo.info.type == CALL) {
      addr_t calleeaddr = callee(&inst, consumed, addr);
      auto calleefn = bin->addrFunc(calleeaddr, true);
      if (isNeverRetfunc(calleefn)) {
        hitret = true;
      } else if (isUIMainfunc(calleefn)) {
        func.name = "_main";
        func.flags |= MFF_EXPORT;
      }
    }

    if (m_arch == X86_64 || m_arch == X86) {
      switch (inst.getOpcode()) {
      case X86::LEA64r: {
        switch (inst.getOperand(1).getReg()) {
        case X86::IP:
        case X86::EIP:
        case X86::RIP: {
          if (inst.getOperand(3).getReg() != X86::NoRegister) {
            assert(0 && "will this situation occur ?");
          }
          addr_t inneraddr = addr + consumed + inst.getOperand(4).getImm();
          if (isDataInFunc(bin, func, inst, inneraddr)) {
            func.difs.insert(inneraddr);
          }
          break;
        }
        default:
          break;
        }
        break;
      }
      case X86::CALLpcrel16:
      case X86::CALLpcrel32:
      case X86::CALL64pcrel32: {
        if (!inst.getOperand(0).getImm()) {
          func.getpc.insert(addr);
          callpop.push_back(std::make_pair(addr + consumed, X86::NoRegister));
          set_popreg = true;
        }
        break;
      }
      case X86::POP32r: {
        if (set_popreg) {
          set_popreg = false;
          callpop.rbegin()->second = inst.getOperand(0).getReg();
        }
        break;
      }
      case X86::ADD32rm: {
        unsigned basereg = inst.getOperand(2).getReg();
        for (auto &cp : callpop) {
          if (basereg == cp.second) {
            addr_t inneraddr = cp.first + inst.getOperand(5).getImm();
            if (isDataInFunc(bin, func, inst, inneraddr)) {
              func.difs.insert(inneraddr);
            }
            break;
          }
        }
        break;
      }
      case X86::MOV32rm:
      case X86::LEA32r: {
        unsigned basereg = inst.getOperand(1).getReg();
        for (auto &cp : callpop) {
          if (basereg == cp.second) {
            addr_t inneraddr = cp.first + inst.getOperand(4).getImm();
            if (isDataInFunc(bin, func, inst, inneraddr)) {
              func.difs.insert(inneraddr);
            }
            break;
          }
        }
        break;
      }
      default: {
        break;
      }
      }
    } else if (m_arch == ARM64) {
      switch (inst.getOpcode()) {
      case AArch64::LDRSWl:
      case AArch64::LDRWl:
      case AArch64::LDRXl:
      case AArch64::LDRSl:
      case AArch64::LDRDl:
      case AArch64::LDRQl: {
        addr_t inneraddr = addr + inst.getOperand(1).getImm() * 4;
        if (isDataInFunc(bin, func, inst, inneraddr)) {
          func.difs.insert(inneraddr);
        }
        break;
      }
      case AArch64::ADR: {
        int64_t inneraddr = addr + (int64_t)inst.getOperand(1).getImm();
        adrptbl[regIndex(inst, 0)] = inneraddr;
        /*
         ADR             X8, jpt_FFFDE0
         NOP
         MOV             X10, X8
         LDRSW           X8, [X10,X9,LSL#2]
         ADD             X8, X8, X10
         BR              X8
         */
        MCInst movinst;
        diser->disassemble((unsigned char *)curop + 4 * 2, 4, movinst);
        if (movinst.getOpcode() == AArch64::ORRXrs &&
            movinst.getOperand(1).getReg() == AArch64::XZR &&
            inst.getOperand(0).getReg() == movinst.getOperand(2).getReg()) {
          adrptbl[regIndex(movinst, 0)] = adrptbl[regIndex(movinst, 2)];
        }
        if (isDataInFunc(bin, func, inst, inneraddr)) {
          func.difs.insert(inneraddr);
        }
        break;
      }
      case AArch64::ADRP: {
        adrp = (addr & ~(4096 - 1)) + 4096 * inst.getOperand(1).getImm();
        adrpreg = inst.getOperand(0).getReg();
        break;
      }
      case AArch64::ADDXri: {
        if (adrp != INVALID_ADDR) {
          if (inst.getOperand(0).getReg() == adrpreg) {
            addr_t inneraddr = adrp + inst.getOperand(2).getImm();
            adrptbl[regIndex(inst, 0)] = inneraddr;
            if (isDataInFunc(bin, func, inst, inneraddr)) {
              func.difs.insert(inneraddr);
            }
          }
          adrp = INVALID_ADDR;
        }
        break;
      }
      case AArch64::CBZW:
      case AArch64::CBZX:
      case AArch64::CBNZW:
      case AArch64::CBNZX: {
        jmpaddr = (addr_t)(addr + inst.getOperand(1).getImm() * 4);
        break;
      }
      case AArch64::TBZW:
      case AArch64::TBZX:
      case AArch64::TBNZW:
      case AArch64::TBNZX: {
        jmpaddr = (addr_t)(addr + inst.getOperand(2).getImm() * 4);
        break;
      }
      case AArch64::STRXui: {
        if (datas) {
          auto u8ptr = (const unsigned char *)curop - 4 * 2;
          // ldrb/ldrh + add
          if ((u8ptr[3] == 0x38 || u8ptr[3] == 0x78) && u8ptr[7] == 0x8B) {
            // intentionally pass through
            /*
             2F 7F 00 D0  ADRP            X15, #unk_101AFD18A@PAGE
             EF 29 06 91  ADD             X15, X15, #unk_101AFD18A@PAGEOFF
             C0 03 00 10  ADR             X0, unk_100B17BE4
             F0 69 71 38  LDRB            W16, [X15,X17]
             00 08 10 8B  ADD             X0, X0, X16,LSL#2
             E0 37 00 F9  STR             X0, [SP,#0x68]
             */
          } else {
            break;
          }
        } else {
          break;
        }
      }
      case AArch64::BR: {
        if (datas) {
          /*
           ADRP            X10, #unk_104D854AE@PAGE
           ADD             X10, X10, #unk_104D854AE@PAGEOFF
           ADR             X11, sub_101948570
           LDRB            W12, [X10,X9]
           ADD             X11, X11, X12,LSL#2
           BR              X11

           ADRL            X25, opcodeDispatch
           LDR             X8, [X25,X8,LSL#3]
           BR              X8
           */
          MachineARM64 marm64;
          MCInst instadr, instldr, instadd;
          bool matched = false;
          unsigned backforward = 3;
          for (; backforward <= 88; backforward++) {
            auto opc = (unsigned char *)curop - 4 * backforward;
            diser->disassemble(opc + 4 * 0, 4, instadr, 0);
            if (instadr.getOpcode() == AArch64::ADR) {
              diser->disassemble(opc + 4 * 1, 4, instldr, 0);
              if (instldr.getOpcode() == AArch64::LDRBBroX ||
                  instldr.getOpcode() == AArch64::LDRHHroX ||
                  instldr.getOpcode() == AArch64::LDRSWroX) {
                diser->disassemble(opc + 4 * 2, 4, instadd, 0);
                if (instadd.getOpcode() == AArch64::ADDXrs &&
                    instadr.getOperand(0).getReg() ==
                        instadd.getOperand(1).getReg()) {
                  matched = true;
                  break;
                }
              }
            } else if (instadr.getOpcode() == AArch64::ADRP) {
              diser->disassemble(opc + 4 * 2, 4, instldr, 0);
              if (instldr.getOpcode() == AArch64::LDRXroX &&
                  instldr.getOperand(1).getReg() ==
                      instadr.getOperand(0).getReg() &&
                  instldr.getOperand(0).getReg() ==
                      inst.getOperand(0).getReg()) {
                matched = true;
                break;
              }
            } else if (marm64.insnType(&instadr) != NORMAL) {
              break;
            }
          }
          if (!matched) {
            /*
             ADRL            X11, jpt_100892E74
             B.HI            def_100892E74
             LDRSW           X9, [X11,X10,LSL#2]
             ADD             X9, X9, X11
             ADD             X11, SP, #0x1650+var_1068
             BR              X9
             */
            for (backforward = 2; backforward <= 88; backforward++) {
              auto opc = (unsigned char *)curop - 4 * backforward;
              diser->disassemble(opc + 4 * 0, 4, instldr, 0);
              if (instldr.getOpcode() == AArch64::LDRSWroX) {
                diser->disassemble(opc + 4 * 1, 4, instadd, 0);
                if (instadd.getOpcode() == AArch64::ADDXrs &&
                    instadd.getOperand(1).getReg() ==
                        instldr.getOperand(0).getReg() &&
                    instadd.getOperand(2).getReg() ==
                        instldr.getOperand(1).getReg()) {
                  matched = true;
                  break;
                }
              } else if (marm64.insnType(&instldr) != NORMAL) {
                break;
              }
            }
            if (matched) {
              auto target = adrptbl[regIndex(instldr, 1)];
              auto tblbuf = (const unsigned char *)bin->addrBuff(target);
              long tblsize = 0;
              auto datait = datas->find(target);
              if (datait != datas->end()) {
                datait++;
                if (datait != datas->end())
                  tblsize = *datait - target;
              }
              auto &a64br =
                  indjmps.insert({addr, std::set<addr_t>()}).first->second;
              for (auto ptr = tblbuf; ptr < tblbuf + tblsize; ptr += 4) {
                auto jmpaddr = (int64_t)target + *(int32_t *)ptr;
                a64br.insert(jmpaddr);
                if (maxjmp < (addr_t)jmpaddr)
                  maxjmp = jmpaddr;
              }
            }
            break;
          }

          auto jmpbase =
              addr - 4 * backforward + instadr.getOperand(1).getImm();
          auto target = adrptbl[regIndex(instldr, 1)];
          auto tarsect = bin->addrSect(target);
          auto tblbuf = (const unsigned char *)bin->addrBuff(target);
          long tblsize = 0;
          if (tarsect) {
            long maxsize = tarsect->addr + tarsect->size - target;
            auto datait = datas->find(target);
            if (datait != datas->end()) {
              datait++;
              if (datait != datas->end()) {
                tblsize = *datait - target;
                if (tblsize > maxsize)
                  tblsize = maxsize;
              }
            }
          }
          auto &a64br =
              indjmps.insert({addr, std::set<addr_t>()}).first->second;
          for (auto ptr = tblbuf; ptr < tblbuf + tblsize;) {
            auto jmpaddr = jmpbase;
            switch (instldr.getOpcode()) {
            case AArch64::LDRXroX:
              jmpaddr = bin->imageBase() + *(uint32_t *)ptr;
              ptr += 8;
              break;
            case AArch64::LDRSWroX:
              // <MCInst 643 <MCOperand Reg:229> <MCOperand Reg:229>
              // <MCOperand Reg:230> <MCOperand Imm:0>>
              if (instadd.getOperand(3).getImm())
                jmpaddr += *(int32_t *)ptr * 4;
              else
                jmpaddr += *(int32_t *)ptr;
              ptr += 4;
              break;
            case AArch64::LDRHHroX:
              if (instadd.getOperand(3).getImm())
                jmpaddr += *(uint16_t *)ptr * 4;
              else
                jmpaddr += *(uint16_t *)ptr;
              ptr += 2;
              break;
            default:
              if (instadd.getOperand(3).getImm())
                jmpaddr += *(uint8_t *)ptr * 4;
              else
                jmpaddr += *(uint8_t *)ptr;
              ptr += 1;
              break;
            }
            a64br.insert(jmpaddr);
            if (maxjmp < jmpaddr)
              maxjmp = jmpaddr;
          }
        }
        break;
      }
      default:
        break;
      }
    } else if (m_arch == ARMV5TE || m_arch == ARM) {
      switch (inst.getOpcode()) {
      case ARM::tCBZ:
      case ARM::tCBNZ: {
        jmpaddr = (addr_t)(addr + 4 + inst.getOperand(1).getImm());
        break;
      }
      case ARM::tLDRpci:
      case ARM::t2LDRpci: {
        addr_t pc = addr + 4;
        pc -= pc % 4;
        addr_t inneraddr = pc + inst.getOperand(1).getImm();
        if (isDataInFunc(bin, func, inst, inneraddr)) {
          func.difs.insert(inneraddr);
        }
        break;
      }
      case ARM::LDRi12: {
        if (inst.getOperand(1).getReg() == ARM::PC) {
          addr_t inneraddr = addr + 8 + inst.getOperand(2).getImm();
          if (isDataInFunc(bin, func, inst, inneraddr)) {
            func.difs.insert(inneraddr);
          }
        }
        break;
      }
      case ARM::VLDRD:
      case ARM::VLDRH:
      case ARM::VLDRS:
      case ARM::VSTRD:
      case ARM::VSTRH:
      case ARM::VSTRS: {
        if (inst.getOperand(1).getReg() == ARM::PC) {
          addr_t pc = addr + (thumb ? 4 : 8);
          pc -= pc % 4;
          addr_t inneraddr = pc + inst.getOperand(2).getImm() * 4;
          if (isDataInFunc(bin, func, inst, inneraddr)) {
            func.difs.insert(inneraddr);
          }
        }
        break;
      }
      case ARM::tADR:
      case ARM::t2ADR: {
        addr_t pc = addr + 4;
        pc -= pc % 4;
        addr_t inneraddr = pc + inst.getOperand(1).getImm();
        if (isDataInFunc(bin, func, inst, inneraddr)) {
          func.difs.insert(inneraddr);
        }
        break;
      }
      case ARM::ADR: {
        addr_t inneraddr = addr + 8 + inst.getOperand(1).getImm();
        if (isDataInFunc(bin, func, inst, inneraddr)) {
          lastadr = inneraddr;
          func.difs.insert(inneraddr);
        }
        break;
      }
      case ARM::t2ADDri: {
        if (inst.getOperand(1).getReg() == ARM::PC) {
          addr_t pc = addr + 4;
          pc -= pc % 4;
          addr_t inneraddr = pc + inst.getOperand(2).getImm();
          if (isDataInFunc(bin, func, inst, inneraddr)) {
            func.difs.insert(inneraddr);
          }
        }
        break;
      }
      case ARM::ADDri: {
        if (inst.getOperand(1).getReg() == ARM::PC) {
          addr_t inneraddr = addr + 8 + inst.getOperand(2).getImm();
          if (isDataInFunc(bin, func, inst, inneraddr)) {
            lastadr = inneraddr;
            func.difs.insert(inneraddr);
          }
        }
        break;
      }
      default:
        break;
      }
    }
    if (jmpaddr != INVALID_ADDR) {
      // printf("JUMP : " ADDRFMT " ==> " ADDRFMT "\n", addr, taraddr);
      jmpfnoffmap[fnoff] = (int)(jmpaddr - func.start);
      func.jdsts.insert(jmpaddr);
      if (jmpaddr > maxjmp) {
        maxjmp = jmpaddr;
      }
    }
    addr += consumed;
    func.insns.push_back(iinfo);

    if (m_arch == ARMV5TE || m_arch == ARM) {
      switch (inst.getOpcode()) {
      case ARM::t2TBB: {
        if (inst.getOperand(0).getReg() == ARM::PC) {
          func.difs.insert(addr);

          std::set<addr_t> tbbtargets;
          int fnoff = (int)(addr - start);
          uint8_t *tbbptr = (uint8_t *)(opbuff + fnoff);
          Insinfo iinfo;
          iinfo.fnoff = fnoff;
          iinfo.info.type = IDATA;
          iinfo.info.oplen = 0;
          tbbtargets.insert(addr);
          while (iinfo.info.oplen == 0 ||
                 tbbtargets.find(addr + iinfo.info.oplen) == tbbtargets.end()) {
            addr_t target = addr + 2 * tbbptr[iinfo.info.oplen];
            tbbtargets.insert(target);
            iinfo.info.oplen++;
          }
          func.insns.push_back(iinfo);
          addr += iinfo.info.oplen;
        }
        break;
      }
      case ARM::t2TBH: {
        if (inst.getOperand(0).getReg() == ARM::PC) {
          func.difs.insert(addr);

          std::set<addr_t> tbhtargets;
          int fnoff = (int)(addr - start);
          uint16_t *tbhptr = (uint16_t *)(opbuff + fnoff);
          Insinfo iinfo;
          iinfo.fnoff = fnoff;
          iinfo.info.type = IDATA;
          iinfo.info.oplen = 0;
          tbhtargets.insert(addr);
          while (iinfo.info.oplen == 0 ||
                 tbhtargets.find(addr + 2 * iinfo.info.oplen) ==
                     tbhtargets.end()) {
            addr_t target = addr + 2 * tbhptr[iinfo.info.oplen];
            tbhtargets.insert(target);
            iinfo.info.oplen++;
          }
          iinfo.info.oplen *= 2;
          func.insns.push_back(iinfo);
          addr += iinfo.info.oplen;
        }
      case ARM::ADDrr: {
        if (inst.getOperand(0).getReg() == ARM::PC) {
          if (lastadr == addr) {
            std::set<addr_t> casetargets;
            int fnoff = (int)(addr - start);
            uint32_t *caseptr = (uint32_t *)(opbuff + fnoff);
            Insinfo iinfo;
            iinfo.fnoff = fnoff;
            iinfo.info.type = IDATA;
            iinfo.info.oplen = 0;
            casetargets.insert(addr);
            while (iinfo.info.oplen == 0 ||
                   casetargets.find(addr + 4 * iinfo.info.oplen) ==
                       casetargets.end()) {
              addr_t target = addr + caseptr[iinfo.info.oplen];
              casetargets.insert(target);
              iinfo.info.oplen++;
            }
            iinfo.info.oplen *= 4;
            func.insns.push_back(iinfo);
            addr += iinfo.info.oplen;
          }
        }
        break;
      } break;
      }
      default:
        break;
      }
    }
  }

  // update pre-analyze's function end
  if (hitret) {
    auto lastii = func.insns.rbegin();
    func.end = start + lastii->fnoff + lastii->info.oplen;
  }
  // clear out of function's dif & jump destination
  if (isobj) {
    func.difs.clear();
  }
  // calculate indirect jump destination indexs
  if (datas && indjmps.size()) {
    for (auto &it : indjmps) {
      auto a64br = it.first;
      Insinfo tmpi;
      tmpi.fnoff = (int)(a64br - func.start);
      auto jmpi = std::lower_bound(func.insns.begin(), func.insns.end(), tmpi);
      auto jmpidx = (int)(jmpi - func.insns.begin());
      for (auto jmpaddr : it.second) {
        if (jmpaddr >= func.end)
          continue;
        tmpi.fnoff = (int)(jmpaddr - func.start);
        auto tari =
            std::lower_bound(func.insns.begin(), func.insns.end(), tmpi);
        bool exists = false;
        for (auto i : tari->comins) {
          if (i == jmpidx) {
            exists = true;
            break;
          }
        }
        if (!exists) {
          jmpi->gouts.push_back((int)(tari - func.insns.begin()));
          tari->comins.push_back(jmpidx);
        }
      }
    }
  }
  for (auto &jmpoff : jmpfnoffmap) {
    Insinfo tmpi;
    tmpi.fnoff = jmpoff.second;
    auto tarinsn = std::lower_bound(func.insns.begin(), func.insns.end(), tmpi);
    if (tarinsn == func.insns.end()) {
      continue;
    }
    tmpi.fnoff = jmpoff.first;
    auto insn = std::lower_bound(func.insns.begin(), func.insns.end(), tmpi);
    if (insn == func.insns.end()) {
      continue;
    }

    int taridx = (int)(tarinsn - func.insns.begin());
    int i = (int)(insn - func.insns.begin());
    if (insn->info.type == JCOND) {
      insn->gouts.push_back(i + 1);
    }
    insn->gouts.push_back(taridx);
    jmpidxmap[i] = taridx;
    if (i && jmpoff.second < insn->fnoff) {
      switch (func.insns[i - 1].info.type) {
      case JCOND:
      case JUMP:
      case RET:
        break;
      default:
        func.loops[i] = taridx;
        break;
      }
    }
  }
  for (int i = 0; i < (int)func.insns.size(); i++) {
    auto &insn = func.insns[i];
    switch (insn.info.type) {
    case JUMP: {
      auto tarfnoff = jmpfnoffmap.find(insn.fnoff);
      if (tarfnoff == jmpfnoffmap.end()) {
        // jump to another function
        break;
      }
      Insinfo tmpi;
      tmpi.fnoff = tarfnoff->second;
      auto found = std::lower_bound(func.insns.begin(), func.insns.end(), tmpi);
      if (found != func.insns.end()) {
        int taridx = (int)(found - func.insns.begin());
        if (!insn.gouts.size() || insn.gouts[0] != taridx) {
          insn.gouts.push_back(taridx);
        }
        jmpidxmap[i] = taridx;
        if (tarfnoff->second < insn.fnoff) {
          func.loops[i] = taridx;
        }
      } else {
        // jump to another function
      }
      break;
    }
    case RET: {
      func.rets.push_back(i);
      break;
    }
    default:
      break;
    }
  }
  for (auto &idxmap : jmpidxmap) {
    func.insns[idxmap.second].comins.push_back(idxmap.first);
  }
}

bool MachineX86::isCallPcrel(void *llvminst) {
  switch (ins->getOpcode()) {
  case X86::CALLpcrel16:
  case X86::CALLpcrel32:
  case X86::CALL64pcrel32:
    return true;
  default:
    return false;
  }
}

bool MachineARM64::isCallPcrel(void *llvminst) {
  switch (ins->getOpcode()) {
  case AArch64::BL:
    return true;
  default:
    return false;
  }
}

bool MachineARM::isCallPcrel(void *llvminst) {
  switch (ins->getOpcode()) {
  case ARM::tBL:
  case ARM::tBLXi:
  case ARM::BL:
  case ARM::BL_pred:
  case ARM::BLXi:
    return true;
  case ARM::BLX:
  case ARM::BLX_pred:
    return ins->getOperand(0).isImm();
  default:
    return false;
  }
}

bool MachineX86::isJumpReg(void *llvminst) {
  switch (ins->getOpcode()) {
  case X86::JMP16r:
  case X86::JMP32r:
  case X86::JMP64r:
    return true;
  default:
    return false;
  }
}

bool MachineX86::isJumpPcrel(void *llvminst) {
  switch (ins->getOpcode()) {
  case X86::JMP_1:
  case X86::JMP_2:
  case X86::JMP_4:
    return true;
  default:
    return false;
  }
}

bool MachineARM64::isJumpReg(void *llvminst) {
  switch (ins->getOpcode()) {
  case AArch64::BRAA:
  case AArch64::BRAAZ:
  case AArch64::BRAB:
  case AArch64::BRABZ:
  case AArch64::BR:
    return true;
  default:
    return false;
  }
}

bool MachineARM64::isJumpPcrel(void *llvminst) {
  switch (ins->getOpcode()) {
  case AArch64::B:
    return true;
  default:
    return false;
  }
}

bool MachineARM::isJumpReg(void *llvminst) {
  switch (ins->getOpcode()) {
  case ARM::tBX:
  case ARM::tBX_RET:
  case ARM::t2BXJ:
  case ARM::BX:
  case ARM::BX_RET:
  case ARM::BX_pred:
    return ins->getOperand(0).isReg();
  default:
    return false;
  }
}

bool MachineARM::isJumpPcrel(void *llvminst) {
  switch (ins->getOpcode()) {
  case ARM::tB:
  case ARM::t2B:
  case ARM::B:
    return true;
  case ARM::BX:
  case ARM::BX_pred:
    return ins->getOperand(0).isImm();
  default:
    return false;
  }
}

bool MachineX86::isCallReg(void *llvminst) {
  switch (ins->getOpcode()) {
  case X86::CALL16r:
  case X86::CALL32r:
  case X86::CALL64r:
    return true;
  default:
    return false;
  }
}

bool MachineARM64::isCallReg(void *llvminst) {
  switch (ins->getOpcode()) {
  case AArch64::BLR:
  case AArch64::BLRAA:
  case AArch64::BLRAB:
  case AArch64::BLRAAZ:
  case AArch64::BLRABZ:
    return true;
  default:
    return false;
  }
}

bool MachineARM::isCallReg(void *llvminst) {
  switch (ins->getOpcode()) {
  case ARM::BLX:
    return ins->getOperand(0).isReg();
  case ARM::BLX_pred:
    return ins->getOperand(1).isReg();
  default:
    return false;
  }
}

bool MachineX86::isCallMem(void *llvminst) {
  switch (ins->getOpcode()) {
  case X86::CALL16m:
  case X86::CALL32m:
  case X86::CALL64m:
  case X86::FARCALL16m:
  case X86::FARCALL32m:
  case X86::FARCALL16i:
  case X86::FARCALL32i:
#if LLVM_VERSION_MAJOR >= 11
  case X86::FARCALL64m:
#else
  case X86::FARCALL64:
#endif
    return true;
  default:
    return false;
  }
}

bool MachineARM64::isCallMem(void *llvminst) { return false; }

bool MachineARM::isCallMem(void *llvminst) {
  switch (ins->getOpcode()) {
  case ARM::tLDRpci:
  case ARM::tLDRpci_pic:
  case ARM::t2LDRpci:
  case ARM::t2LDRpci_pic:
  case ARM::t2LDRpcrel:
    return true;
  default:
    return false;
  }
}

InsnType MachineX86::insnType(void *llvminst, OpcodeInfo *opinfo) {
  if (isCall(llvminst)) {
    return CALL;
  }
  unsigned opcode = ins->getOpcode();
  switch (opcode) {
  case X86::JMP16m:
  case X86::JMP16r:
  case X86::JMP32m:
  case X86::JMP32r:
  case X86::JMP64m:
  case X86::JMP64r:
  case X86::JMP16m_NT:
  case X86::JMP16r_NT:
  case X86::JMP32m_NT:
  case X86::JMP32r_NT:
  case X86::JMP64m_NT:
  case X86::JMP64r_NT:
  case X86::JMP_1:
  case X86::JMP_2:
  case X86::JMP_4:
    return JUMP;
  default:
    break;
  }
  if (opcode >= X86::RET && opcode <=
#if LLVM_VERSION_MAJOR >= 14
                                X86::RETI64
#else
                                X86::RETW
#endif
  ) {
    return RET;
  }
  if (opcode == X86::INT || opcode == X86::INT3) {
    return TRAP;
  }
  if (opcode == X86::SYSENTER || opcode == X86::SYSCALL) {
    return SYSCALL;
  }
#if LLVM_VERSION_MAJOR >= 11
  if ((opcode >= X86::JCC_1 && opcode <= X86::JECXZ) || opcode == X86::JRCXZ) {
    return JCOND;
  }
#else
  if (opcode == X86::JCXZ || opcode == X86::JECXZ || opcode == X86::JRCXZ) {
    return JCOND;
  }
  if (opcode >= X86::JAE_1 && opcode <= X86::JL_4) {
    return JCOND;
  }
  if (opcode >= X86::JNE_1 && opcode <= X86::JS_4) {
    return JCOND;
  }
#endif
  return NORMAL;
}

InsnType MachineARM64::insnType(void *llvminst, OpcodeInfo *opinfo) {
  if (isCall(llvminst)) {
    return CALL;
  }
  unsigned opcode = ins->getOpcode();
  if (opinfo) {
    switch (opcode) {
    case AArch64::ST1Fourv16b:
    case AArch64::ST1Fourv1d:
    case AArch64::ST1Fourv2d:
    case AArch64::ST1Fourv2s:
    case AArch64::ST1Fourv4h:
    case AArch64::ST1Fourv4s:
    case AArch64::ST1Fourv8b:
    case AArch64::ST1Fourv8h:
    case AArch64::ST1Onev16b:
    case AArch64::ST1Onev1d:
    case AArch64::ST1Onev2d:
    case AArch64::ST1Onev2s:
    case AArch64::ST1Onev4h:
    case AArch64::ST1Onev4s:
    case AArch64::ST1Onev8b:
    case AArch64::ST1Onev8h:
    case AArch64::ST1Threev16b:
    case AArch64::ST1Threev1d:
    case AArch64::ST1Threev2d:
    case AArch64::ST1Threev2s:
    case AArch64::ST1Threev4h:
    case AArch64::ST1Threev4s:
    case AArch64::ST1Threev8b:
    case AArch64::ST1Threev8h:
    case AArch64::ST1Twov16b:
    case AArch64::ST1Twov1d:
    case AArch64::ST1Twov2d:
    case AArch64::ST1Twov2s:
    case AArch64::ST1Twov4h:
    case AArch64::ST1Twov4s:
    case AArch64::ST1Twov8b:
    case AArch64::ST1Twov8h:
    case AArch64::ST1i16:
    case AArch64::ST1i32:
    case AArch64::ST1i64:
    case AArch64::ST1i8:
    case AArch64::ST2Twov16b:
    case AArch64::ST2Twov2d:
    case AArch64::ST2Twov2s:
    case AArch64::ST2Twov4h:
    case AArch64::ST2Twov4s:
    case AArch64::ST2Twov8b:
    case AArch64::ST2Twov8h:
    case AArch64::ST2i16:
    case AArch64::ST2i32:
    case AArch64::ST2i64:
    case AArch64::ST2i8:
    case AArch64::ST3Threev16b:
    case AArch64::ST3Threev2d:
    case AArch64::ST3Threev2s:
    case AArch64::ST3Threev4h:
    case AArch64::ST3Threev4s:
    case AArch64::ST3Threev8b:
    case AArch64::ST3Threev8h:
    case AArch64::ST3i16:
    case AArch64::ST3i32:
    case AArch64::ST3i64:
    case AArch64::ST3i8:
    case AArch64::ST4Fourv16b:
    case AArch64::ST4Fourv2d:
    case AArch64::ST4Fourv2s:
    case AArch64::ST4Fourv4h:
    case AArch64::ST4Fourv4s:
    case AArch64::ST4Fourv8b:
    case AArch64::ST4Fourv8h:
    case AArch64::ST4i16:
    case AArch64::ST4i32:
    case AArch64::ST4i64:
    case AArch64::ST4i8:
    case AArch64::STPDi:
    case AArch64::STPQi:
    case AArch64::STPSi:
    case AArch64::STPWi:
    case AArch64::STPXi:
    case AArch64::STRBBui:
    case AArch64::STRBroW:
    case AArch64::STRBroX:
    case AArch64::STRDui:
    case AArch64::STRDroW:
    case AArch64::STRDroX:
    case AArch64::STRHHui:
    case AArch64::STRHHroW:
    case AArch64::STRHHroX:
    case AArch64::STRHui:
    case AArch64::STRHroW:
    case AArch64::STRHroX:
    case AArch64::STRQui:
    case AArch64::STRQroW:
    case AArch64::STRQroX:
    case AArch64::STRSui:
    case AArch64::STRSroW:
    case AArch64::STRSroX:
    case AArch64::STRWui:
    case AArch64::STRWroW:
    case AArch64::STRWroX:
    case AArch64::STRXui:
    case AArch64::STRXroW:
    case AArch64::STRXroX:
      opinfo->keeprv = true;
      break;
    case AArch64::SUBSWri:
    case AArch64::SUBSWrs:
    case AArch64::SUBSWrx:
    case AArch64::SUBSXri:
    case AArch64::SUBSXrs:
    case AArch64::SUBSXrx:
    case AArch64::SUBSXrx64:
    case AArch64::ADDSWri:
    case AArch64::ADDSWrs:
    case AArch64::ADDSWrx:
    case AArch64::ADDSXri:
    case AArch64::ADDSXrs:
    case AArch64::ADDSXrx:
    case AArch64::ADDSXrx64:
    case AArch64::ANDSWri:
    case AArch64::ANDSWrs:
    case AArch64::ANDSXri:
    case AArch64::ANDSXrs:
      switch (ins->getOperand(0).getReg()) {
      case AArch64::WZR:
      case AArch64::XZR:
        opinfo->keeprv = true;
        break;
      default:
        break;
      }
      break;
    default:
      break;
    }
  }
  switch (opcode) {
  case AArch64::B:
  case AArch64::BR:
  case AArch64::BRAA:
  case AArch64::BRAB:
  case AArch64::BRAAZ:
  case AArch64::BRABZ:
    return JUMP;
  case AArch64::Bcc:
    if (opinfo) {
      opinfo->bcc = true;
    }
    return JCOND;
  case AArch64::TBZW:
  case AArch64::TBZX:
  case AArch64::TBNZW:
  case AArch64::TBNZX:
    if (opinfo) {
      opinfo->tbznz = true;
    }
    return JCOND;
  case AArch64::CBZW:
  case AArch64::CBZX:
  case AArch64::CBNZW:
  case AArch64::CBNZX:
    if (opinfo) {
      opinfo->cbznz = true;
    }
    return JCOND;
  case AArch64::RET:
  case AArch64::RETAA:
  case AArch64::RETAB:
  case AArch64::RET_ReallyLR:
    return RET;
  case AArch64::BRK:
    return TRAP;
  case AArch64::SVC:
    return SYSCALL;
  case AArch64::UDF:
    return IDATA;
  default:
    if (opinfo) {
      for (unsigned i = 0; i < ins->getNumOperands(); i++) {
        auto opr = ins->getOperand(i);
        if (opr.isReg()) {
          auto reg = opr.getReg();
          auto s = AArch64::S0 <= reg && reg <= AArch64::S31;
          auto d = AArch64::D0 <= reg && reg <= AArch64::D31;
          auto q = AArch64::Q0 <= reg && reg <= AArch64::Q31;
          if (s || d || q) {
            opinfo->vfp = true;
            break;
          }
        }
      }
      switch (opcode) {
      case AArch64::LDARB:
      case AArch64::LDARH:
      case AArch64::LDARW:
      case AArch64::LDARX:
        opinfo->acquire = true;
        break;
      case AArch64::STLRB:
      case AArch64::STLRH:
      case AArch64::STLRW:
      case AArch64::STLRX:
        opinfo->release = true;
        break;
      case AArch64::LDXPW:
      case AArch64::LDXPX:
      case AArch64::LDXRB:
      case AArch64::LDXRH:
      case AArch64::LDXRW:
      case AArch64::LDXRX:
      case AArch64::LDAXPW:
      case AArch64::LDAXPX:
      case AArch64::LDAXRB:
      case AArch64::LDAXRH:
      case AArch64::LDAXRW:
      case AArch64::LDAXRX:
        opinfo->synclock = true;
        break;
      case AArch64::STXPW:
      case AArch64::STXPX:
      case AArch64::STXRB:
      case AArch64::STXRH:
      case AArch64::STXRW:
      case AArch64::STXRX:
      case AArch64::STLXPW:
      case AArch64::STLXPX:
      case AArch64::STLXRB:
      case AArch64::STLXRH:
      case AArch64::STLXRW:
      case AArch64::STLXRX:
      case AArch64::CLREX:
        opinfo->syncunlock = true;
        break;
      case AArch64::ADRP:
      case AArch64::ADR:
      case AArch64::LDRSWl:
      case AArch64::LDRWl:
      case AArch64::LDRXl:
      case AArch64::LDRSl:
      case AArch64::LDRDl:
      case AArch64::LDRQl: {
        opinfo->pcrel = true;
        break;
      }
      case AArch64::STPXi:
      case AArch64::STPXpre:
      case AArch64::STPXpost:
      case AArch64::LDPXi:
      case AArch64::LDPXpre:
      case AArch64::LDPXpost: {
        for (unsigned i = 0; i < ins->getNumOperands(); i++) {
          auto opr = ins->getOperand(i);
          if (opr.isReg()) {
            if (opr.getReg() == AArch64::LR) {
              opinfo->lrref = true;
              break;
            }
          }
        }
        break;
      }
      case AArch64::LDRBBui:
      case AArch64::LDRBui:
      case AArch64::LDRDui:
      case AArch64::LDRHHui:
      case AArch64::LDRHui:
      case AArch64::LDRQui:
      case AArch64::LDRSBWui:
      case AArch64::LDRSBXui:
      case AArch64::LDRSHWui:
      case AArch64::LDRSHXui:
      case AArch64::LDRSWui:
      case AArch64::LDRSui:
      case AArch64::LDRWui:
      case AArch64::LDRXui:
      case AArch64::STRBBui:
      case AArch64::STRBui:
      case AArch64::STRDui:
      case AArch64::STRHHui:
      case AArch64::STRHui:
      case AArch64::STRQui:
      case AArch64::STRSui:
      case AArch64::STRWui:
      case AArch64::STRXui:
        opinfo->ldstrui = true;
        break;
      default:
        break;
      }
    }
    return NORMAL;
  }
}

InsnType MachineARM::insnType(void *llvminst, OpcodeInfo *opinfo) {
  if (isCall(llvminst)) {
    return CALL;
  }
  unsigned opcode = ins->getOpcode();
  switch (opcode) {
  case ARM::tB:
  case ARM::t2B:
  case ARM::B:
    return JUMP;
  case ARM::tBX:
  case ARM::BX:
  case ARM::BX_pred:
    if (ins->getOperand(0).getReg() == ARM::LR) {
      return RET;
    }
    return JUMP;
  case ARM::tBX_RET:
  case ARM::BX_RET:
    return RET;
  case ARM::tBcc:
  case ARM::t2Bcc:
  case ARM::Bcc:
    return JCOND;
  case ARM::LDMIA_RET:
  case ARM::t2LDMIA_RET:
  case ARM::tPOP_RET:
    return RET;
  case ARM::LDR_POST_IMM:
  case ARM::LDR_PRE_IMM:
  case ARM::LDRi12:
    if (ins->getOperand(0).getReg() == ARM::PC) {
      return RET;
    }
    return NORMAL;
  case ARM::TRAP:
#if LLVM_VERSION_MAJOR >= 22
  case ARM::tTRAP:
#else
  case ARM::TRAPNaCl:
#endif
  case ARM::BKPT:
  case ARM::tBKPT:
    return TRAP;
  case ARM::SVC:
  case ARM::tSVC:
    return SYSCALL;
  default:
    if (opcode == ARM::tPOP || opcode == ARM::LDMIA_UPD) {
      for (unsigned i = 0; i < ins->getNumOperands(); i++) {
        if (ins->getOperand(i).isReg() &&
            ins->getOperand(i).getReg() == ARM::PC) {
          return RET;
        }
      }
    }
    return NORMAL;
  }
}

addr_t MachineX86::jumpee(void *llvminst, int opclen, addr_t pc) {
  unsigned opcode = ins->getOpcode();
  switch (opcode) {
#if LLVM_VERSION_MAJOR >= 11
  case X86::JCC_1:
  case X86::JCC_2:
  case X86::JCC_4:
  case X86::JMP_1:
  case X86::JMP_2:
  case X86::JMP_4:
#else
  case X86::JAE_1:
  case X86::JA_1:
  case X86::JBE_1:
  case X86::JB_1:
  case X86::JE_1:
  case X86::JGE_1:
  case X86::JG_1:
  case X86::JLE_1:
  case X86::JL_1:
  case X86::JNE_1:
  case X86::JNO_1:
  case X86::JNP_1:
  case X86::JNS_1:
  case X86::JO_1:
  case X86::JP_1:
  case X86::JS_1:
  case X86::JMP_1:
  case X86::JAE_2:
  case X86::JA_2:
  case X86::JBE_2:
  case X86::JB_2:
  case X86::JE_2:
  case X86::JGE_2:
  case X86::JG_2:
  case X86::JLE_2:
  case X86::JL_2:
  case X86::JNE_2:
  case X86::JNO_2:
  case X86::JNP_2:
  case X86::JNS_2:
  case X86::JO_2:
  case X86::JP_2:
  case X86::JS_2:
  case X86::JMP_2:
  case X86::JAE_4:
  case X86::JA_4:
  case X86::JBE_4:
  case X86::JB_4:
  case X86::JE_4:
  case X86::JGE_4:
  case X86::JG_4:
  case X86::JLE_4:
  case X86::JL_4:
  case X86::JNE_4:
  case X86::JNO_4:
  case X86::JNP_4:
  case X86::JNS_4:
  case X86::JO_4:
  case X86::JP_4:
  case X86::JS_4:
  case X86::JMP_4:
#endif
    return (addr_t)((int64_t)pc + ins->getOperand(0).getImm() + opclen);
  default:
    break;
  }
  return INVALID_ADDR;
}

addr_t MachineARM64::jumpee(void *llvminst, int opclen, addr_t pc) {
  switch (ins->getOpcode()) {
  case AArch64::B:
    return (addr_t)((int64_t)pc + ins->getOperand(0).getImm() * 4);
  case AArch64::Bcc:
    return (addr_t)((int64_t)pc + ins->getOperand(1).getImm() * 4);
  default:
    return dstAddr(llvminst, opclen, pc);
  }
}

addr_t MachineARM::jumpee(void *llvminst, int opclen, addr_t pc) {
  switch (ins->getOpcode()) {
  case ARM::B:
    return (addr_t)((int64_t)pc + ins->getOperand(0).getImm() + 8);
  case ARM::Bcc:
    return (addr_t)((int64_t)pc + ins->getOperand(0).getImm() + 8);
  case ARM::tB:
  case ARM::t2B:
  case ARM::tBcc:
  case ARM::t2Bcc:
    return (addr_t)((int64_t)pc + ins->getOperand(0).getImm() + 4);
  default:
    return INVALID_ADDR;
  }
}

addr_t MachineX86::callee(void *llvminst, int opclen, addr_t pc) {
  switch (ins->getOpcode()) {
  case X86::CALLpcrel16:
  case X86::CALLpcrel32:
  case X86::CALL64pcrel32:
    return (addr_t)((int64_t)pc + ins->getOperand(0).getImm() + opclen);
  default:
    break;
  }
  return INVALID_ADDR;
}

addr_t MachineARM64::callee(void *llvminst, int opclen, addr_t pc) {
  switch (ins->getOpcode()) {
  case AArch64::BL:
    return (addr_t)((int64_t)pc + ins->getOperand(0).getImm() * 4);
  default:
    return INVALID_ADDR;
  }
}

addr_t MachineARM::callee(void *llvminst, int opclen, addr_t pc) {
  switch (ins->getOpcode()) {
  case ARM::tBL:
    return (addr_t)((int64_t)pc + ins->getOperand(2).getImm() + 4);
  case ARM::tBLXi:
    return (addr_t)llvm::alignDown(
        (int64_t)pc + ins->getOperand(2).getImm() + 4, 4);
  case ARM::BL:
  case ARM::BL_pred:
  case ARM::BLXi:
    return (addr_t)((int64_t)pc + ins->getOperand(0).getImm() + 8);
  case ARM::BLX:
  case ARM::BLX_pred:
    if (ins->getOperand(0).isImm()) {
      return (addr_t)((int64_t)pc + ins->getOperand(0).getImm() + 8);
    }
  default:
    return INVALID_ADDR;
  }
}

addr_t Machine::dstAddr(void *llvminst, int opclen, addr_t pc) {
  addr_t dst = jumpee(llvminst, opclen, pc);
  if (dst == INVALID_ADDR) {
    return callee(llvminst, opclen, pc);
  }
  return dst;
}

addr_t MachineARM64::dstAddr(void *llvminst, int opclen, addr_t pc) {
  switch (ins->getOpcode()) {
  case AArch64::B:
    return (addr_t)((int64_t)pc + ins->getOperand(0).getImm() * 4);
  case AArch64::CBZW:
  case AArch64::CBZX:
  case AArch64::CBNZW:
  case AArch64::CBNZX:
  case AArch64::Bcc:
    return (addr_t)((int64_t)pc + ins->getOperand(1).getImm() * 4);
  case AArch64::BL:
    return (addr_t)((int64_t)pc + ins->getOperand(0).getImm() * 4);
  case AArch64::TBZW:
  case AArch64::TBZX:
  case AArch64::TBNZW:
  case AArch64::TBNZX:
    return (addr_t)((int64_t)pc + ins->getOperand(2).getImm() * 4);
  default:
    return INVALID_ADDR;
  }
}

addr_t MachineARM::dstAddr(void *llvminst, int opclen, addr_t pc) {
  switch (ins->getOpcode()) {
  case ARM::tCBZ:
  case ARM::tCBNZ:
    return (addr_t)((int64_t)pc + ins->getOperand(1).getImm() + 4);
  default:
    return Machine::dstAddr(llvminst, opclen, pc);
  }
}

} // namespace aether
