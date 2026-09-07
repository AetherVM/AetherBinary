# AetherBinary - A library for MachO/ELF/PE analysis
**AetherBinary** is the backend analysis engine for MachO/ELF/PE used by [AetherVM](https://github.com/AetherVM), which is an LLVM-native binary analysis and emulation platform built around instruction lifting to **LLVM IR**. 

But, it can be played with in [Cutter](https://github.com/rizinorg/cutter) or Terminal within a C++ REPL, too.

## Terminal
In this REPL context, there's an `aether::Binary *` named `bin`, which is constructed from your input binary file, all the time, you can use it directly.
```c++
AetherBinary-v0.1.0-macos-arm64 % icpp aebi.cc /tmp/binary/ios-arm64 
AetherBinary 0.1.0. Copyright (c) 2026 aethervm.com.                            
Playing with a binary file using C++.
>>> for (auto &[a, s] : bin->sections()) s.dump()
Section HEADER {
  .type = Code
  .addr = 0x100000000
  .foff = 0x0
  .size = 0x4000 / 16384
}
Section __text {
  .type = Code
  .addr = 0x100004000
  .foff = 0x4000
  .size = 0x3289c / 207004
}
#...
>>> bin->functions().begin()->second.dump()
Function aebi_100004000 {
  .begin = 0x100004000
  .end   = 0x100004010
  .size  = 16
}
>>> bin->dump(0x100004000, 0x100004000 + 16)
Section __text:
Function aebi_100004000:
100004000 80 01 00 d0      	adrp	x0, #204800
100004004 00 80 39 91      	add	x0, x0, #0xe60
100004008 a1 03 80 52      	mov	w1, #0x1d
10000400c 98 1d 00 14      	b	#0x7660
```

## Cutter
To apply AetherBinary for Cutter, you need to have [Cutter++](https://github.com/GeekNeo/CutterPlusPlus), which is an interactive modern C++ REPL for binary analysis.

In this REPL context, there's an `aether::Binary *` named `bin`, which is constructed from the current input binary file in Cutter, all the time, you can use it directly. You can combine Cutter's APIs in this REPL as well.
```c++
C++ >>> #include "/tmp/AetherBinary-v0.1.0-macos-arm64/cutter.h"
C++ >>> for (auto &[a, s] : bin->sections()) s.dump()
AetherBinary's analyzing /tmp/binary/ios-arm64...
AetherBinary is parsing ios-arm64's functions (0%)...
#...
AetherBinary is parsing ios-arm64's functions (100%)...
                                                                                
AetherBinary is reparsing ios-arm64's functions (0%)...
#...
AetherBinary is reparsing ios-arm64's functions (100%)...
                                                                                
AetherBinary is analyzing ios-arm64's functions (0%)...
#...
AetherBinary is analyzing ios-arm64's functions (100%)...
                                                                                
AetherBinary 0.1.0. Copyright (c) 2026 aethervm.com.
Playing with a binary file using C++.
Section HEADER {
  .type = Code
  .addr = 0x100000000
  .foff = 0x0
  .size = 0x4000 / 16384
}
Section __text {
  .type = Code
  .addr = 0x100004000
  .foff = 0x4000
  .size = 0x3289c / 207004
}
#...
C++ >>> bin->functions().begin()->second.dump()
Function aebi_100004000 {
  .begin = 0x100004000
  .end   = 0x100004010
  .size  = 16
}
C++ >>> bin->dump(Core()->getOffset(), Core()->getOffset() + 16)
Section __text:
Function _main:
10000405c ff 83 00 d1      	sub	sp, sp, #0x20
100004060 fd 7b 01 a9      	stp	x29, x30, [sp, #0x10]
100004064 fd 43 00 91      	add	x29, sp, #0x10
100004068 e3 03 01 aa      	mov	x3, x1
C++ >>> bin->dump(Core()->getOffset(), Core()->getOffset() + 0x60)
Section __cstring:
10003ab80 34 32 64 62 33 32 32 64 61 66 30 66 61 64 66 65 
10003ab90 37 65 32 36 64 33 62 64 31 2f 6c 69 62 72 61 72 
10003aba0 79 2f 73 74 64 2f 73 72 63 2f 2e 2e 2f 2e 2e 2f 
10003abb0 62 61 63 6b 74 72 61 63 65 2f 73 72 63 2f 73 79 
```
### Screenshot
![Screenshot](https://raw.githubusercontent.com/AetherVM/AetherBinary/main/screenshot/Cutter++.png)

## Build
### Windows prepare
If you're building on Windows, firstly setup the MSVC environment, otherwise skip this:
```sh
# all the following steps must be done in "x64 Native Tools Command Prompt for VS"
# or
# run VS_ROOT/.../VC/Auxiliary/Build/vcvarsall.bat to initialize for 'x64'
# replace it to arm64 if you're on a Windows-ARM64 device.
vcvarsall x64
```
### ICPP Build
To build your own version, you need to have [ICPP](https://github.com/vpand/icpp), **Ninja**, **CMake** available in current terminal session. After a recursive clone of this repo, then build it in one go:
```sh
/path/to/icpp build.cc
```
After aaa... while, the package should be at: build-Release/install.

## Issue
If you encounter any problems when using AetherBinary, before opening an issue, please check the [Bug Report](https://github.com/AetherVM/AetherBinary/blob/main/.github/ISSUE_TEMPLATE/bug_report.md) template, and provide as many details as you can. Only if we can reproduce the problem, we can then solve it.

## Contact
If you have any questions or thoughts, just feel free to email to me:
```
neoliu2011@gmail.com
```
Any feedback is welcome.
