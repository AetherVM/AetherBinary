# AetherBinary - A library for MachO/ELF/PE analysis.
# Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
# SPDX-License-Identifier: Apache License, Version 2.0
# See LICENSE file in the root directory for full license text.

# cmake
cmake_minimum_required(VERSION 3.20)

# Default to a Release config. Required before project() because Windows defaults to Debug
set(CMAKE_BUILD_TYPE "Release" CACHE STRING "")
if(CMAKE_BUILD_TYPE STREQUAL "")
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
endif()

if(UNIX AND NOT APPLE)
  set(LINUX TRUE)
endif()

# setup for cmake's compiler pre-check
if(LINUX)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++ -I${ICPP_INSTALL_DIR}/include/c++/v1" CACHE STRING "" FORCE)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -nostdlib++" CACHE STRING "" FORCE)
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -nostdlib++" CACHE STRING "" FORCE)
endif()

project(AetherBinary)

# setup to use icpp's C++ runtime
if(MSVC)
  set(LLVM_ENABLE_EH TRUE)
  set(LLVM_ENABLE_RTTI TRUE)
  add_compile_options("/clang:-nostdinc++" "/clang:-nostdlib++" 
    "-I${ICPP_INSTALL_DIR}/include/c++/v1" /EHsc
  )
  link_directories("${ICPP_INSTALL_DIR}/lib")
  add_link_options("/nodefaultlib:msvcprt.lib" c++.lib) 
elseif(LINUX)
  add_compile_options(-nostdinc++ -nostdlib++ -fPIC 
    -I${ICPP_INSTALL_DIR}/include/c++/v1
  )
  add_link_options(@${CMAKE_SOURCE_DIR}/ld.txt
    ${ICPP_INSTALL_DIR}/lib/libc++.so.1
    ${ICPP_INSTALL_DIR}/lib/libc++abi.so.1 
    ${ICPP_INSTALL_DIR}/lib/libunwind.so.1) 
endif()

# enable targets which remill supports even though AetherBinary doesn't support Sparc yet
set(LLVM_TARGETS_TO_BUILD "X86;ARM;AArch64;Sparc" CACHE STRING "" FORCE)

# disable unused components
set(LLVM_ENABLE_ZLIB "OFF" CACHE STRING "" FORCE)
set(LLVM_ENABLE_ZSTD "OFF" CACHE STRING "" FORCE)
set(LLVM_INCLUDE_RUNTIMES OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_UTILS OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_TESTS OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(LLVM_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(LLVM_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  
# as we're using the icpp's clang, any further checks are redundant
set(LLVM_COMPILER_CHECKED TRUE)
set(LLVM_COMPILER_IS_GCC_COMPATIBLE FALSE)

# build llvm as a shared library
set(LLVM_BUILD_LLVM_DYLIB ON CACHE BOOL "" FORCE)
set(LLVM_BUILD_LLVM_DYLIB_VIS ON CACHE BOOL "" FORCE)
set(LLVM_LINK_LLVM_DYLIB ON CACHE BOOL "" FORCE)

set(CMAKE_INSTALL_PREFIX "${CMAKE_CURRENT_BINARY_DIR}/install" CACHE PATH "Install path prefix" FORCE)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../third/llvm-project/llvm
                 ${CMAKE_CURRENT_BINARY_DIR}/llvm)
