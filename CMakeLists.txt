# AetherBinary - A library for MachO/ELF/PE analysis.
# Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
# SPDX-License-Identifier: Apache License, Version 2.0
# See LICENSE file in the root directory for full license text.

cmake_minimum_required(VERSION 3.20)
project(AetherBinary VERSION 0.1.1 LANGUAGES C CXX)

if(UNIX AND NOT APPLE)
  set(LINUX TRUE)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(PROJECT_VERSION_STRING "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

# find the dependent LLVM package, which is built in the previous step
find_package(LLVM CONFIG REQUIRED)

# setup to use icpp's C++ runtime
if(MSVC)
  add_compile_options("/clang:-nostdinc++" "/clang:-nostdlib++" 
    "-I${ICPP_INSTALL_DIR}/include/c++/v1"
  )
  link_directories("${ICPP_INSTALL_DIR}/lib")
  add_link_options("/nodefaultlib:msvcprt.lib" c++.lib) 
elseif(LINUX)
  add_compile_options("-nostdinc++" "-nostdlib++" 
    "-I${ICPP_INSTALL_DIR}/include/c++/v1"
  )
  add_link_options(@${CMAKE_SOURCE_DIR}/cmake/llvm/ld.txt
    ${ICPP_INSTALL_DIR}/lib/libc++.so.1
    ${ICPP_INSTALL_DIR}/lib/libc++abi.so.1 
    ${ICPP_INSTALL_DIR}/lib/libunwind.so.1) 
endif()

configure_file(
  "${CMAKE_SOURCE_DIR}/include/Version.h.in"
  "${CMAKE_BINARY_DIR}/generated/Version.h"
  @ONLY
)

set(HEADER_FILES
  include/AetherArch.h
  include/AetherBinary.h
  include/AetherCommop.h
  include/AetherELF.h
  include/AetherFile.h
  include/AetherMachO.h
  include/AetherMeta.h
  include/AetherOther.h
  include/AetherPE.h
  include/AetherRegister.h
  include/CommDef.h
  include/Disassembler.h
  src/AetherBinaryPriv.hpp
  src/MachOTrie.hpp
)

set(SOURCE_FILES
  src/AetherArch.cpp
  src/AetherBinary.cpp
  src/AetherCommop.cpp
  src/AetherELF.cpp
  src/AetherMachO.cpp
  src/AetherMeta.cpp
  src/AetherOther.cpp
  src/AetherPE.cpp
  src/Assembler.cpp
  src/Disassembler.cpp
)

add_library(AetherBinary SHARED
  ${SOURCE_FILES}
  ${HEADER_FILES}
)

# link the LLVM shared library
if(MSVC)
  target_link_directories(AetherBinary PRIVATE ${LLVM_LIBRARY_DIRS})
  target_link_libraries(AetherBinary PRIVATE LLVM-22 LLVMSupport)
else()
  target_link_libraries(AetherBinary PRIVATE LLVM LLVMSupport)
endif()

target_include_directories(AetherBinary PRIVATE 
  ${LLVM_INCLUDE_DIRS}
  ${LLVM_BUILD_DIR}/include
  ${LLVM_BUILD_DIR}/lib # for the opcodes of targets
)

if(APPLE)
  set_target_properties(AetherBinary PROPERTIES
    SKIP_BUILD_RPATH TRUE
    SKIP_INSTALL_RPATH TRUE
  )
  target_link_options(AetherBinary PRIVATE
    -Wl,-rpath,@executable_path
    -Wl,-rpath,@executable_path/../lib
    -Wl,-rpath,@loader_path
    -Wl,-rpath,@loader_path/../lib
    -Wl,-install_name,@rpath/libAetherBinary.dylib
  )
endif()

target_include_directories(AetherBinary PUBLIC
  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/generated>
  $<INSTALL_INTERFACE:include>
)

if(MSVC)
  set(ZLIB_BUILD_TESTING OFF CACHE BOOL "" FORCE)
  set(ZLIB_BUILD_SHARED OFF CACHE BOOL "" FORCE)
  add_subdirectory(${CMAKE_SOURCE_DIR}/third/zlib
                   ${CMAKE_BINARY_DIR}/zlib
                   EXCLUDE_FROM_ALL)

  target_link_libraries(AetherBinary PRIVATE zlibstatic)
  add_dependencies(AetherBinary zlibstatic)

  target_compile_options(AetherBinary PRIVATE 
    # /EHsc enables standard synchronous C++ exception handling
    /EHsc)

  set(DISABLE_RTTI /GR-)
else()
  set(DISABLE_RTTI -fno-rtti)
endif()

target_compile_options(AetherBinary PRIVATE
  -DAETHER_DLLIMPL=1

  ${DISABLE_RTTI}
)
target_compile_features(AetherBinary PUBLIC cxx_std_20)

target_compile_definitions(AetherBinary PRIVATE
  PROJECT_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
  PROJECT_VERSION_MINOR=${PROJECT_VERSION_MINOR}
  PROJECT_VERSION_PATCH=${PROJECT_VERSION_PATCH}
  PROJECT_VERSION_STRING="${PROJECT_VERSION_STRING}"
)

# Install rules
install(TARGETS AetherBinary
  EXPORT AetherBinaryTargets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.h"
)

install(EXPORT AetherBinaryTargets
  NAMESPACE AetherBinary::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AetherBinary
)

configure_package_config_file(
  "${CMAKE_SOURCE_DIR}/cmake/AetherBinaryConfig.cmake.in"
  "${CMAKE_BINARY_DIR}/generated/AetherBinaryConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AetherBinary
  NO_SET_AND_CHECK_MACRO
  NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

write_basic_package_version_file(
  "${CMAKE_BINARY_DIR}/generated/AetherBinaryConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

install(FILES
  "${CMAKE_BINARY_DIR}/generated/AetherBinaryConfig.cmake"
  "${CMAKE_BINARY_DIR}/generated/AetherBinaryConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AetherBinary
)

if(MSVC)
  set(LIBLLVM "LLVM-22.dll")
  set(LIBLLVMDIR ${LLVM_TOOLS_BINARY_DIR})
  set(LLVM_INSTALL_DIR ${CMAKE_INSTALL_BINDIR})
elseif(APPLE)
  set(LIBLLVM "libLLVM.dylib")
  set(LIBLLVMDIR ${LLVM_LIBRARY_DIRS})
  set(LLVM_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR})
else()
  set(LIBLLVM "libLLVM.so.22.1")
  set(LIBLLVMDIR ${LLVM_LIBRARY_DIRS})
  set(LLVM_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR})
endif()

install(FILES
  ${LIBLLVMDIR}/${LIBLLVM}
  DESTINATION ${LLVM_INSTALL_DIR}
)

install(FILES
  ${CMAKE_SOURCE_DIR}/script/comdef.h
  ${CMAKE_SOURCE_DIR}/script/aebi.cc
  ${CMAKE_SOURCE_DIR}/script/cutter.h
  ${CMAKE_SOURCE_DIR}/script/cutter.h.cc
  DESTINATION ${CMAKE_INSTALL_PREFIX}
)
