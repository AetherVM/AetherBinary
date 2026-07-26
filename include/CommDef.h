// AetherBinary - A library for MachO/ELF/PE analysis.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

#pragma once

#ifdef _WIN32
#ifdef AETHER_DLLIMPL
#define __AETHER_API__ __declspec(dllexport)
#else
#define __AETHER_API__ __declspec(dllimport)
#endif // end of AETHER_DLLIMPL
#else
#define __AETHER_API__ __attribute__((visibility("default")))
#endif // end of _WIN32

typedef unsigned long long addr_t;

#define ADDRFMT "%llx"

#define AETHER_ANOYPREFIX "aebi_"

namespace aether {

constexpr addr_t INVALID_ADDR = (addr_t)(-1);

} // namespace aether
