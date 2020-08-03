//==--- CodeGenABITypes.cpp - Convert Clang types to LLVM types for ABI ----==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// CodeGenMangling provides name mangling facilities.
//===----------------------------------------------------------------------===//

#include "clang/CodeGen/CodeGenMangling.h"
#include "CodeGenModule.h"

using namespace llvm;

namespace clang {
namespace CodeGen {

StringRef getMangledName(CodeGenModule& CGM, GlobalDecl GD) {
  return CGM.getMangledName(GD);
}

} // namespace CodeGen
} // namespace clang
