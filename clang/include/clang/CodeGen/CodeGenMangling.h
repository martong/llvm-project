//==---- CodeGenMangling.h - Get mangled names for AST nodes ---------------==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// CodeGenMangling provides name mangling facilities.
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_CODEGEN_CODEGENMANGLING_H
#define LLVM_CLANG_CODEGEN_CODEGENMANGLING_H

#include "clang/AST/GlobalDecl.h"
#include "llvm/ADT/StringRef.h"

namespace clang {
namespace CodeGen {
class CodeGenModule;

llvm::StringRef getMangledName(CodeGenModule& CGM, GlobalDecl GD);

} // namespace CodeGen
} // namespace clang

#endif
