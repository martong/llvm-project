//== IRContext.h - Get info from the IR in CSA -*- C++ -*--------------------=//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines auxilary structures for getting data from the IR inside
// the Clang Static Analyzer.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_STATICANALYZER_CORE_IRCONTEXT_H
#define LLVM_CLANG_STATICANALYZER_CORE_IRCONTEXT_H

#include <memory>

namespace llvm {
class LLVMContext;
} // namespace llvm

namespace clang {
class CodeGenerator;
class CompilerInstance;

namespace ento {

class IRContext {
  std::unique_ptr<clang::CodeGenerator> CodeGen;
  std::unique_ptr<llvm::LLVMContext> LLVMCtx;

public:
  IRContext(CompilerInstance &CI);
  ~IRContext();
};

} // namespace ento
} // namespace clang

#endif
