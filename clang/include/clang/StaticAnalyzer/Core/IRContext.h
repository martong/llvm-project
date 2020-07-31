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
class Module;
} // namespace llvm

namespace clang {
class ASTContext;
class CodeGenerator;
class CompilerInstance;
class FunctionDecl;

namespace ento {

class IRContext {
  std::unique_ptr<clang::CodeGenerator> CodeGen;
  std::unique_ptr<llvm::LLVMContext> LLVMCtx;

public:
  IRContext(CompilerInstance &CI);
  ~IRContext();
  void handleTranslationUnit(ASTContext &C);
  llvm::Module *getModule();
  llvm::Module *getFunction(const FunctionDecl *FD);
};

} // namespace ento
} // namespace clang

#endif
