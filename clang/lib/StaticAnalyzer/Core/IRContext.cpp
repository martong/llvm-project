//===-------------- IRContext.cpp -----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Core/IRContext.h"
#include "clang/CodeGen/ModuleBuilder.h"
#include "clang/Frontend/CompilerInstance.h"
#include "llvm/IR/LLVMContext.h"

using namespace llvm;
using namespace clang;
using namespace ento;

IRContext::IRContext(CompilerInstance& CI) {
  std::string ModuleName("csa_module");
  LLVMCtx = std::make_unique<LLVMContext>();
  CodeGen.reset(CreateLLVMCodeGen(
      CI.getDiagnostics(), ModuleName,
      CI.getHeaderSearchOpts(), CI.getPreprocessorOpts(),
      CI.getCodeGenOpts(), *LLVMCtx));
  CodeGen->HandleTranslationUnit(CI.getASTContext());
  assert(CodeGen->GetModule());
}

IRContext::~IRContext() {
  CodeGen->ReleaseModule();
}
