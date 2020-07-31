//===-------------- IRContext.cpp -----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclGroup.h"
#include "clang/StaticAnalyzer/Core/IRContext.h"
#include "clang/CodeGen/ModuleBuilder.h"
#include "clang/Frontend/CompilerInstance.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"

using namespace llvm;
using namespace clang;
using namespace ento;

IRContext::IRContext(CompilerInstance &CI) {
  std::string ModuleName("csa_module");
  LLVMCtx = std::make_unique<LLVMContext>();
  CodeGen.reset(CreateLLVMCodeGen(
      CI.getDiagnostics(), ModuleName, CI.getHeaderSearchOpts(),
      CI.getPreprocessorOpts(), CI.getCodeGenOpts(), *LLVMCtx));
}

IRContext::~IRContext() { CodeGen->ReleaseModule(); }

void IRContext::handleTranslationUnit(ASTContext &C) {
  //C.getTranslationUnitDecl()->dump();
  CodeGen->Initialize(C);
  for (Decl *D : C.getTranslationUnitDecl()->decls()) {
    CodeGen->HandleTopLevelDecl(DeclGroupRef(D));
  }
  CodeGen->HandleTranslationUnit(C);
  assert(CodeGen->GetModule());
}

llvm::Module *IRContext::getModule() { return CodeGen->GetModule(); }

llvm::Module *IRContext::getFunction(const FunctionDecl *FD) {
    //CodeGen->HandleTopLevelDecl(DeclGroupRef(const_cast<FunctionDecl*>(FD)));
    auto *M = CodeGen->GetModule();
    return M;
}
