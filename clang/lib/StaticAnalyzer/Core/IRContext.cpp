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

llvm::Module *IRContext::getFunction(const FunctionDecl *FD) {
    assert(*CodeGen);
    //CodeGen->HandleTopLevelDecl(DeclGroupRef(const_cast<FunctionDecl*>(FD)));
    auto *M = (*CodeGen)->GetModule();
    return M;
}
