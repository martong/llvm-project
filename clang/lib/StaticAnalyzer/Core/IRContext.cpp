//===-------------- IRContext.cpp -----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Core/IRContext.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclGroup.h"
#include "clang/CodeGen/CodeGenMangling.h"
#include "clang/CodeGen/ModuleBuilder.h"
#include "clang/Frontend/CompilerInstance.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"

using namespace llvm;
using namespace clang;
using namespace ento;

llvm::Function *IRContext::getFunction(const FunctionDecl *FD) {
    assert(*CodeGen);

    auto *M = (*CodeGen)->GetModule();

    static int i = 0;
    if (i == 0) {
        //M->dump();
        ++i;
    }

    if (isa<CXXConstructorDecl>(FD) || isa<CXXDestructorDecl>(FD) ||
        FD->hasAttr<CUDAGlobalAttr>())
      return nullptr;

    CodeGen::CodeGenModule &CGM = (*CodeGen)->CGM();
    StringRef Name = getMangledName(CGM, FD);
    //llvm::errs() << "Name: " << Name << "\n";

    // There are functions which are not generated. E.g. not used operator=, etc.
    //if(!M->getFunction(Name)) {
      //llvm::errs() << "Name: " << Name << "\n";
    //}
    return M->getFunction(Name);
}
