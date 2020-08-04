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

#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/LoopAnalysisManager.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/StandardInstrumentations.h"
#include "llvm/Transforms/Utils/EntryExitInstrumenter.h"

using namespace llvm;
using namespace clang;
using namespace ento;

void IRContext::init() {
  // TargetMachine is not set, so we will not do optimizations based on
  // target-aware cost modeling of IR contructs. Still, a default
  // TargetIRAnalysis is registerd in registerFunctionAnalyses. That will use
  // the module's datalayout to construct a baseline conservative result.
  PassBuilder PB;

  LoopAnalysisManager LAM(true);
  FunctionAnalysisManager FAM(true);
  CGSCCAnalysisManager CGAM(true);
  ModuleAnalysisManager MAM(true);

  // Register the AA manager first so that our version is the one used.
  FAM.registerPass([&] { return PB.buildDefaultAAPipeline(); });

  auto *M = (*CodeGen)->GetModule();

  // Register the target library analysis directly and give it a customized
  // preset TLI.
  Triple TargetTriple(M->getTargetTriple());
  std::unique_ptr<TargetLibraryInfoImpl> TLII(
      new TargetLibraryInfoImpl(TargetTriple));
  FAM.registerPass([&] { return TargetLibraryAnalysis(*TLII); });

  // Register all the basic analyses with the managers.
  PB.registerModuleAnalyses(MAM);
  PB.registerCGSCCAnalyses(CGAM);
  PB.registerFunctionAnalyses(FAM);
  PB.registerLoopAnalyses(LAM);
  PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

  ModulePassManager MPM(true);

  PB.registerPipelineStartEPCallback([](ModulePassManager &MPM) {
    MPM.addPass(createModuleToFunctionPassAdaptor(
        EntryExitInstrumenterPass(/*PostInlining=*/false)));
  });

  MPM = PB.buildPerModuleDefaultPipeline(PassBuilder::OptimizationLevel::O2,
                                         /*debug=*/true);
  MPM.run(*M, MAM);
  M->dump();
}

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
