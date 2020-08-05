//===-------------- IRContext.cpp -----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Core/IRContext.h"
#include "clang/CodeGen/CodeGenMangling.h"
#include "clang/CodeGen/ModuleBuilder.h"

#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Transforms/Utils/EntryExitInstrumenter.h"

using namespace llvm;
using namespace clang;
using namespace ento;

void IRContext::runOptimizerPipeline() {
  if (CodeGen == nullptr)
    return;

  // TargetMachine is not set, so we will not do optimizations based on
  // target-aware cost modeling of IR contructs. Still, a default
  // TargetIRAnalysis is registerd in registerFunctionAnalyses. That will use
  // the module's datalayout to construct a baseline conservative result.
  PassBuilder PB;

  // FIXME make this an option.
  constexpr const bool Debug = false;

  LoopAnalysisManager LAM(Debug);
  FunctionAnalysisManager FAM(Debug);
  CGSCCAnalysisManager CGAM(Debug);
  ModuleAnalysisManager MAM(Debug);

  // Register the AA manager first so that our version is the one used.
  FAM.registerPass([&] { return PB.buildDefaultAAPipeline(); });

  auto *M = CodeGen->GetModule();

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

  ModulePassManager MPM(Debug);

  PB.registerPipelineStartEPCallback([](ModulePassManager &MPM) {
    MPM.addPass(createModuleToFunctionPassAdaptor(
        EntryExitInstrumenterPass(/*PostInlining=*/false)));
  });

  MPM = PB.buildPerModuleDefaultPipeline(PassBuilder::OptimizationLevel::O2,
                                         Debug);
  MPM.run(*M, MAM);
}

llvm::Function *IRContext::getFunction(GlobalDecl GD) {
  if (CodeGen == nullptr)
    return nullptr;

  CodeGen::CodeGenModule &CGM = CodeGen->CGM();
  StringRef Name = getMangledName(CGM, GD);

  auto *M = CodeGen->GetModule();
  // There are functions which are not generated. E.g. not used operator=, etc.
  return M->getFunction(Name);
}

llvm::Function *IRContext::getFunction(const FunctionDecl *FD) {
  if (CodeGen == nullptr)
    return nullptr;

  // We use the complete versions of the constructors and desctructors.
  // Use the other overload of getFunction to get the base object ctor/dtor.
  GlobalDecl GD;
  if (const auto *CD = dyn_cast<CXXConstructorDecl>(FD))
    GD = GlobalDecl(CD, Ctor_Complete);
  else if (const auto *DD = dyn_cast<CXXDestructorDecl>(FD))
    GD = GlobalDecl(DD, Dtor_Complete);
  else if (FD->hasAttr<CUDAGlobalAttr>())
    GD = GlobalDecl(FD, KernelReferenceKind::Kernel);
  else
    GD = GlobalDecl(FD);

  return getFunction(GD);
}
