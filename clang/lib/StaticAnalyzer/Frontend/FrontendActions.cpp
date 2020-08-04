//===--- FrontendActions.cpp ----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Frontend/FrontendActions.h"
#include "clang/StaticAnalyzer/Frontend/AnalysisConsumer.h"
#include "clang/StaticAnalyzer/Frontend/ModelConsumer.h"
#include "clang/Frontend/MultiplexConsumer.h"

#include "clang/CodeGen/ModuleBuilder.h"
#include "clang/Frontend/CompilerInstance.h"

#include "llvm/IR/LLVMContext.h"

using namespace clang;
using namespace ento;

namespace {
std::unique_ptr<CodeGenerator> BuildCodeGen(CompilerInstance &CI,
                                            llvm::LLVMContext &LLVMCtx) {
  StringRef ModuleName("csa_module");
  CodeGenOptions &CGO = CI.getCodeGenOpts();
  // Set the optimization level, so CodeGenFunciton would emit lifetime
  // markers which are used by some LLVM analysis (e.g. AliasAnalysis).
  CGO.OptimizationLevel = 2; // -O2
  return std::unique_ptr<CodeGenerator>(CreateLLVMCodeGen(
      CI.getDiagnostics(), ModuleName, CI.getHeaderSearchOpts(),
      CI.getPreprocessorOpts(), CGO, LLVMCtx));
}
} // namespace

AnalysisAction::~AnalysisAction() {}

std::unique_ptr<ASTConsumer>
AnalysisAction::CreateASTConsumer(CompilerInstance &CI, StringRef InFile) {
  std::vector<std::unique_ptr<ASTConsumer>> ASTConsumers;
  auto AConsumer = CreateAnalysisConsumer(CI);

  // FIXME handle Opts
  LLVMCtx = std::make_shared<llvm::LLVMContext>();
  auto CGConsumer = BuildCodeGen(CI, *LLVMCtx);
  AConsumer->setCodeGen(CGConsumer.get());
  ASTConsumers.push_back(std::move(CGConsumer));

  ASTConsumers.push_back(std::move(AConsumer));
  return std::make_unique<MultiplexConsumer>(std::move(ASTConsumers));
}

std::unique_ptr<AnalysisAction> CreateAnalysisAction() {
  return std::make_unique<AnalysisAction>();
}

ParseModelFileAction::ParseModelFileAction(llvm::StringMap<Stmt *> &Bodies)
    : Bodies(Bodies) {}

std::unique_ptr<ASTConsumer>
ParseModelFileAction::CreateASTConsumer(CompilerInstance &CI,
                                        StringRef InFile) {
  return std::make_unique<ModelConsumer>(Bodies);
}
