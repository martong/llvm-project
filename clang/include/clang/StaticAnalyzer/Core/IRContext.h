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

#include "clang/AST/GlobalDecl.h"

namespace llvm {
class Function;
} // namespace llvm

namespace clang {
class CodeGenerator;
class FunctionDecl;

namespace ento {

// Static Analyzer components can get access to the LLVM IR of a translation
// unit throught this class.
class IRContext {
  // Set by AnalysisAction if the AnalyzerOptions requires that.
  clang::CodeGenerator*& CodeGen;

public:
  IRContext(clang::CodeGenerator*& CodeGen) : CodeGen(CodeGen) {}
  void runOptimizerPipeline();
  llvm::Function *getFunction(GlobalDecl GD);
  // Get the LLVM code for a function. We use the complete versions of the
  // constructors and desctructors in this overload. Use the other overload to
  // get the base object ctor/dtor.
  llvm::Function *getFunction(const FunctionDecl *FD);
};

} // namespace ento
} // namespace clang

#endif
