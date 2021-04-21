/*
** -----------------------------------------------------------------------------
** Copyright (c) Ericsson AB, 2020
** -----------------------------------------------------------------------------
**
** The copyright to the document(s) herein is the property of
**
** Ericsson AB, Sweden.
**
** The document(s) may be used, copied or otherwise distributed only with
** the written permission from Ericsson AB or in accordance with the
** terms and conditions stipulated in the agreement/contract under which
** the document(s) have been supplied.
**
** -----------------------------------------------------------------------------
*/

#include <string>

#include "clang/Basic/SourceManager.h"

#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"

#include "clang/Basic/TargetInfo.h"

#include "CheckerUtils/Common.h"

#include "BugReporterHelper.h"
#include "CppHelpers.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

using namespace clang;
using namespace ento;
using namespace ericsson;

// Port of the Coverity PASS_BY_VALUE checker.

// Approximate work time: 2 hours

// This is not using the AST_CHECKER macros intentionally: checkPreCall provides
// us with a much more convenient API than matchers.

// TODO: if an stl container is not mutated but passed bz value it should warn.

namespace {
StringRef cfg_bugName = "Pass by value";
StringRef cfg_bugCategory = "C++";
StringRef cfg_reportMessage = "Passing large object by value (size: $N bytes)";

// TODO: In C++11, check if move ctor is called, and ignore those cases

class LargeObjectPassedChecker : public Checker<check::PreCall> {
public:
  void checkPreCall(const CallEvent &call, CheckerContext &context) const {
    const Decl *d = call.getDecl();
    if (!d)
      return;

    if (isInSysHeader(call.getSourceRange().getBegin(),
                      context.getSourceManager())) {
      return;
    }

    const auto *funcDecl = llvm::dyn_cast<FunctionDecl>(d);
    if (!funcDecl)
      return;

    ASTContext &astContext = context.getASTContext();
    for (unsigned i = 0; i < funcDecl->getNumParams(); ++i) {
      const Expr *argExpr = call.getArgExpr(i);
      if (!argExpr)
        continue;

      QualType argType = argExpr->getType();
      assert(!argType.isNull());

      if (argType->isBuiltinType())
        return;

      // we have to check how the AST looks when calling a move ctor, and filter
      // those cases out

      QualType paramType = funcDecl->getParamDecl(i)->getType();
      assert(!paramType.isNull());

      if (paramType->isAnyPointerType() || paramType->isBlockPointerType() ||
          paramType->isNullPtrType() ||
          paramType->isReferenceType()) // source: SVals.h:291 (Loc::isLocType)
      {
        // not pass-by-value, so we don't care
        continue;
      }

      uint64_t size = astContext.getTypeSize(argExpr->getType());
      if (size > static_cast<uint64_t>(
                     context.getAnalysisManager()
                         .getAnalyzerOptions()
                         .getCheckerIntegerOption(this, "SizeThreshold"))) {
        if (!isValidLoc(argExpr))
          continue;

        const Expr *origExpr = call.getOriginExpr();

        ast_type_traits::DynTypedNode keyNode =
            ast_type_traits::DynTypedNode::create(*origExpr);

        PathDiagnosticLocation loc = PathDiagnosticLocation(
            argExpr, context.getSourceManager(), context.getLocationContext());

        SmallVector<SourceRange, 1> ranges;
        ranges.push_back(d->getSourceRange());

        std::string report_msg = str_replace(cfg_reportMessage.str(), "$N",
                                             std::to_string(size / 8));

        AnalysisManager &mgr = context.getAnalysisManager();
        BugReporter &br = context.getBugReporter();

        emitFlowReport(keyNode, mgr, br, this, cfg_bugName, cfg_bugCategory,
                       report_msg, loc, ranges);
      }
    }
  }

private:
  mutable std::unique_ptr<BugType> m_bugType;
};

} // end namespace

void ento::registerLargeObjectPassedChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<LargeObjectPassedChecker>();
}

bool ento::shouldRegisterLargeObjectPassedChecker(const CheckerManager &mgr) {
  return true;
}
