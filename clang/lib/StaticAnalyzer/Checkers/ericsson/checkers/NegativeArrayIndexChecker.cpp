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

// ===-------------------NegativeArrayIndexChecker.cpp --------------------===//
//
// This checker tries to detect array subscript expressions (array indexing),
// where the index is a negative integer. Negative literal indexing is a clang
// warning in itself, but this checker uses symbolic execution to reason about
// indexing with variables as well.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
class NegativeArrayIndexChecker
    : public Checker<check::PreStmt<ArraySubscriptExpr>> {

  mutable BuiltinBug BB{
      this,
      "Array is indexed with a negative value. Possible integer overflow."};

public:
  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
};
} // end anonymous namespace

/**
 * The checker tries to reason about the value of the index in array subscript
 * expressions, and emit a warning if a negative index value is encountered.
 */
void NegativeArrayIndexChecker::checkPreStmt(const ArraySubscriptExpr *ASE,
                                             CheckerContext &C) const {

  const auto *Index = ASE->getIdx();

  // No warnings are needed when indexing with an integer literal.
  // We assume that it is intentional.
  auto v = clang::ast_matchers::match(
      clang::ast_matchers::findAll(clang::ast_matchers::declRefExpr()), *Index,
      C.getASTContext());

  if (v.empty())
    return;

  // Get the symbolic value of the index.
  const auto IndexSVal = C.getSVal(Index);

  const auto State = C.getState();
  auto &SValBuilder = C.getSValBuilder();

  // Evaluate IndexSVal < 0 symbolically.
  const auto IsIndexNegative = SValBuilder.evalBinOp(
      State, BO_LT, IndexSVal, SValBuilder.makeZeroArrayIndex(),
      SValBuilder.getArrayIndexType());

  // If there is not enough information about the value of the index, then don't
  // proceed.
  const auto DefinitelyNegativeIndex = IsIndexNegative.getAs<DefinedSVal>();
  if (!DefinitelyNegativeIndex)
    return;

  const auto AssumptionPair = State->assume(DefinitelyNegativeIndex.getValue());

  // Only emit report if the index is definitely smaller than zero, that it is
  // feasible that it is smaller, but it is not possible that it is equal or
  // greater.
  if (!AssumptionPair.first || AssumptionPair.second)
    return;

  // This error is not fatal, the analysis can go on.
  const auto *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  // Report the error.
  auto R = std::make_unique<PathSensitiveBugReport>(BB, BB.getDescription(), N);
  R->addRange(Index->getSourceRange());
  C.emitReport(std::move(R));
}

void ento::registerNegativeArrayIndexChecker(CheckerManager &mgr) {
  mgr.registerChecker<NegativeArrayIndexChecker>();
}

bool ento::shouldRegisterNegativeArrayIndexChecker(const CheckerManager &mgr) {
  return true;
}
