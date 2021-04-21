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

// SufficientSizeArrayIndexingChecker.cpp ---------------------------------===//
//
// This checker checks for indexing an array with integer types that are not
// sufficiently large in size to cover the array.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

#include "clang/AST/TypeOrdering.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/DynamicSize.h"

using namespace clang;
using namespace ento;

namespace {
class SufficientSizeArrayIndexingChecker
    : public Checker<check::PreStmt<ArraySubscriptExpr>> {

  mutable llvm::DenseMap<QualType, BugType> BugTypeCache;

  BugType &GetBugTypeForType(const QualType T) const;

public:
  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
};
} // end anonymous namespace

/**
 * Helper method to get the cached BugType for the QualType used for indexing.
 * In case of a cache miss create the corresponding BugType, and cache it in
 * case we encounter it later on.
 */
BugType &
SufficientSizeArrayIndexingChecker::GetBugTypeForType(const QualType T) const {

  auto BT = BugTypeCache.find(T);

  // If we have already encountered the type, the BugType is cached.
  if (BT != BugTypeCache.end())
    return BT->getSecond();

  // Store the BugType into the cache.
  BugTypeCache.insert(std::make_pair(
      T,
      BuiltinBug{this, (Twine("Indexing array with type '") + T.getAsString() +
                        "' cannot cover the whole range of the array's "
                        "index set, which results in memory waste. "
                        "Consider using a type with greater maximum "
                        "value.")
                           .str()
                           .c_str()}));

  return BugTypeCache.find(T)->getSecond();
}

/**
 * Main entrypoint of the checker. The checker analyzes array indexing
 * operations (expression of type ArraySubscriptExpr), and tries to determine
 * the maximum possible value of the indexing type. Then it tries to reason
 * about wheter this maximum is big enough to actually access every element of
 * the array. To determine the size of the array, symbolic execution is used.
 * This way, dynamically allocated arrays can also be checked.
 */
void SufficientSizeArrayIndexingChecker::checkPreStmt(
    const ArraySubscriptExpr *ASE, CheckerContext &C) const {

  const auto *Base = ASE->getBase();
  const auto *Index = ASE->getIdx();

  const auto IndexType = Index->getType();

  // Should not warn on literal index expressions.
  if (dyn_cast<IntegerLiteral>(Index->IgnoreParenCasts()))
    return;

  // Get the maximal value of the index type.
  const auto MaxIndexValue =
      llvm::APSInt::getMaxValue(C.getASTContext().getIntWidth(IndexType),
                                IndexType->isUnsignedIntegerType());
  const nonloc::ConcreteInt MaxIndexValueSVal(MaxIndexValue);

  // Get the symbolic representation of the array. This is needed to reason
  // about the underlying memory regions.
  const auto BaseSVal = C.getSVal(Base);

  // Try to get the memory region associated with the base of the
  // ArraySubscriptExpr.
  const auto *BaseMemRegion = BaseSVal.getAsRegion();

  // If no memory is associated with the expression the checker exits early.
  if (!BaseMemRegion)
    return;

  // In order to get the extent try to cast the regions to SubRegion type.
  const auto *BaseSubRegion = dyn_cast<SubRegion>(BaseMemRegion);
  if (!BaseSubRegion)
    return;

  // Get the memory region of the whole array, because BaseMemRegion only
  // contains the first element.
  const auto *SuperMemRegion = BaseSubRegion->getSuperRegion();

  // If the parent region is the same as the base we definitely do not have an
  // array indexing situation.
  if (BaseMemRegion == SuperMemRegion)
    return;

  const auto *SuperSubRegion = dyn_cast<SubRegion>(SuperMemRegion);

  // The checker has to access the extent of both the sub and the superregion.
  if (!SuperSubRegion)
    return;

  const auto State = C.getState();
  auto &SValBuilder = C.getSValBuilder();

  // Try to reason about the number of elements in the array.
  // RegionStore has a getSizeInElements method which assumes the value too
  // eagerly, so this leaner, and more general implementation is used instead.
  const auto BaseRegionSize = getDynamicSize(State, BaseSubRegion, SValBuilder);
  const auto SuperRegionSize = getDynamicSize(State, SuperSubRegion, SValBuilder);
  const auto SizeInElements =
      SValBuilder.evalBinOp(State, BO_Div, SuperRegionSize, BaseRegionSize,
                            C.getASTContext().getSizeType());

  if (!SizeInElements.isConstant())
    return;

  // The criterium for correctness is: the size of the array minus one should be
  // lesser than or equal to the maximum positive value of the indextype.
  // Symbolic execution is used all the way to ensure maximal coverage of
  // possible cases.
  const auto Constant1SVal = SValBuilder.makeIntVal(1, true);
  const auto NumArrayElemsMinusOne =
      SValBuilder.evalBinOp(State, BO_Sub, SizeInElements, Constant1SVal,
                            C.getASTContext().UnsignedLongLongTy);

  if (NumArrayElemsMinusOne.isUnknownOrUndef())
    return;

  const auto TypeCanIndexEveryElement = SValBuilder.evalBinOp(
      State, BO_LE, NumArrayElemsMinusOne, MaxIndexValueSVal, IndexType);

  // Determine wheter we can reason about the value of the constructed symbolic
  // expression.
  if (TypeCanIndexEveryElement.isUnknownOrUndef())
    return;

  // Make an assumption on both possibilities, namely that the size
  // of the array minus one is smaller than the maximum value of the index type
  // (meaning that for every element there exists an index through which it can
  // be accessed), and the alternative, that it is greater of equal.
  const auto AssumptionPair =
      State->assume(TypeCanIndexEveryElement.castAs<DefinedSVal>());

  // To avoid false positives the checker is conservative when considering the
  // possibily of correct indexing. If the there is a chance that the indexing
  // can be correct or the incorrect case is not certain, there will be no
  // warning emitted.
  if (AssumptionPair.first && !AssumptionPair.second)
    return;

  // The analysis can continue onward even if an error was found.
  const auto *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  // Get the cached BugType, its message is specific to the index type.
  auto &BT = GetBugTypeForType(IndexType);

  // Report the error.
  auto R = std::make_unique<PathSensitiveBugReport>(BT, BT.getDescription(), N);
  R->addRange(Index->getSourceRange());
  C.emitReport(std::move(R));
}

void ento::registerSufficientSizeArrayIndexingChecker(CheckerManager &mgr) {
  mgr.registerChecker<SufficientSizeArrayIndexingChecker>();
}

bool ento::shouldRegisterSufficientSizeArrayIndexingChecker(
    const CheckerManager &mgr) {
  return true;
}
