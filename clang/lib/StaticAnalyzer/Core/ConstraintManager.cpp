//===- ConstraintManager.cpp - Constraints on symbolic values. ------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//  This file defined the interface to manage constraints on symbolic values.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Core/PathSensitive/ConstraintManager.h"
#include "clang/AST/Type.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState_Fwd.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "llvm/ADT/ScopeExit.h"
#include "llvm/ADT/Statistic.h"

using namespace clang;
using namespace ento;

#define DEBUG_TYPE "CoreEngine"

STATISTIC(NumAssume, "The # of assume calls");
STATISTIC(NumAssumeRecurse, "The # of recursive assume calls");
STATISTIC(AssumeStackSize01, "The # of assume stack size between 0 and 1");
STATISTIC(AssumeStackSize23, "The # of assume stack size between 2 and 3");
STATISTIC(AssumeStackSize45, "The # of assume stack size between 4 and 5");
STATISTIC(AssumeStackSize67, "The # of assume stack size between 6 and 7");
STATISTIC(AssumeStackSize89, "The # of assume stack size between 8 and 9");
STATISTIC(AssumeStackSize1011, "The # of assume stack size between 10 and 11");
STATISTIC(AssumeStackSize1213, "The # of assume stack size between 12 and 13");
STATISTIC(AssumeStackSize1415, "The # of assume stack size between 14 and 15");
STATISTIC(AssumeStackSize16XX, "The # of assume stack size greater equal than 16");

ConstraintManager::~ConstraintManager() = default;

static DefinedSVal getLocFromSymbol(const ProgramStateRef &State,
                                    SymbolRef Sym) {
  const MemRegion *R =
      State->getStateManager().getRegionManager().getSymbolicRegion(Sym);
  return loc::MemRegionVal(R);
}

ConditionTruthVal ConstraintManager::checkNull(ProgramStateRef State,
                                               SymbolRef Sym) {
  QualType Ty = Sym->getType();
  DefinedSVal V = Loc::isLocType(Ty) ? getLocFromSymbol(State, Sym)
                                     : nonloc::SymbolVal(Sym);
  const ProgramStatePair &P = assumeDual(State, V);
  if (P.first && !P.second)
    return ConditionTruthVal(false);
  if (!P.first && P.second)
    return ConditionTruthVal(true);
  return {};
}

template <typename AssumeFunction>
ConstraintManager::ProgramStatePair
ConstraintManager::assumeDualImpl(ProgramStateRef &State,
                                  AssumeFunction &Assume) {

  // Assume functions might recurse (see `reAssume` or `tryRearrange`). During
  // the recursion the State might not change anymore, that means we reached a
  // fixpoint.
  // We avoid infinite recursion of assume calls by checking already visited
  // States on the stack of assume function calls.
  ++NumAssume;
  if (AssumeStack.size() < 2)
    ++AssumeStackSize01;
  else if (AssumeStack.size() < 4)
    ++AssumeStackSize23;
  else if (AssumeStack.size() < 6)
    ++AssumeStackSize45;
  else if (AssumeStack.size() < 8)
    ++AssumeStackSize67;
  else if (AssumeStack.size() < 10)
    ++AssumeStackSize89;
  else if (AssumeStack.size() < 12)
    ++AssumeStackSize1011;
  else if (AssumeStack.size() < 14)
    ++AssumeStackSize1213;
  else if (AssumeStack.size() < 16)
    ++AssumeStackSize1415;
  else
    ++AssumeStackSize16XX;
  const ProgramState *RawSt = State.get();
  if (AssumeStack.contains(RawSt)) {
    ++NumAssumeRecurse;
    return {State, State};
  }
  AssumeStack.push(RawSt);
  auto AssumeStackBuilder =
      llvm::make_scope_exit([this]() { AssumeStack.pop(); });

  ProgramStateRef StTrue = Assume(true);

  if (!StTrue) {
    ProgramStateRef StFalse = Assume(false);
    if (LLVM_UNLIKELY(!StFalse)) { // both infeasible
      ProgramStateRef StInfeasible = State->cloneAsPosteriorlyOverconstrained();
      assert(StInfeasible->isPosteriorlyOverconstrained());
      // Checkers might rely on the API contract that both returned states
      // cannot be null. Thus, we return StInfeasible for both branches because
      // it might happen that a Checker uncoditionally uses one of them if the
      // other is a nullptr. This may also happen with the non-dual and
      // adjacent `assume(true)` and `assume(false)` calls. By implementing
      // assume in therms of assumeDual, we can keep our API contract there as
      // well.
      return ProgramStatePair(StInfeasible, StInfeasible);
    }
    return ProgramStatePair(nullptr, StFalse);
  }

  ProgramStateRef StFalse = Assume(false);
  if (!StFalse) {
    return ProgramStatePair(StTrue, nullptr);
  }

  return ProgramStatePair(StTrue, StFalse);
}

ConstraintManager::ProgramStatePair
ConstraintManager::assumeDual(ProgramStateRef State, DefinedSVal Cond) {
  auto AssumeFun = [&](bool Assumption) {
    return assumeInternal(State, Cond, Assumption);
  };
  return assumeDualImpl(State, AssumeFun);
}

ConstraintManager::ProgramStatePair
ConstraintManager::assumeInclusiveRangeDual(ProgramStateRef State, NonLoc Value,
                                            const llvm::APSInt &From,
                                            const llvm::APSInt &To) {
  auto AssumeFun = [&](bool Assumption) {
    return assumeInclusiveRangeInternal(State, Value, From, To, Assumption);
  };
  return assumeDualImpl(State, AssumeFun);
}

ProgramStateRef ConstraintManager::assume(ProgramStateRef State,
                                          DefinedSVal Cond, bool Assumption) {
  ConstraintManager::ProgramStatePair R = assumeDual(State, Cond);
  return Assumption ? R.first : R.second;
}

ProgramStateRef
ConstraintManager::assumeInclusiveRange(ProgramStateRef State, NonLoc Value,
                                        const llvm::APSInt &From,
                                        const llvm::APSInt &To, bool InBound) {
  ConstraintManager::ProgramStatePair R =
      assumeInclusiveRangeDual(State, Value, From, To);
  return InBound ? R.first : R.second;
}
