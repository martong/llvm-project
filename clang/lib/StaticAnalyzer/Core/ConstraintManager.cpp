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
#include "llvm/ADT/Statistic.h"

using namespace clang;
using namespace ento;

#define DEBUG_TYPE "CoreEngine"

STATISTIC(NumInfeasible, "The # of infeasible states");
STATISTIC(NumFeasible, "The # of feasible states");

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

ConstraintManager::ProgramStatePair
ConstraintManager::assumeDual(ProgramStateRef State, DefinedSVal Cond) {
  ProgramStateRef StTrue = assumeInternal(State, Cond, true);

  if (!StTrue) {
    ProgramStateRef StFalse = assumeInternal(State, Cond, false);
    if (!StFalse) { // both infeasible
      ProgramStateRef Infeasible = State->cloneAsInfeasible();
      assert(Infeasible->isInfeasible());
      ++NumInfeasible;
      return ProgramStatePair(Infeasible, Infeasible);
    }
    ++NumFeasible;
    return ProgramStatePair(nullptr, StFalse);
  }

  ProgramStateRef StFalse = assumeInternal(State, Cond, false);
  if (!StFalse) {
    return ProgramStatePair(StTrue, nullptr);
  }

  return ProgramStatePair(StTrue, StFalse);
}

ProgramStateRef ConstraintManager::assume(ProgramStateRef State,
                                          DefinedSVal Cond, bool Assumption) {
  ConstraintManager::ProgramStatePair R = assumeDual(State, Cond);
  return Assumption ? R.first : R.second;
}
