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

//===-- SpecialReturnValueStatisticsCollector.cpp -----------------*- C++ -*--//

// This checker collects statistics about calls whether their return value
// is checked for (non-) negativeness in case of integer or (non-) nullness in
// case of pointer types.  Warnings emitted are not for human consumption.
// Instead, the output of the checker must be piped into
// `tools/gen_yaml_for_special_return_values.py` in order to generate file
// `SpecialReturn.yaml` for checker `api.SpecialReturn`.
//
// The raw output of this checker is the following for every function call:
//
// Special Return Value:<filename>:<line>:<column>,<func. USR>,<negative>,<null>
//
// The element before the last element is 1 if the return value type of the
// called function is integer and the return value of the call is checked
// whether it is < 0 or >= 0, 0 otherwise.
//
// The last element is 1 if the return value type of the called function is
// pointer and the return value of the call is checked whether it is == NULL or
// != 0, 0 otherwise.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

#include "clang/Index/USRGeneration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {

struct SpecialReturnValue {
private:
  const CallExpr *Call;
  const FunctionDecl *Function;
  bool checkedForNegative, checkedForNull;

  SpecialReturnValue(const CallExpr *CE, const FunctionDecl *FD, bool cNe,
                     bool cNu)
      : Call(CE), Function(FD), checkedForNegative(cNe), checkedForNull(cNu) {}

public:
  const CallExpr *getCall() const { return Call; }
  const FunctionDecl *getFunction() const { return Function; }
  bool isCheckedForNegative() const { return checkedForNegative; }
  bool isCheckedForNull() const { return checkedForNull; }

  static SpecialReturnValue getUsage(const CallExpr *CE,
                                     const FunctionDecl *FD) {
    return SpecialReturnValue(CE, FD, false, false);
  }

  SpecialReturnValue checkForNegative() const {
    return SpecialReturnValue(Call, Function, true, checkedForNull);
  }

  SpecialReturnValue checkForNull() const {
    return SpecialReturnValue(Call, Function, checkedForNegative, true);
  }

  bool operator==(const SpecialReturnValue &X) const {
    return Call == X.Call && Function == X.Function &&
           checkedForNegative == X.checkedForNegative &&
           checkedForNull == X.checkedForNull;
  }

  bool operator!=(const SpecialReturnValue &X) const {
    return Call != X.Call || Function != X.Function ||
           checkedForNegative != X.checkedForNegative ||
           checkedForNull != X.checkedForNull;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddPointer(Call);
    ID.AddPointer(Function);
    ID.AddBoolean(checkedForNegative);
    ID.AddBoolean(checkedForNull);
  }
};

struct CheckedCallData {
  bool forNegative, forNull;
  const FunctionDecl *func;
};

llvm::DenseMap<const CallExpr *, CheckedCallData> CheckedCalls;

class SpecialReturnValueStatisticsCollector
    : public Checker<check::PostCall, check::PostStmt<BinaryOperator>,
                     check::DeadSymbols, check::EndOfTranslationUnit> {
  void handleComparison(BinaryOperator::Opcode, SymbolRef Sym, const SVal &Val,
                        CheckerContext &C) const;

public:
  SpecialReturnValueStatisticsCollector() {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostStmt(const BinaryOperator *BO, CheckerContext &C) const;
  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;
  void checkEndOfTranslationUnit(const TranslationUnitDecl *TU,
                                 AnalysisManager &Mgr, BugReporter &BR) const;
};
} // namespace

REGISTER_MAP_WITH_PROGRAMSTATE(SpecialReturnValueMap, SymbolRef,
                               SpecialReturnValue)

void SpecialReturnValueStatisticsCollector::checkPostCall(
    const CallEvent &Call, CheckerContext &C) const {
  const auto *Func = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!Func)
    return;

  if (Func->getReturnType()->isVoidType())
    return;

  const auto *Orig = dyn_cast_or_null<CallExpr>(Call.getOriginExpr());
  if (!Orig)
    return;

  const auto RetSym = Call.getReturnValue().getAsSymbol();
  if (!RetSym)
    return;

  auto State = C.getState();
  State = State->set<SpecialReturnValueMap>(
      RetSym, SpecialReturnValue::getUsage(Orig, Func));
  C.addTransition(State);
}

void SpecialReturnValueStatisticsCollector::checkPostStmt(
    const BinaryOperator *BO, CheckerContext &C) const {
  if (!BO->isRelationalOp() && !BO->isEqualityOp())
    return;

  auto State = C.getState();
  const auto *LCtx = C.getLocationContext();

  const auto LVal = State->getSVal(BO->getLHS(), LCtx),
             RVal = State->getSVal(BO->getRHS(), LCtx);

  if (const auto LSym = LVal.getAsSymbol()) {
    handleComparison(BO->getOpcode(), LSym, RVal, C);
  }
  if (const auto RSym = RVal.getAsSymbol()) {
    handleComparison(BinaryOperator::reverseComparisonOp(BO->getOpcode()), RSym,
                     LVal, C);
  }
}

void SpecialReturnValueStatisticsCollector::checkDeadSymbols(
    SymbolReaper &SR, CheckerContext &C) const {
  auto State = C.getState();

  auto SymbolMap = State->get<SpecialReturnValueMap>();
  for (const auto Sym : SymbolMap) {
    if (!SR.isLive(Sym.first)) {
      const auto *Call = Sym.second.getCall();
      const auto *FD = Sym.second.getFunction();
      CheckedCalls[Call].func = FD;
      if (Sym.second.isCheckedForNegative()) {
        CheckedCalls[Call].forNegative = true;
      }
      if (Sym.second.isCheckedForNull()) {
        CheckedCalls[Call].forNull = true;
      }
      State = State->remove<SpecialReturnValueMap>(Sym.first);
    }
  }

  C.addTransition(State);
}

void SpecialReturnValueStatisticsCollector::checkEndOfTranslationUnit(
    const TranslationUnitDecl *TU, AnalysisManager &Mgr,
    BugReporter &BR) const {
  const auto &SM = Mgr.getASTContext().getSourceManager();
  for (const auto C : CheckedCalls) {
    const auto *CE = C.first;
    const auto Checks = C.second;
    const auto *FD = Checks.func;

    SmallString<256> USR;
    clang::index::generateUSRForDecl(FD, USR);

    SmallString<256> Buf;
    llvm::raw_svector_ostream Out(Buf);
    Out << "Special Return Value: " << CE->getBeginLoc().printToString(SM)
        << ",\"" << USR << "\"," << (int)Checks.forNegative << ","
        << (int)Checks.forNull;

    const auto &AC = Mgr.getAnalysisDeclContext(FD);

    PathDiagnosticLocation CELoc =
        PathDiagnosticLocation::createBegin(CE, BR.getSourceManager(), AC);
    BR.EmitBasicReport(FD, getCheckerName(), "Statistics", "API", Out.str(),
                       CELoc);
  }
}

void SpecialReturnValueStatisticsCollector::handleComparison(
    BinaryOperator::Opcode Op, SymbolRef Sym, const SVal &Val,
    CheckerContext &C) const {
  auto State = C.getState();
  auto &CM = State->getConstraintManager();

  const auto *Usage = State->get<SpecialReturnValueMap>(Sym);
  if (!Usage)
    return;

  if (Usage->isCheckedForNegative() || Usage->isCheckedForNull())
    return;

  const auto T = Sym->getType();
  if (T->isIntegerType() || T->isPointerType()) {
    const llvm::APSInt *IntVal = nullptr;
    if (const auto &CI = Val.getAs<nonloc::ConcreteInt>()) {
      IntVal = &CI->getValue();
    } else if (const auto &CI = Val.getAs<loc::ConcreteInt>()) {
      IntVal = &CI->getValue();
    } else if (const auto &SV = Val.getAs<nonloc::SymbolVal>()) {
      IntVal = CM.getSymVal(State, SV->getSymbol());
    }

    if (IntVal) {
      if (T->isIntegerType() &&
          (((Op == BO_GE || Op == BO_LT) && *IntVal == 0) ||
           ((Op == BO_GT || Op == BO_LE) && *IntVal == -1))) {
        C.addTransition(
            State->set<SpecialReturnValueMap>(Sym, Usage->checkForNegative()));
        return;
      }

      if (T->isPointerType() && (Op == BO_EQ || Op == BO_NE) && *IntVal == 0) {
        C.addTransition(
            State->set<SpecialReturnValueMap>(Sym, Usage->checkForNull()));
        return;
      }
    }
  }

  if (const auto RSym = Val.getAsSymbol()) {
    if (const auto *RUsage = State->get<SpecialReturnValueMap>(RSym)) {
      if (RUsage->isCheckedForNegative()) {
        C.addTransition(
            State->set<SpecialReturnValueMap>(Sym, Usage->checkForNegative()));
        return;
      }
      if (RUsage->isCheckedForNull()) {
        C.addTransition(
            State->set<SpecialReturnValueMap>(Sym, Usage->checkForNull()));
        return;
      }
    }
  }
}

void ento::registerSpecialReturnValueStatisticsCollector(CheckerManager &Mgr) {
  Mgr.registerChecker<SpecialReturnValueStatisticsCollector>();
}

bool ento::shouldRegisterSpecialReturnValueStatisticsCollector(
    const CheckerManager &mgr) {
  return true;
}
