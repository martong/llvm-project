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

#include <iostream>
#include <string>

#include "clang/AST/Stmt.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/SourceManager.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerHelpers.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CoreEngine.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"

#include "llvm/ADT/DenseMap.h"

#include "CheckerUtils/Buffer.h"
#include "CheckerUtils/Common.h"
#include "CheckerUtils/DumpHelper.h"
#include "CheckerUtils/Tracking.h"

// the idea comes from the Coverity FORWARD_NULL and REVERSE_INULL checkers
// based on IdempotentOperationChecker.cpp and the replaced
// forward_reverse_null.cpp

// TODO:
// - maybe do some real disagnostics with BugReporterVisitor-s?
// - write tests!

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

using namespace clang;
using namespace ento;
using namespace ericsson;

namespace {
StringRef cfg_bugCategory = "C++";
StringRef cfg_bugName = "Invariable pointer branch";

using MemRegionRef = const clang::ento::MemRegion *;

struct PtrConditionInfo {
  enum ValueInfo { Unknown, Null, NonNull };

  static ValueInfo getValueInfo(const ConditionTruthVal &truthVal) {
    if (truthVal.isUnderconstrained())
      return Unknown;
    if (truthVal.isConstrainedTrue())
      return Null;
    return NonNull;
  }

  ExplodedNode *node = nullptr;
  SVal ptr; // FIXME: do we need this? is this always the same per path?
  ValueInfo ptrValue = Unknown;
  bool conditionChecksNull =
      false; // whether the condition is satisfied if the ptr is NULL

  PtrConditionInfo() = default;
};

class InvariablePtrBranchChecker
    : public Checker<check::BranchCondition, check::EndAnalysis> {
public:
  void checkBranchCondition(const Stmt *condStmt,
                            CheckerContext &context) const;
  void checkEndAnalysis(ExplodedGraph &graph, BugReporter &br,
                        ExprEngine &engine) const;

private:
  // normally, we would store this in the ProgramState, but that is not
  // possible not, because we're doing an all-paths analysis
  mutable llvm::DenseMap<const Expr *, PtrConditionInfo> m_conditionInfos;

  mutable std::unique_ptr<BugType> m_bugType;
};

void InvariablePtrBranchChecker::checkBranchCondition(
    const Stmt *condStmt, CheckerContext &context) const {
  ProgramStateRef state = context.getState();

  using namespace clang::ast_matchers;

  auto matcher = expr(anyOf(
      implicitCastExpr(
          // hasType(builtinType(hasName("_Bool"))), // TODO: figure out how
          // to check against bool
          hasSourceExpression(
              ignoringParenImpCasts(expr(hasType(pointerType())).bind("ptr"))))
          .bind("impCast"),
      unaryOperator( // TODO: this is incapable of detecting something like
                     // !!ptr
          hasOperatorName("!"), hasUnaryOperand(ignoringParenImpCasts(
                                    expr(hasType(pointerType())).bind("ptr"))))
          .bind("unaryOp"),
      binaryOperator(anyOf(hasOperatorName("=="), hasOperatorName("!=")),
                     hasEitherOperand(ignoringParenImpCasts(
                         expr(hasType(pointerType())).bind("ptr"))),
                     hasEitherOperand(ignoringParenImpCasts(anyOf(
                         integerLiteral(equals(0)), cxxNullPtrLiteralExpr()))))
          .bind("binOp")));

  auto nodes = match(matcher, *condStmt, context.getASTContext());
  if (!nodes.empty()) {
    const auto *condExpr = llvm::dyn_cast<Expr>(condStmt);
    SVal ptrRaw = context.getSVal(nodes[0].getNodeAs<Expr>("ptr"));
    MemRegionRef ptrRegion = ptrRaw.getAsRegion();
    if (!ptrRegion)
      return;
    SVal ptr = state->getSVal(ptrRegion);

    /*std::cout << "Branch condition: " << Buffer::getSourceCode(condExpr,
       context) << " on ptr val " << dump(ptr)
        << " (raw: " << dump(ptrRaw) << "; region: " << dump(ptrRegion) <<
       ")" << std::endl;*/

    PtrConditionInfo &condInfo = m_conditionInfos[condExpr];
    if (!condInfo.node) {
      // this condition is not yet tracked
      // std::cout << " - beginning to track with null info: " <<
      // dump(state->isNull(ptr)) << std::endl;

      condInfo.node = context.addTransition();
      condInfo.ptr = ptr;
      condInfo.ptrValue = PtrConditionInfo::getValueInfo(state->isNull(ptr));

      condInfo.conditionChecksNull = true;
      if (nodes[0].getNodeAs<UnaryOperator>("unaryOp")) {
        condInfo.conditionChecksNull = false;
      }
      if (const auto *binOp = nodes[0].getNodeAs<BinaryOperator>("binOp")) {
        if (binOp->getOpcodeStr() == "!=") {
          condInfo.conditionChecksNull = false;
        }
      }
    } else {
      if (condInfo.ptrValue == PtrConditionInfo::Unknown) {
        // already unknown value
        // std::cout << " - is already unknown value, ignoring" <<
        // std::endl;
      } else {
        PtrConditionInfo::ValueInfo valInfo =
            PtrConditionInfo::getValueInfo(state->isNull(ptr));
        if (condInfo.ptrValue != valInfo) {
          // std::cout << " - value mismatch, old: " <<
          // dumpValueInfo(condInfo.ptrValue) << "; new: " <<
          // dumpValueInfo(valInfo) << std::endl;
          condInfo.ptrValue = PtrConditionInfo::Unknown;
        }
      }
    }

    // std::cout << std::endl;
  }
}
void InvariablePtrBranchChecker::checkEndAnalysis(ExplodedGraph &graph,
                                                  BugReporter &br,
                                                  ExprEngine &engine) const {
  for (const std::pair<const Expr *, PtrConditionInfo> &p : m_conditionInfos) {
    const PtrConditionInfo &ptrCondInfo = p.second;
    PtrConditionInfo::ValueInfo ptrValInfo = ptrCondInfo.ptrValue;

    if (ptrValInfo != PtrConditionInfo::Unknown) {
      // TODO: more detailed message, also use the conditionChecksNull and
      // ptrValue information
      PtrConditionInfo::ValueInfo branchValInfo =
          (ptrCondInfo.conditionChecksNull ? PtrConditionInfo::Null
                                           : PtrConditionInfo::NonNull);
      std::string msg;
      if (ptrValInfo == branchValInfo) {
        msg = "The condition is satisfied on all code paths, and the "
              "branch will always be taken.";
      } else {
        msg = "The condition cannot be satisfied on any code paths, "
              "and the branch will never be taken.";
      }

      if (!m_bugType) {
        m_bugType = std::make_unique<clang::ento::BugType>(this, cfg_bugName,
                                                           cfg_bugCategory);
      }

      std::unique_ptr<BasicBugReport> report(new BasicBugReport(
          *m_bugType, std::string("This check is pointless: ") + msg,
          PathDiagnosticLocation(p.first, br.getSourceManager(),
                                 p.second.node->getLocationContext())));
      // FIXME: Was `report->markInteresting(p.second.ptr);` but no
      // `markInteresting()` in `BasicBugReport`. `PathSensitiveBugReport`
      // needs `ExplodedNode` constructor parameter.
      br.emitReport(std::move(report));
    }
  }

  m_conditionInfos.clear();
}

} // end namespace

void ento::registerInvariablePtrBranchChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<InvariablePtrBranchChecker>();
}

bool ento::shouldRegisterInvariablePtrBranchChecker(const CheckerManager &mgr) {
  return true;
}
