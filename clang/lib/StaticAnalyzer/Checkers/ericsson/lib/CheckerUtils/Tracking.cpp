#include "llvm/ADT/Optional.h"

#include "clang/AST/Expr.h"
#include "clang/AST/ExprObjC.h"
#include "clang/AST/Stmt.h"

#include "clang/Analysis/ProgramPoint.h"

#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExplodedGraph.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporterVisitors.h"

#include "CheckerUtils/Tracking.h"

namespace clang {
namespace ento {
namespace ericsson {

// Based on lib/StaticAnalyzer/Core/BugReporterVisitors.cpp, from line 858

static const Expr *peelOffOuterExpr(const Expr *Ex, const ExplodedNode *N) {
  Ex = Ex->IgnoreParenCasts();
  if (const auto *EWC = dyn_cast<ExprWithCleanups>(Ex)) {
    return peelOffOuterExpr(EWC->getSubExpr(), N);
  }
  if (const auto *OVE = dyn_cast<OpaqueValueExpr>(Ex)) {
    return peelOffOuterExpr(OVE->getSourceExpr(), N);
  }

  // Peel off the ternary operator.
  if (const auto *CO = dyn_cast<ConditionalOperator>(Ex)) {
    // Find a node where the branching occured and find out which branch
    // we took (true/false) by looking at the ExplodedGraph.
    const ExplodedNode *NI = N;
    do {
      ProgramPoint ProgPoint = NI->getLocation();
      if (llvm::Optional<BlockEdge> BE = ProgPoint.getAs<BlockEdge>()) {
        const CFGBlock *srcBlk = BE->getSrc();
        if (const Stmt *term = srcBlk->getTerminatorStmt()) {
          if (term == CO) {
            bool TookTrueBranch = (*(srcBlk->succ_begin()) == BE->getDst());
            if (TookTrueBranch)
              return peelOffOuterExpr(CO->getTrueExpr(), N);
            return peelOffOuterExpr(CO->getFalseExpr(), N);
          }
        }
      }
      NI = NI->getFirstPred();
    } while (NI);
  }
  return Ex;
}

SVal getSourceLValue(const Stmt *S, const ExplodedNode *N) {
  // TODO: would it make sense to check if S is actually an implicit
  // lvalue-to-rvalue cast here?

  bool IsArg = false; // ???

  if (const auto *Ex = dyn_cast<Expr>(S)) {
    Ex = Ex->IgnoreParenCasts();
    const Expr *PeeledEx = peelOffOuterExpr(Ex, N); // inline this?
    if (Ex != PeeledEx)
      S = PeeledEx;
  }

  const Expr *Inner = nullptr;
  if (const auto *Ex = dyn_cast<Expr>(S)) {
    Ex = Ex->IgnoreParenCasts();
    if (ExplodedGraph::isInterestingLValueExpr(Ex) ||
        CallEvent::isCallStmt(Ex)) {
      Inner = Ex;
    }
  }

  if (IsArg && !Inner) {
    assert(N->getLocation().getAs<CallEnter>() &&
           "Tracking arg but not at call");
  } else {
    // Walk through nodes until we get one that matches the statement exactly.
    // Alternately, if we hit a known lvalue for the statement, we know we've
    // gone too far (though we can likely track the lvalue better anyway).
    do {
      const ProgramPoint &pp = N->getLocation();
      if (llvm::Optional<StmtPoint> ps = pp.getAs<StmtPoint>()) {
        if (ps->getStmt() == S || ps->getStmt() == Inner)
          break;
      } else if (llvm::Optional<CallExitEnd> CEE = pp.getAs<CallExitEnd>()) {
        if (CEE->getCalleeContext()->getCallSite() == S ||
            CEE->getCalleeContext()->getCallSite() == Inner) {
          break;
        }
      }
      N = N->getFirstPred();
    } while (N);

    if (!N)
      return UnknownVal();
  }

  ProgramStateRef state = N->getState();

  // The message send could be nil due to the receiver being nil.
  // At this point in the path, the receiver should be live since we are at the
  // message send expr. If it is nil, start tracking it.
  /*if (const Expr *Receiver = NilReceiverBRVisitor::getNilReceiver(S, N))
trackNullOrUndefValue(N, Receiver, report, false, EnableNullFPSuppression);*/ // FIXME:
  // what to do
  // with this?

  // See if the expression we're interested refers to a variable.
  // If so, we can track both its contents and constraints on its value.
  if (Inner && ExplodedGraph::isInterestingLValueExpr(Inner)) {
    // const MemRegion* R = 0;

    // Find the ExplodedNode where the lvalue (the value of 'Ex')
    // was computed.  We need this for getting the location value.
    const ExplodedNode *LVNode = N;
    while (LVNode) {
      if (llvm::Optional<PostStmt> P =
              LVNode->getLocation().getAs<PostStmt>()) {
        if (P->getStmt() == Inner)
          break;
      }
      LVNode = LVNode->getFirstPred();
    }
    assert(LVNode && "Unable to find the lvalue node.");
    ProgramStateRef LVState = LVNode->getState();
    SVal LVal = LVState->getSVal(Inner, LVNode->getLocationContext());
    return LVal;
  }

  return UnknownVal();
}

// --

const ExplodedNode *getLastStmtNode(const ExplodedNode *sourceNode,
                                    CheckerContext &) {
  const ExplodedNode *currentNode = sourceNode;
  do {
    assert(currentNode->pred_size() == 1 &&
           "Unable to decide which was the last "
           "Stmt, there are multiple preceeding "
           "nodes!");
    currentNode = currentNode->getFirstPred();
  } while (currentNode && !currentNode->getLocationAs<StmtPoint>());
  return currentNode;
}

} // namespace ericsson
} // namespace ento
} // namespace clang
