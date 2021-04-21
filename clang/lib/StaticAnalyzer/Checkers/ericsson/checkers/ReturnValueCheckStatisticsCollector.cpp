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

//==- ReturnValueCheckStatisticsCollector.cpp --------------------*- C++ -*-==//
//
// This checker collects statistics about calls whether their return value
// is used (assigned, compared or passed as argument).  Warnings emitted are
// not for human consumption. Instead, the output of the checker must be piped
// into `tools/gen_yaml_for_return_value_checks.py` in order to generate file
// `UncheckedReturn.yaml` for checker `api.UncheckedReturn`.
//
// The raw output of this checker is the following for every function call:
//
// Return Value Check:<filename>:<line>:<column>,<function USR>,<unchecked>
//
// The last element is 1 if the call was a call where the return value was not
// checked, 0 otherwise.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

#include "clang/AST/StmtVisitor.h"
#include "clang/Index/USRGeneration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"

using namespace clang;
using namespace ento;

namespace {

class ReturnValueCheckVisitor : public StmtVisitor<ReturnValueCheckVisitor> {

  BugReporter &BR;
  AnalysisDeclContext *AC;
  CheckerNameRef CN;
  llvm::DenseMap<const CallExpr *, bool> Calls;

  void handleStmt(Stmt *S);

public:
  ReturnValueCheckVisitor(BugReporter &br, AnalysisDeclContext *ac,
                          CheckerNameRef cn)
      : BR(br), AC(ac), CN(cn) {}

  ~ReturnValueCheckVisitor() {
    for (const auto Call : Calls) {
      const FunctionDecl *FD = Call.first->getDirectCallee();
      if (!FD)
        continue;

      SmallString<256> USR;
      clang::index::generateUSRForDecl(FD, USR);

      const auto &SM = AC->getASTContext().getSourceManager();
      SmallString<1024> buf;
      llvm::raw_svector_ostream os(buf);
      os << "Return Value Check:" << Call.first->getBeginLoc().printToString(SM)
         << "," << USR << "," << (unsigned)Call.second << "\n";

      const char *bugType = "Statistics";

      PathDiagnosticLocation CELoc = PathDiagnosticLocation::createBegin(
          Call.first, BR.getSourceManager(), AC);

      BR.EmitBasicReport(AC->getDecl(), CN, bugType, "API", os.str(), CELoc);
    }
  }

  void VisitStmt(Stmt *S);
  void VisitCallExpr(CallExpr *CE);
  void VisitCompoundStmt(CompoundStmt *S);
  void VisitDoStmt(DoStmt *S);
  void VisitForStmt(ForStmt *S);
  void VisitCXXForRangeStmt(CXXForRangeStmt *S);
  void VisitIfStmt(IfStmt *S);
  void VisitSwitchStmt(SwitchStmt *S);
  void VisitCaseStmt(CaseStmt *S);
  void VisitWhileStmt(WhileStmt *S);

private:
  ReturnValueCheckVisitor(const ReturnValueCheckVisitor &) = delete;
  ReturnValueCheckVisitor(ReturnValueCheckVisitor &&) = delete;
  ReturnValueCheckVisitor &operator=(const ReturnValueCheckVisitor &) = delete;
  ReturnValueCheckVisitor &operator=(ReturnValueCheckVisitor &&) = delete;
};

} // namespace

void ReturnValueCheckVisitor::VisitStmt(Stmt *S) {
  for (Stmt *Child : S->children()) {
    if (Child) {
      Visit(Child);
    }
  }
}

void ReturnValueCheckVisitor::VisitCallExpr(CallExpr *CE) {
  if (!isa<UnresolvedLookupExpr>(CE->getCallee()) && !isa<CXXOperatorCallExpr>(CE) &&
      !CE->getCallReturnType(AC->getASTContext())->isVoidType()) {
    Calls[CE];
  }
  for (Stmt *Child : CE->children()) {
    if (Child) {
      Visit(Child);
    }
  }
}

void ReturnValueCheckVisitor::VisitCompoundStmt(CompoundStmt *S) {
  for (Stmt *Child : S->children()) {
    handleStmt(Child);
  }
}

void ReturnValueCheckVisitor::VisitDoStmt(DoStmt *S) {
  if (S->getCond())
    Visit(S->getCond());
  handleStmt(S->getBody());
}

void ReturnValueCheckVisitor::VisitForStmt(ForStmt *S) {
  if (S->getInit())
    Visit(S->getInit());
  if (S->getCond())
    Visit(S->getCond());
  if (S->getInc())
    Visit(S->getInc());
  handleStmt(S->getBody());
}

void ReturnValueCheckVisitor::VisitCXXForRangeStmt(CXXForRangeStmt *S) {
  handleStmt(S->getBody());
}

void ReturnValueCheckVisitor::VisitIfStmt(IfStmt *S) {
  if (S->getCond())
    Visit(S->getCond());
  handleStmt(S->getThen());
  handleStmt(S->getElse());
}

void ReturnValueCheckVisitor::VisitSwitchStmt(SwitchStmt *S) {
  if (S->getInit())
    Visit(S->getInit());
  if (S->getCond())
    Visit(S->getCond());
  handleStmt(S->getBody());
}

void ReturnValueCheckVisitor::VisitCaseStmt(CaseStmt *S) {
  for (Stmt *Child : S->children()) {
    handleStmt(Child);
  }
}

void ReturnValueCheckVisitor::VisitWhileStmt(WhileStmt *S) {
  if (S->getCond())
    Visit(S->getCond());
  handleStmt(S->getBody());
}

void ReturnValueCheckVisitor::handleStmt(Stmt *S) {
  if (!S)
    return;

  if (auto *EwCu = dyn_cast<ExprWithCleanups>(S)) {
    S = EwCu->getSubExpr();
  }
  if (auto *CE = dyn_cast<CallExpr>(S)) {
    if (!isa<UnresolvedLookupExpr>(CE->getCallee()) && !isa<CXXOperatorCallExpr>(CE) &&
        !CE->getCallReturnType(AC->getASTContext())->isVoidType()) {
      Calls[CE] = true;
    }
  }
  Visit(S);
}

namespace {
class ReturnValueCheckStatisticsCollector : public Checker<check::ASTCodeBody> {
public:
  ReturnValueCheckStatisticsCollector() {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ReturnValueCheckVisitor visitor(BR, Mgr.getAnalysisDeclContext(D),
                                    getCheckerName());
    visitor.Visit(D->getBody());
  }
};
} // namespace

void ento::registerReturnValueCheckStatisticsCollector(CheckerManager &Mgr) {
  Mgr.registerChecker<ReturnValueCheckStatisticsCollector>();
}

bool ento::shouldRegisterReturnValueCheckStatisticsCollector(
    const CheckerManager &mgr) {
  return true;
}
