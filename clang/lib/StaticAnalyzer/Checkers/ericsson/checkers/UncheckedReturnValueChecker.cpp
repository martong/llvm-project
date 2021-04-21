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

//==- UncheckedReturnValueChecker.cpp ----------------------------*- C++ -*-==//
//
// This checker finds calls to functions where the return value of the called
// function should be checked but it is not used in any way: not stored,
// not compared to some value, not passed as argument of another function etc.
//
// The USRs (Unified Symbol Resolution) of functions whose return value is to
// be checked must be listed in a YAML file called `UncheckedReturn.yaml`. The
// location of this file must be passed to the checker as analyzer option
// `api-metadata-path`.
//
// Example YAML file:
//
//--- UncheckedReturn.yaml ---------------------------------------------------//
//
// #
// # UncheckedReturn metadata format 1.0
//
// - c:@F@function1#
// - c:@F@function2#
// - c:@N@namespace1@F@function3#
//
//----------------------------------------------------------------------------//
//
// To auto-generate this YAML file on statistical base see checker
// `statisticsCollector.ReturnValueCheck`.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

#include "clang/AST/StmtVisitor.h"
#include "clang/Index/USRGeneration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"

#include "llvm/ADT/StringSet.h"
#include "llvm/Support/YAMLTraits.h"

#include "CheckerUtils/LoadMetadata.h"

using namespace clang;
using namespace ento;
using namespace ericsson;

namespace {
class UncheckedReturnValueVisitor
    : public StmtVisitor<UncheckedReturnValueVisitor> {

  BugReporter &BR;
  AnalysisDeclContext *AC;
  CheckerNameRef CN;
  void checkUncheckedReturnValue(CallExpr *CE);
  void handleStmt(Stmt *S);

public:
  UncheckedReturnValueVisitor(BugReporter &br, AnalysisDeclContext *ac,
                              CheckerNameRef cn)
      : BR(br), AC(ac), CN(cn) {}

  void VisitCompoundStmt(CompoundStmt *S);
  void VisitDoStmt(DoStmt *S);
  void VisitForStmt(ForStmt *S);
  void VisitCXXForRangeStmt(CXXForRangeStmt *S);
  void VisitIfStmt(IfStmt *S);
  void VisitSwitchStmt(SwitchStmt *S);
  void VisitWhileStmt(WhileStmt *S);
};

} // namespace

void UncheckedReturnValueVisitor::VisitCompoundStmt(CompoundStmt *S) {
  if (!S)
    return;

  for (Stmt *Child : S->children()) {
    handleStmt(Child);
  }
}

void UncheckedReturnValueVisitor::VisitDoStmt(DoStmt *S) {
  if (S->getCond())
    Visit(S->getCond());
  handleStmt(S->getBody());
}

void UncheckedReturnValueVisitor::VisitForStmt(ForStmt *S) {
  if (S->getInit())
    Visit(S->getInit());
  if (S->getCond())
    Visit(S->getCond());
  if (S->getInc())
    Visit(S->getInc());
  handleStmt(S->getBody());
}

void UncheckedReturnValueVisitor::VisitCXXForRangeStmt(CXXForRangeStmt *S) {
  handleStmt(S->getBody());
}

void UncheckedReturnValueVisitor::VisitIfStmt(IfStmt *S) {
  if (S->getCond())
    Visit(S->getCond());
  handleStmt(S->getThen());
  handleStmt(S->getElse());
}

void UncheckedReturnValueVisitor::VisitSwitchStmt(SwitchStmt *S) {
  if (S->getInit())
    Visit(S->getInit());
  if (S->getCond())
    Visit(S->getCond());
  handleStmt(S->getBody());
}

void UncheckedReturnValueVisitor::VisitWhileStmt(WhileStmt *S) {
  if (S->getCond())
    Visit(S->getCond());
  handleStmt(S->getBody());
}

static llvm::StringSet<> FuncsReturningError;

void UncheckedReturnValueVisitor::handleStmt(Stmt *S) {
  if (!S)
    return;

  if (auto *EwCu = dyn_cast<ExprWithCleanups>(S)) {
    S = EwCu->getSubExpr();
  }
  if (auto *CE = dyn_cast<CallExpr>(S)) {
    if (!isa<CXXOperatorCallExpr>(CE)) {
      checkUncheckedReturnValue(CE);
    }
  }
  Visit(S);
}

void UncheckedReturnValueVisitor::checkUncheckedReturnValue(CallExpr *CE) {
  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD)
    return;

  SmallString<256> USR;
  clang::index::generateUSRForDecl(FD, USR);

  if (!FuncsReturningError.count(USR))
    return;

  // Issue a warning.
  SmallString<512> buf;
  llvm::raw_svector_ostream os(buf);
  os << "Return value is not checked in call to '" << *FD
     << "\' (but it should be, based on call statistics)";

  PathDiagnosticLocation CELoc =
      PathDiagnosticLocation::createBegin(CE, BR.getSourceManager(), AC);

  BR.EmitBasicReport(AC->getDecl(), CN, "Unchecked return value", "API",
                     os.str(), CELoc);
}

namespace {
class UncheckedReturnValueChecker : public Checker<check::ASTCodeBody> {
public:
  UncheckedReturnValueChecker() {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &mgr,
                        BugReporter &BR) const {
    UncheckedReturnValueVisitor visitor(BR, mgr.getAnalysisDeclContext(D),
                                        getCheckerName());
    visitor.Visit(D->getBody());
  }
};
} // namespace

void ento::registerUncheckedReturnValueChecker(CheckerManager &Mgr) {
  const auto *checker = Mgr.registerChecker<UncheckedReturnValueChecker>();

  llvm::Optional<std::vector<std::string>> ReturningErrorVec;
  const StringRef metadataPath =
      Mgr.getAnalyzerOptions().getCheckerStringOption(checker,
                                                      "APIMetadataPath", true);

  metadata::loadYAMLData(metadataPath, "UncheckedReturn.yaml", "1.0",
                         Mgr.getCurrentCheckerName(), ReturningErrorVec);
  for (const auto &FREV : *ReturningErrorVec) {
    FuncsReturningError.insert(FREV);
  }
}

bool ento::shouldRegisterUncheckedReturnValueChecker(
    const CheckerManager &mgr) {
  return true;
}
