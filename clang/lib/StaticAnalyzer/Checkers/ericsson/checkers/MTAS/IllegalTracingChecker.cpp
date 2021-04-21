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

#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"

#include "CheckerUtils/Common.h"
#include "CheckerUtils/VisitorBase.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

using namespace clang;
using namespace ento;
using namespace ericsson;

namespace {

// TODO: also warn if a funtion pointer to printf is stored!

StringRef cfg_bugName = "Illegal tracing";
StringRef cfg_bugCategory = "MTAS";

class IllegalTracingVisitor : public RecursiveASTVisitor<IllegalTracingVisitor>,
                              public VisitorBasedCheckerBase {
public:
  IllegalTracingVisitor(AnalysisManager &mgr, BugReporter &br,
                        BugType *const bugType)
      : VisitorBasedCheckerBase(mgr, br, bugType) {}

  // TODO: test if this actually improves efficiency when implemented this way
  bool TraverseDecl(Decl *d) {
    if (!d || (d->getBeginLoc().isValid() && !checkLocation(d))) {
      return true; // bail out early if we have an irrelevant file
    }

    return RecursiveASTVisitor<IllegalTracingVisitor>::TraverseDecl(d);
  }

  bool VisitCallExpr(CallExpr *call) {
    if (!checkLocation(call))
      return true;

    const FunctionDecl *func = call->getDirectCallee();

    if (!func)
      return true;

    std::string name = func->getNameAsString();

    if (name == "printf") {
      reportBug(call,
                "It is prohibited to use cstdio for tracing in MTAS code.");
    }

    return true;
  }

  bool VisitDeclRefExpr(DeclRefExpr *declRefExpr) {
    if (!checkLocation(declRefExpr))
      return true;

    const ValueDecl *decl = declRefExpr->getDecl();
    if (!decl)
      return true;

    std::string name = decl->getQualifiedNameAsString();

    if (name == "std::cout" || name == "std::cerr") {
      reportBug(declRefExpr,
                "It is prohibited to use iostreams for tracing in MTAS code.");
    }

    return true;
  }
};

struct IllegalTracingChecker : public Checker<check::EndOfTranslationUnit> {
  void checkEndOfTranslationUnit(const TranslationUnitDecl *tuDecl,
                                 AnalysisManager &mgr, BugReporter &br) const {
    if (!m_bugType)
      m_bugType = std::make_unique<clang::ento::BugType>(this, cfg_bugName,
                                                         cfg_bugCategory);
    IllegalTracingVisitor c(mgr, br, m_bugType.get());
    c.TraverseDecl(const_cast<TranslationUnitDecl *>(tuDecl));
  }

private:
  mutable std::unique_ptr<BugType> m_bugType;
};

} // namespace
void ento::registerIllegalTracingChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<IllegalTracingChecker>();
}

bool ento::shouldRegisterIllegalTracingChecker(const CheckerManager &mgr) {
  return true;
}
