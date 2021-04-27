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

#include "Templates/ASTCheckers.h"
#include "Matchers/Generic.h"

using namespace clang;
using namespace ast_matchers;
using namespace ento::ericsson;

// forEachDescendant casue a crash in some cases in clang 3.3
AST_CHECKER(PreferInitChecker, "Prefer initialization to assignment.") {
  BUG_TYPE(name = "Prefer initialization to assignment", category = "C++")

  MATCHER(cxxConstructorDecl(forEachDescendant(
      cxxOperatorCallExpr(
          unless( // ignore if-s, loops and exception handling statements
              hasAncestor(stmt(isControlflowConstruct(),
                               unless(conditionalOperator())))),
          hasOverloadedOperatorName("="),
          hasArgument(0, memberExpr(hasObjectExpression(cxxThisExpr()))))
          .bind(KEY_NODE))))

  HANDLE_MATCH(boundNodes, analysisManager) {
    REPORT_BUG(
        "Prefer using initialization list in constructors to using assignment "
        "operators.");
  }
}

bool ento::shouldRegisterPreferInitChecker(const CheckerManager &mgr) {
  const LangOptions &LO = mgr.getLangOpts();
  return LO.CPlusPlus;
}
