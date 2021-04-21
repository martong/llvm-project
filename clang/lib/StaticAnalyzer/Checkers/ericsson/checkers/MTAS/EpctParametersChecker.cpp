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

#include "Matchers/Generic.h"
#include "Templates/ASTCheckers.h"

using namespace clang;
using namespace ast_matchers;
using namespace ento::ericsson;

AST_CHECKER(EpctParametersChecker, "Finds deprecated epct parameter uses.") {
  BUG_TYPE(name = "Deprecated epct parameter usage", category = "MTAS")

  BUILD_MATCHER() {
    return callExpr(callee(functionDecl(matchesName("DicosEnvironment::.*"))))
        .bind(KEY_NODE);
  }

  HANDLE_MATCH(boundNodes, analysisManager) {
    REPORT_BUG("Using epct parameters for configuration should be deprecated.");
  }
}

bool ento::shouldRegisterEpctParametersChecker(const CheckerManager &mgr) {
  return true;
}
