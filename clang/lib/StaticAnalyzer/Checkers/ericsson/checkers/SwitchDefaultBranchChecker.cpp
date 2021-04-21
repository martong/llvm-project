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
#include "llvm/Support/raw_ostream.h"

#include "Matchers/Generic.h"

using namespace clang;
using namespace ast_matchers;
using namespace ento::ericsson;

AST_CHECKER(SwitchDefaultBranchChecker,
            "MISRA-C 15.3 Always add a default branch to switch statement.") {
  BUG_TYPE(name = "Always add a default branch to switch statement",
           category = "MISRA-C")

  BUILD_MATCHER() {
    return switchStmt(has(compoundStmt().bind("swcompound"))).bind(KEY_NODE);
  }

  HANDLE_MATCH(boundNodes, analysisManager) {
    const auto *cmpStmt = boundNodes.getNodeAs<Stmt>("swcompound");
    bool hasDefaultBranch = false;
    bool isDefaultBranchLast = false;
    for (const Stmt *Child : cmpStmt->children()) {
      if (Child && isa<DefaultStmt>(Child)) {
        hasDefaultBranch = true;
        isDefaultBranchLast = true;
      }
      if (Child && isa<CaseStmt>(Child)) {
        isDefaultBranchLast = false;
      }
    }
    if (!hasDefaultBranch) {
      REPORT_BUG(
          "The switch statement should always contain a default clause.");
    } else if (!isDefaultBranchLast) {
      REPORT_BUG("In the switch statement the default branch should be the "
                 "final one.");
    }
  }
}

bool ento::shouldRegisterSwitchDefaultBranchChecker(const CheckerManager &mgr) {
  return true;
}
