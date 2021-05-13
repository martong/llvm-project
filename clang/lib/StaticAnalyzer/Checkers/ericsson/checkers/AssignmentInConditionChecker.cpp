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

#include "CheckerUtils/Common.h"
#include "Matchers/Generic.h"
#include "Templates/ASTCheckers.h"

using namespace clang;
using namespace ast_matchers;
using namespace ento::ericsson;

/**
 * Implements MISRA-C rule 13.1
 */
AST_CHECKER(AssignmentInConditionChecker,
            "MISRA-C 13.1: Assignment operator is used in a condition") {

  BUG_TYPE(name = "MISRA-C 13.1", category = "MISRA-C")

  BUILD_MATCHER() {
    auto hasAssign =
        hasCondition(expr(hasDescendant(binaryOperator(hasOperatorName("=")).bind("AssignOp")))
                         .bind(KEY_NODE));

    return stmt(anyOf(ifStmt(hasAssign), doStmt(hasAssign), forStmt(hasAssign),
                      whileStmt(hasAssign), conditionalOperator(hasAssign)));
  }

  HANDLE_MATCH(boundNodes, analysisManager) {
    const SourceManager &SM = analysisManager.getSourceManager();
    const auto *AssignOp = boundNodes.getNodeAs<Expr>("AssignOp");
    // Check if the assignment is inside a macro in a system header.
    // Some system API calls are implemented this way and otherwise cause unnecessary warnings.
    // Note: This code should work if getBeginLoc returns invalid (if possible).
    SourceLocation SpellingLoc = SM.getSpellingLoc(AssignOp->getBeginLoc());
    if (isInSysHeader(SpellingLoc, SM) && SM.isMacroBodyExpansion(AssignOp->getBeginLoc()))
      return;

    // FIXME: Use location of AssignOp for the bug report.
    REPORT_BUG("Assignment operator is used in a condition");
  }
}

bool ento::shouldRegisterAssignmentInConditionChecker(
    const CheckerManager &mgr) {
  return true;
}
