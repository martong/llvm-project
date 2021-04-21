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

/**
 * Implements MISRA-C rule 16.5.
 */
AST_CHECKER(FunctionsWithNoParamChecker,
            "MISRA-C 16.5: Functions with no parameters "
            "shall be declared and defined with void "
            "parameter list.") {

  BUG_TYPE(name = "MISRA-C 16.5", category = "MISRA-C")

  BUILD_MATCHER() { return functionDecl(parameterCountIs(0)).bind(KEY_NODE); }

  HANDLE_MATCH(boundNodes, analysisManager) {
    const auto *dcl = boundNodes.getNodeAs<FunctionDecl>(KEY_NODE);

    if (!dcl)
      return;
    QualType type = dcl->getType();
    if (type.isNull())
      return;
    if (isa<FunctionNoProtoType>(type.getTypePtr())) {
      REPORT_BUG_WITH(
          "Functions with no parameters shall be declared and defined "
          "with void parameter list.",
          location = dcl);
    }
  }
}

bool ento::shouldRegisterFunctionsWithNoParamChecker(
    const CheckerManager &mgr) {
  return true;
}
