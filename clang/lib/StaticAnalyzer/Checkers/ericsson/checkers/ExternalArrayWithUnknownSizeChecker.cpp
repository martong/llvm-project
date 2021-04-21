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
 * Implements MISRA-C rule 8.12
 */
AST_CHECKER(
    ExternalArrayWithUnknownSizeChecker,
    "MISRA-C 8.12: Declaration of an external array with unknown size") {

  BUG_TYPE(name = "MISRA-C 8.12", category = "MISRA-C")

  BUILD_MATCHER() {
    return varDecl(unless(isDefinition()), has(incompleteArrayType()))
        .bind(KEY_NODE);
  }

  HANDLE_MATCH(boundNodes, analysisManager) {
    REPORT_BUG("External array with unknown size");
  }
}

bool ento::shouldRegisterExternalArrayWithUnknownSizeChecker(
    const CheckerManager &mgr) {
  return true;
}
