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

using namespace clang;
using namespace ento::ericsson;

AST_CHECKER(TspBuiltinTypesChecker,
            "Detects usage of portability-unsafe data types") {
  BUG_TYPE(name = "Use of portability-unsafe data type", category = "TSP")

  BUILD_MATCHER() {
    using namespace clang::ast_matchers;

    return varDecl(hasType(builtinType(anything()).bind("varType")))
        .bind(KEY_NODE);
  }

  HANDLE_MATCH(boundNodes, analysisManager) {
    BuiltinType::Kind vTypeKind =
        boundNodes.getNodeAs<BuiltinType>("varType")->getKind();
    if (vTypeKind == BuiltinType::Short || vTypeKind == BuiltinType::Long ||
        vTypeKind == BuiltinType::Float) {
      REPORT_BUG("Variable declared with 'short', 'float' or 'long' type.");
    }
  }
}

bool ento::shouldRegisterTspBuiltinTypesChecker(const CheckerManager &mgr) {
  return true;
}
