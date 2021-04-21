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

AST_CHECKER(SerializeWithoutObserverChecker,
            "Finds classes that support serialisation "
            "but not inherit from "
            "ISerializerObserver.") {
  BUG_TYPE(name = "Serialization without observer", category = "MTAS")

  BUILD_MATCHER() {
    return cxxRecordDecl(
               has(cxxMethodDecl(hasName("serialize"))),
               unless(isDerivedFrom("NodeControlSupport::ISerializerObserver")),
               unless(hasName("NodeControlSupport::ISerializeObserver")))
        .bind(KEY_NODE);
  }

  HANDLE_MATCH(boundNodes, analysisManager) {
    REPORT_BUG("Serialization without inheriting from ISerializerObserver.");
  }
}

bool ento::shouldRegisterSerializeWithoutObserverChecker(
    const CheckerManager &mgr) {
  return true;
}
