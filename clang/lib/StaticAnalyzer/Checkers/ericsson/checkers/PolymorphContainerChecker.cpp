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

#include "Matchers/STL.h"
#include "Templates/ASTCheckers.h"

using namespace clang;
using namespace ast_matchers;
using namespace ento::ericsson;

// NOTE: Gives duplicate warnings with virtual dtor poly on containers.
// TODO: false positive if there is no free operation through the base pointer
// Almost unusable without flow analysis

AST_CHECKER(PolymorphContainerChecker,
            "Finds plymorphic use of STL containers") {
  BUG_TYPE(name = "Polymorphic containers", category = "STL")

  BUILD_MATCHER() {
    return castExpr(anyOf(implicitCastExpr(hasImplicitDestinationType(pointsTo(
                                               namedDecl(stlContainer()))))
                              .bind(KEY_NODE),
                          explicitCastExpr(hasDestinationType(pointsTo(
                                               namedDecl(stlContainer()))))
                              .bind(KEY_NODE)));
  }

  HANDLE_MATCH(boundNodes, analysisManager) {
    const auto *cast = boundNodes.getNodeAs<CastExpr>(KEY_NODE);
    assert(cast);

    if (cast->getCastKind() == CK_DerivedToBase) {
      REPORT_BUG("Polymorphic use of an STL container is an error.");
    }
  }
}

bool ento::shouldRegisterPolymorphContainerChecker(const CheckerManager &mgr) {
  const LangOptions &LO = mgr.getLangOpts();
  return LO.CPlusPlus;
}
