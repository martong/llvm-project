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

AST_CHECKER(MisuseEnumAsConditionChecker,
            "Check invalid use of enum like boolean.") {
  BUG_TYPE(name = "Enum as boolean.", category = "C++")

  BUILD_MATCHER() {
    return stmt(anyOf(
        implicitCastExpr(
            hasImplicitDestinationType(unqualifiedType(isBoolType())),
            unless(hasSourceExpression(
                binaryOperator(anyOf(hasOperatorName("&"), hasOperatorName("|"),
                                     hasOperatorName("^"))))))
            .bind(KEY_NODE),
        explicitCastExpr(hasDestinationType(unqualifiedType(isBoolType())),
                         unless(hasSourceExpression(binaryOperator(
                             anyOf(hasOperatorName("&"), hasOperatorName("|"),
                                   hasOperatorName("^"))))))
            .bind(KEY_NODE)));
  }

  HANDLE_MATCH(boundNodes, analysisManager) {
    const auto *cast = boundNodes.getNodeAs<CastExpr>(KEY_NODE);
    assert(cast);

    if (cast->getSubExpr()->getType()->isEnumeralType()) {
      const EnumDecl *enumDecl =
          cast->getSubExpr()->getType()->getAs<EnumType>()->getDecl();

      bool isTrue = false, isFalse = false;
      int count = 0;
      for (auto enum_ : enumDecl->enumerators()) {
        if (enum_->getInitVal() == 0) {
          isFalse = true;
        } else {
          isTrue = true;
        }

        ++count;
      }

      // valid use if it has 2 constant and exactly one of them equal null
      if (2 != count || !isTrue || !isFalse)
        REPORT_BUG("Enum use like a boolean.");
    }
  }
}

bool ento::shouldRegisterMisuseEnumAsConditionChecker(
    const CheckerManager &mgr) {
  return true;
}
