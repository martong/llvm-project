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

AST_CHECKER(SerializeVersionChecker, "MTAS StartRestart rule 20.") {
  BUG_TYPE(name = "User-defined object serialize.", category = "C++")

  BUILD_MATCHER() {
    /// Class with getClass method which const, override, return type unsigned
    /// int.
    auto getClassPattern = hasMethod(
        allOf(hasName("getClassVersion"), isConst(), isOverride(),
              returns(asString("unsigned int")), decl().bind("method")));

    /// Class which is derived from ISerializerObserver, override its serailize
    /// method and has or has not getClassVersion
    return cxxRecordDecl(
               isDefinition(), isDerivedFrom(hasName("ISerializerObserver")),
               hasMethod(allOf(hasName("serialize"), isConst(), isOverride(),
                               hasAnyParameter(hasType(pointerType(pointee(
                                   qualType(asString("class ISerialize"))
                                       .bind("type"))))))),
               anyOf(getClassPattern, unless(getClassPattern)))
        .bind(KEY_NODE);
  }

  HANDLE_MATCH(boundNodes, analysisManager) {
    const auto *mDecl = boundNodes.getNodeAs<CXXMethodDecl>("method");

    if (mDecl) {                // if no getClassVersion declared in class
      if (mDecl->isDefined()) { // its declared but definition not avaible
        auto matcher = compoundStmt(hasDescendant(returnStmt(hasDescendant(
            castExpr(castKind(CK_IntegralCast),
                     hasSourceExpression(anyOf(
                         cxxBoolLiteral(), characterLiteral(), floatLiteral(),
                         integerLiteral(), expr().bind("expr"))))))));
        auto nodes = match(matcher, *mDecl->getBody(), mDecl->getASTContext());

        if (!nodes.empty()) {
          const auto *mExpr2 = nodes[0].getNodeAs<Expr>("expr");

          // return is literal or null
          if (!mExpr2 ||
              mExpr2->isNullPointerConstant(
                  mDecl->getASTContext(), Expr::NPC_ValueDependentIsNotNull) !=
                  Expr::NPCK_NotNull) {
            REPORT_BUG("Missing or not valid getClassVersion method.");
          }
        }
      }
    } else
      REPORT_BUG("Missing or not valid getClassVersion method.");
  }
}

bool ento::shouldRegisterSerializeVersionChecker(const CheckerManager &mgr) {
  return true;
}
