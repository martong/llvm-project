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

AST_CHECKER(PredWithStateChecker, "Predicates should not have states.") {
  BUG_TYPE(name = "Predicates with state", category = "C++")

  // TODO: check if the member in the memberexpr is realy the member of the
  // functor, and thhe memberExpr is also in the same functor (equalBoundNodes
  // or whatever)
  MATCHER(memberExpr(hasAncestor(cxxMethodDecl(unless(isConst()),
                                               hasName("operator()"),
                                               returns(asString("_Bool")))),
                     member(hasParent(cxxRecordDecl(has(cxxMethodDecl(
                         hasName("operator()"), returns(asString("_Bool"))))))),
                     unless(hasParent(cxxMemberCallExpr())),
                     unless(hasDeclaration(
                         fieldDecl(anyOf(hasType(unqualifiedType(type(anyOf(
                                             referenceType(), pointerType())))),
                                         hasType(isConstQualified()))))))
              .bind(KEY_NODE))

  HANDLE_MATCH(boundNodes, analysisManager) {
    const auto *m = boundNodes.getNodeAs<MemberExpr>(KEY_NODE);

    REPORT_BUG("The result of the predicate relies on the state: '" +
               m->getMemberDecl()->getQualifiedNameAsString() + "'");
  }
}

bool ento::shouldRegisterPredWithStateChecker(const CheckerManager &mgr) {
  const LangOptions &LO = mgr.getLangOpts();
  return LO.CPlusPlus;
}
