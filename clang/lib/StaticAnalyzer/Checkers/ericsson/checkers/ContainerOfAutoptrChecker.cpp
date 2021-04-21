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

#include "Matchers/Generic.h"
#include "Matchers/STL.h"

using namespace clang;
using namespace ast_matchers;
using namespace ento::ericsson;

// TODO: somehow try to get the SourceRange of the container of auto_ptr, and
// use REPORT_BUG_WITH addRange
// TODO: data-flow analysis? check if an invalidating algorithm is ever used on
// the container?

AST_CHECKER(
    ContainerOfAutoptrChecker,
    "Finds instances where a container with std::auto_ptr items is used") {

  BUG_TYPE(name = "Container of auto_ptr", category = "STL")

  BUILD_MATCHER() {
    auto decl = namedDecl(
        replicateTemplateSpecWithArgument(
            classTemplateSpecializationDecl(
                stlContainer(), stlContainerItem(refersToType(hasDeclaration(
                                    recordDecl(hasName("std::auto_ptr")))))),
            true),
        unless(matchesName("iterator")));

    // TODO: also detect in template arguments, as base class, etc.
    return varDecl(hasType(decl)).bind(KEY_NODE);
  }

  HANDLE_MATCH(boundNodes, analysisManager) {
    REPORT_BUG("Using containers of std::auto_ptrs is not recommended, "
               "because standard algorithms involving assignments (e.g. "
               "std::sort) will invalidate them.");
  }
}

bool ento::shouldRegisterContainerOfAutoptrChecker(const CheckerManager &mgr) {
  const LangOptions &LO = mgr.getLangOpts();
  return LO.CPlusPlus;
}
