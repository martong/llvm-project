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

AST_CHECKER(AllocWithStateChecker, "Finds stateful allocators.") {
  BUG_TYPE(name = "Allocator with state", category = "STL")

  BUILD_MATCHER() {
    auto containerWithAlloc =
        recordDecl(anyOf(stlContainer(), hasName("std::basic_string")));

    return varDecl(hasType(namedDecl(
                       replicateTemplateSpecWithArgument(
                           allOf(classTemplateSpecializationDecl(),
                                 containerWithAlloc.bind("container")),
                           true),
                       unless(matchesName("iterator")))))
        .bind(KEY_NODE);
  }

  HANDLE_MATCH(nodes, mgr) {
    const auto *D =
        nodes.getNodeAs<ClassTemplateSpecializationDecl>("container");
    assert(D);

    const auto &list = D->getTemplateArgs();
    const auto &arg =
        list.get(list.size() -
                 1); // assuming the last template parameter is the allocator

    if (arg.getKind() != TemplateArgument::Type)
      return;

    const auto &type = arg.getAsType();

    const CXXRecordDecl *allocatorDecl = type->getAsCXXRecordDecl();
    if (!allocatorDecl)
      return;

    if (!allocatorDecl->field_empty()) {
      REPORT_BUG("This variable uses the type '" +
                 allocatorDecl->getQualifiedNameAsString() +
                 "' as allocator, which contains state (e.g. field '" +
                 allocatorDecl->field_begin()->getNameAsString() +
                 "'). Allocator classes should be stateless.");
    }
  }
}

bool ento::shouldRegisterAllocWithStateChecker(const CheckerManager &mgr) {
  const LangOptions &LO = mgr.getLangOpts();
  return LO.CPlusPlus;
}
