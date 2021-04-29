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
#include "llvm/Support/raw_ostream.h"

#include "Matchers/Generic.h"

using namespace clang;
using namespace ast_matchers;
using namespace ento::ericsson;

AST_CHECKER(PointerDeclChecker,
            "When declaring pointer data or a function that returns "
            "a pointer type, the preferred use of * is adjacent to "
            "the data name or function name and not adjacent to the "
            "type name.") {
  BUG_TYPE(
      name = "The preferred use of * is adjacent to the data name or function "
             "name and not adjacent to the type name.",
      category = "Linux Kernel")

  BUILD_MATCHER() {
    return decl(
               eachOf(functionDecl(returns(pointerType())), has(pointerType())),
               unless(typedefDecl()), unless(cxxConversionDecl()), unless(isImplicit()))
        .bind(KEY_NODE);
  }

  HANDLE_MATCH(boundNodes, analysisManager) {
    SourceLocation qualNameBeginLoc;
    if (const auto *declarator = boundNodes.getNodeAs<DeclaratorDecl>(KEY_NODE))
      if (NestedNameSpecifierLoc qualifierLoc = declarator->getQualifierLoc())
        qualNameBeginLoc = qualifierLoc.getLocalBeginLoc();

    if (qualNameBeginLoc.isInvalid()) {
      const auto *decl = boundNodes.getNodeAs<Decl>(KEY_NODE);
      qualNameBeginLoc = decl->getLocation();
    }

    if (qualNameBeginLoc.isMacroID())
      return;

    const char *c = FullSourceLoc(qualNameBeginLoc.getLocWithOffset(-1),
                                  analysisManager.getSourceManager())
                        .getCharacterData();

    if (c) {
      if (isWhitespace(c[0]))
        REPORT_BUG("Write * adjacent to the variable or function name "
                   "instead of the type name.");
    }
  }
}

bool ento::shouldRegisterPointerDeclChecker(const CheckerManager &mgr) {
  return true;
}
