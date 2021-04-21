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

AST_CHECKER(LicenseManagementChecker, "Finds raw license management.") {
  BUG_TYPE(name = "Raw license management", category = "MTAS")

  BUILD_MATCHER() {
    return functionDecl(
        hasDescendant(
            callExpr(callee(functionDecl(anyOf(
                         hasName("TSPLicenseManagerBackend::requestLicense"),
                         hasName("LMFeatureHandler_mod::licenseRequest")))))
                .bind(KEY_NODE)),
        unless(matchesName("TSPLicenseManagerBackend::.*")));
  }

  HANDLE_MATCH(boundNodes, analysisManager) {
    REPORT_BUG("TSPLicenseManagerBackend should be used instead of raw license "
               "management.");
  }
}

bool ento::shouldRegisterLicenseManagementChecker(const CheckerManager &mgr) {
  return true;
}
