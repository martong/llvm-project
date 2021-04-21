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

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;
using namespace clang::ast_matchers;

namespace {
class Callback : public MatchFinder::MatchCallback {
  BugReporter &BR;
  CheckerNameRef CN;

public:
  void run(const MatchFinder::MatchResult &Result);
  Callback(CheckerNameRef name, BugReporter &Reporter) : BR(Reporter),
                                                         CN(name) {}
};

void Callback::run(const MatchFinder::MatchResult &Result) {
  const auto *UnionDecl = Result.Nodes.getNodeAs<RecordDecl>("union");
  assert(UnionDecl);

  // Don't check unions with more than 2 fields.
  if (std::distance(UnionDecl->field_begin(), UnionDecl->field_end()) > 2)
    return;

  const FieldDecl *FirstIntField = nullptr;
  const FieldDecl *FirstMemsizeField = nullptr;

  for (const auto *Field : UnionDecl->fields()) {
    QualType FTy = Field->getType();
    // getTypeInfo asserts on dependentTypes
    if (FTy->isDependentType())
      return;

    TypeInfo FieldInfo = Field->getASTContext().getTypeInfo(FTy);

    // Find first pointer or memsize field.
    if (!FirstMemsizeField)
      if (FTy->isPointerType() ||
          (FTy->isIntegerType() && FieldInfo.Width == 64))
        FirstMemsizeField = Field;

    // Find first 32-bit wide field.
    if (!FirstIntField)
      if (FieldInfo.Width == 32)
        FirstIntField = Field;
  }

  if (!FirstIntField || !FirstMemsizeField)
    return;

  PathDiagnosticLocation UnionDeclLoc{UnionDecl, BR.getSourceManager()};
  // Make a static BugType in order to provide long-enough lifetime.
  static BugType BTY{CN, "Non portable union", "portability"};
  std::unique_ptr<BugReport> Report = std::make_unique<BasicBugReport>(
      BTY,
      "This union may be prone to 32 to 64 bits portability problems "
      "in case this 32-bit wide field is used to alter the bit-fields of the "
      "pointer or long in this union that has target dependent size.",
      UnionDeclLoc);
  PathDiagnosticLocation MemSizeFieldLoc{FirstMemsizeField,
                                         BR.getSourceManager()};

  Report->addNote("memsize or pointer field", MemSizeFieldLoc);
  PathDiagnosticLocation IntFieldLoc{FirstIntField, BR.getSourceManager()};
  Report->addNote("32-bit wide field", IntFieldLoc);
  BR.emitReport(std::move(Report));
}

class NonPortableUnionChecker : public Checker<check::EndOfTranslationUnit> {
public:
  void checkEndOfTranslationUnit(const TranslationUnitDecl *TU,
                                 AnalysisManager &AM, BugReporter &B) const;
};

void NonPortableUnionChecker::checkEndOfTranslationUnit(
    const TranslationUnitDecl *TU, AnalysisManager &AM, BugReporter &B) const {
  MatchFinder F;
  Callback CB(getCheckerName(), B);
  F.addMatcher(
      recordDecl(allOf(isUnion(), anyOf(has(fieldDecl(hasType(pointerType()))),
                                        has(fieldDecl(hasType(isInteger()))))))
          .bind("union"),
      &CB);
  F.matchAST(AM.getASTContext());
}
} // namespace

void ento::registerNonPortableUnionChecker(CheckerManager &mgr) {
  mgr.registerChecker<NonPortableUnionChecker>();
}

bool ento::shouldRegisterNonPortableUnionChecker(const CheckerManager &mgr) {
  return true;
}
