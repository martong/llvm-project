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
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {

class MemsizeParamOverloadChecker
    : public Checker<check::ASTDecl<FunctionDecl>, check::PreStmt<CallExpr>> {
public:
  void checkASTDecl(const FunctionDecl *FD, AnalysisManager &AM,
                    BugReporter &) const {
    if (!FD->getDeclName().isIdentifier())
      return;

    MyOverloadCandidates &overloads = funcs[FD->getQualifiedNameAsString()];

    bool doInsert =
        overloads.empty() ||
        std::any_of(
            overloads.begin(), overloads.end(),
            [this, FD](const auto *candidate) {
              return !this->dangerousParamPositions(candidate, FD).empty();
            });

    if (doInsert)
      overloads.insert(FD->getMostRecentDecl());
  }

  void checkPreStmt(const CallExpr *call, CheckerContext &CC) const {
    const FunctionDecl *FD = call->getDirectCallee();

    if (!FD)
      return;

    if (!FD->getDeclName().isIdentifier())
      return;

    auto it = funcs.find(FD->getQualifiedNameAsString());
    if (it == funcs.end())
      return;

    for (const FunctionDecl *candidate : it->second) {
      unsigned candNum = candidate->getNumParams();
      unsigned callNum = call->getNumArgs();

      if (callNum != candNum &&
          (callNum <= candNum ||
           !llvm::isa<CXXDefaultArgExpr>(call->getArg(candNum))))
        continue;

      ParamPositions pos = dangerousParamPositions(FD, candidate);

      if (pos.empty())
        continue;

      unsigned p = *pos.begin();

      QualType t =
          stripElaboratedTypes(call->getArg(p)->IgnoreImpCasts()->getType());

      bool reportNeeded;
      if (AnyTypedefType)
        reportNeeded =
            llvm::isa<TypedefType>(t) &&
            FixedSizeInts.find(t.getAsString()) == FixedSizeInts.end();
      else
        reportNeeded = refersMemsizeType(t);

      if (reportNeeded) {
        BugReporter &BR = CC.getBugReporter();
        const SourceManager &SM = BR.getSourceManager();
        PathDiagnosticLocation loc(call->getBeginLoc(), SM);

        SourceLocation CallLoc = call->getBeginLoc();
        std::string FilePos = SM.getFilename(CallLoc).str();
        FilePos += ':';
        FilePos += std::to_string(SM.getSpellingLineNumber(CallLoc));
        FilePos += ':';
        FilePos += std::to_string(SM.getSpellingColumnNumber(CallLoc));

        static BugType bugType(this, "Erroneous Overload",
                               categories::LogicError);
        std::unique_ptr<BasicBugReport> bugReport(new BasicBugReport(
            bugType,
            "Overload resolution of this call depends on the architecture "
            "(because of parameter " +
                std::to_string(p + 1) +
                "). Two or "
                "more functions are defined with the same name, but "
                "architecture dependent arguments.",
            loc));
        bugReport->addNote("candidate function of call at " + FilePos,
                           PathDiagnosticLocation(FD->getBeginLoc(), SM));
        bugReport->addNote(
            "candidate function of call at " + FilePos,
            PathDiagnosticLocation(candidate->getBeginLoc(), SM));
        BR.emitReport(std::move(bugReport));

        break;
      }
    }
  }

  bool AnyTypedefType;

private:
  typedef llvm::SmallPtrSet<const FunctionDecl *, 4> MyOverloadCandidates;
  typedef llvm::SmallVector<unsigned, 4> ParamPositions;

  static const llvm::StringSet<> FixedSizeInts;
  static const llvm::StringSet<> MemsizeTypes;

  QualType stripElaboratedTypes(QualType t) const {
    while (const ElaboratedType *et = llvm::dyn_cast<ElaboratedType>(t))
      t = et->desugar();

    return t;
  }

  bool refersMemsizeType(clang::QualType t) const {
    while (const clang::TypedefType *tt =
               llvm::dyn_cast<clang::TypedefType>(t)) {
      if (MemsizeTypes.find(tt->getDecl()->getName()) != MemsizeTypes.end())
        return true;
      t = tt->desugar();
    }

    return MemsizeTypes.find(t.getAsString()) != MemsizeTypes.end();
  }

  ParamPositions dangerousParamPositions(const FunctionDecl *f1,
                                         const FunctionDecl *f2) const {
    ParamPositions result;

    unsigned pNum1 = f1->getNumParams();
    unsigned pNum2 = f2->getNumParams();

    for (unsigned i = 0, n = std::min(pNum1, pNum2); i < n; ++i) {
      const ParmVarDecl *param1 = f1->getParamDecl(i);
      const ParmVarDecl *param2 = f2->getParamDecl(i);

      QualType param1Type = param1->getType().getCanonicalType();
      QualType param2Type = param2->getType().getCanonicalType();

      if (param1Type->isDependentType() || param2Type->isDependentType())
        continue;

      if (!param1Type->isIntegerType() || !param2Type->isIntegerType())
        continue;

      if (param1->getASTContext().getTypeSize(param1Type) ==
          param2->getASTContext().getTypeSize(param2Type))
        continue;

      result.push_back(i);
    }

    return result;
  }

  mutable llvm::StringMap<MyOverloadCandidates> funcs;
};

// TODO: Depending on the definition of std::int32_t one of these may result
// after desugaring the QualType. It would be better to desugar the namespace
// somehow, but I couldn't find its way.
const llvm::StringSet<> MemsizeParamOverloadChecker::FixedSizeInts{
    "int8_t",       "int16_t",       "int32_t",       "int64_t",
    "uint8_t",      "uint16_t",      "uint32_t",      "uint64_t",
    "std::int8_t",  "std::int16_t",  "std::int32_t",  "std::int64_t",
    "std::uint8_t", "std::uint16_t", "std::uint32_t", "std::uint64_t",
    "::int8_t",     "::int16_t",     "::int32_t",     "::int64_t",
    "::uint8_t",    "::uint16_t",    "::uint32_t",    "::uint64_t"};

const llvm::StringSet<> MemsizeParamOverloadChecker::MemsizeTypes{
    "size_t",      "ptrdiff_t",      "intptr_t",      "uintptr_t",
    "std::size_t", "std::ptrdiff_t", "std::intptr_t", "std::uintptr_t"};

} // namespace

void ento::registerMemsizeParamOverloadChecker(CheckerManager &Mgr) {
  auto Chk = Mgr.registerChecker<MemsizeParamOverloadChecker>();
  Chk->AnyTypedefType =
      Mgr.getAnalyzerOptions().getCheckerBooleanOption(Chk, "AnyTypedefType");
}

bool ento::shouldRegisterMemsizeParamOverloadChecker(
    const CheckerManager &mgr) {
  return true;
}
