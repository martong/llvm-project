#ifndef __AST_CHECKERS_TEMPLATE_H__
#define __AST_CHECKERS_TEMPLATE_H__

#include <memory>
#include <string>
#include <utility> // std::move

#include "llvm/ADT/PointerUnion.h"
#include "llvm/ADT/SmallVector.h"

#include "clang/Analysis/PathDiagnostic.h"
#include "clang/ASTMatchers/ASTMatchers.h"

#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

#include "CheckerUtils/Common.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

namespace clang {
class Stmt;
class Decl;
namespace ento {
class BugReporter;
class AnalysisManager;
} // namespace ento
} // namespace clang

// See the wiki for documentation:
// https://plc.inf.elte.hu/model/trac/wiki/WritingASTCheckers

// The following skeleton code can be used to start developing an AST matcher:
/*
#include "templates/ast_checkers.h"

using namespace clang;
using namespace ast_matchers;

AST_CHECKER(SampleChecker, "Description of SampleChecker")
{
    BUG_TYPE(name = "Sample bug", category = "Samples")

    BUILD_MATCHER()
    {
        return myMatcher;
    }

    HANDLE_MATCH(boundNodes, analysisManager)
    {
        REPORT_BUG("Sample error message");
    }
}
*/

namespace clang {
namespace ento {
namespace ericsson {
namespace template_impl_details {

// TODO: Discriminated union or boost variant like stuff
class MatcherProxy {
public:
  MatcherProxy(::clang::ast_matchers::DeclarationMatcher &&declMatcher);
  MatcherProxy(::clang::ast_matchers::StatementMatcher &&stmtMatcher);
  MatcherProxy(MatcherProxy &&) noexcept;
  ~MatcherProxy();

  MatcherProxy(const MatcherProxy &) = delete;
  MatcherProxy operator=(const MatcherProxy &) = delete;
  MatcherProxy &operator=(MatcherProxy &&) = delete;

  bool isDeclMatcher() const;
  bool isStmtMatcher() const;

  const ::clang::ast_matchers::DeclarationMatcher *asDeclMatcher() const;
  const ::clang::ast_matchers::StatementMatcher *asStmtMatcher() const;

private:
  const bool m_isDecl;
  const bool m_isStmt;
  const void *m_matcher;
};

struct BugTypeBuilder {
  llvm::StringRef name = "(unspecified name)";
  llvm::StringRef category = "(unspecified category)";

  ::clang::ento::BugType *
  getBugType(const clang::ento::CheckerBase *base) const {
    return new ::clang::ento::BugType(base, name, category);
  }
};

struct BugReportBuilder {
  std::string message = "(No message specified)"; // TODO: llvm::Twine instead
  llvm::PointerUnion<const ::clang::Stmt *, const ::clang::Decl *>
      location; // use llvm::PointerUnion3, 4 when more type params are required
  ::clang::SourceRange addRange;
  llvm::SmallVector<std::pair<std::string, ::clang::ento::PathDiagnosticLocation>, 0>
      notes;
};

class AstCheckerBase : public ::clang::ento::Checker<
                           ::clang::ento::check::EndOfTranslationUnit> {
public:
  virtual ~AstCheckerBase();

  AstCheckerBase() = default;
  AstCheckerBase(const AstCheckerBase &) = delete;
  AstCheckerBase &operator=(const AstCheckerBase &) = delete;

  virtual ::clang::ento::BugType *getBugType() const = 0;
  virtual MatcherProxy getMatcher(::clang::ento::AnalysisManager &) const = 0;
  virtual void handleMatch(const ::clang::ast_matchers::BoundNodes &,
                           ::clang::ento::AnalysisManager &,
                           llvm::SmallVector<BugReportBuilder, 1> &) const = 0;

  void checkEndOfTranslationUnit(const ::clang::TranslationUnitDecl *tuDecl,
                                 ::clang::ento::AnalysisManager &mgr,
                                 ::clang::ento::BugReporter &br) const;

private:
  void _emitReport(const BugReportBuilder &report,
                   const ::clang::DynTypedNode keyNode,
                   ::clang::ento::AnalysisManager &mgr,
                   ::clang::ento::BugReporter &br) const;

  mutable std::unique_ptr<::clang::ento::BugType> m_bugType;
};

} // end namespace template_impl_details
} // namespace ericsson
} // namespace ento
} // namespace clang

#define KEY_NODE "__AST_CHECKER_KEYNODE__"

#define _AST_CHECKER_INTERNAL(_checkerName)                                    \
  namespace {                                                                  \
  ::clang::ento::BugType *getBugType(const clang::ento::CheckerBase *base);    \
  template_impl_details::MatcherProxy                                          \
  getMatcher(::clang::ento::AnalysisManager &,                                 \
             const clang::ento::CheckerBase *checker);                         \
  void handleMatch(                                                            \
      const ::clang::ast_matchers::BoundNodes &,                               \
      ::clang::ento::AnalysisManager &,                                        \
      const clang::ento::CheckerBase *checker,                                 \
      llvm::SmallVector<template_impl_details::BugReportBuilder, 1> &);        \
  class _checkerName : public ::template_impl_details::AstCheckerBase {        \
  public:                                                                      \
    virtual ::clang::ento::BugType *getBugType() const override {              \
      return ::getBugType(this);                                               \
    }                                                                          \
    virtual template_impl_details::MatcherProxy                                \
    getMatcher(::clang::ento::AnalysisManager &mgr) const override {           \
      return ::getMatcher(mgr, this);                                          \
    }                                                                          \
    virtual void                                                               \
    handleMatch(const ::clang::ast_matchers::BoundNodes &nodes,                \
                ::clang::ento::AnalysisManager &mgr,                           \
                llvm::SmallVector<template_impl_details::BugReportBuilder, 1>  \
                    &reports) const override {                                 \
      ::handleMatch(nodes, mgr, this, reports);                                \
    }                                                                          \
  };                                                                           \
  }                                                                            \
                                                                               \
  void ento::register##_checkerName(CheckerManager &Mgr) {                     \
    Mgr.registerChecker<_checkerName>();                                       \
  }                                                                            \
  namespace

// {} -- fix syntax highlighting

#define AST_CHECKER_PRIVATE(_checkerName) _AST_CHECKER_INTERNAL(_checkerName)
#define AST_CHECKER(_checkerName, _description)                                \
  _AST_CHECKER_INTERNAL(_checkerName)

#define BUG_TYPE(...)                                                          \
  ::clang::ento::BugType *getBugType(const clang::ento::CheckerBase *base) {   \
    template_impl_details::BugTypeBuilder b;                                   \
    auto &name = b.name;                                                       \
    auto &category = b.category;                                               \
    __VA_ARGS__;                                                               \
    (void)name;                                                                \
    (void)category;                                                            \
    return b.getBugType(base);                                                 \
  }

#define BUILD_MATCHER_WITH(_analysisManager, checker)                          \
  template_impl_details::MatcherProxy getMatcher(                              \
      ::clang::ento::AnalysisManager &_analysisManager,                        \
      const clang::ento::CheckerBase *checker)
#define BUILD_MATCHER()                                                        \
  template_impl_details::MatcherProxy getMatcher(                              \
      ::clang::ento::AnalysisManager &, const clang::ento::CheckerBase *)
#define MATCHER(_matcherExpr)                                                  \
  BUILD_MATCHER() {                                                            \
    return template_impl_details::MatcherProxy((_matcherExpr));                \
  }

#define HANDLE_MATCH(_nodesVar, _analysisManagerVar)                           \
  void handleMatch(const ::clang::ast_matchers::BoundNodes &_nodesVar,         \
                   ::clang::ento::AnalysisManager &_analysisManagerVar,        \
                   const clang::ento::CheckerBase *checker,                    \
                   llvm::SmallVector<template_impl_details::BugReportBuilder,  \
                                     1> &__bugReports)

#define REPORT_BUG_WITH(_message, ...)                                         \
  {                                                                            \
    template_impl_details::BugReportBuilder b;                                 \
    auto &location = b.location;                                               \
    auto &message = b.message;                                                 \
    auto &addRange = b.addRange;                                               \
    auto &notes = b.notes;                                                     \
    message = (_message);                                                      \
    __VA_ARGS__;                                                               \
    (void)location;                                                            \
    (void)addRange;                                                            \
    (void)notes;                                                               \
    __bugReports.push_back(b);                                                 \
  }

#define REPORT_BUG(_message) REPORT_BUG_WITH(_message, )

#endif // __AST_CHECKERS_TEMPLATE_H__
