#include "CheckerUtils/VisitorBase.h"

#include "CheckerUtils/Common.h"

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"

#include <BugReporterHelper.h>

namespace clang {
namespace ento {
namespace ericsson {

VisitorBasedCheckerBase::VisitorBasedCheckerBase(
    clang::ento::AnalysisManager &mgr, clang::ento::BugReporter &br,
    clang::ento::BugType *const bugType)
    : m_mgr(mgr), m_br(br), m_bugType(bugType) {}

void VisitorBasedCheckerBase::reportBug(const Decl *node, StringRef message) {
  if (!checkLocation(node->getBeginLoc()))
    return;

  PathDiagnosticLocation loc =
      PathDiagnosticLocation(node, m_mgr.getSourceManager());
  SourceRange range = SourceRange(node->getLocation());

  DynTypedNode keyNode = DynTypedNode::create(*node);

  const Decl *parentDecl = nullptr;
  parentDecl = SearchValidEnclosingDecl(m_mgr, keyNode);

  auto bug_report = std::make_unique<BasicBugReport>(*m_bugType, message, loc);
  bug_report->setDeclWithIssue(parentDecl);
  bug_report->addRange(range);
  m_br.emitReport(std::move(bug_report));
}

void VisitorBasedCheckerBase::reportBug(const Stmt *stmt, StringRef message) {
  if (!checkLocation(stmt->getBeginLoc()))
    return;

  ASTContext &astContext = m_mgr.getASTContext();

  DynTypedNode keyNode = DynTypedNode::create(*stmt);

  const Decl *parentDecl = nullptr;
  parentDecl = SearchValidEnclosingDecl(m_mgr, keyNode);
  std::unique_ptr<BugReport> bugReport;

  if (parentDecl) {
    bugReport = std::make_unique<BasicBugReport>(
        *m_bugType, message,
        PathDiagnosticLocation(stmt, m_mgr.getSourceManager(),
                               m_mgr.getAnalysisDeclContext(parentDecl)));
  } else {
    SourceRange sourceRange = stmt->getSourceRange();
    if (!sourceRange.isValid() || isImplicitNode(stmt)) {
      auto parents = astContext.getParents(*stmt);
      assert(!parents.empty() &&
             "The given node is implicit, and has no explicit parents!");

      if (const auto *parentStmt = parents[0].get<Stmt>()) {
        reportBug(parentStmt,
                  (message + " (Issued for implicit child node.)").str());
      } else if (const auto *parentDecl = parents[0].get<Decl>()) {
        reportBug(parentDecl,
                  (message + " (Issued for implicit child node.)").str());
      } else {
        assert(false && "Parent type unhandled!");
      }

      return;
    }

    bugReport = std::make_unique<BasicBugReport>(
        *m_bugType, message,
        PathDiagnosticLocation(sourceRange.getBegin(),
                               m_mgr.getSourceManager()));
  }

  m_br.emitReport(std::move(bugReport));
}

void VisitorBasedCheckerBase::reportBug(SourceLocation loc, StringRef message) {
  if (!checkLocation(loc))
    return;

  m_br.emitReport(std::make_unique<BasicBugReport>(
      *m_bugType, message,
      PathDiagnosticLocation(loc, m_mgr.getSourceManager())));
}

StringRef VisitorBasedCheckerBase::getSourceCode(const SourceRange &range) {
  return Lexer::getSourceText(CharSourceRange::getCharRange(range),
                              m_mgr.getSourceManager(), m_mgr.getLangOpts());
}

bool VisitorBasedCheckerBase::checkLocation(SourceLocation loc) {
  if (!loc.isValid())
    return false;

  const SourceManager &sm = m_mgr.getSourceManager();
  if (isInSysHeader(sm.getSpellingLoc(loc), sm))
    return false;

  return true;
}

} // namespace ericsson
} // namespace ento
} // namespace clang
