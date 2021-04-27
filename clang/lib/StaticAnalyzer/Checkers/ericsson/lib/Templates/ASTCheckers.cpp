#include "Templates/ASTCheckers.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/ASTTypeTraits.h"
#include "clang/Basic/SourceManager.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include <cassert>
#include <vector>

#include <BugReporterHelper.h>

namespace clang {
namespace ento {
namespace ericsson {
namespace template_impl_details {

MatcherProxy::MatcherProxy(ast_matchers::DeclarationMatcher &&declMatcher)
    : m_isDecl(true), m_isStmt(false),
      m_matcher(new ast_matchers::DeclarationMatcher(declMatcher)) {}

MatcherProxy::MatcherProxy(
    ::clang::ast_matchers::StatementMatcher &&stmtMatcher)
    : m_isDecl(false), m_isStmt(true),
      m_matcher(new ast_matchers::StatementMatcher(stmtMatcher)) {}

MatcherProxy::MatcherProxy(MatcherProxy &&other) noexcept
    : m_isDecl(other.m_isDecl), m_isStmt(other.m_isStmt),
      m_matcher(other.m_matcher) {
  other.m_matcher = nullptr;
}

bool MatcherProxy::isDeclMatcher() const { return m_isDecl; }
bool MatcherProxy::isStmtMatcher() const { return m_isStmt; }

const ast_matchers::DeclarationMatcher *MatcherProxy::asDeclMatcher() const {
  return m_isDecl ? reinterpret_cast<const ast_matchers::DeclarationMatcher *>(
                        m_matcher)
                  : nullptr;
}

const ast_matchers::StatementMatcher *MatcherProxy::asStmtMatcher() const {
  return m_isStmt ? reinterpret_cast<const ast_matchers::StatementMatcher *>(
                        m_matcher)
                  : nullptr;
}

MatcherProxy::~MatcherProxy() {
  if (m_isDecl) {
    delete asDeclMatcher();
  } else if (m_isStmt) {
    delete asStmtMatcher();
  }
}

AstCheckerBase::~AstCheckerBase() = default;

void AstCheckerBase::checkEndOfTranslationUnit(const TranslationUnitDecl *,
                                               AnalysisManager &mgr,
                                               BugReporter &br) const {
  if (!m_bugType)
    m_bugType.reset(getBugType());

  SourceManager &sourceManager = mgr.getSourceManager();
  ASTContext &astContext = mgr.getASTContext();

  MatcherProxy matcherProxy = getMatcher(mgr);

  std::vector<ast_matchers::BoundNodes> nodesList;
  if (const ast_matchers::DeclarationMatcher *declMatcher =
          matcherProxy.asDeclMatcher()) {
    nodesList = findAllMatches(*declMatcher, astContext);
  } else if (const ast_matchers::StatementMatcher *stmtMatcher =
                 matcherProxy.asStmtMatcher()) {
    nodesList = findAllMatches(*stmtMatcher, astContext);
  } else {
    assert(false && "The AST_CHECKER macro family only supports "
                    "statemenet and declaration matchers!");
  }

  for (const ast_matchers::BoundNodes &nodes : nodesList) {
    SourceLocation matchLoc;
    ast_type_traits::DynTypedNode dynNode;
    if (const auto *matchedDecl = nodes.getNodeAs<Decl>(KEY_NODE)) {
      matchLoc = matchedDecl->getBeginLoc();
      dynNode = ast_type_traits::DynTypedNode::create(*matchedDecl);
    } else if (const auto *matchedStmt = nodes.getNodeAs<Stmt>(KEY_NODE)) {
      matchLoc = matchedStmt->getBeginLoc();
      dynNode = ast_type_traits::DynTypedNode::create(*matchedStmt);
    } else {
      assert(false && "No node of supported type (Stmt, Decl) "
                      "has been bound as KEY_NODE!");
    }

    if (matchLoc.isValid() && !isInSysHeader(matchLoc, sourceManager)) {
      llvm::SmallVector<BugReportBuilder, 1> reports;
      handleMatch(nodes, mgr, reports);

      for (const BugReportBuilder &report : reports) {
        _emitReport(report, dynNode, mgr, br);
      }
    }
  }
}

void AstCheckerBase::_emitReport(const BugReportBuilder &report,
                                 const ast_type_traits::DynTypedNode keyNode,
                                 AnalysisManager &mgr, BugReporter &br) const {
  const Decl *decl = nullptr;
  const Stmt *stmt = nullptr;

  if (report.location.isNull()) {
    decl = keyNode.get<Decl>();
    stmt = keyNode.get<Stmt>();
  } else {
    decl = report.location.dyn_cast<const Decl *>();
    stmt = report.location.dyn_cast<const Stmt *>();
  }
  std::unique_ptr<BasicBugReport> bugReport;
  const Decl *parentDecl = nullptr;

  // fetching the enclosing declaration of the bug
  parentDecl = SearchValidEnclosingDecl(mgr, keyNode);

  if (decl) {
    bugReport = std::make_unique<clang::ento::BasicBugReport>(
        *m_bugType, report.message,
        PathDiagnosticLocation(decl, mgr.getSourceManager()));
  } else if (stmt) {
    if (parentDecl) {
      bugReport = std::make_unique<clang::ento::BasicBugReport>(
          *m_bugType, report.message,
          PathDiagnosticLocation(stmt, mgr.getSourceManager(),
                                 mgr.getAnalysisDeclContext(parentDecl)));
    } else {
      bugReport = std::make_unique<clang::ento::BasicBugReport>(
          *m_bugType, report.message,
          PathDiagnosticLocation(stmt->getBeginLoc(), mgr.getSourceManager()));
      bugReport->addRange(stmt->getSourceRange());
    }
  } else {
    assert(false && "AST_CHECKER only supports reporting "
                    "statements and declarations.");
  }

  if (report.addRange.isValid()) {
    bugReport->addRange(report.addRange);
  }
  if (parentDecl)
    bugReport->setDeclWithIssue(parentDecl);
  for (auto &&note : report.notes)
    bugReport->addNote(note.first, note.second);
  br.emitReport(std::move(bugReport));
}
} // namespace template_impl_details
} // namespace ericsson
} // namespace ento
} // namespace clang

