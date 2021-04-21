#ifndef __VISITOR_BASE_H_
#define __VISITOR_BASE_H_

#include "llvm/ADT/StringRef.h"

#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"

namespace clang {
class Decl;
class Stmt;
namespace ento {
class BugReporter;
class BugType;
} // namespace ento
} // namespace clang

namespace clang {
namespace ento {
namespace ericsson {

class VisitorBasedCheckerBase {
public:
  VisitorBasedCheckerBase(clang::ento::AnalysisManager &mgr,
                          clang::ento::BugReporter &br,
                          clang::ento::BugType *const bugType);

  VisitorBasedCheckerBase(const VisitorBasedCheckerBase &) = delete;
  VisitorBasedCheckerBase &operator=(const VisitorBasedCheckerBase &) = delete;

protected:
  bool checkLocation(clang::SourceLocation loc);

  template <typename TNode> bool checkLocation(const TNode *node) {
    return checkLocation(node->getBeginLoc());
  }

  void reportBug(const clang::Decl *node, llvm::StringRef message);

  void reportBug(const clang::Stmt *stmt, llvm::StringRef message);

  void reportBug(clang::SourceLocation loc, llvm::StringRef message);

  llvm::StringRef getSourceCode(const clang::SourceRange &range);

  template <typename TNode> llvm::StringRef getSourceCode(const TNode *node) {
    clang::SourceRange range;
    range.setBegin(node->getBeginLoc());

    // getEndLoc() returns the beginning of the last token
    range.setEnd(
        node->getEndLoc().getLocWithOffset(clang::Lexer::MeasureTokenLength(
            node->getEndLoc(), m_mgr.getSourceManager(), m_mgr.getLangOpts())));
    return getSourceCode(range);
  }

  clang::ento::AnalysisManager &getAnalysisManager() { return m_mgr; }

  clang::ento::AnalysisManager &m_mgr;
  clang::ento::BugReporter &m_br;
  clang::ento::BugType *const m_bugType;
};

} // namespace ericsson
} // namespace ento
} // namespace clang

#endif
