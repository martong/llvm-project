#ifndef __COMMON_H__
#define __COMMON_H__

#include <cassert>
#include <string>
#include <vector>

#include "clang/AST/ASTConsumer.h"
#include "clang/Basic/SourceManager.h"

#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"

#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringRef.h"

namespace clang {
class ASTContext;
class CXXRecordDecl;
class CXXBaseSpecifier;
} // namespace clang

namespace clang {
namespace ento {
namespace ericsson {

using llvm::SmallString;
using llvm::StringRef;

const clang::CXXRecordDecl *
getBaseFromSpecifier(const clang::CXXBaseSpecifier specifier);

// Specifies whether the given AST node originates from a system header.
template <typename TNode>
bool isInSysHeader(const TNode *node,
                   const clang::SourceManager &sourceManager) {
  clang::SourceLocation nodeLoc = node->getBeginLoc();

  if (nodeLoc.isInvalid()) // cannot decide so report false
    return false;

  return sourceManager.isInSystemHeader(nodeLoc) ||
         sourceManager.isInExternCSystemHeader(nodeLoc);
}

bool isInSysHeader(clang::SourceLocation loc,
                   const clang::SourceManager &sourceManager);

template <typename TNode> bool isValidLoc(const TNode *node) {
  return node->getBeginLoc().isValid();
}

namespace impl_detail {
class GenericMatchCallback
    : public clang::ast_matchers::MatchFinder::MatchCallback {
public:
  std::vector<clang::ast_matchers::BoundNodes> node;

  virtual void
  run(const clang::ast_matchers::MatchFinder::MatchResult &Result) {
    node.push_back(Result.Nodes);
  }
};
} // namespace impl_detail

// Returns all bound nodes who are bound by the specified matcher expression in
// the translation unit specified by the given ASTContext. This function adds no
// bindings on its own, and the AST nodes must be retrieved manually from the
// bound nodes.
template <typename TMatcher>
std::vector<clang::ast_matchers::BoundNodes>
findAllMatches(TMatcher &&matcher, clang::ASTContext &ctx) {
  impl_detail::GenericMatchCallback cb;
  clang::ast_matchers::MatchFinder f;
  f.addMatcher(matcher, &cb);

  std::unique_ptr<clang::ASTConsumer> c = f.newASTConsumer();
  c->HandleTranslationUnit(ctx);

  return cb.node;
}

// Returns all nodes who satisfy the specified matcher in the current
// translation unit. Note: this will return a list of AST nodes, instead of a
// list of BoundNodes.
template <typename TResultNode, template <typename TMatchedNode> class TMatcher>
std::vector<const TResultNode *> findAllMatchedNodes(
    TMatcher<TResultNode> &&matcher, clang::ento::AnalysisManager &manager,
    bool ignoreSystemHeaders = true, bool ignoreNodesWithInvalidLoc = true) {
  const auto matchedNodes =
      findAllMatches(matcher.bind("__runMatcher__"), manager.getASTContext());

  std::vector<const TResultNode *> nodes;
  nodes.reserve(matchedNodes.size());

  for (const clang::ast_matchers::BoundNodes &bnode : matchedNodes) {
    const TResultNode *rnode = bnode.getNodeAs<TResultNode>("__runMatcher__");
    assert(rnode && "Matched node is NULL, wrong TResultNode?");

    if (!(ignoreNodesWithInvalidLoc && !isValidLoc(rnode)) &&
        !(ignoreSystemHeaders &&
          isInSysHeader(rnode, manager.getSourceManager())))
      nodes.push_back(rnode);
  }

  return nodes;
}

// Returns the body of the specified control statement: IfStmt, DoStmt,
// WhileStmt, ForStmt or ForRangeStmt. This is useful when you do not know
// during the runtime the exact type of the stmt, but you do know it's a control
// flow statement, and you need its body.
const clang::Stmt *getControlStmtBody(const clang::Stmt *controlStmt);

bool isImplicitNode(const clang::Stmt *stmt);

bool isLoopConstructStmt(const clang::Stmt *stmt);
bool isControlFlowConstructStmt(const clang::Stmt *stmt);

SmallString<128> removeTemplateArguments(StringRef S);

} // namespace ericsson
} // namespace ento
} // namespace clang

#endif // __COMMON_H__
