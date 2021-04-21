#ifndef __TRACKING_H__
#define __TRACKING_H__

#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

namespace clang {
class Stmt;
namespace ento {
class SVal;
class CheckerContext;
} // namespace ento
} // namespace clang

namespace clang {
namespace ento {
namespace ericsson {

// Attempts to find the SVal representing the lvalue from which the given rvalue
// expression is loaded. Returns UnknownSVal() if it cannot be found.
clang::ento::SVal getSourceLValue(const clang::Stmt *rvalueExpr,
                                  const clang::ento::ExplodedNode *node);

// Gets the ExplodedNode belonging to the last Stmt executed. This is useful in
// for example checkEndFunction if you want to get the return instruction.
const clang::ento::ExplodedNode *
getLastStmtNode(const clang::ento::ExplodedNode *sourceNode,
                clang::ento::CheckerContext &context);

inline const clang::ento::ExplodedNode *
getLastStmtNode(clang::ento::CheckerContext &context) {
  return getLastStmtNode(context.getPredecessor(), context);
}

inline const clang::Stmt *
getLastStmt(const clang::ento::ExplodedNode *sourceNode,
            clang::ento::CheckerContext &context) {
  const clang::ento::ExplodedNode *node = getLastStmtNode(sourceNode, context);
  if (!node)
    return nullptr;

  return node->getLocationAs<clang::StmtPoint>()->getStmt();
}

inline const clang::Stmt *getLastStmt(clang::ento::CheckerContext &context) {
  return getLastStmt(context.getPredecessor(), context);
}

} // namespace ericsson
} // namespace ento
} // namespace clang

#endif // __TRACKING_H__
