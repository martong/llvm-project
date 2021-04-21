#include "CheckerUtils/Common.h"

#include "clang/AST/DeclCXX.h"

namespace clang {
namespace ento {
namespace ericsson {

using namespace clang::ast_matchers;

const CXXRecordDecl *getBaseFromSpecifier(const CXXBaseSpecifier specifier) {
  return specifier.getType()->getAsCXXRecordDecl();
}

bool isInSysHeader(SourceLocation loc, const SourceManager &sourceManager) {
  return sourceManager.isInSystemHeader(loc) ||
         sourceManager.isInExternCSystemHeader(loc);
}

const Stmt *getControlStmtBody(const Stmt *controlStmt) {
  if (const auto *ifStmt = dyn_cast<IfStmt>(controlStmt)) {
    return ifStmt->getThen();
  }
  if (const auto *forStmt = dyn_cast<ForStmt>(controlStmt)) {
    return forStmt->getBody();
  }
  if (const auto *whileStmt = dyn_cast<WhileStmt>(controlStmt)) {
    return whileStmt->getBody();
  }
  if (const auto *doStmt = dyn_cast<DoStmt>(controlStmt)) {
    return doStmt->getBody();
  }
  if (const auto *forRangeStmt = dyn_cast<CXXForRangeStmt>(controlStmt)) {
    return forRangeStmt->getBody();
  }
  return nullptr;
}

bool isImplicitNode(const Stmt *stmt) {
  return isa<ExprWithCleanups>(stmt) || isa<ImplicitCastExpr>(stmt) ||
         isa<MaterializeTemporaryExpr>(stmt) || isa<CXXConstructExpr>(stmt);
}

bool isLoopConstructStmt(const Stmt *stmt) {
  switch (stmt->getStmtClass()) {
  case Stmt::ForStmtClass:
  case Stmt::CXXForRangeStmtClass:
  case Stmt::WhileStmtClass:
  case Stmt::DoStmtClass:
    return true;

  default:
    return false;
  }
}

bool isControlFlowConstructStmt(const Stmt *stmt) {
  if (isLoopConstructStmt(stmt))
    return true;

  switch (stmt->getStmtClass()) {
  case Stmt::IfStmtClass:
  case Stmt::ConditionalOperatorClass:
  case Stmt::CXXTryStmtClass:
  case Stmt::CXXCatchStmtClass:
    return true;

  default:
    return false;
  }
}

SmallString<128> removeTemplateArguments(StringRef S) {
  SmallString<128> Result;
  llvm::raw_svector_ostream res(Result);
  int angles = 0;

  for (size_t i = 0; i < S.size(); ++i) {
    if (!angles && i >= 9 &&
        (S.substr(i - 9, 10) == " operator<" ||
         S.substr(i - 9, 10) == " operator>" ||
         S.substr(i - 9, 10) == ":operator<" ||
         S.substr(i - 9, 10) == ":operator>")) {
      res << S[i];
      continue;
    }

    if (!angles && i >= 10 &&
        (S.substr(i - 10, 11) == " operator<<" ||
         S.substr(i - 10, 11) == " operator>>" ||
         S.substr(i - 10, 11) == " operator->" ||
         S.substr(i - 10, 11) == ":operator<<" ||
         S.substr(i - 10, 11) == ":operator>>" ||
         S.substr(i - 10, 11) == ":operator->")) {
      res << S[i];
      continue;
    }

    angles += (S[i] == '<');
    if (!angles) {
      res << S[i];
    }
    angles -= (S[i] == '>');
  }

  return Result;
}

} // namespace ericsson
} // namespace ento
} // namespace clang
