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

#include <unordered_map>
#include <unordered_set>
#include <utility>

#include <algorithm>

#include <cassert>

#include "llvm/ADT/StringRef.h"

#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"

#include "CheckerUtils/Common.h"
#include "CheckerUtils/VisitorBase.h"
#include "CppHelpers.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

using namespace clang;
using namespace ento;
using namespace ericsson;

namespace {

StringRef cfg_bugName = "Reduce Scope";
StringRef cfg_bugCategory = "C++";

struct DeclInfo {
  const CompoundStmt *enclosingCS;
  unsigned begin, end;
};

class ReduceScopeVisitor : public RecursiveASTVisitor<ReduceScopeVisitor>,
                           public VisitorBasedCheckerBase {
public:
  ReduceScopeVisitor(AnalysisManager &mgr, BugReporter &br,
                     BugType *const bugType)
      : VisitorBasedCheckerBase(mgr, br, bugType) {}

  bool VisitCompoundStmt(CompoundStmt *s) {
    if (!checkLocation(s))
      return true;

    const CompoundStmt *parent = nullptr;
    ast_type_traits::DynTypedNode node =
        ast_type_traits::DynTypedNode::create(*s);

    ASTContext &actxt = m_mgr.getASTContext();

    DynTypedNodeList p = actxt.getParents(node);
    if (!p.empty()) {
      // Do not bother with CompoundStmts under switch statements
      if (p[0].get<SwitchStmt>())
        return true;

      // Moving declarations into loops change the semantics of the code
      if (p[0].get<DoStmt>() || p[0].get<ForStmt>() || p[0].get<WhileStmt>() ||
          p[0].get<CXXForRangeStmt>()) {
        return true;
      }
    }

    while (!parent) {
      DynTypedNodeList p = actxt.getParents(node);
      if (p.empty())
        return true;

      // FIXME:
      // In case of multiple template instantiations only one of them is
      // considered.
      parent = p[0].get<CompoundStmt>();
      node = p[0];
    }

    compoundStmtTree[parent].insert(s);

    return true;
  }

  bool VisitDeclRefExpr(DeclRefExpr *d) {
    if (!checkLocation(d))
      return true;

    const ValueDecl *decl = d->getDecl();
    const DeclContext *dctxt = decl->getDeclContext();

    // Only interested in declRefExprs that are referenced in function and
    // method scopes.
    if (!dctxt->isFunctionOrMethod())
      return true;

    // We can not reduce the scope of function parameters
    if (llvm::dyn_cast<ParmVarDecl>(decl))
      return true;

    // We can not reduce the scope of catch parameters either
    if (const auto *varDecl = llvm::dyn_cast<VarDecl>(decl)) {
      if (varDecl->isExceptionVariable())
        return true;
    }

    SourceManager &src_mgr = m_mgr.getSourceManager();
    DeclInfo info{};
    if (declToRefs.count(decl)) {
      info = declToRefs[decl];
      info.begin =
          std::min(info.begin, src_mgr.getFileOffset(d->getBeginLoc()));
      info.end = std::max(
          info.end, src_mgr.getFileOffset(Lexer::getLocForEndOfToken(
                        d->getEndLoc(), 0, src_mgr, m_mgr.getLangOpts())));
    } else {
      info.begin = src_mgr.getFileOffset(d->getBeginLoc());
      info.end = src_mgr.getFileOffset(Lexer::getLocForEndOfToken(
          d->getEndLoc(), 0, src_mgr, m_mgr.getLangOpts()));

      ASTContext &actxt = decl->getASTContext();

      const CompoundStmt *cs = nullptr;
      ast_type_traits::DynTypedNode node =
          ast_type_traits::DynTypedNode::create(*decl);

      DynTypedNodeList p = actxt.getParents(node);
      while (!cs && p.size()) {
        // FIXME:
        // In case of multiple template instantiations only one of them is
        // considered.
        cs = p[0].get<CompoundStmt>();
        p = actxt.getParents(p[0]);
      }
      if (!cs)
        return true;

      info.enclosingCS = cs;
    }
    declToRefs[decl] = info;

    return true;
  }

  void reportReducableScopes() {
    for (const auto &declToRef : declToRefs) {
      if (isScopeReduceable(declToRef.second)) {
        reportBug(declToRef.first, "The scope of variable '" +
                                       declToRef.first->getNameAsString() +
                                       "' can be reduced.");
      }
    }
  }

private:
  bool isScopeReduceable(const DeclInfo &info) {
    assert(info.enclosingCS);

    for (const CompoundStmt *inner : compoundStmtTree[info.enclosingCS]) {
      if (inner->getBeginLoc().getRawEncoding() < info.begin &&
          Lexer::getLocForEndOfToken(inner->getEndLoc(), 0,
                                     m_mgr.getSourceManager(),
                                     m_mgr.getLangOpts())
                  .getRawEncoding() > info.end) {
        return true;
      }
    }
    return false;
  }

  std::unordered_map<const ValueDecl *, DeclInfo> declToRefs;
  std::unordered_map<const CompoundStmt *,
                     std::unordered_set<const CompoundStmt *>>
      compoundStmtTree;
};

struct ReduceScopeChecker : public Checker<check::EndOfTranslationUnit> {
  void checkEndOfTranslationUnit(const TranslationUnitDecl *tuDecl,
                                 AnalysisManager &mgr, BugReporter &br) const {
    if (!m_bugType)
      m_bugType = std::make_unique<clang::ento::BugType>(this, cfg_bugName,
                                                         cfg_bugCategory);

    ReduceScopeVisitor rs(mgr, br, m_bugType.get());
    rs.TraverseDecl(const_cast<TranslationUnitDecl *>(tuDecl));

    rs.reportReducableScopes();
  }

private:
  mutable std::unique_ptr<BugType> m_bugType;
};
} // end namespace

void ento::registerReduceScopeChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<ReduceScopeChecker>();
}

bool ento::shouldRegisterReduceScopeChecker(const CheckerManager &mgr) {
  return true;
}
