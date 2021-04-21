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

#include <string>

#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/SourceManager.h"

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

#include "clang/Analysis/CallGraph.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"

#include "CheckerUtils/Common.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

using namespace clang;
using namespace ento;
using namespace ericsson;

namespace {
/** Instances of *_Dialogue Setup classes must be created
    in systemStarted() for static processes and
    in start() for dynamic processes. */

StringRef cfg_bugName = "Dialogue Setup Create";
StringRef cfg_bugCategory = "MTAS";
StringRef cfg_reportMessage =
    "Instances of Dialogue *_Setup classes must be created in systemStarted() "
    "for static processes and in start() for dynamic processes.";

class DialogueSetupCreateChecker : public Checker<check::EndOfTranslationUnit> {
public:
  void checkEndOfTranslationUnit(const TranslationUnitDecl *tuDecl,
                                 AnalysisManager &mgr, BugReporter &br) const {
    using namespace clang::ast_matchers;

    if (!m_bugType)
      m_bugType = std::make_unique<clang::ento::BugType>(this, cfg_bugName,
                                                         cfg_bugCategory);

    // Build CallGraph for current translation unit
    CallGraph c;
    c.addToCallGraph(const_cast<TranslationUnitDecl *>(tuDecl));
    CallGraph r;
    getReverseCallGraph(c, r);

    SourceManager &sourceManager = mgr.getSourceManager();
    std::string targetClassNameSuffix = "_Setup";

    auto matcher =
        cxxMethodDecl(
            hasDescendant(
                cxxConstructExpr(hasDeclaration(cxxMethodDecl(ofClass(
                                     cxxRecordDecl().bind("recordDecl")))))
                    .bind("constructExpr")))
            .bind("methodDecl");
    for (const clang::ast_matchers::BoundNodes &bnode :
         findAllMatches(matcher, mgr.getASTContext())) {
      const auto *recD = bnode.getNodeAs<CXXRecordDecl>("recordDecl");
      if (recD) {
        std::string recordName = recD->getNameAsString();
        size_t pos = recordName.rfind(targetClassNameSuffix);

        if (pos == (recordName.length() - targetClassNameSuffix.length()) &&
            pos != std::string::npos) {
          const auto *d = bnode.getNodeAs<CXXMethodDecl>("methodDecl");
          std::set<CallGraphNode *> alreadyVisited;
          if (d && !isInSysHeader(d, sourceManager) &&
              (d->getNameAsString().compare("systemStarted") &&
               (d->getNameAsString().compare("start") ||
                hasSystemStartedMethod(d->getParent())) &&
               !isCalledFromValidPlace(r.getNode(d), alreadyVisited))) {
            const auto *cExpr =
                bnode.getNodeAs<CXXConstructExpr>("constructExpr");
            SourceLocation bugLoc = cExpr->getSourceRange().getBegin();
            br.emitReport(std::make_unique<BasicBugReport>(
                *m_bugType, cfg_reportMessage,
                PathDiagnosticLocation(bugLoc, sourceManager)));
          }
        }
      }
    }
  }

private:
  /// @brief Make a reverse graph from parameter graph,
  /// e.g.: in c: a -> b, then in r: b <- a
  void getReverseCallGraph(CallGraph &c, CallGraph &r) const {
    for (CallGraph::iterator git = c.begin(), get = c.end(); git != get;
         ++git) {
      auto *decl = const_cast<Decl *>(git->first);
      if (c.getRoot()->getDecl() != decl) {
        CallGraphNode *d = r.getOrInsertNode(decl);
        for (auto dc : *git->second) {
          CallGraphNode *node = r.getOrInsertNode(dc.Callee->getDecl());
          node->addCallee({d,dc.CallExpr});
        }
      }
    }
  }

  /// @brief Valid if all branch has start or systemStarted node in route
  bool isCalledFromValidPlace(CallGraphNode *node,
                              std::set<CallGraphNode *> &alreadyVisited) const {
    if (node && alreadyVisited.find(node) == alreadyVisited.end()) {
      alreadyVisited.insert(node);
      bool isValidBranch = node->size() != 0;
      for (auto &elem : *node) {
        if (auto *md = dyn_cast<CXXMethodDecl>(elem.Callee->getDecl())) {
          // if (!(!md->getNameAsString().compare("systemStarted") ||
          //       (!md->getNameAsString().compare("start") &&
          //        !hasSystemStartedMethod(md->getParent()))))
          if (md->getNameAsString().compare("systemStarted") &&
              (md->getNameAsString().compare("start") ||
               hasSystemStartedMethod(md->getParent()))) {
            isValidBranch =
                isValidBranch && isCalledFromValidPlace(elem, alreadyVisited);
          }
        }
      }
      return isValidBranch;
    }
    return false;
  }

  /// @brief Has systemStarted method of the current class
  bool hasSystemStartedMethod(const CXXRecordDecl *rd) const {
    if (rd) {
      for (auto method : rd->methods()) {
        if (!method->getNameAsString().compare("systemStarted"))
          return true;
      }
    }
    return false;
  }

  mutable std::unique_ptr<BugType> m_bugType;
};

} // namespace

void ento::registerDialogueSetupCreateChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<DialogueSetupCreateChecker>();
}

bool ento::shouldRegisterDialogueSetupCreateChecker(const CheckerManager &mgr) {
  return true;
}
