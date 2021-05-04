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

#include <cassert>
#include <set>

#include "llvm/ADT/StringRef.h"
#include "llvm/Support/MemoryBuffer.h"

#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"

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

StringRef cfg_bugName = "MTAS Conventions";
StringRef cfg_bugCategory = "MTAS";

class MtasConventionsVisitor
    : public RecursiveASTVisitor<MtasConventionsVisitor>,
      public VisitorBasedCheckerBase {
public:
  MtasConventionsVisitor(AnalysisManager &mgr, BugReporter &br,
                         BugType *const bugType)
      : VisitorBasedCheckerBase(mgr, br, bugType) {}

  // TODO: test if this actually improves efficiency when implemented this way
  bool TraverseDecl(Decl *d) {
    if (!d || (d->getBeginLoc().isValid() && !checkLocation(d))) {
      return true; // bail out early if we have an irrelevant file
    }

    return RecursiveASTVisitor<MtasConventionsVisitor>::TraverseDecl(d);
  }

  bool VisitTranslationUnitDecl(TranslationUnitDecl *d) {
    if (!d)
      return true;

    SourceManager &mgr = d->getASTContext().getSourceManager();

    for (SourceManager::fileinfo_iterator it = mgr.fileinfo_begin();
         it != mgr.fileinfo_end(); ++it) {

      FileID fid = mgr.translateFile(it->first);

      if (isInSysHeader(mgr.getLocForStartOfFile(fid), mgr))
        continue;

      processBuffer(mgr.getBufferOrNone(fid), fid, mgr);
    }

    return true;
  }

  bool VisitTagDecl(TagDecl *d) {
    if (!checkLocation(d))
      return true;

    AccessSpecifier access = AS_public;
    for (auto decl : d->decls()) {
      if (access == decl->getAccess() || access == AS_none)
        continue;

      if (access > decl->getAccess() && isa<AccessSpecDecl>(decl)) {
        reportBug(decl, "The order of visibility in a class should be: "
                        "public, protected, private (whereas here '" +
                            getAccessString(access) +
                            "' is followed by this '" +
                            getAccessString(decl->getAccess()) + "').");
        break;
      }
      access = decl->getAccess();
    }
    return true;
  }

  bool VisitTypeDecl(TypeDecl *d) {
    if (!checkLocation(d))
      return true;

    if (!d->getDeclName().isIdentifier())
      return true;
    StringRef name = d->getName();

    if (name.size() > 0 && isLower(name[0])) {
      reportBug(d, "Type names should start with an uppercase letter.");
    }

    return true;
  }

  bool VisitVarDecl(VarDecl *d) {
    if (!checkLocation(d) || !d->getIdentifier())
      return true;

    QualType qualTy = d->getType();
    StringRef name = d->getName();

    auto &source_mgr = m_mgr.getSourceManager();
    auto loc = source_mgr.getPresumedLoc(d->getBeginLoc());

    StringRef fileName(loc.getFilename());

    if (fileName.endswith(".hh") &&
        d->isThisDeclarationADefinition() == VarDecl::Definition &&
        d->hasGlobalStorage()) {
      reportBug(d, "Definitions should be only in .cc files.");
    }

    if (qualTy.isConstQualified()) {
      for (char c : name) {
        if (isLower(c)) {
          reportBug(d, "Constants should only contain uppercase letters.");
          break;
        }
      }
      if (name.size() > 1 && qualTy->isBooleanType() &&
          name.substr(0, 2) != "IS") {
        reportBug(
            d, "Constant boolean variable names should be prefixed with 'IS'.");
      }
    } else {
      if (name.size() > 0 && isUpper(name[0])) {
        reportBug(d, "Variable names should start with a lowercase letter.");
      }
      if (name.size() > 1 && qualTy->isBooleanType() &&
          name.substr(0, 2) != "is") {
        reportBug(d, "Boolean variable names should be prefixed with 'is'.");
      }
    }

    return true;
  }

  bool VisitEnumConstantDecl(EnumConstantDecl *d) {
    if (!checkLocation(d))
      return true;

    if (!d->getDeclName().isIdentifier())
      return true;
    StringRef name = d->getName();
    for (char c : name) {
      if (isLower(c)) {
        reportBug(d, "Constants should only contain uppercase letters.");
        break;
      }
    }

    return true;
  }

  bool VisitFunctionDecl(FunctionDecl *d) {
    if (!checkLocation(d))
      return true;

    auto &source_mgr = m_mgr.getSourceManager();
    auto loc = source_mgr.getPresumedLoc(d->getBeginLoc());

    StringRef fileName(loc.getFilename());

    if (fileName.find(".hh") != std::string::npos &&
        d->doesThisDeclarationHaveABody() &&
        d->getTemplatedKind() == FunctionDecl::TK_NonTemplate) {
      reportBug(d, "Definitions should be only in .cc files.");
    }

    if (!isa<CXXConstructorDecl>(d)) {
      if (!d->getDeclName().isIdentifier())
        return true;

      StringRef name = d->getName();
      if (name.size() > 0 && isUpper(name[0])) {
        reportBug(
            d,
            "Function and method names should start with a lowercase letter.");
      }
    }

    return true;
  }

  bool VisitCXXMethodDecl(CXXMethodDecl *d) {
    if (!checkLocation(d) || !d->getDeclName().isIdentifier())
      return true;

    auto qualTy = d->getReturnType();
    StringRef name = d->getName();

    if (name.size() > 1 && qualTy->isBooleanType() &&
        name.substr(0, 2) != "is") {
      reportBug(d, "Methods returning bool should be prefixed with 'is'.");
    }

    return true;
  }

  bool VisitNamespaceDecl(NamespaceDecl *d) {
    if (!checkLocation(d))
      return true;

    if (!d->getDeclName().isIdentifier())
      return true;

    // Should be all lowercase
    for (char c : d->getName()) {
      if (isUpper(c)) {
        reportBug(d, "Namespace names should not contain uppercase letters.");
        break;
      }
    }

    return true;
  }

  bool VisitTemplateDecl(TemplateDecl *d) {
    if (!checkLocation(d))
      return true;

    // Arguments should be one upppercase letter
    for (NamedDecl *paramDecl : *d->getTemplateParameters()) {
      if (!paramDecl->getDeclName().isIdentifier())
        continue;

      StringRef paramDeclName = paramDecl->getName();
      if (paramDeclName.size() > 1 ||
          (paramDeclName.size() == 1 && isLower(paramDeclName[0]))) {
        reportBug(paramDecl,
                  "Template parameter names should consist of a single "
                  "uppercase letter.");
      }
    }

    return true;
  }

  bool VisitDeclRefExpr(DeclRefExpr *d) {
    if (!checkLocation(d))
      return true;

    // Globals should prefixed with ::

    // global if it a NamespaceDecl or TranslationUnitDecl as parent
    ASTContext &context = m_mgr.getASTContext();
    DynTypedNodeList v = context.getParents(*d->getDecl());

    if (v.empty())
      return true;

    DynTypedNode parent = v[0];
    if (parent.get<NamespaceDecl>() || parent.get<TranslationUnitDecl>()) {
      // now check if it was referred with '::'
      if (!Lexer::getSourceText(
               CharSourceRange::getCharRange(d->getSourceRange()),
               m_mgr.getSourceManager(), m_mgr.getLangOpts())
               .startswith("::")) {
        reportBug(d, "Global variables should always be referenced "
                     "absolutely, i.e. with the '::' prefix.");
      }
    }

    return true;
  }

  bool VisitFieldDecl(FieldDecl *d) {
    if (!checkLocation(d->getBeginLoc()))
      return true;

    if (!d->getDeclName().isIdentifier())
      return true;

    StringRef name = d->getName();
    if ((name.size() > 0 && name[0] != 'm') ||
        (name.size() > 1 && isLower(name[1]))) {
      reportBug(d,
                "Class variables should be prefixed with 'm', followed by an "
                "uppercase character.");
    }

    return true;
  }

  bool VisitImplicitCastExpr(ImplicitCastExpr *d) {
    if (!checkLocation(d))
      return true;

    Expr *sourceExpr = d->getSubExprAsWritten();

    QualType sourceType = sourceExpr->getType();
    QualType destType = d->getType();

    StringRef sourceExprKind = sourceExpr->getStmtClassName();
    if (destType->isBooleanType() && sourceExprKind.endswith("Literal"))
      return true;

    if (sourceType->getUnqualifiedDesugaredType() ==
        destType->getUnqualifiedDesugaredType()) {
      return true;
    }

    if (d->getCastKind() == CK_DerivedToBase ||
        d->getCastKind() == CK_UncheckedDerivedToBase ||
        d->getCastKind() == CK_BaseToDerivedMemberPointer) {
      return true;
    }

    if (sourceType->isBuiltinType() && destType->isBooleanType()) {
      // avoid implicit tests for 0, 0.0, etc.
      // e.g. if(x != 0) instead of if(x)
      reportBug(d, "Avoid implicit tests for zero values (converting type '" +
                       sourceType.getAsString() + "' to boolean)!");
    } else {
      reportBug(
          d,
          "Implicit casts are disallowed: use explicit cast to convert type '" +
              sourceType.getAsString() + "' to '" + destType.getAsString() +
              "'.");
    }

    return true;
  }

  // use while(true) for infinite loops, not while(1) or for(;;)
  bool VisitWhileStmt(WhileStmt *d) {
    if (!checkLocation(d))
      return true;

    checkAssignmentInCondition(d);

    const Expr *condExpr = d->getCond()->IgnoreParenImpCasts();
    if (const auto *intLiteral = llvm::dyn_cast<IntegerLiteral>(condExpr)) {
      if (intLiteral->getValue() != 0) {
        reportBug(
            condExpr,
            "Only while(true) constructs should be used for infinite loops.");
      }
    }

    return true;
  }

  bool VisitForStmt(ForStmt *d) {
    if (!checkLocation(d))
      return true;

    checkAssignmentInCondition(d);

    if (!d->getInit() && !d->getCond() && !d->getInc()) { // matches for(;;)
      reportBug(
          d, "Only while(true) constructs should be used for infinite loops.");
    }

    return true;
  }

  bool VisitDoStmt(DoStmt *d) {
    if (!checkLocation(d))
      return true;

    reportBug(d, "Do while loops should be avoided.");

    checkAssignmentInCondition(d);

    return true;
  }

  bool VisitIfStmt(IfStmt *d) {
    checkAssignmentInCondition(d);
    return true;
  }

  // Iterators should be i, j, k

  // Extension must be .cc or .hh

private:
  template <typename TNode> void checkAssignmentInCondition(TNode *d) {
    if (!checkLocation(d))
      return;

    const Expr *condExpr = d->getCond();

    if (!condExpr)
      return;

    using namespace clang::ast_matchers;

    auto assignment = expr(hasDescendant(
        expr(anyOf(binaryOperator(isAssignmentOperator()),
                   cxxOperatorCallExpr(isAssignmentOperator())))));
    auto nodes = match(assignment, *condExpr, m_mgr.getASTContext());

    if (!nodes.empty()) {
      reportBug(condExpr, "Assignments should be avoided in conditions.");
    }
  }

  void processBuffer(const llvm::Optional<llvm::MemoryBufferRef> buffer,
                     FileID fid, SourceManager &mgr) {
    if (!buffer)
      return;

    // We need to account column and line numbers to be able to get back source
    // locations to report bugs
    unsigned col = 0, line = 1;

    for (const char *it = buffer->getBufferStart();
         it != buffer->getBufferEnd(); ++it) {
      if (*it == '\n') {
        col = 0;
        ++line;
      } else {
        ++col;
      }

      if (*it == '\t' || *it == '\v' || *it == 12) {
        SourceLocation loc = mgr.translateLineCol(fid, line, col);
        reportBug(loc, "Invalid character is used near this position.");
      }
    }
  }

  std::string getAccessString(AccessSpecifier access) const {
    switch (access) {
    case AS_public:
      return "public";
    case AS_protected:
      return "protected";
    case AS_private:
      return "private";
    default:
      return "(none)";
    }
  }
};

struct MtasConventionsChecker : public Checker<check::EndOfTranslationUnit> {
  void checkEndOfTranslationUnit(const TranslationUnitDecl *tuDecl,
                                 AnalysisManager &mgr, BugReporter &br) const {
    if (!m_bugType)
      m_bugType = std::make_unique<clang::ento::BugType>(this, cfg_bugName,
                                                         cfg_bugCategory);
    MtasConventionsVisitor c(mgr, br, m_bugType.get());
    c.TraverseDecl(const_cast<TranslationUnitDecl *>(tuDecl));

    // 80 column limit
    // header guard (there is a tool in clang tools extra)
    // pointer and reference next to the types
  }

private:
  mutable std::unique_ptr<BugType> m_bugType;
};

} // namespace
void ento::registerMtasConventionsChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<MtasConventionsChecker>();
}

bool ento::shouldRegisterMtasConventionsChecker(const CheckerManager &mgr) {
  return true;
}
