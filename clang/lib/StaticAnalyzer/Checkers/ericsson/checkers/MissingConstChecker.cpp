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
#include <unordered_map>
#include <utility>
#include <vector>

#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "llvm/ADT/StringRef.h"

#include "CheckerUtils/Common.h"
#include "CheckerUtils/VisitorBase.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

using namespace clang;
using namespace ento;
using namespace ericsson;

// This checker is based on constantine: https://github.com/rizsotto/Constantine
// TODO: handle mutable keyword on method const analysis?
// TODO: handle variables that are referenced through a reference to an alias
// (arbitrary depth).

namespace {
StringRef cfg_bugName = "Missing const";
StringRef cfg_bugCategory = "C++";

typedef std::pair<QualType, SourceRange> Usage;
typedef std::unordered_map<const DeclaratorDecl *, std::vector<Usage>>
    DeclToUsages;
using Declarations = std::set<const DeclaratorDecl *>;
using Methods = std::set<const CXXMethodDecl *>;

Declarations getVariablesFromContext(const DeclContext *ctx, bool withoutArgs) {
  Declarations result;
  for (auto decl : ctx->decls()) {
    if (const auto *varDecl = dyn_cast<VarDecl>(decl)) {
      if (!(withoutArgs && isa<ParmVarDecl>(varDecl))) {
        result.insert(varDecl);
      }
    }
  }
  return result;
}

Declarations getReferencedDeclarationsFromExpr(const Expr *expr);

bool getReferencedDeclarationsFromExprHelper(const Stmt *stmt,
                                             Declarations &result) {
  if (const auto *declRef = dyn_cast<DeclRefExpr>(stmt)) {
    result.insert(dyn_cast<DeclaratorDecl>(declRef->getDecl()));
    return true;
  }
  if (auto memberRef = dyn_cast<MemberExpr>(stmt)) {
    while (auto baseMemberRef = dyn_cast<MemberExpr>(memberRef->getBase())) {
      memberRef = baseMemberRef;
    }
    result.insert(dyn_cast<DeclaratorDecl>(memberRef->getMemberDecl()));
    return true;
  }
  return false;
}

Declarations getReferencedDeclarationsFromExpr(const Expr *expr) {
  Declarations result;

  if (!expr)
    return result;

  getReferencedDeclarationsFromExprHelper(expr, result);

  for (auto child : expr->children()) {
    const auto *subExpr = dyn_cast<Expr>(child);
    if (!getReferencedDeclarationsFromExprHelper(child, result) && subExpr) {
      Declarations tmp = getReferencedDeclarationsFromExpr(subExpr);
      result.insert(tmp.begin(), tmp.end());
    }
  }

  return result;
}

Declarations getReferencedDeclarations(const DeclaratorDecl *D) {
  Declarations result;

  Declarations temp;
  temp.insert(D);

  while (!temp.empty()) {
    const auto current = *(temp.begin());
    temp.erase(temp.begin());

    if (current) {
      result.insert(current);
    } else {
      continue;
    }

    const auto type = current->getType();
    if (!(type->isReferenceType() || type->isPointerType())) {
      continue;
    }

    if (const auto *var = dyn_cast<VarDecl>(current)) {
      Declarations tmp = getReferencedDeclarationsFromExpr(var->getInit());
      result.insert(tmp.begin(), tmp.end());
    }
  }

  return result;
}

Declarations getVariablesFromRecord(const CXXRecordDecl *record) {
  Declarations result;
  for (auto f : record->fields()) {
    if (const auto *field = dyn_cast<FieldDecl>(f)) {
      result.insert(field);
    }
  }
  for (auto b : record->bases()) {
    if (const CXXRecordDecl *base = getBaseFromSpecifier(b)) {
      Declarations tmp = getVariablesFromRecord(base);
      result.insert(tmp.begin(), tmp.end());
    }
  }
  return result;
}

Methods getMethodsFromRecord(const CXXRecordDecl *record) {
  Methods result;
  for (auto m : record->methods()) {
    if (const auto *method = dyn_cast<CXXMethodDecl>(m)) {
      result.insert(method->getCanonicalDecl());
    }
  }
  for (auto b : record->bases()) {
    if (const CXXRecordDecl *base = getBaseFromSpecifier(b)) {
      Methods tmp = getMethodsFromRecord(base);
      result.insert(tmp.begin(), tmp.end());
    }
  }
  return result;
}

class UsageCollector : public clang::RecursiveASTVisitor<UsageCollector> {
public:
  UsageCollector(DeclToUsages &usages, QualType type)
      : usages(usages), qualifierTracker(type) {}

  bool VisitDeclRefExpr(const DeclRefExpr *expr) {
    updateQualifierState();
    registerUsage(expr->getDecl(), expr->getSourceRange());
    return true;
  }

  bool VisitMemberExpr(const MemberExpr *expr) {
    updateQualifierState();
    registerUsage(expr->getMemberDecl(), expr->getSourceRange());
    return true;
  }

  bool VisitCastExpr(const CastExpr *expr) {
    updateQualifierState();
    return true;
  }

  bool VisitUnaryOperator(const UnaryOperator *expr) {
    if (expr->getOpcode() == UO_AddrOf || expr->getOpcode() == UO_Deref) {
      updateQualifierState();
    }
    return true;
  }

private:
  void updateQualifierState() {
    if (qualifierTracker != QualType())
      return;
  }

  void registerUsage(const ValueDecl *decl, const SourceRange &range) {
    Usage u(qualifierTracker, range);
    if (auto const D = dyn_cast<DeclaratorDecl>(decl->getCanonicalDecl())) {
      usages[D].push_back(u);
    }

    qualifierTracker = QualType();
  }

  DeclToUsages &usages;
  // TODO: better to only store a flag if const qualified?
  QualType qualifierTracker;
};

void RegisterDeclUsage(DeclToUsages &usages, const Expr *usageExpr,
                       const QualType &type = QualType()) {
  UsageCollector collector(usages, type);

  collector.TraverseStmt(
      const_cast<Stmt *>(static_cast<const Stmt *>(usageExpr)));
}

class MutationCollector : public RecursiveASTVisitor<MutationCollector> {
public:
  explicit MutationCollector(DeclToUsages &mutations) : mutations(mutations) {}

  bool VisitBinaryOperator(const BinaryOperator *stmt) {
    if (stmt->isAssignmentOp())
      RegisterDeclUsage(mutations, stmt->getLHS());
    return true;
  }

  bool VisitUnaryOperator(const UnaryOperator *stmt) {
    if (stmt->isIncrementDecrementOp()) {
      RegisterDeclUsage(mutations, stmt->getSubExpr());
    }
    return true;
  }

  bool VisitCXXConstructExpr(const CXXConstructExpr *stmt) {
    const auto constructor = stmt->getConstructor();
    for (unsigned i = 0; i < constructor->getNumParams(); ++i) {
      const auto decl = constructor->getParamDecl(i);
      if (IsNonConstReferenced(decl->getType())) {
        RegisterDeclUsage(mutations, stmt->getArg(i),
                          (*(decl->getType())).getPointeeType());
      }
    }
    return true;
  }

  bool VisitCallExpr(const CallExpr *stmt) {
    // some function call is a member call and has 'this' as a first
    // argument, which is not checked here.
    const int offset = HasThisAsFirstArgument(stmt) ? 1 : 0;

    if (const auto *callee = stmt->getDirectCallee()) {
      const unsigned maxIdx =
          std::min(callee->getNumParams(), stmt->getNumArgs());
      for (unsigned i = 0; i < maxIdx; ++i) {
        const auto *param = callee->getParamDecl(i);
        if (IsNonConstReferenced(param->getType())) {
          assert(i + offset < stmt->getNumArgs());
          RegisterDeclUsage(mutations, stmt->getArg(i + offset),
                            (*(param->getType())).getPointeeType());
        }
      }
    }
    return true;
  }

  bool VisitCXXMemberCallExpr(const CXXMemberCallExpr *stmt) {
    if (const auto *md = stmt->getMethodDecl()) {
      if ((!md->isConst()) && (!md->isStatic())) {
        RegisterDeclUsage(mutations, stmt->getImplicitObjectArgument());
      }
    }
    return true;
  }

  bool VisitCXXOperatorCallExpr(const CXXOperatorCallExpr *stmt) {
    // the implementation relies on that here the first argument
    // is the 'this', while it was not the case with CXXMethodDecl.
    if (const auto *callee = stmt->getDirectCallee()) {
      if (const auto *md = dyn_cast<CXXMethodDecl>(callee)) {
        if ((!md->isConst()) && (!md->isStatic()) && (0 < stmt->getNumArgs())) {
          RegisterDeclUsage(mutations, stmt->getArg(0));
        }
      }
    }
    return true;
  }

  bool VisitCXXNewExpr(const CXXNewExpr *stmt) {
    for (unsigned i = 0, end = stmt->getNumPlacementArgs(); i < end; ++i) {
      // FIXME: not all placement argument are mutating.
      RegisterDeclUsage(mutations, stmt->getPlacementArg(i));
    }
    return true;
  }

private:
  static bool IsNonConstReferenced(const QualType &type) {
    return ((*type).isReferenceType() || (*type).isPointerType()) &&
           (!(*type).getPointeeType().isConstQualified());
  }

  static bool HasThisAsFirstArgument(const CallExpr *stmt) {
    return (isa<CXXOperatorCallExpr>(stmt)) && (stmt->getDirectCallee()) &&
           (isa<CXXMethodDecl>(stmt->getDirectCallee()));
  }

  DeclToUsages &mutations;
};

// Will be used to check if a method can be static
class AccessCollector : public RecursiveASTVisitor<AccessCollector> {
public:
  explicit AccessCollector(DeclToUsages &accesses) : accesses(accesses) {}

  bool VisitDeclRefExpr(const DeclRefExpr *stmt) {
    RegisterDeclUsage(accesses, stmt);
    return true;
  }

  bool VisitMemberExpr(const MemberExpr *stmt) {
    if (isCXXThisExpr(stmt)) {
      RegisterDeclUsage(accesses, stmt);
    }
    return true;
  }

private:
  bool isCXXThisExpr(const Stmt *stmt) {
    if (isa<CXXThisExpr>(stmt))
      return true;
    for (auto child : stmt->children()) {
      if (isCXXThisExpr(child))
        return true;
    }
    return false;
  }

  DeclToUsages &accesses;
};

class MissingConstVisitor : public RecursiveASTVisitor<MissingConstVisitor>,
                            public VisitorBasedCheckerBase {
public:
  MissingConstVisitor(AnalysisManager &mgr, BugReporter &br, BugType *bugType,
                      bool checkValueParams)
      : VisitorBasedCheckerBase(mgr, br, bugType),
        checkValueParams(checkValueParams) {}

  ~MissingConstVisitor() {
    for (const DeclaratorDecl *d : constCandidates) {
      if (!d->isImplicit() && !d->getType().getTypePtr()->isDependentType())
        reportBug(d, "This declaration could be const.");
    }
  }

  bool VisitFunctionDecl(FunctionDecl *f) {
    if (!checkLocation(f))
      return true;

    if (!f->isThisDeclarationADefinition())
      return true;

    if (auto m = dyn_cast<CXXMethodDecl>(f)) {
      HandleMethodDecl(m);
    } else {
      HandleFunctionDecl(f);
    }

    return true;
  }

private:
  MissingConstVisitor(const MissingConstVisitor &) = delete;
  MissingConstVisitor(MissingConstVisitor &&) = delete;
  MissingConstVisitor &operator=(const MissingConstVisitor &) = delete;
  MissingConstVisitor &operator=(MissingConstVisitor &&) = delete;

  bool isMethod(const CXXMethodDecl *m) {
    return !m->isStatic() && m->isUserProvided() &&
           !m->isCopyAssignmentOperator() && !m->isMoveAssignmentOperator() &&
           !isa<CXXConstructorDecl>(m) && !isa<CXXConversionDecl>(m) &&
           !isa<CXXDestructorDecl>(m);
  }

  void HandleFunctionDecl(FunctionDecl *f) {
    DeclToUsages mutations;
    analyzeBody(f, mutations);
  }

  void HandleMethodDecl(CXXMethodDecl *m) {
    // variable constness
    DeclToUsages mutations;
    analyzeBody(m, mutations);

    // Method constness
    if (m->isVirtual() || !isMethod(m) || m->isConst())
      return;
    DeclToUsages accesses;
    {
      AccessCollector collector(accesses);
      collector.TraverseStmt(m->getBody());
    }

    const CXXRecordDecl *record = m->getParent()->getCanonicalDecl();

    Methods methods = getMethodsFromRecord(record);
    Declarations members = getVariablesFromRecord(record);

    int changedMembers = 0;
    for (const auto *member : members) {
      if (mutations.count(member))
        ++changedMembers;
    }

    int mutatingMethodCalls = 0;
    for (const auto *method : methods) {
      if (!method->isConst() && !method->isStatic() && accesses.count(method)) {
        ++mutatingMethodCalls;
      }
    }

    if (changedMembers == 0 && mutatingMethodCalls == 0)
      constCandidates.insert(m);
  }

  void analyzeBody(FunctionDecl *f, DeclToUsages &mutations) {
    {
      MutationCollector mutationCollector(mutations);
      mutationCollector.TraverseStmt(f->getBody());
    }
    Declarations candidates = getVariablesFromContext(f, !checkValueParams);

    // Every non const variable is a candidate for being const
    for (const auto *d : candidates) {
      if (!d->getType().getNonReferenceType().isConstQualified()) {
        constCandidates.insert(d);
      }
    }

    for (const DeclaratorDecl *d : candidates) {
      if (mutations.count(d)) {
        // Track declarations that could be modified through pointer or
        // reference
        for (const auto decl : getReferencedDeclarations(d)) {
          changedDecls.insert(decl);
          constCandidates.erase(decl);
        }
      }
    }
  }

  Declarations constCandidates;
  Declarations changedDecls;
  bool checkValueParams;
};

struct MissingConstChecker : public Checker<check::EndOfTranslationUnit> {
  void checkEndOfTranslationUnit(const TranslationUnitDecl *tuDecl,
                                 AnalysisManager &mgr, BugReporter &br) const {
    if (!m_bugType)
      m_bugType = std::make_unique<clang::ento::BugType>(this, cfg_bugName,
                                                         cfg_bugCategory);

    MissingConstVisitor missingConst(
        mgr, br, m_bugType.get(),
        mgr.getAnalyzerOptions().getCheckerBooleanOption(this,
                                                         "CheckValueParams"));
    missingConst.TraverseDecl(const_cast<TranslationUnitDecl *>(tuDecl));
  }

private:
  mutable std::unique_ptr<BugType> m_bugType;
};
} // end namespace

void ento::registerMissingConstChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<MissingConstChecker>();
}

bool ento::shouldRegisterMissingConstChecker(const CheckerManager &mgr) {
  return true;
}
