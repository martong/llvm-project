#ifndef EXTRA_AST_MATCHERS_H
#define EXTRA_AST_MATCHERS_H

#include "clang/AST/Decl.h"
#include "clang/AST/DeclCXX.h"

#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchersInternal.h"

#include "CheckerUtils/Common.h"

namespace clang {

class Stmt;
class IndirectGotoStmt;

namespace ast_matchers {

/*
 * Matches indirect goto statements
 * */
const internal::VariadicDynCastAllOfMatcher<Stmt, IndirectGotoStmt>
    indirectGotoStmt;

AST_MATCHER_P(ClassTemplateDecl, hasTemplatedDecl,
              internal::Matcher<CXXRecordDecl>, InnerMatcher) {
  return InnerMatcher.matches(*(Node.getTemplatedDecl()), Finder, Builder);
}

AST_MATCHER_P_OVERLOAD(CXXRecordDecl, hasBase,
                       internal::Matcher<CXXBaseSpecifier>, InnerMatcher, 1) {
  for (auto it : Node.bases()) {
    if (InnerMatcher.matches(it, Finder, Builder)) {
      return true;
    }
  }
  return false;
}

AST_MATCHER_P(CXXRecordDecl, hasBaseType, internal::Matcher<QualType>,
              InnerMatcher) {
  for (auto it : Node.bases()) {
    if (InnerMatcher.matches(it.getType(), Finder, Builder)) {
      return true;
    }
  }
  return false;
}

AST_MATCHER(CXXBaseSpecifier, isPublicBase) {
  return Node.getAccessSpecifier() == AS_public;
}

AST_MATCHER(CXXBaseSpecifier, isProtectedBase) {
  return Node.getAccessSpecifier() == AS_protected;
}

AST_MATCHER(CXXBaseSpecifier, isPrivateBase) {
  return Node.getAccessSpecifier() == AS_private;
}

AST_MATCHER(CXXBaseSpecifier, isVirtualBase) { return Node.isVirtual(); }

AST_MATCHER_P(CXXBaseSpecifier, baseType, internal::Matcher<QualType>,
              InnerMatcher) {
  return InnerMatcher.matches(Node.getType(), Finder, Builder);
}

AST_MATCHER_P(QualType, unqualifiedType, internal::Matcher<Type>,
              InnerMatcher) {
  return InnerMatcher.matches(*Node, Finder, Builder);
}

AST_MATCHER_P_OVERLOAD(Type, desugar, internal::Matcher<Type>, InnerMatcher,
                       0) {
  return InnerMatcher.matches(*Node.getUnqualifiedDesugaredType(), Finder,
                              Builder);
}

AST_MATCHER_P_OVERLOAD(QualType, desugar, internal::Matcher<QualType>,
                       InnerMatcher, 1) {
  // return InnerMatcher.matches(Node.getDesugaredType(astContext??), Finder,
  // Builder);
  return InnerMatcher.matches(QualType(Node->getUnqualifiedDesugaredType(), 0),
                              Finder, Builder);
}

AST_MATCHER_P(ArrayType, arrayElementType, internal::Matcher<Type>,
              InnerMatcher) {
  return InnerMatcher.matches(*Node.getElementType(), Finder, Builder);
}

/*AST_MATCHER_P(TypedefType, underlyingType, internal::Matcher<QualType>,
InnerMatcher)
{
    return InnerMatcher.matches(Node.desugar(), Finder, Builder);
}*/

AST_MATCHER_P(TypeDecl, declaresType, internal::Matcher<Type>, InnerMatcher) {
  if (const Type *type = Node.getTypeForDecl()) {
    return InnerMatcher.matches(*type, Finder, Builder);
  }
  return false;
}

const internal::VariadicDynCastAllOfMatcher<Decl, TypeDecl> typeDecl;

AST_MATCHER_P2_OVERLOAD(Type, asQualified, unsigned, qualifiers,
                        internal::Matcher<QualType>, InnerMatcher, 1) {
  return InnerMatcher.matches(QualType(&Node, qualifiers), Finder, Builder);
}

AST_MATCHER_P(Type, asQualified, internal::Matcher<QualType>, InnerMatcher) {
  return InnerMatcher.matches(QualType(&Node, 0), Finder, Builder);
}

AST_MATCHER(Type, isBoolType) { return Node.isBooleanType(); }

AST_MATCHER_P(CastExpr, castKind, clang::CastKind, kind) {
  return Node.getCastKind() == kind;
}

AST_MATCHER_P(ClassTemplateDecl, hasAnySpecialization,
              internal::Matcher<ClassTemplateSpecializationDecl>,
              InnerMatcher) {
  for (auto it : Node.specializations()) {
    if (InnerMatcher.matches(*it, Finder, Builder)) {
      return true;
    }
  }
  return false;
}

AST_MATCHER_P(QualType, equalsType, QualType, type) { return Node == type; }

AST_MATCHER(Stmt, isImplicitStmt) { return ::clang::ento::ericsson::isImplicitNode(&Node); }

// Clang does have a hasMethod, but it does not look through inheritance I
// believe
AST_MATCHER_P(CXXRecordDecl, containsMethod, internal::Matcher<CXXMethodDecl>,
              innerMatcher) {
  return cxxRecordDecl(anyOf(has(cxxMethodDecl(innerMatcher)),
                             isDerivedFrom(cxxRecordDecl(
                                 has(cxxMethodDecl(innerMatcher))))))
      .matches(Node, Finder, Builder);
}

AST_MATCHER(Stmt, isLoopConstruct) { return ::clang::ento::ericsson::isLoopConstructStmt(&Node); }

AST_MATCHER(Stmt, isControlflowConstruct) {
  return ::clang::ento::ericsson::isControlFlowConstructStmt(&Node);
}

AST_POLYMORPHIC_MATCHER(nothing, void(internal::AllNodeBaseTypes)) {
  return false;
}

// TODO: Replace with a better method, when there will be supported ways
// keres pl. std::vector<bool> vagy std::vector<std::vector<bool>>, vagy stb.
// beágyazásokat
DeclarationMatcher replicateTemplateSpecWithArgument(DeclarationMatcher decl,
                                                     bool zeroLevel = false);

} // end namespace ast_matchers
} // end namespace clang

#endif // EXTRA_AST_MATCHERS_H
