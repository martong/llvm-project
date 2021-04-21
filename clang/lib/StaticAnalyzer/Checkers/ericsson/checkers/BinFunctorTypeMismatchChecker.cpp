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

#include "Templates/ASTCheckers.h"
#include "Matchers/Generic.h"
//#include "checker-utils/dumphelper.hpp"

//#include <iostream>

using namespace clang;
using namespace ast_matchers;
using namespace ento::ericsson;

// NOTE: Intentionally fails on typedefs?
// TODO: Validate against references to types (see the slides of the Advanced
// STL Presentation of Norbert Pataki)
// TODO: Detect wrong argument count!

AST_CHECKER(
    BinFunctorTypeMismatchChecker,
    "Detects std::binary_function template parameter type mismatches.") {
  BUG_TYPE(name = "Binary functor type inconsistency", category = "STL")

  BUILD_MATCHER() {
    return cxxRecordDecl(
               isDefinition(),
               // hasBaseType(qualType(hasDeclaration(namedDecl(hasName("std::binary_function")).bind("baseDecl"))).bind("baseType")),
               // // -- this does not work for template classes
               hasBaseType(qualType().bind("baseType")),
               has(cxxMethodDecl(hasName("operator()"),
                                 hasParameter(0, hasType(type().bind("P1"))),
                                 hasParameter(1, hasType(type().bind("P2"))),
                                 returns(type().bind("P3")))
                       .bind(KEY_NODE)))
        .bind("class");
  }

  std::string _getTypeName(const Type *type) {
    return QualType(type, 0).getAsString();
  }

  std::string _getTypeNameInfo(const Type *type) {
    if (type->isBooleanType() && !type->getAs<TypedefType>()) {
      return "type 'bool'";
    }

    std::string typeCategory = "type";
    if (type->getAs<TemplateTypeParmType>()) {
      typeCategory = "template parameter";
    }

    return typeCategory + " '" + _getTypeName(type) + "'";
  }

  bool _matchTypes(const Type *T, const Type *P, const std::string &name,
                   std::string *o_message, const ASTContext &ctxt) {
    assert(T && P);

    if (T == P)
      return true;

    if (P->isReferenceType() &&
        P->getPointeeType()->getCanonicalTypeUnqualified() ==
          T->getCanonicalTypeUnqualified())
      return true;

    if (P->isPointerType() && T->isPointerType() &&
        P->getPointeeType()->getCanonicalTypeUnqualified() ==
          T->getPointeeType()->getCanonicalTypeUnqualified())
      return true;

    *o_message = name + ": given " + _getTypeNameInfo(P) + " while expecting " +
                 _getTypeNameInfo(T) + ".";
    return false;
  }

  HANDLE_MATCH(bnode, mgr) {
    auto classDecl = bnode.getNodeAs<CXXRecordDecl>("class");
    auto method = bnode.getNodeAs<CXXMethodDecl>(KEY_NODE);
    auto baseType = bnode.getNodeAs<QualType>("baseType");
    assert(classDecl);
    assert(method);
    assert(baseType);

    std::string baseTypeName = _getTypeName(baseType->getTypePtr());
    baseTypeName = baseTypeName.substr(0, baseTypeName.find('<'));
    if (baseTypeName != "std::binary_function") {
      return;
    }

    const Type *T1 = nullptr, *T2, *T3;
    if (const auto recordType = baseType->getTypePtr()->getAs<RecordType>()) {
      if (const auto templateSpecDecl =
              llvm::dyn_cast_or_null<ClassTemplateSpecializationDecl>(
                  recordType->getDecl())) {
        const TemplateArgumentList &templateArgs =
            templateSpecDecl
                ->getTemplateInstantiationArgs(); // TODO: use
                                                  // getTemplateArgs()
                                                  // instead?
        T1 = templateArgs.get(0).getAsType().getTypePtr();
        T2 = templateArgs.get(1).getAsType().getTypePtr();
        T3 = templateArgs.get(2).getAsType().getTypePtr();
      }
    } else if (const auto tempSpecType =
                   baseType->getTypePtr()
                       ->getAs<TemplateSpecializationType>()) {
      T1 = tempSpecType->getArg(0).getAsType().getTypePtr();
      T2 = tempSpecType->getArg(1).getAsType().getTypePtr();
      T3 = tempSpecType->getArg(2).getAsType().getTypePtr();
    }

    assert(
        T1 &&
        "Failed to find the template argument types for std::binary_function!");
    if (!T1) {
      return;
    }

    /*BOUND_NODE(Type, "T1")
    bnode.getNodeAs<Type>("T1")
    bound_node<Type>("T1")*/

    std::string msgPrefix =
        "The class '" + classDecl->getQualifiedNameAsString() +
        "' is an std::binary_function, but the types don't match on ";
    std::string msgSuffix;
    SourceRange typeSourceRange;

    if (!_matchTypes(T1, bnode.getNodeAs<Type>("P1"), "parameter 1", &msgSuffix,
                     mgr.getASTContext())) {
      typeSourceRange = method->getParamDecl(0)
                            ->getTypeSourceInfo()
                            ->getTypeLoc()
                            .getSourceRange();
    } else if (!_matchTypes(T2, bnode.getNodeAs<Type>("P2"), "parameter 2",
                            &msgSuffix, mgr.getASTContext())) {
      typeSourceRange = method->getParamDecl(1)
                            ->getTypeSourceInfo()
                            ->getTypeLoc()
                            .getSourceRange();
    } else if (!_matchTypes(T3, bnode.getNodeAs<Type>("P3"), "the return value",
                            &msgSuffix, mgr.getASTContext())) {
      typeSourceRange = method->getTypeSourceInfo()
                            ->getTypeLoc()
                            .getAs<FunctionTypeLoc>()
                            .getReturnLoc()
                            .getSourceRange();
    } else {
      // all types match
      return;
    }

    REPORT_BUG_WITH(message = msgPrefix + msgSuffix,
                    addRange = typeSourceRange);
  }
}

bool ento::shouldRegisterBinFunctorTypeMismatchChecker(
    const CheckerManager &mgr) {
  const LangOptions &LO = mgr.getLangOpts();
  return LO.CPlusPlus;
}
