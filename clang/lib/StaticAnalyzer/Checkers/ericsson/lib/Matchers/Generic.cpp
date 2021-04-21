#include "Matchers/Generic.h"

using namespace clang;
using namespace ast_matchers;

static const int templateInstCheckNestDeph = 3;

DeclarationMatcher
clang::ast_matchers::replicateTemplateSpecWithArgument(DeclarationMatcher decl,
                                                       bool zeroLevel) {
  auto templateSpecWithArgument = [](DeclarationMatcher decl) {
    return classTemplateSpecializationDecl(
        hasAnyTemplateArgument(refersToType(hasDeclaration(decl))));
  };

  DeclarationMatcher matcher = templateSpecWithArgument(decl);
  for (int i = 0; i < templateInstCheckNestDeph; ++i) {
    matcher = anyOf(matcher, templateSpecWithArgument(matcher));
  }

  if (zeroLevel)
    return anyOf(matcher, decl);

  return matcher;
}
