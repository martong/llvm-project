#ifndef __MATCHERS_BACKPORT_H__
#define __MATCHERS_BACKPORT_H__

#include <string>

#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchersInternal.h"
#include "clang/ASTMatchers/ASTMatchersMacros.h"

namespace clang {

class Stmt;
class Decl;
class Type;
class QualType;

namespace ast_matchers {} // end namespace ast_matchers
} // end namespace clang

#endif // __MATCHERS_BACKPORT_H__