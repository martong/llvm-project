#ifndef __MATCHERS_DEBUG_H__
#define __MATCHERS_DEBUG_H__

#include <iostream>

#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"

#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/PrettyPrinter.h"

#include "clang/Basic/LangOptions.h"

#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchersInternal.h"
#include "clang/ASTMatchers/ASTMatchersMacros.h"

#include "CheckerUtils/Common.h"
#include "Matchers/Generic.h"

namespace clang {

namespace ast_matchers {

AST_POLYMORPHIC_MATCHER_P(writeMessage, void(internal::AllNodeBaseTypes),
                          std::string, msg) {
  llvm::errs() << msg << "\n";
  return true;
}

AST_POLYMORPHIC_MATCHER_P(dump,
                          AST_POLYMORPHIC_SUPPORTED_TYPES(Stmt, Decl, QualType),
                          std::string, label) {
  llvm::errs() << label << ": ";
  Node.dump();
  return true;
}

AST_MATCHER_P(NamedDecl, dumpName, std::string, label) {
  llvm::errs() << label << ": " << Node.getQualifiedNameAsString() << "\n";
  return true;
}

AST_MATCHER_P(Type, dumpType, std::string, label) {
  llvm::errs() << label << ": "
               << QualType::getAsString(&Node,
                                        Qualifiers(),
                                        PrintingPolicy(LangOptions()))
               << "\n";
  return true;
}

namespace debug_detail {
inline void dumpInfoHelper(const Stmt *stmt) {
  llvm::errs() << stmt->getStmtClassName();
  if (const Expr *expr = llvm::dyn_cast_or_null<Expr>(stmt)) {
    if (::clang::ento::ericsson::isImplicitNode(expr))
      llvm::errs() << " [implicit]";
    else
      llvm::errs() << " [explicit]";
  }
}

inline void dumpInfoHelper(const Decl *decl) {
  llvm::errs() << decl->getDeclKindName();
}
inline void dumpInfoHelper(const void *) {
  llvm::errs() << "(Unknown: not Stmt or Decl)";
}
} // namespace debug_detail

AST_POLYMORPHIC_MATCHER_P(dumpInfo, void(internal::AllNodeBaseTypes),
                          std::string, label) {
  llvm::errs() << label << ": ";
  debug_detail::dumpInfoHelper(&Node);
  llvm::errs() << "\n";
  return true;
}

AST_POLYMORPHIC_MATCHER(pause, void(internal::AllNodeBaseTypes)) {
  std::string _;
  std::getline(std::cin, _);
  return true;
}

} // end namespace ast_matchers

} // end namespace clang

#endif // __MATCHERS_DEBUG_H__
