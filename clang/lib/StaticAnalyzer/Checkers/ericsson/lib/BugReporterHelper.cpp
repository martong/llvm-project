#include <iostream>
#include <string>

#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/SourceManager.h"

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"

#include "llvm/Support/raw_ostream.h"

namespace clang {
namespace ento {
namespace ericsson {

using namespace llvm;

bool CheckValidEnclosingDeclContextSignature(
    const ast_type_traits::DynTypedNode &pNode) {

  const auto *D = pNode.get<Decl>();
  if (D == nullptr)
    return false;
  // Valid enclosing decls which can be used by the hash generator
  if (const auto *ND = dyn_cast<NamedDecl>(D)) {
    switch (ND->getKind()) {
    case Decl::Namespace:
    case Decl::Record:
    case Decl::CXXRecord:
    case Decl::Enum:
    case Decl::CXXConstructor:
    case Decl::CXXDestructor:
    case Decl::CXXConversion:
    case Decl::CXXMethod:
    case Decl::Function:
    case Decl::ObjCMethod:
      return true;
    default:
      return false;
    }
  }
  return false;
}

const Decl *
SearchValidEnclosingDecl(AnalysisManager &mgr,
                         const ast_type_traits::DynTypedNode &keyNode) {

  // go up in the AST searching for valid enclosing declarations
  ast_type_traits::DynTypedNode pNode =
      mgr.getASTContext().getParents(keyNode)[0];

  while (!mgr.getASTContext().getParents(pNode).empty() &&
         !(CheckValidEnclosingDeclContextSignature(pNode))) {
    pNode = mgr.getASTContext().getParents(pNode)[0];
  }
  return pNode.get<NamedDecl>();
}

void emitFlowReport(ast_type_traits::DynTypedNode keyNode, AnalysisManager &mgr,
                    BugReporter &br, const CheckerBase *checker,
                    StringRef bugName, StringRef bugCategory, StringRef bugStr,
                    PathDiagnosticLocation loc,
                    ArrayRef<SourceRange> ranges = None) {

  // SourceManager& sourceManager = mgr.getSourceManager();

  const Decl *parentDecl = nullptr;
  parentDecl = SearchValidEnclosingDecl(mgr, keyNode);

  br.EmitBasicReport(parentDecl, checker, bugName, bugCategory, bugStr, loc,
                     ranges);
}

} // namespace ericsson
} // namespace ento
} // namespace clang
