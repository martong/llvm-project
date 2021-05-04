#ifndef BUG_REPORTER_HELPER_HH
#define BUG_REPORTER_HELPER_HH

#include <iostream>
#include <string>

#include "clang/Basic/SourceManager.h"

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"

namespace clang {
namespace ento {
namespace ericsson {

/*
 * Search for a valid enclosing Decl if there is any
 * */
const clang::Decl *SearchValidEnclosingDecl(clang::ento::AnalysisManager &mgr,
                                            const clang::DynTypedNode &keyNode);
/*
 * Check if it is a valid enclosing decl which is used for bug id hash
 * generation
 * */
bool CheckValidEnclosingDeclContextSignature(const clang::DynTypedNode &pNode);

/*
 * report helper mainly for flow based checkers
 * */
void emitFlowReport(clang::DynTypedNode keyNode,
                    clang::ento::AnalysisManager &mgr,
                    clang::ento::BugReporter &br,
                    const clang::ento::CheckerBase *checker,
                    llvm::StringRef bugName, llvm::StringRef bugCategory,
                    llvm::StringRef bugStr,
                    clang::ento::PathDiagnosticLocation loc,
                    llvm::ArrayRef<clang::SourceRange> ranges = llvm::None);

} // namespace ericsson
} // namespace ento
} // namespace clang

#endif // BUG_REPORTER_HELPER_HH
