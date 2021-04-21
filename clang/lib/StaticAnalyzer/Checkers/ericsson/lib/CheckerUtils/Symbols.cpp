#include "CheckerUtils/Symbols.h"

#include "clang/AST/Decl.h"
#include "clang/AST/DeclCXX.h"

#include "clang/Analysis/AnalysisDeclContext.h"

#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"

namespace clang {
namespace ento {
namespace ericsson {

const MemRegion *getThisObject(CheckerContext &context) {
  const auto *methodDecl =
      dyn_cast<CXXMethodDecl>(context.getLocationContext()->getDecl());
  if (!methodDecl)
    return nullptr;

  const MemRegion *thisRegion =
      context.getSValBuilder()
          .getCXXThis(methodDecl->getParent(), context.getStackFrame())
          .getAsRegion();

  assert(thisRegion);

  return context.getState()->getSVal(thisRegion).getAsRegion();
}

} // namespace ericsson
} // namespace ento
} // namespace clang
