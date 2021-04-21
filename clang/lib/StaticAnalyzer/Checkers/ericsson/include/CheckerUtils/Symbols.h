#ifndef __SYMBOLS_H__
#define __SYMBOLS_H__

// TODO: figure out a better file name

namespace clang {
namespace ento {
class MemRegion;
class CheckerContext;
} // namespace ento
} // namespace clang

namespace clang {
namespace ento {
namespace ericsson {

// Gets the MemRegion representing the 'this' object we're currently in, i.e.
// evaluating a method of.
// Returns nullptr if we're not currently evaluating a CXXMethodDecl.
const clang::ento::MemRegion *
getThisObject(clang::ento::CheckerContext &context);

} // namespace ericsson
} // namespace ento
} // namespace clang

#endif // __SYMBOLS_H__