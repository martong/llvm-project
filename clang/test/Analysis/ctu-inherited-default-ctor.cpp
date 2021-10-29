// Should not crash with '-analyzer-opt-analyze-headers' option during CTU analysis.
//
// RUN: rm -rf %t && mkdir -p %t/ctudir
// RUN: %clang_cc1 -std=c++14 -triple x86_64-pc-linux-gnu \
// RUN:   -emit-pch -o %t/ctudir/ctu-inherited-default-ctor-other.cpp.ast \
// RUN:    %S/Inputs/ctu-inherited-default-ctor-other.cpp
// RUN: echo "c:@N@clang@S@DeclContextLookupResult@SingleElementDummyList ctu-inherited-default-ctor-other.cpp.ast" \
// RUN:   > %t/ctudir/externalDefMap.txt
//
// expected-no-diagnostics
//

namespace clang {}
namespace llvm {}
namespace clang {
class DeclContextLookupResult {
  static int *const SingleElementDummyList;
};
} // namespace clang
