// RUN: %clang_analyze_cc1 -std=c++14 -triple x86_64-pc-linux-gnu \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -analyzer-stats \
// RUN:   -analyze-function='baruser(int)' -x c++ \
// RUN:   -verify=nonctu %s

// RUN: %clang_analyze_cc1 %s -std=c++14 -triple x86_64-pc-linux-gnu \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -analyze-function='baruser(int)' -x c++ \
// RUN:   -analyzer-stats 2>&1 | FileCheck %s
// CHECK: 19 CoreEngine           - The # of steps executed.

// RUN: rm -rf %t && mkdir %t
// RUN: mkdir -p %t/ctudir
// RUN: %clang_cc1 -std=c++14 -triple x86_64-pc-linux-gnu \
// RUN:   -emit-pch -o %t/ctudir/ctu-onego-existingdef-other.cpp.ast %S/Inputs/ctu-onego-existingdef-other.cpp
// RUN: cp %S/Inputs/ctu-onego-existingdef-other.cpp.externalDefMap.ast-dump.txt %t/ctudir/externalDefMap.txt
// RUN: %clang_analyze_cc1 -std=c++14 -triple x86_64-pc-linux-gnu \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -analyzer-config experimental-enable-naive-ctu-analysis=true \
// RUN:   -analyzer-config ctu-dir=%t/ctudir \
// RUN:   -verify=ctu %s \
// RUN:   -analyzer-stats \
// RUN:   -analyze-function='baruser(int)' -x c++ \
// RUN:   -analyzer-config max-nodes=19
//                         ^^^^^^^^^^^^ Here we limit the number of nodes to
//                         that we had in the nonctu run. See the FileCheck
//                         above. This way, the second run on the FWList is
//                         disabled.

// Existing and equal function definition in both TU. `other` calls `bar` thus
// `bar` will be indirectly imported. During the import we recognize that there
// is an existing definition in the main TU, so we don't create a new Decl.
// Thus, ctu should not bifurcate on the call of `bar` it should directly
// inlinie that as in the case of nonctu.
int bar() {
  return 0;
}

void other(); // Defined in the other TU.

void baruser(int) {
  other();
  int x = bar();
  (void)(1 / x);
  // ctu-warning@-1{{Division by zero}}
  // nonctu-warning@-2{{Division by zero}}
}
