// RUN: rm -rf %t && mkdir %t
// RUN: mkdir -p %t/ctudir
// RUN: %clang_cc1 -std=c++14 -triple x86_64-pc-linux-gnu \
// RUN:   -emit-pch -o %t/ctudir/ctu-onego-astloadorder-other.cpp.ast %S/Inputs/ctu-onego-astloadorder-other.cpp
// RUN: cp %S/Inputs/ctu-onego-astloadorder-other.cpp.externalDefMap.ast-dump.txt %t/ctudir/externalDefMap.txt

//Here we completely supress the CTU work list execution. We should not load
//the AST of the other TU in this case, neither should we process the inlining
//of the 'other' function.
// RUN: %clang_analyze_cc1 -std=c++14 -triple x86_64-pc-linux-gnu \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -analyzer-config experimental-enable-naive-ctu-analysis=true \
// RUN:   -analyzer-config display-ctu-progress=true \
// RUN:   -analyzer-config ctu-max-nodes-mul=0 \
// RUN:   -analyzer-config ctu-max-nodes-min=0 \
// RUN:   -analyzer-config ctu-dir=%t/ctudir %s 2>&1 | FileCheck --check-prefix=STU-CHECK %s
// STU-CHECK-NOT: CTU loaded AST file
// STU-CHECK: Division by zero
// STU-CHECK-NOT: (1 / y)
// STU-CHECK: (1 / x)
// STU-CHECK-NOT: (1 / y)

//Here we enable the CTU work list execution. We should load
//the AST of the other TU in this case, and we should process the inlining
//of the 'other' function.
// RUN: %clang_analyze_cc1 -std=c++14 -triple x86_64-pc-linux-gnu \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -analyzer-config experimental-enable-naive-ctu-analysis=true \
// RUN:   -analyzer-config display-ctu-progress=true \
// RUN:   -analyzer-config ctu-max-nodes-mul=100 \
// RUN:   -analyzer-config ctu-max-nodes-min=1000 \
// RUN:   -analyzer-config ctu-dir=%t/ctudir %s 2>&1 | FileCheck --check-prefix=CTU-CHECK %s
// CTU-CHECK: CTU loaded AST file
//The order of the bugreports might be reversed, but that is irrelevant (that
//is why we use the DAG).
// CTU-CHECK-DAG: Division by zero
// CTU-CHECK-DAG: Division by zero
// CTU-CHECK-DAG: (1 / x)
// CTU-CHECK-DAG: (1 / y)

void other(); // Defined in the other TU.

void baruser(int x) {
  other();
  if (x == 0)
    (void)(1 / x);
}
