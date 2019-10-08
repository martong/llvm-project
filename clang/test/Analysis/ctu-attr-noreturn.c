// Test that imported function decls inherit attributes from existing functions
// in the "to" ctx and this way false positives are eliminated.
//
// RUN: rm -rf %t && mkdir %t
// RUN: mkdir -p %t/ctudir2
// RUN: %clang_cc1 -triple x86_64-pc-linux-gnu \
// RUN:   -emit-pch -o %t/ctudir2/ctu-attr-noreturn-other.c.ast \
// RUN:   %S/Inputs/ctu-attr-noreturn-other.c
// RUN: cp %S/Inputs/ctu-attr-noreturn.externalDefMap.txt \
// RUN:    %t/ctudir2/externalDefMap.txt
// RUN: %clang_cc1 -triple x86_64-pc-linux-gnu -fsyntax-only -std=c89 -analyze \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-config experimental-enable-naive-ctu-analysis=true \
// RUN:   -analyzer-config ctu-dir=%t/ctudir2 \
// RUN:   -verify %s

// expected-no-diagnostics

__attribute__((noreturn)) void fatal(void);

typedef struct {
  int a;
  int b;
} Data;

void ff(Data* data);

int caller(void) {
  Data d;
  ff(&d);
  int i = (int)d.b;// If the import of inherited attrs fail then a bug is
                   // reported here: "Assigned value is garbage or undefined".
  return i;
}
