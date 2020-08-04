// RUN: %clang_analyze_cc1 %s \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -analyzer-config ipa=none \
// RUN:   -analyzer-config generate-llvm-ir=true \
// RUN:   -triple i686-unknown-linux \
// RUN:   -verify

void clang_analyzer_eval(int);

int g = 0;
int foo(int *x) { return *x; }

void test() {
  g = 3;
  int l = 0;
  foo(&l);
  clang_analyzer_eval(g == 3); // expected-warning{{TRUE}}
}
