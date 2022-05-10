// RUN: %clang_analyze_cc1 %s \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -verify

void clang_analyzer_eval(int);

int test(int flag) {
  if (-flag == 0) {
    clang_analyzer_eval(-flag == 0); // expected-warning{{TRUE}}
    clang_analyzer_eval(-flag > 0);  // expected-warning{{FALSE}}
    clang_analyzer_eval(-flag < 0);  // expected-warning{{FALSE}}
  }
  (void)(flag);
  return 42;
}
