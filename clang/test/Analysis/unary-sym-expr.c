// RUN: %clang_analyze_cc1 %s \
// RUN:   -analyzer-checker=core,debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -verify

void clang_analyzer_eval(int);
void clang_analyzer_dump(int);
void clang_analyzer_explain(int);

int test(int flag) {

  clang_analyzer_dump(-flag);    // expected-warning{{-reg_$0<int flag>}}
  clang_analyzer_explain(-flag); // expected-warning{{- (argument 'flag')}}

  if (-flag == 0) {
    clang_analyzer_eval(-flag == 0); // expected-warning{{TRUE}}
    clang_analyzer_eval(-flag > 0);  // expected-warning{{FALSE}}
    clang_analyzer_eval(-flag < 0);  // expected-warning{{FALSE}}
  }
  (void)(flag);
  return 42;
}
