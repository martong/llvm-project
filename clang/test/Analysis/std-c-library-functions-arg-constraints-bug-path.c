// RUN: %clang_analyze_cc1 %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=apiModeling.StdCLibraryFunctions \
// RUN:   -analyzer-checker=apiModeling.StdCLibraryFunctionArgs \
// RUN:   -analyzer-checker=debug.ExprInspection \
// RUN:   -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-output=text \
// RUN:   -verify

void clang_analyzer_eval(int);

int glob;

#define EOF -1

int isalnum(int);

void test_alnum_symbolic(int x) {
  int ret = isalnum(x);
  (void)ret;
  clang_analyzer_eval(EOF <= x && x <= 255); // expected-warning{{TRUE}} expected-note{{TRUE}} expected-note{{Left side of '&&' is true}} expected-note{{'x' is <= 255}}
}

void test_alnum_symbolic2(int x) {
  if (x > 255) { // expected-note{{Assuming 'x' is > 255}} expected-note{{Taking true branch}}
    int ret = isalnum(x); // expected-warning{{Function argument constraint is not satisfied}} expected-note{{Function argument constraint is not satisfied}}
    (void)ret;
  }
}
