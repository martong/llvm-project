// RUN: %clang_analyze_cc1 %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=apiModeling.StdCLibraryFunctions \
// RUN:   -analyzer-checker=apiModeling.StdCLibraryFunctionArgs \
// RUN:   -analyzer-checker=debug.ExprInspection \
// RUN:   -triple x86_64-unknown-linux-gnu \
// RUN:   -verify

void clang_analyzer_eval(int);

int glob;

typedef struct FILE FILE;
#define EOF -1

int isalnum(int);

void test_alnum_concrete(int v) {
  int ret = isalnum(256); // expected-warning{{Function argument constraint is not satisfied}}
  (void)ret;
}

void test_alnum_symbolic(int x) {
  int ret = isalnum(x);
  (void)ret;
  clang_analyzer_eval(EOF <= x && x <= 255); // expected-warning{{TRUE}}
}

void test_alnum_symbolic2(int x) {
  if (x > 255) {
    int ret = isalnum(x); // expected-warning{{Function argument constraint is not satisfied}}
    (void)ret;
  }
}

void test_alnum_infeasible_path(int x, int y) {
  int ret = isalnum(x);
  y = 0;
  clang_analyzer_eval(EOF <= x && x <= 255); // expected-warning{{TRUE}}

  if (x > 255) {                             // This path is no longer feasible.
    ret = isalnum(x);
    ret = x / y; // No warning here
  }

  ret = x / y; // expected-warning{{Division by zero}}
}
