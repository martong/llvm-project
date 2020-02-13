// RUN: %clang_analyze_cc1 %s \
// RUN:   -analyzer-checker=apiModeling.StdCLibraryFunctions \
// RUN:   -analyzer-checker=debug.ExprInspection \
// RUN:   -triple x86_64-unknown-linux-gnu

void clang_analyzer_eval(int);

int glob;

typedef struct FILE FILE;
#define EOF -1

int isalnum(int);
void test_alnum_concrete() {
  int ret = isalnum(256); // expected-warning{{Function argument constraint is not satisfied}}
  (void)ret;
}
void test_alnum_symbolic(int x) {
  int ret = isalnum(x);
  (void)ret;
  clang_analyzer_eval(EOF <= x && x <= 255); // expected-warning{{TRUE}}
}
