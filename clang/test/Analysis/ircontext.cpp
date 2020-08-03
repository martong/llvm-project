// RUN: %clang_analyze_cc1 %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-config ipa=none \
// RUN:   -triple i686-unknown-linux \
// RUN:   -verify

// expected-no-diagnostics

void clang_analyzer_eval(int);

int g = 0;
int foo(int *x) { return *x; }

void test() {
  g = 3;
  int l = 0;
  foo(&l);
}
