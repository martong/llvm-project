// RUN: %clang_analyze_cc1 -std=c++14 -analyzer-checker=core,unix.Malloc,debug.ExprInspection %s -analyzer-config eagerly-assume=false -verify

extern void clang_analyzer_eval(bool);
extern void clang_analyzer_warnIfReached();
extern void clang_analyzer_printState();

void test() {
  int i = 2;
  clang_analyzer_eval(i == 2); // expected-warning{{TRUE}}
}
