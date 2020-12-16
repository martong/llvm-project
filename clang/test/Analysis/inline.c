// RUN: %clang_analyze_cc1 -analyzer-checker=core,debug.ExprInspection -verify %s

void clang_analyzer_eval(int);
void clang_analyzer_checkInlined(int);

// Test that passing a struct value with an uninitialized field does
// not trigger a warning if we are inlining and the body is available.
int test_1() {
  int b = 2;
  b += 3;
  return 3;
}
