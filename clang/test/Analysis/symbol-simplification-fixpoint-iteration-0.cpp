// RUN: %clang_analyze_cc1 %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=debug.ExprInspection \
// RUN:   -verify

// In this test we check whether the solver's symbol simplification mechanism
// is capable of reaching a fixpoint.

void clang_analyzer_printState();
void clang_analyzer_warnIfReached();

void test_contradiction(int a, int b, int c, int d, int x) {
  if (a + b != c)
    return;
  clang_analyzer_printState();
  if (b != 0)
    return;
  clang_analyzer_printState();

  // Keep the symbols and the constraints! alive.
  (void)(a * b * c * d);
  return;
}
