// RUN: %clang_analyze_cc1 %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=debug.ExprInspection \
// RUN:   -verify

// In this test we check whether the solver's symbol simplification mechanism
// is capable of reaching a fixpoint.

void clang_analyzer_printState();
void clang_analyzer_warnIfReached();

void test_contradiction(int a, int b, int c, int d, int x) {
  if (a + b + c != d)
    return;
  if (a == d)
    return;
  if (c + b != 0)
    return;
  clang_analyzer_warnIfReached(); // expected-warning{{REACHABLE}}
  clang_analyzer_printState();

  // Bring in the contradiction.
  if (b != 0)
    return;

  // After the simplification of `b == 0` we have:
  //   b == 0
  //   a + c == d
  //   a != d
  //   c == 0
  // Doing another iteration we reach the fixpoint (with a contradiction):
  //   b == 0
  //   a == d
  //   a != d
  //   c == 0
  clang_analyzer_warnIfReached(); // no-warning, i.e. UNREACHABLE
  clang_analyzer_printState();

  // Enabling expensive checks would trigger an assertion failure here without
  // the fixpoint iteration.
  if (a + c == x)
    return;

  // Keep the symbols and the constraints! alive.
  (void)(a * b * c * d * x);
  return;
}
