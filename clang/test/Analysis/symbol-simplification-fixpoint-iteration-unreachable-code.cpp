// RUN: %clang_analyze_cc1 %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=debug.ExprInspection \
// RUN:   -verify

// In this test we check whether the solver's symbol simplification mechanism
// is capable of reaching a fixpoint.

void clang_analyzer_warnIfReached();

void test_contradiction(int a, int b, int c, int d, int x) {
  if (a + b + c != d)
    return;
  if (a == d)
    return;
  if (b + c != 0)
    return;
  clang_analyzer_warnIfReached(); // expected-warning{{REACHABLE}}

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

  // Enabling expensive checks would trigger an assertion failure here without
  // the fixpoint iteration.
  if (a + c == x)
    return;

  // Keep the symbols and the constraints! alive.
  (void)(a * b * c * d * x);
  return;
}

void clang_analyzer_printState();
void test_condtradiction_in_disequality_info(int a, int b, int c, int d) {
  if (a == d)
    return;
  if (a != 0)
    return;
  clang_analyzer_printState();
  (void)(a * b * c * d);
}

int pthread_mutex_lock(void *);
void clang_analyzer_printState();
void clang_analyzer_warnIfReached();
void clang_analyzer_eval(int);
void clang_analyzer_dump(int);
void top(int i, int n) {
  int rem = i % n; // -->     n != 0
  if (rem != i)    // --> i % n == i, associated constraint: ((i % n) != i) : {[0,0]}
    return;
  if (n != 1)      // -->     n == 1 --> i % 1 == i --> i == 0
    return;
  clang_analyzer_eval(i == 0); // expected-warning{{TRUE}}
  if (rem != i)    // --> i % n != i
    clang_analyzer_warnIfReached(); // no-warning
  (void)(i * n * rem);
}
