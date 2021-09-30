// RUN: %clang_analyze_cc1 %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -verify

// Here we test that if it turns out that the parent state is infeasible then
// both children States (more precisely the ExplodedNodes) are marked as a
// Sink.
// We rely on an existing defect of the underlying constraint solver. However,
// in the future we might strengthen the solver to discover the infeasibility
// right when we create the parent state. At that point this test will fail,
// and either we shall find another solver weakness to have this test case
// functioning, or we shall simply remove this test.

void clang_analyzer_warnIfReached();
void clang_analyzer_eval(int);

int a, b, c, d, e;
void f() {

  if (a == 0)
    return;

  if (e != c)
    return;

  d = e - c;
  b = d;
  a -= d;

  if (a != 0)
    return;

  clang_analyzer_warnIfReached(); // expected-warning{{REACHABLE}}

  /* The BASELINE passes these checks ('wrning' is used to avoid lit to match)
  // The parent state is already infeasible, look at this contradiction:
  clang_analyzer_eval(b > 0);  // expected-wrning{{FALSE}}
  clang_analyzer_eval(b <= 0); // expected-wrning{{FALSE}}
  // Crashes with expensive checks.
  if (b > 0) {
    clang_analyzer_warnIfReached(); // no-warning, OK
    return;
  }
  // Should not be reachable.
  clang_analyzer_warnIfReached(); // expected-wrning{{REACHABLE}}
  */

  // The parent state is already infeasible, but we realize that only if b is
  // constrained.
  clang_analyzer_eval(b > 0);  // expected-warning{{UNKNOWN}}
  clang_analyzer_eval(b <= 0); // expected-warning{{UNKNOWN}}
  if (b > 0) {
    clang_analyzer_warnIfReached(); // no-warning
    return;
  }
  clang_analyzer_warnIfReached(); // no-warning
}
