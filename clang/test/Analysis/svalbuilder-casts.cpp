// RUN: %clang_analyze_cc1 %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=debug.ExprInspection \
// RUN:   -analyzer-config support-symbolic-integer-casts=true \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -triple x86_64-unknown-linux-gnu \
// RUN:   -verify

// Test that the SValBuilder is able to look up and use a constraint for an
// operand of a SymbolCast, when the operand is constrained to a const value.

void clang_analyzer_eval(int);
void clang_analyzer_warnIfReached();

extern void abort() __attribute__((__noreturn__));
#define assert(expr) ((expr) ? (void)(0) : abort())

void test(int x) {
  // Constrain a SymSymExpr to a constant value.
  assert(x * x == 1);
  // It is expected to be able to get the constraint for the operand of the
  // cast.
  clang_analyzer_eval((char)(x * x) == 1); // expected-warning{{TRUE}}
  clang_analyzer_eval((long)(x * x) == 1); // expected-warning{{TRUE}}
}

void test1(int x) {
  // Even if two lower bytes of `x` equal to zero, it doesn't mean that
  // the entire `x` is zero. We are not able to know the exact value of x.
  // It can be one of  65536 possible values like [0, 65536, 131072, ...]
  // and so on. To avoid huge range sets we still assume `x` in the range
  // [INT_MIN, INT_MAX].
  if (!(short)x) {
    if (!x)
      clang_analyzer_warnIfReached(); // expected-warning {{REACHABLE}}
    else
      clang_analyzer_warnIfReached(); // expected-warning {{REACHABLE}}
  }
}

void test2(int x) {
  // If two lower bytes of `x` equal to zero, and we know x to be 65537,
  // which is not truncated to short as zero. Thus the branch is infisible.
  short s = x;
  if (!s) {
    if (x == 65537 || x == 131073)
      clang_analyzer_warnIfReached(); // no-warning
    else
      clang_analyzer_warnIfReached(); // expected-warning {{REACHABLE}}
  }
}
