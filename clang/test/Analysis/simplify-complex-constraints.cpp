// RUN: %clang_analyze_cc1 %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -verify

// Here we test whether the analyzer is capable to simplify existing
// constraints based on newly added constraints on sub-expression.

void clang_analyzer_eval(bool);
void clang_analyzer_printState();

int test_left_tree_constrained(int x, int y, int z) {
  if (x + y + z != 0)
    return 0;
  if (x + y != 0)
    return 0;
  clang_analyzer_eval(x + y + z == 0); // expected-warning{{TRUE}}
  clang_analyzer_eval(x + y == 0);     // expected-warning{{TRUE}}
  clang_analyzer_eval(z == 0);         // expected-warning{{TRUE}}
  clang_analyzer_printState();
  x = y = z = 1;
  return 0;
}

int test_right_tree_constrained(int x, int y, int z) {
  if (x + (y + z) != 0)
    return 0;
  if (y + z != 0)
    return 0;
  clang_analyzer_eval(x + y + z == 0); // expected-warning{{TRUE}}
  clang_analyzer_eval(y + z == 0);     // expected-warning{{TRUE}}
  clang_analyzer_eval(x == 0);         // expected-warning{{TRUE}}
  return 0;
}
