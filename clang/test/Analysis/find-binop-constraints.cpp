// RUN: %clang_analyze_cc1 %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -verify

void clang_analyzer_eval(bool);

int test_legacy_behavior(int x, int y) {
  if (y != 0)
    return 0;
  if (x + y != 0)
    return 0;
  clang_analyzer_eval(x + y == 0); // expected-warning{{TRUE}}
  clang_analyzer_eval(y == 0);     // expected-warning{{TRUE}}
  return y / (x + y);              // expected-warning{{Division by zero}}
}

int test_rhs_further_constrained(int x, int y) {
  if (x + y != 0)
    return 0;
  if (y != 0)
    return 0;
  clang_analyzer_eval(x + y == 0); // expected-warning{{TRUE}}
  clang_analyzer_eval(y == 0);     // expected-warning{{TRUE}}
  return 0;
}

int test_lhs_further_constrained(int x, int y) {
  if (x + y != 0)
    return 0;
  if (x != 0)
    return 0;
  clang_analyzer_eval(x + y == 0); // expected-warning{{TRUE}}
  clang_analyzer_eval(x == 0);     // expected-warning{{TRUE}}
  return 0;
}

int test_lhs_and_rhs_further_constrained(int x, int y) {
  if (x % y != 1)
    return 0;
  if (x != 1)
    return 0;
  if (y != 2)
    return 0;
  clang_analyzer_eval(x % y == 1); // expected-warning{{TRUE}}
  clang_analyzer_eval(y == 2);     // expected-warning{{TRUE}}
  return 0;
}

int test_commutativity(int x, int y) {
  if (x + y != 0)
    return 0;
  if (y != 0)
    return 0;
  clang_analyzer_eval(y + x == 0); // expected-warning{{TRUE}}
  clang_analyzer_eval(y == 0);     // expected-warning{{TRUE}}
  return 0;
}

int test_binop_when_height_is_2_r(int a, int x, int y, int z) {
  switch (a) {
  case 1: {
    if (x + y + z != 0)
      return 0;
    if (z != 0)
      return 0;
    clang_analyzer_eval(x + y + z == 0); // expected-warning{{TRUE}}
    clang_analyzer_eval(z == 0);         // expected-warning{{TRUE}}
    break;
  }
  case 2: {
    if (x + y + z != 0)
      return 0;
    if (y != 0)
      return 0;
    clang_analyzer_eval(x + y + z == 0); // expected-warning{{TRUE}}
    clang_analyzer_eval(y == 0);         // expected-warning{{TRUE}}
    break;
  }
  case 3: {
    if (x + y + z != 0)
      return 0;
    if (x != 0)
      return 0;
    clang_analyzer_eval(x + y + z == 0); // expected-warning{{TRUE}}
    clang_analyzer_eval(x == 0);         // expected-warning{{TRUE}}
    break;
  }
  case 4: {
    if (x + y + z != 0)
      return 0;
    if (x + y != 0)
      return 0;
    clang_analyzer_eval(x + y + z == 0); // expected-warning{{TRUE}}
    clang_analyzer_eval(x + y == 0);     // expected-warning{{TRUE}}
    break;
  }
  case 5: {
    if (z != 0)
      return 0;
    if (x + y + z != 0)
      return 0;
    clang_analyzer_eval(x + y + z == 0); // expected-warning{{TRUE}}
    if (y != 0)
      return 0;
    clang_analyzer_eval(y == 0);         // expected-warning{{TRUE}}
    clang_analyzer_eval(z == 0);         // expected-warning{{TRUE}}
    clang_analyzer_eval(x + y + z == 0); // expected-warning{{TRUE}}
    break;
  }

  }
  return 0;
}
