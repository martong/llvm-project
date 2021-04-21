// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.misrac.AssignmentInCondition -Wno-everything -verify %s
void f1() {
  int a = 1, b = 2;

  a = b;
  if (a == 2) {
  }
}

void f2() {
  int a = 1, b = 2;

  if ((a = b) == 2) {// expected-warning {{Assignment operator is used in a condition}}
  }
}

void f3() {
  int a = 1, b = 2;

  while ((a = b) == 2) {// expected-warning {{Assignment operator is used in a condition}}
  }
}

void f4() {
  int a = 1, b = 2;

  do {
  } while ((a = b) == 2);// expected-warning {{Assignment operator is used in a condition}}
}

void f5() {
  int a = 1, b = 2;

  for (;(a = b) == 2;) {// expected-warning {{Assignment operator is used in a condition}}
  }
}

void f6() {
  int a = 1, b = 2, x;

  x = (a = b) == 2 ? 1 : 0;// expected-warning {{Assignment operator is used in a condition}}
}

void f7() {
  int a = 1, b = 2, c = 6;

  if ((a - (b = c)) == 2) {// expected-warning {{Assignment operator is used in a condition}}
  }
}

int main() {
  return 0;
}
