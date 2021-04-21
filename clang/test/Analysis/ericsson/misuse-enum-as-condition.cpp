// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.cpp.MisuseEnumAsCondition -Wno-everything -verify %s
enum color {red, green, blue};
enum abc { A, B};
enum xyz { X = 1, Y = 2};

color getGreen() { return green; }
xyz getX() { return X; }

void f()
{
  color c;
  if (c)  // expected-warning {{Enum use like a boolean}} //  warn
    c = red;

  abc a = A;
  if (a)  // ok
    a = B;
}

void g()
{
  if(getGreen())  // expected-warning {{Enum use like a boolean}} // warn
    f();

  if (getX()) // expected-warning {{Enum use like a boolean}} // warn
    f();
}
