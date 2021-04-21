// RUN: %clang_analyze_cc1 -std=c++14 -analyzer-checker=alpha.ericsson.statisticscollector.ReturnValueCheck %s -verify 

/*
This test is to reproduce a case that caused a crash before it was fixed.
The intention is to get a CallExpr that contains a Callee that has an
"overloaded function type" as the type.

The call to "f_overload" is the place where an unresolved overload set
appears in the template part of the lambda (because "auto"). The type of
"p" is not known so the overload is not resolved.
(The AST contains this template part even if it has then a instantiation
with the fixed type, int in this case.)
*/

template<class T, class F>
void templ(const T& t, F f) {
  f(t);
}

int f_overload(int) {
  return 1;
}

int f_overload(double) {
  return 2;
}

void f1() {
  int i = 0;
  templ(i, [](const auto &p) {
    f_overload(p); // expected-warning{{c:@F@f_overload#I#,1}}
  });
}
